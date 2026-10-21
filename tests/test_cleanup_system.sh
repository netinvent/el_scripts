#!/usr/bin/env bash

# Tests for cleanup_system() in el_configurator.sh
#
# The end of run cleanup used to be an unconditional block. That block is correct when it prepares
# a VM for cloning and destructive when the script is re run on a machine already in service: it
# removed /var/lib/dnf, which is where dnf keeps history.sqlite, so dnf history undo and rollback
# were gone for good, along with the logs, the NetworkManager leases and the DNSSEC trust anchor.
# It also deleted /etc/*-, which is not editor litter but the backup copies shadow-utils keeps of
# passwd, shadow, group and gshadow.
#
# cleanup_system() splits that into a live mode and a master mode. These tests run the real
# function against a sandbox tree, with the absolute paths rewritten into a work directory and the
# external commands stubbed on PATH, and assert what each mode does and does not remove.
#
# Usage: tests/test_cleanup_system.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^cleanup_system() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate cleanup_system() in [${SCRIPT}]"
    exit 2
fi
end=$(awk -v s="${start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")

WORK=$(mktemp -d)
HELPERS="${WORK}/cleanup_system.sh"
BIN="${WORK}/bin"
CALLS="${WORK}/calls.log"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${BIN}"

# Read by the extracted function, which the linter cannot see, hence the SC2034 waivers
# shellcheck disable=SC2034
LOG_FILE=/dev/null
LOGGED_ERRORS=0
# shellcheck disable=SC2034
POST_INSTALL_SCRIPT_GOOD=true
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
        # shellcheck disable=SC2034
        POST_INSTALL_SCRIPT_GOOD=false
    fi
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

# The function operates on absolute system paths, which these tests must not touch. Rewrite them
# into the work directory. rm stays real so that removal can actually be asserted
sed -n "${start},${end}p" "${SCRIPT}" \
    | sed -E "s#([ \"])/(root|etc|tmp|var|proc)/#\1${WORK}/\2/#g" > "${HELPERS}"

# Stubs for everything the function shells out to. They record the call and succeed, so that
# command -v finds them and the branch under test is the one that runs
for cmd in dnf apt-get systemd-tmpfiles journalctl cloud-init sync; do
    {
        echo "#!/bin/sh"
        echo "echo \"${cmd} \$*\" >> \"\${CALLS}\""
        echo "exit 0"
    } > "${BIN}/${cmd}"
    chmod +x "${BIN}/${cmd}"
done
# shred has to actually remove the file, that is the behaviour being asserted
{
    echo "#!/bin/sh"
    echo "echo \"shred \$*\" >> \"\${CALLS}\""
    echo "for a in \"\$@\"; do case \"\${a}\" in -*) ;; *) rm -f \"\${a}\" ;; esac; done"
    echo "exit 0"
} > "${BIN}/shred"
chmod +x "${BIN}/shred"
export CALLS
PATH="${BIN}:${PATH}"

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

assert_gone() {
    if [ ! -e "${WORK}/${1}" ]; then pass "${2}"; else fail "${2}" "${WORK}/${1} still exists"; fi
}
assert_kept() {
    if [ -e "${WORK}/${1}" ]; then pass "${2}"; else fail "${2}" "${WORK}/${1} was removed"; fi
}
called() { grep -q "^${1}" "${CALLS}" 2>/dev/null; }

setup_tree() {
    rm -rf "${WORK:?}/root" "${WORK:?}/etc" "${WORK:?}/tmp" "${WORK:?}/var" "${WORK:?}/proc"
    rm -f "${CALLS}"
    mkdir -p "${WORK}/root" "${WORK}/etc/sysconfig" "${WORK}/tmp/.X11-unix" \
             "${WORK}/var/tmp/systemd-private-abc" "${WORK}/var/log/rhsm" "${WORK}/var/log/apt" \
             "${WORK}/var/lib/dnf" "${WORK}/var/lib/yum/repos" "${WORK}/var/lib/yum/yumdb" \
             "${WORK}/var/cache/yum" "${WORK}/var/lib/authselect/backups" \
             "${WORK}/var/lib/apt/lists" "${WORK}/var/backups" "${WORK}/var/lib/NetworkManager" \
             "${WORK}/var/lib/dhcp" "${WORK}/var/lib/unbound" "${WORK}/var/lib/cloud/instances" \
             "${WORK}/proc/sys/vm"
    # The kickstart files carry the root password hash
    echo 'rootpw --iscrypted somehash' > "${WORK}/root/anaconda-ks.cfg"
    echo 'rootpw --iscrypted somehash' > "${WORK}/root/original-ks.cfg"
    # Editor and package leftovers, which both modes remove
    : > "${WORK}/etc/hosts.bak"
    : > "${WORK}/etc/hosts~"
    : > "${WORK}/etc/sysconfig/network~"
    # shadow-utils backup copies, which neither mode may touch
    for f in passwd- shadow- group- gshadow- subuid- subgid-; do
        echo 'root:x:0:0' > "${WORK}/etc/${f}"
    done
    # Evidence and recovery paths, master only
    : > "${WORK}/var/log/kdebug"
    : > "${WORK}/var/log/dmesg"
    : > "${WORK}/var/log/dmesg.old"
    : > "${WORK}/var/log/messages"
    : > "${WORK}/var/lib/dnf/history.sqlite"
    : > "${WORK}/var/lib/yum/yumdb/keep"
    : > "${WORK}/var/cache/yum/keep"
    : > "${WORK}/var/log/rhsm/rhsm.log"
    : > "${WORK}/var/lib/authselect/backups/pre-el"
    : > "${WORK}/var/lib/apt/lists/deb.debian.org_dists_Release"
    : > "${WORK}/var/log/apt/history.log"
    : > "${WORK}/var/log/apt/term.log"
    : > "${WORK}/var/backups/dpkg.status.0.gz"
    : > "${WORK}/var/backups/shadow.bak"
    : > "${WORK}/var/lib/NetworkManager/secret_key"
    : > "${WORK}/var/lib/NetworkManager/internal-eth0.lease"
    : > "${WORK}/var/lib/dhcp/dhclient.leases"
    : > "${WORK}/var/lib/unbound/root.key"
    : > "${WORK}/var/lib/cloud/instances/i-abc"
    : > "${WORK}/var/log/cloud-init.log"
    # In use temporary state that a live run must not disturb
    : > "${WORK}/tmp/.X11-unix/X0"
    : > "${WORK}/var/tmp/systemd-private-abc/tmp"
}

echo "Testing cleanup_system from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== live mode keeps evidence and recovery paths =="

FLAVOR=rhel
setup_tree
LOGGED_ERRORS=0
cleanup_system live > /dev/null
rc=$?

if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "returns 0 and logs no ERROR"
else
    fail "returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi

assert_kept "var/lib/dnf/history.sqlite" "dnf history.sqlite survives, so dnf history undo still works"
assert_kept "var/log/messages"           "logs survive"
assert_kept "var/log/kdebug"             "debug logs survive"
assert_kept "var/lib/NetworkManager/internal-eth0.lease" "the DHCP lease survives"
assert_kept "var/lib/unbound/root.key"   "the DNSSEC trust anchor survives"
assert_kept "var/lib/authselect/backups/pre-el" "the authselect rollback point survives"
assert_gone "proc/sys/vm/drop_caches"    "the page cache is not dropped on a live machine"
assert_kept "tmp/.X11-unix/X0"           "the tmpfiles managed socket directory survives"
assert_kept "var/tmp/systemd-private-abc/tmp" "the PrivateTmp backing tree survives"

if called "systemd-tmpfiles --clean"; then
    pass "temporary files go through systemd-tmpfiles --clean, which honours the age policy"
else
    fail "temporary files go through systemd-tmpfiles --clean" "$(cat "${CALLS}" 2>/dev/null)"
fi

echo
echo "== both modes still remove secrets and litter =="

assert_gone "root/anaconda-ks.cfg" "anaconda-ks.cfg is shredded, it holds the root password hash"
assert_gone "root/original-ks.cfg" "original-ks.cfg is shredded"
if called "shred"; then
    pass "the kickstart files are shredded rather than unlinked"
else
    fail "the kickstart files are shredded rather than unlinked"
fi
assert_gone "etc/hosts.bak"          "/etc/*.bak is removed"
assert_gone "etc/hosts~"             "/etc/*~ is removed"
assert_gone "etc/sysconfig/network~" "/etc/sysconfig/*~ is removed"
if called "dnf clean all"; then
    pass "the dnf cache is emptied with dnf clean all, which leaves history alone"
else
    fail "the dnf cache is emptied with dnf clean all" "$(cat "${CALLS}" 2>/dev/null)"
fi

echo
echo "== the shadow-utils backup copies are never touched =="

# /etc/*- sat in the old delete list next to /etc/*~ and /etc/*.bak, which reads like editor litter
# but is not: these are the backups useradd, passwd and vipw maintain, and the only way back if one
# of the account databases is lost
for f in passwd- shadow- group- gshadow- subuid- subgid-; do
    assert_kept "etc/${f}" "/etc/${f} survives"
done

echo
echo "== master mode forgets what a golden image must forget =="

FLAVOR=rhel
setup_tree
LOGGED_ERRORS=0
cleanup_system master > /dev/null
rc=$?

if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "returns 0 and logs no ERROR"
else
    fail "returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi

assert_gone "var/lib/dnf/history.sqlite" "the dnf transaction history is removed"
assert_gone "var/log/kdebug"             "debug logs are removed"
assert_gone "var/log/dmesg"              "dmesg logs are removed"
assert_gone "var/lib/authselect/backups/pre-el" "the authselect backups are removed"
assert_gone "var/log/rhsm/rhsm.log"      "the subscription-manager logs are removed"
assert_gone "var/lib/NetworkManager/secret_key" "the NetworkManager state is removed"
assert_gone "var/lib/dhcp/dhclient.leases"      "the DHCP leases are removed"
assert_gone "var/lib/unbound/root.key"   "the DNSSEC trust anchor is removed"
assert_gone "tmp/.X11-unix"              "tmp is wiped outright"
assert_gone "var/tmp/systemd-private-abc" "var/tmp is wiped outright"
assert_kept "proc/sys/vm/drop_caches"    "the page cache is dropped before the image is captured"

# The old code used /var/lib/cloud/a*, which matches nothing: the tree is data, handlers, instance,
# instances, scripts, seed and sem
if called "cloud-init clean"; then
    pass "cloud-init state is reset with cloud-init clean, not a glob that matches nothing"
else
    fail "cloud-init state is reset with cloud-init clean" "$(cat "${CALLS}" 2>/dev/null)"
fi

for f in passwd- shadow- group- gshadow-; do
    assert_kept "etc/${f}" "/etc/${f} survives master mode too"
done

echo
echo "== master mode on debian reaches the apt equivalents =="

FLAVOR=debian
setup_tree
LOGGED_ERRORS=0
cleanup_system master > /dev/null

assert_gone "var/lib/apt/lists/deb.debian.org_dists_Release" "the apt lists are removed"
assert_gone "var/log/apt/history.log" "the apt transaction record is removed"
assert_gone "var/backups/dpkg.status.0.gz" "the rotated dpkg status files are removed"
assert_gone "var/backups/shadow.bak"  "the /var/backups account copies are removed"
if called "apt-get clean"; then
    pass "the apt cache is emptied with apt-get clean"
else
    fail "the apt cache is emptied with apt-get clean" "$(cat "${CALLS}" 2>/dev/null)"
fi
if called "dnf"; then
    fail "dnf is not called on debian" "$(cat "${CALLS}" 2>/dev/null)"
else
    pass "dnf is not called on debian"
fi

echo
echo "== live mode on debian keeps the apt history =="

FLAVOR=debian
setup_tree
cleanup_system live > /dev/null
assert_kept "var/log/apt/history.log" "the apt transaction record survives a live run"
assert_kept "var/lib/apt/lists/deb.debian.org_dists_Release" "the apt lists survive a live run"

echo
echo "== the mode argument is validated =="

FLAVOR=rhel
setup_tree
LOGGED_ERRORS=0
if cleanup_system wipe-everything > /dev/null 2>&1; then
    fail "an unknown mode returns non-zero"
elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "an unknown mode returns non-zero and logs an ERROR"
else
    fail "an unknown mode logs an ERROR"
fi
assert_kept "root/anaconda-ks.cfg"       "an unknown mode removes nothing at all"
assert_kept "var/lib/dnf/history.sqlite" "an unknown mode leaves the dnf history alone"

setup_tree
LOGGED_ERRORS=0
cleanup_system > /dev/null
assert_kept "var/lib/dnf/history.sqlite" "a call with no argument defaults to live, not master"
assert_gone "root/anaconda-ks.cfg"       "a call with no argument still does the live cleanup"

echo
echo "== the call site is gated on the mode =="

if grep -qE '^cleanup_system "\$\{CLEANUP_MODE\}"' "${SCRIPT}"; then
    pass "the end of run cleanup goes through cleanup_system"
else
    fail "the end of run cleanup goes through cleanup_system" "$(grep -n 'cleanup_system' "${SCRIPT}")"
fi

if grep -qE '^CLEANUP_MODE=live' "${SCRIPT}"; then
    pass "CLEANUP_MODE defaults to live, so a re run cannot destroy history"
else
    fail "CLEANUP_MODE defaults to live" "$(grep -n '^CLEANUP_MODE=' "${SCRIPT}")"
fi

# The old unconditional block, with its /bin/ prefixed removals at the top level of the script
if grep -vE '^[[:space:]]*#' "${SCRIPT}" | grep -qE '^/bin/rm -rf'; then
    fail "the unconditional cleanup block is gone" \
         "$(grep -nE '^/bin/rm -rf' "${SCRIPT}" | head -5)"
else
    pass "the unconditional cleanup block is gone"
fi

# Neither bad glob may appear in any code line. Both are mentioned in comments explaining why they
# were dropped, so the comments have to be stripped before matching or this passes for free
code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")
if printf '%s\n' "${code_only}" | grep -qE '/etc/\*-'; then
    fail "no code line deletes /etc/*-" "$(printf '%s\n' "${code_only}" | grep -nE '/etc/\*-')"
else
    pass "no code line deletes /etc/*-"
fi
if printf '%s\n' "${code_only}" | grep -qE '/var/lib/cloud/a\*'; then
    fail "the /var/lib/cloud/a* glob is gone"
else
    pass "the /var/lib/cloud/a* glob is gone"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
