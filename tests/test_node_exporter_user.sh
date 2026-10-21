#!/usr/bin/env bash

# Tests for NODE_EXPORTER_USER and the two helpers that support it
#
# node_exporter was installed to run as root. Every collector this script enables works without it:
#
#   systemd, logind   go over the shared system bus. node_exporter only talks to systemd directly
#                     when given --collector.systemd.private, and its own help calls that flag
#                     "strongly discouraged since it requires root". This script never passes it.
#   interrupts        /proc/interrupts, world readable
#   processes         /proc/*/stat, world readable. hidepid=2 would hide those, but the ANSSI
#                     control file lists mount_option_proc_hidepid under related_rules rather than
#                     rules, and ssg/controls.py selects only the latter, so the profile does not
#                     set it
#   textfile          reads a directory, see below
#
# Debian's own prometheus-node-exporter package runs as User=prometheus with no capabilities at all,
# which is the same collector set unprivileged on every Debian install.
#
# What cannot give up root is the jobs that *fill* the textfile directory: smartctl and nvme both
# need it. So those keep running as root and only the reading side changes, which needs the
# directory setgid and the writers on a umask that leaves the group able to read.
#
# Usage: tests/test_node_exporter_user.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

WORK=$(mktemp -d)
BIN="${WORK}/bin"
CALLS="${WORK}/calls.log"
HELPERS="${WORK}/helpers.sh"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${BIN}"

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

extract_fn() {
    local s e
    s=$(grep -n "^${1}() {" "${SCRIPT}" | head -n 1 | cut -d: -f1)
    if [ -z "${s}" ]; then
        echo "Cannot locate ${1}() in [${SCRIPT}]" >&2
        exit 2
    fi
    e=$(awk -v s="${s}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
    sed -n "${s},${e}p" "${SCRIPT}"
}

# The helpers write under /var/lib/node_exporter, which these tests must not touch. Redirect that
# whole tree into the work directory.
{
    extract_fn setup_node_exporter_user
    extract_fn prepare_node_exporter_textfile_dir
} | sed "s#/var/lib/node_exporter#${WORK}/var/lib/node_exporter#g" > "${HELPERS}"

# Stubs that record their arguments. chown is stubbed because the tests do not run as root and
# cannot change group ownership. chmod is stubbed because the mode cannot be read back everywhere:
# on the Windows filesystems this suite also runs on, chmod is a no-op and every mode reads as 755
# or 644, so asserting the resulting mode would fail on a correct script. The arguments are the
# thing under test anyway.
for cmd in useradd chown chmod; do
    {
        echo "#!/bin/sh"
        echo "echo \"${cmd} \$*\" >> \"\${CALLS}\""
        echo "exit \${${cmd}_RC:-0}"
    } > "${BIN}/${cmd}"
    chmod +x "${BIN}/${cmd}"
done
# id -u <name> answers according to KNOWN_USERS
cat > "${BIN}/id" <<'STUB'
#!/bin/sh
echo "id $*" >> "${CALLS}"
for a in "$@"; do
    case " ${KNOWN_USERS} " in
        *" ${a} "*) echo 4242; exit 0 ;;
    esac
done
exit 1
STUB
chmod +x "${BIN}/id"
export CALLS KNOWN_USERS useradd_RC chown_RC chmod_RC
PATH="${BIN}:${PATH}"

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

DIR="${WORK}/var/lib/node_exporter/textfile_collector"
reset() {
    rm -rf "${WORK:?}/var"
    rm -f "${CALLS}"
    LOGGED_ERRORS=0
}

echo "Testing NODE_EXPORTER_USER handling from [${SCRIPT}]"
echo
echo "== the account is created only when it is needed =="

reset
NODE_EXPORTER_USER=root
KNOWN_USERS=""
setup_node_exporter_user; rc=$?
if [ "${rc}" -eq 0 ] && ! grep -q '^useradd' "${CALLS}" 2>/dev/null; then
    pass "root needs no account created"
else
    fail "root needs no account created" "rc=${rc} $(cat "${CALLS}" 2>/dev/null)"
fi

reset
NODE_EXPORTER_USER=prometheus
KNOWN_USERS=""
setup_node_exporter_user; rc=$?
if [ "${rc}" -eq 0 ] && grep -q '^useradd.*prometheus' "${CALLS}"; then
    pass "a missing account is created"
else
    fail "a missing account is created" "rc=${rc} $(cat "${CALLS}" 2>/dev/null)"
fi

# A metrics exporter has no business with a login shell or a home directory
for flag in -- --system --no-create-home --shell; do
    [ "${flag}" = -- ] && continue
    if grep -q -- "${flag}" "${CALLS}"; then
        pass "the account is created with ${flag}"
    else
        fail "the account is created with ${flag}" "$(cat "${CALLS}")"
    fi
done

reset
NODE_EXPORTER_USER=prometheus
KNOWN_USERS="prometheus"
setup_node_exporter_user; rc=$?
if [ "${rc}" -eq 0 ] && ! grep -q '^useradd' "${CALLS}"; then
    pass "an account that already exists is reused, not recreated"
else
    fail "an account that already exists is reused" "rc=${rc} $(cat "${CALLS}")"
fi

reset
NODE_EXPORTER_USER="not a name"
KNOWN_USERS=""
if setup_node_exporter_user > /dev/null 2>&1; then
    fail "an unusable account name is refused"
elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "an unusable account name is refused and logged"
else
    fail "an unusable account name is logged"
fi

reset
NODE_EXPORTER_USER=prometheus
KNOWN_USERS=""
useradd_RC=1
if setup_node_exporter_user > /dev/null 2>&1; then
    fail "a failed useradd returns non-zero"
elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a failed useradd returns non-zero and logs an ERROR"
else
    fail "a failed useradd logs an ERROR"
fi
useradd_RC=0

echo
echo "== the textfile directory is left readable by that account =="

reset
NODE_EXPORTER_USER=prometheus
KNOWN_USERS="prometheus"
prepare_node_exporter_textfile_dir; rc=$?

if [ "${rc}" -eq 0 ] && [ -d "${DIR}" ]; then
    pass "the directory is created"
else
    fail "the directory is created" "rc=${rc}"
fi

# setgid, so a file written by root takes the directory's group rather than root's own
if grep -qE '^chmod 2750 ' "${CALLS}"; then
    pass "the directory is set to 2750, setgid and closed to everyone else"
else
    fail "the directory is set to 2750" "$(grep '^chmod' "${CALLS}" 2>/dev/null)"
fi

if grep -q '^chown root:prometheus' "${CALLS}"; then
    pass "the directory is given to the node_exporter group"
else
    fail "the directory is given to the node_exporter group" "$(cat "${CALLS}")"
fi

# node_exporter has to be able to traverse the parent to reach it, and mkdir honours whatever umask
# the run inherited, which the ANSSI profile sets to 0077
if grep -qE '^chmod 0755 .*/var/lib/node_exporter$' "${CALLS}"; then
    pass "the parent is set traversable at 0755"
else
    fail "the parent is set traversable at 0755" "$(grep '^chmod' "${CALLS}" 2>/dev/null)"
fi

# Files an earlier run left behind predate the group
reset
NODE_EXPORTER_USER=prometheus
KNOWN_USERS="prometheus"
mkdir -p "${DIR}"
: > "${DIR}/smart_metrics.prom"
prepare_node_exporter_textfile_dir > /dev/null
if grep -qE '^chmod 0640 .*\.prom' "${CALLS}"; then
    pass "a file left by an earlier run is made group readable"
else
    fail "a file left by an earlier run is made group readable" "$(grep '^chmod' "${CALLS}" 2>/dev/null)"
fi
if grep -qE '^chown root:prometheus .*\.prom' "${CALLS}"; then
    pass "and is given to the group as well"
else
    fail "and is given to the group as well" "$(cat "${CALLS}")"
fi

reset
NODE_EXPORTER_USER=root
KNOWN_USERS=""
prepare_node_exporter_textfile_dir > /dev/null
if grep -q '^chown root:root' "${CALLS}"; then
    pass "with root the group is root, and no account is invented"
else
    fail "with root the group is root" "$(cat "${CALLS}")"
fi

echo
echo "== the writers keep root, and leave the group able to read =="

# smartctl and nvme both need root, so these jobs cannot drop it. What changes is the mode of what
# they write: the ANSSI profile sets the login umask to 0077, and a file at 0600 is unreadable to
# its group no matter which group that is.
code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")
crons=$(printf '%s\n' "${code_only}" | grep -oE '\*/5 \* \* \* \* root [^>]*' | wc -l)
with_umask=$(printf '%s\n' "${code_only}" | grep -cE '\*/5 \* \* \* \* root umask 0027; ')
if [ "${crons}" -gt 0 ] && [ "${crons}" -eq "${with_umask}" ]; then
    pass "all ${crons} textfile cron jobs set umask 0027"
else
    fail "all textfile cron jobs set umask 0027" "${with_umask} of ${crons}" \
         "$(printf '%s\n' "${code_only}" | grep -oE '\*/5 \* \* \* \* root [^>]*')"
fi

if printf '%s\n' "${code_only}" | grep -qE '\*/5 \* \* \* \* root umask 0027; (python3|/bin/bash)'; then
    pass "and still run as root, since smartctl and nvme need it"
else
    fail "and still run as root" "$(printf '%s\n' "${code_only}" | grep -oE '\*/5 \* \* \* \* root [^>]*')"
fi

# That script does its own redirection rather than letting cron do it, so it sets its own umask
if printf '%s\n' "${code_only}" | grep -qE '^umask 0027$'; then
    pass "el_configurator_metrics.sh sets its own umask, since it redirects for itself"
else
    fail "el_configurator_metrics.sh sets its own umask" "$(grep -n 'umask' "${SCRIPT}" | head -5)"
fi

echo
echo "== the service unit names the account =="

dropin=$(sed -n '/^harden_node_exporter_service() {/,/^}$/p' "${SCRIPT}")
case "${dropin}" in
    *'User=${NODE_EXPORTER_USER}'*) pass "the drop-in sets User from the option" ;;
    *) fail "the drop-in sets User from the option" "$(printf '%s\n' "${dropin}" | grep -n 'User')" ;;
esac
case "${dropin}" in
    *'Group=${NODE_EXPORTER_USER}'*) pass "the drop-in sets Group from the option" ;;
    *) fail "the drop-in sets Group from the option" ;;
esac
case "${dropin}" in
    *'NODE_EXPORTER_USER}" != root'*) pass "and leaves the unit alone when the option is root" ;;
    *) fail "and leaves the unit alone when the option is root" ;;
esac

echo
echo "== the option itself =="

# Which of the two it defaults to is the author's call, and it has been both. What matters is that
# the value is one the helper can actually use: anything else stops the run at setup_node_exporter_user
if grep -qE '^NODE_EXPORTER_USER=(root|[a-z_][a-z0-9_-]*)$' "${SCRIPT}"; then
    pass "NODE_EXPORTER_USER holds a usable account name"
else
    fail "NODE_EXPORTER_USER holds a usable account name" "$(grep -n '^NODE_EXPORTER_USER=' "${SCRIPT}")"
fi

# It holds a name, not a flag. Listing it with the true/false options would have every run refuse to
# start, since validate_boolean_options cannot read "prometheus" as a boolean.
if sed -n '/^BOOLEAN_OPTIONS=(/,/^)$/p' "${SCRIPT}" | grep -q 'NODE_EXPORTER_USER'; then
    fail "NODE_EXPORTER_USER is not listed among the true/false options" \
         "validate_boolean_options would refuse every run"
else
    pass "NODE_EXPORTER_USER is not listed among the true/false options"
fi

# The private systemd connection is the one node_exporter says needs root
if printf '%s\n' "${code_only}" | grep -q 'collector.systemd.private'; then
    fail "the root-requiring private systemd connection is not enabled" \
         "$(printf '%s\n' "${code_only}" | grep -n 'systemd.private')"
else
    pass "the root-requiring private systemd connection is not enabled"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
