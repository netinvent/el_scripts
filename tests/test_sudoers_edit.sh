#!/usr/bin/env bash

# Tests for the guarded sudoers edit helpers of el_configurator.sh
#
# sudo refuses to run at all when sudoers has a syntax error, and the ANSSI profile disables the
# root account on EL10, so a bad edit here can lock a machine out for good. The point of these
# helpers is that nothing reaches the real sudoers file until visudo has accepted it. These tests
# hold that line, and check that a rejected edit leaves the original byte for byte identical.
#
# Usage: tests/test_sudoers_edit.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

HELPERS=$(mktemp)
WORK=$(mktemp -d)
trap 'rm -f "${HELPERS}"; rm -rf "${WORK}"' EXIT

extract_function() {
    local first last
    first=$(grep -n "^${1}() {" "${SCRIPT}" | head -n 1 | cut -d: -f1)
    if [ -z "${first}" ]; then
        echo "Cannot locate ${1}() in [${SCRIPT}]"
        exit 2
    fi
    last=$(awk -v s="${first}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
    sed -n "${first},${last}p" "${SCRIPT}" >> "${HELPERS}"
    echo "${first}-${last}"
}

begin_lines=$(extract_function sudoers_begin_edit)
commit_lines=$(extract_function sudoers_commit_edit)
extract_function escape_bre > /dev/null
extract_function set_conf_value > /dev/null

# Stubs for what the extracted helpers expect from the surrounding script.
# These are read by the extracted code, which the linter cannot see, hence the SC2034 waivers
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

# Stand-in for visudo. VISUDO_RC decides whether the edit is accepted, so both branches are
# exercised deterministically on a machine that has no sudo installed.
# shellcheck disable=SC2329
visudo() { return "${VISUDO_RC:-0}"; }
VISUDO_RC=0

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
SKIPPED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }
skip() { SKIPPED=$((SKIPPED + 1)); printf '  skip %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

SUDOERS="${WORK}/sudoers"
ORIGINAL='Defaults    env_reset
Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin
Defaults noexec
root ALL=(ALL) ALL
%wheel ALL=(ALL) ALL
'

# The real file is 0440, which root writes through without trouble. These tests do not run as
# root, so the fixture uses an owner writable mode instead. What matters here is that the mode is
# preserved across a commit, not what the mode happens to be.
reset_sudoers() {
    [ -f "${SUDOERS}" ] && chmod 0600 "${SUDOERS}"
    printf '%s' "${ORIGINAL}" > "${SUDOERS}"
    chmod 0640 "${SUDOERS}"
    LOGGED_ERRORS=0
}

echo "Testing the sudoers edit helpers in [${SCRIPT}]"
echo "  sudoers_begin_edit   lines ${begin_lines}"
echo "  sudoers_commit_edit  lines ${commit_lines}"
echo
echo "== an edit visudo rejects never reaches the real file =="

reset_sudoers
before_hash=$(sha256sum "${SUDOERS}" | cut -d' ' -f1)
VISUDO_RC=1
if sudoers_begin_edit "${SUDOERS}"; then
    printf 'this is not valid sudoers at all\n' >> "${SUDOERS_EDIT_FILE}"
    sudoers_commit_edit
    rc=$?
else
    rc=99
fi
VISUDO_RC=0
after_hash=$(sha256sum "${SUDOERS}" | cut -d' ' -f1)

if [ "${rc}" -eq 1 ]; then
    pass "a rejected edit returns 1"
else
    fail "a rejected edit returns 1" "returned ${rc}"
fi
if [ "${before_hash}" = "${after_hash}" ]; then
    pass "a rejected edit leaves sudoers byte for byte identical"
else
    fail "a rejected edit leaves sudoers byte for byte identical" "the file changed"
fi
if [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a rejected edit logs an ERROR"
else
    fail "a rejected edit logs an ERROR"
fi
if [ -z "${SUDOERS_EDIT_FILE}" ]; then
    pass "the temporary copy is cleaned up after a rejected edit"
else
    fail "the temporary copy is cleaned up after a rejected edit" "SUDOERS_EDIT_FILE=${SUDOERS_EDIT_FILE}"
fi

echo
echo "== an edit visudo accepts is applied =="

reset_sudoers
inode_before=$(stat -c %i "${SUDOERS}" 2>/dev/null || echo unknown)
mode_before=$(stat -c %a "${SUDOERS}" 2>/dev/null || echo unknown)
if sudoers_begin_edit "${SUDOERS}"; then
    sed -i 's/^Defaults noexec/#Defaults noexec/g' "${SUDOERS_EDIT_FILE}"
    set_conf_value "${SUDOERS_EDIT_FILE}" "Defaults timestamp_timeout" "15" "=" > /dev/null
    sudoers_commit_edit
    rc=$?
else
    rc=99
fi
inode_after=$(stat -c %i "${SUDOERS}" 2>/dev/null || echo unknown)
mode_after=$(stat -c %a "${SUDOERS}" 2>/dev/null || echo unknown)

if [ "${rc}" -eq 0 ]; then
    pass "an accepted edit returns 0"
else
    fail "an accepted edit returns 0" "returned ${rc}"
fi
if grep -q '^#Defaults noexec' "${SUDOERS}"; then
    pass "the noexec line was commented out"
else
    fail "the noexec line was commented out" "$(grep -n noexec "${SUDOERS}")"
fi
if grep -q '^Defaults timestamp_timeout=15$' "${SUDOERS}"; then
    pass "the CIS timestamp_timeout default was added"
else
    fail "the CIS timestamp_timeout default was added" "$(cat "${SUDOERS}")"
fi
if grep -q '^root ALL=(ALL) ALL$' "${SUDOERS}" && grep -q '^%wheel ALL=(ALL) ALL$' "${SUDOERS}"; then
    pass "the rest of the file survived the edit"
else
    fail "the rest of the file survived the edit" "$(cat "${SUDOERS}")"
fi
if [ "${inode_before}" = "${inode_after}" ]; then
    pass "the file keeps its inode, so permissions and SELinux context are untouched"
else
    fail "the file keeps its inode" "${inode_before} -> ${inode_after}"
fi
if [ "${mode_before}" = "${mode_after}" ]; then
    pass "the file keeps its mode (${mode_after})"
else
    fail "the file keeps its mode" "${mode_before} -> ${mode_after}"
fi
if [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "an accepted edit logs no ERROR"
else
    fail "an accepted edit logs no ERROR" "errors=${LOGGED_ERRORS}"
fi

echo
echo "== the helpers refuse rather than guess =="

reset_sudoers
if sudoers_begin_edit "${WORK}/no_such_sudoers" || [ "${LOGGED_ERRORS}" -lt 1 ]; then
    fail "a missing sudoers file is refused with an ERROR"
else
    pass "a missing sudoers file is refused with an ERROR"
fi

reset_sudoers
before_hash=$(sha256sum "${SUDOERS}" | cut -d' ' -f1)
# Hide the stub so the helper sees a system without visudo
saved_visudo=$(declare -f visudo)
unset -f visudo
if sudoers_begin_edit "${SUDOERS}" || [ "${LOGGED_ERRORS}" -lt 1 ]; then
    fail "without visudo the helper refuses to edit"
else
    pass "without visudo the helper refuses to edit"
fi
eval "${saved_visudo}"
if [ "${before_hash}" = "$(sha256sum "${SUDOERS}" | cut -d' ' -f1)" ]; then
    pass "without visudo the file is left untouched"
else
    fail "without visudo the file is left untouched"
fi

LOGGED_ERRORS=0
SUDOERS_EDIT_FILE=""
if sudoers_commit_edit || [ "${LOGGED_ERRORS}" -lt 1 ]; then
    fail "committing with no edit in progress is refused with an ERROR"
else
    pass "committing with no edit in progress is refused with an ERROR"
fi

echo
echo "== el_configurator.sh no longer writes sudoers unguarded =="

if grep -qE '^[[:space:]]*(sed -i|echo).*[^_]/etc/sudoers' "${SCRIPT}"; then
    fail "no direct write to /etc/sudoers remains" \
         "$(grep -nE '^[[:space:]]*(sed -i|echo).*[^_]/etc/sudoers' "${SCRIPT}")"
else
    pass "no direct write to /etc/sudoers remains"
fi

if grep -qE '^[[:space:]]*set_conf_value[[:space:]]+/etc/sudoers' "${SCRIPT}"; then
    fail "no unvalidated set_conf_value on /etc/sudoers remains" \
         "$(grep -nE '^[[:space:]]*set_conf_value[[:space:]]+/etc/sudoers' "${SCRIPT}")"
else
    pass "no unvalidated set_conf_value on /etc/sudoers remains"
fi

if grep -qE '^[[:space:]]*if sudo -V \| grep' "${SCRIPT}"; then
    fail "the sudo-rs probe no longer runs sudo unconditionally" \
         "$(grep -nE '^[[:space:]]*if sudo -V \| grep' "${SCRIPT}")"
else
    pass "the sudo-rs probe no longer runs sudo unconditionally"
fi

echo
echo "== ALLOW_SUDO restores execute on sudo without granting read =="

# The scap profile locks sudo down immediately before this runs: file_permissions_sudo sets
# /usr/bin/sudo to 4110 and sudo_dedicated_group gives it to group root, so only root can execute
# it. Undoing that on purpose is what ALLOW_SUDO is for, so a fixed mode belongs here: a chmod u+s
# would leave 4110 in place and achieve nothing at all.
# Comment lines are excluded, because the reasoning in the script names these modes in prose.
sudo_chmod=$(grep -nE '^[[:space:]]*chmod [0-7]{3,4} /usr/bin/sudo' "${SCRIPT}" | grep -vE '^[0-9]+:[[:space:]]*#')

case "${sudo_chmod}" in
    '')
        fail "a mode is written to /usr/bin/sudo" \
             "nothing found. u+s alone would leave the profile's 4110 in place and do nothing" ;;
    *'chmod 4111 /usr/bin/sudo'*)
        pass "sudo is set to 4111, which is the mode RHEL itself ships" ;;
    *)
        fail "sudo is set to 4111" "${sudo_chmod}" ;;
esac

# 4755 additionally grants read to group and other, which nothing in this block needs
if printf '%s' "${sudo_chmod}" | grep -q '4755'; then
    fail "sudo is not made readable by group and other" "${sudo_chmod}"
else
    pass "sudo is not made readable by group and other"
fi

echo
if [ "${SKIPPED}" -gt 0 ]; then
    printf 'passed %d, failed %d, skipped %d\n' "${PASSED}" "${FAILED}" "${SKIPPED}"
else
    printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
fi
[ "${FAILED}" -eq 0 ]
