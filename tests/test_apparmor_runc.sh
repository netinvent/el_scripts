#!/usr/bin/env bash

# Tests for disabling the AppArmor runc profile in el_configurator.sh
#
# The link into apparmor.d/disable/ used to be made with plain ln -s, which fails with "File
# exists" the second time the script runs. That logged an ERROR, flipped POST_INSTALL_SCRIPT_GOOD,
# printed the FAILURE banner and published el_configurator_state 1 on a machine where the profile
# was already correctly disabled. The README documents re-running this script on an existing
# system, so that was the common path, not an edge case.
#
# Usage: tests/test_apparmor_runc.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^disable_apparmor_runc_profile() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate disable_apparmor_runc_profile() in [${SCRIPT}]"
    exit 2
fi
end=$(awk -v s="${start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")

HELPERS=$(mktemp)
WORK=$(mktemp -d)
trap 'rm -f "${HELPERS}"; rm -rf "${WORK}"' EXIT
sed -n "${start},${end}p" "${SCRIPT}" > "${HELPERS}"

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

RESTARTS="${WORK}/restarts"
# shellcheck disable=SC2329
systemctl() { printf '%s\n' "$*" >> "${RESTARTS}"; return 0; }

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
SKIPPED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }
skip() { SKIPPED=$((SKIPPED + 1)); printf '  skip %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

# Symlinks are not always usable on a Windows checkout. Probe once rather than reporting failures
# that say nothing about the code.
symlinks_work() {
    local probe="${WORK}/symlink_probe"
    rm -rf "${probe}"
    mkdir -p "${probe}"
    : > "${probe}/target"
    ln -s "${probe}/target" "${probe}/link" 2>/dev/null
    [ -L "${probe}/link" ]
}

AA="${WORK}/apparmor.d"
reset_apparmor() {
    rm -rf "${AA}"
    mkdir -p "${AA}"
    [ "${1}" = noprofile ] || printf 'profile runc {}\n' > "${AA}/runc"
    [ "${1}" = nodisabledir ] || mkdir -p "${AA}/disable"
    : > "${RESTARTS}"
    LOGGED_ERRORS=0
}

echo "Testing disable_apparmor_runc_profile from [${SCRIPT}] lines ${start}-${end}"
echo

if ! symlinks_work; then
    echo "== behaviour =="
    skip "the symlink behaviour tests" "this filesystem cannot create symlinks, checked on CI instead"
else
    echo "== the profile is disabled, and stays disabled on a re-run =="

    reset_apparmor
    disable_apparmor_runc_profile "${AA}" > /dev/null
    rc=$?
    if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
        pass "first run returns 0 and logs no ERROR"
    else
        fail "first run returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
    fi
    if [ -L "${AA}/disable/runc" ]; then
        pass "the disable symlink is created"
    else
        fail "the disable symlink is created" "$(ls -l "${AA}/disable" 2>&1)"
    fi
    if grep -q 'restart apparmor' "${RESTARTS}"; then
        pass "apparmor is restarted so the link takes effect"
    else
        fail "apparmor is restarted" "$(cat "${RESTARTS}")"
    fi

    # This is the regression: plain ln -s fails here with "File exists"
    LOGGED_ERRORS=0
    : > "${RESTARTS}"
    disable_apparmor_runc_profile "${AA}" > /dev/null
    rc=$?
    if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
        pass "a second run returns 0 and logs no ERROR, so the banner stays green"
    else
        fail "a second run returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
    fi
    if [ -L "${AA}/disable/runc" ]; then
        pass "a second run leaves the link in place"
    else
        fail "a second run leaves the link in place"
    fi

    reset_apparmor nodisabledir
    disable_apparmor_runc_profile "${AA}" > /dev/null
    rc=$?
    if [ "${rc}" -eq 0 ] && [ -L "${AA}/disable/runc" ]; then
        pass "a link is made even when the disable directory did not exist"
    else
        fail "a link is made even when the disable directory did not exist" "rc=${rc}"
    fi
fi

# Creating the directory needs no symlink support, so this runs everywhere. Without it the link
# would simply fail on a system where apparmor.d/disable has not been created yet.
reset_apparmor nodisabledir
disable_apparmor_runc_profile "${AA}" > /dev/null 2>&1
if [ -d "${AA}/disable" ]; then
    pass "a missing disable directory is created"
else
    fail "a missing disable directory is created" "$(find "${AA}" -maxdepth 1 2>&1 | head -4)"
fi

echo
echo "== nothing to do, and failures =="

reset_apparmor noprofile
disable_apparmor_runc_profile "${AA}" > /dev/null
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "no runc profile is not an error"
else
    fail "no runc profile is not an error" "rc=${rc} errors=${LOGGED_ERRORS}"
fi

# On RHEL there is no apparmor.d at all, and that must be silent rather than noisy
rm -rf "${AA}"
LOGGED_ERRORS=0
disable_apparmor_runc_profile "${AA}" > /dev/null
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a system without AppArmor at all is not an error"
else
    fail "a system without AppArmor at all is not an error" "rc=${rc} errors=${LOGGED_ERRORS}"
fi

# A disable path that cannot be created must be reported
reset_apparmor
rm -rf "${AA}/disable"
: > "${AA}/disable"          # a file where the directory should be
LOGGED_ERRORS=0
if disable_apparmor_runc_profile "${AA}" > /dev/null 2>&1; then
    fail "an unusable disable directory returns non-zero"
elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "an unusable disable directory returns non-zero and logs an ERROR"
else
    fail "an unusable disable directory logs an ERROR"
fi

echo
echo "== the flag that fixes the re-run =="

# Even where the filesystem emulates symlinks with copies, the semantic behind the regression still
# reproduces: a second plain ln -s fails, ln -sf succeeds over the existing destination. That single
# character is the whole of the fix, so it is worth asserting on every platform rather than only
# where the behavioural tests above can run.
sem="${WORK}/semantic"
rm -rf "${sem}"
mkdir -p "${sem}"
: > "${sem}/target"
ln -s "${sem}/target" "${sem}/link" > /dev/null 2>&1
first_rc=$?
ln -s "${sem}/target" "${sem}/link" > /dev/null 2>&1
second_rc=$?
ln -sf "${sem}/target" "${sem}/link" > /dev/null 2>&1
forced_rc=$?

if [ "${first_rc}" -eq 0 ] && [ "${second_rc}" -ne 0 ]; then
    pass "a plain ln -s does fail the second time, which is the bug being fixed"
else
    skip "a plain ln -s fails the second time" \
         "this ln does not behave that way here, first=${first_rc} second=${second_rc}"
fi
if [ "${forced_rc}" -eq 0 ]; then
    pass "ln -sf succeeds over an existing destination, which is the fix"
else
    fail "ln -sf succeeds over an existing destination" "rc=${forced_rc}"
fi

helper_body=$(sed -n "${start},${end}p" "${SCRIPT}" | grep -vE '^[[:space:]]*#')
case "${helper_body}" in
    *'ln -sf '*) pass "the helper links with ln -sf" ;;
    *)           fail "the helper links with ln -sf" "$(printf '%s' "${helper_body}" | grep -n 'ln ')" ;;
esac

echo
echo "== el_configurator.sh wiring =="

if grep -qE '^[[:space:]]*disable_apparmor_runc_profile$' "${SCRIPT}"; then
    pass "the AppArmor section calls the helper"
else
    fail "the AppArmor section calls the helper"
fi

# The original defect: a plain ln -s that fails the second time round
if grep -nE '^[^#]*ln -s [^f]' "${SCRIPT}" | grep -q 'apparmor'; then
    fail "no plain ln -s remains for the apparmor link" \
         "$(grep -nE '^[^#]*ln -s [^f]' "${SCRIPT}" | grep apparmor)"
else
    pass "no plain ln -s remains for the apparmor link"
fi

echo
if [ "${SKIPPED}" -gt 0 ]; then
    printf 'passed %d, failed %d, skipped %d\n' "${PASSED}" "${FAILED}" "${SKIPPED}"
else
    printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
fi
[ "${FAILED}" -eq 0 ]
