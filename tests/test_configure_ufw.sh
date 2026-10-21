#!/usr/bin/env bash

# Tests for the ufw setup in el_configurator.sh
#
# ufw used to be enabled before any allow rule existed. The README documents running this script by
# hand on an existing Debian machine, which in practice means over ssh, so that ordering put a
# default deny policy in front of the session doing the work, and stranded the machine if the run
# stopped there. These tests assert that no rule ever lands after the firewall comes up, and that a
# whitelist ufw rejected outright cannot end with a firewall nobody can get past.
#
# Usage: tests/test_configure_ufw.sh [path/to/el_configurator.sh]

# This file sets the configuration globals the extracted function reads. The linter cannot see that
# code, so it reports every one of them as unused, hence a file wide waiver rather than a dozen
# individual ones.
# shellcheck disable=SC2034

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^configure_ufw() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate configure_ufw() in [${SCRIPT}]"
    exit 2
fi
end=$(awk -v s="${start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")

HELPERS=$(mktemp)
WORK=$(mktemp -d)
trap 'rm -f "${HELPERS}"; rm -rf "${WORK}"' EXIT
sed -n "${start},${end}p" "${SCRIPT}" > "${HELPERS}"

# The function reads its options through is_enabled, so that helper has to come along too. Without
# it the call is an unknown command, exits 127, and every option silently reads as off, which looks
# exactly like a configuration failure rather than a missing helper.
ie_start=$(grep -n '^is_enabled() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${ie_start}" ]; then
    echo "Cannot locate is_enabled() in [${SCRIPT}]"
    exit 2
fi
ie_end=$(awk -v s="${ie_start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
sed -n "${ie_start},${ie_end}p" "${SCRIPT}" >> "${HELPERS}"

# Stubs for what the extracted helper expects from the surrounding script.
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

# Every ufw and systemctl call is appended to a file, so the order they happened in can be checked
# afterwards. A file rather than a variable, because some calls run inside a pipeline subshell.
CALLS="${WORK}/calls"
# UFW_ALLOW_RC decides whether ufw accepts the allow rules, so both branches are exercised on a
# machine that has no ufw at all.
UFW_ALLOW_RC=0

# shellcheck disable=SC2329
ufw() {
    printf '%s\n' "ufw $*" >> "${CALLS}"
    case "${1}" in
        allow) return "${UFW_ALLOW_RC}" ;;
        *) return 0 ;;
    esac
}
# The script calls ufw by absolute path. bash allows a function name containing slashes when it is
# declared with the function keyword, and that shadows the PATH lookup. If a future shell refuses
# it, bail rather than run tests that quietly exercise nothing.
if ! eval 'function /sbin/ufw() { ufw "$@"; }' 2>/dev/null; then
    echo "Cannot stub /sbin/ufw on this shell, these tests would not exercise the real code path"
    exit 2
fi
# shellcheck disable=SC2329
systemctl() { printf '%s\n' "systemctl $*" >> "${CALLS}"; return 0; }

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

run_case() {
    : > "${CALLS}"
    LOGGED_ERRORS=0
    configure_ufw > /dev/null 2>&1
    return $?
}

# Line number of the first call matching a pattern, or 0 when absent
first_call() { grep -n -- "${1}" "${CALLS}" 2>/dev/null | head -n 1 | cut -d: -f1; }

assert_rules_before_enable() {
    local label="${1}"
    local first_allow last_allow enable_at
    first_allow=$(first_call 'ufw allow')
    enable_at=$(first_call 'ufw enable')
    last_allow=$(grep -n -- 'ufw allow' "${CALLS}" 2>/dev/null | tail -n 1 | cut -d: -f1)
    if [ -z "${first_allow}" ] || [ -z "${enable_at}" ]; then
        fail "${label}" "expected both allow and enable calls, got:" "$(cat "${CALLS}")"
    elif [ "${last_allow}" -lt "${enable_at}" ]; then
        pass "${label}"
    else
        fail "${label}" "last allow at line ${last_allow}, enable at line ${enable_at}" "$(cat "${CALLS}")"
    fi
}

echo "Testing configure_ufw from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== every rule is in place before the firewall comes up =="

FIREWALL_WHITELIST_IP_LIST=""
FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=true
NODE_EXPORTER_USE_IP_WHITELISTS=true
UFW_ALLOW_RC=0
run_case
assert_rules_before_enable "no whitelist: ssh is allowed before ufw is enabled"
if grep -q '^ufw allow ssh$' "${CALLS}"; then
    pass "no whitelist: a generic ssh rule is added"
else
    fail "no whitelist: a generic ssh rule is added" "$(cat "${CALLS}")"
fi

FIREWALL_WHITELIST_IP_LIST="192.168.200.0/24:10.0.0.1"
FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=true
run_case
assert_rules_before_enable "whitelist, all ports: rules land before ufw is enabled"
if [ "$(grep -c '^ufw allow from' "${CALLS}")" -eq 2 ]; then
    pass "whitelist, all ports: one rule per whitelisted address"
else
    fail "whitelist, all ports: one rule per whitelisted address" "$(cat "${CALLS}")"
fi

FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=false
run_case
assert_rules_before_enable "whitelist, ssh only: rules land before ufw is enabled"
if [ "$(grep -c 'port 22 proto tcp' "${CALLS}")" -eq 2 ] && [ "$(grep -c 'port 9100 proto tcp' "${CALLS}")" -eq 2 ]; then
    pass "whitelist, ssh only: ssh and node exporter rules are both added"
else
    fail "whitelist, ssh only: ssh and node exporter rules are both added" "$(cat "${CALLS}")"
fi

echo
echo "== a firewall nobody can get past is never enabled =="

FIREWALL_WHITELIST_IP_LIST="not-an-address"
FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=true
UFW_ALLOW_RC=1
run_case
rc=$?
if [ "${rc}" -eq 1 ]; then
    pass "when every rule is rejected, the function returns 1"
else
    fail "when every rule is rejected, the function returns 1" "returned ${rc}"
fi
if ! grep -q 'ufw enable' "${CALLS}"; then
    pass "when every rule is rejected, ufw is never enabled"
else
    fail "when every rule is rejected, ufw is never enabled" "$(cat "${CALLS}")"
fi
if ! grep -q 'systemctl' "${CALLS}"; then
    pass "when every rule is rejected, the service is not started either"
else
    fail "when every rule is rejected, the service is not started either" "$(cat "${CALLS}")"
fi
if [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "refusing to enable is logged as an ERROR"
else
    fail "refusing to enable is logged as an ERROR"
fi

FIREWALL_WHITELIST_IP_LIST=""
UFW_ALLOW_RC=1
run_case
if ! grep -q 'ufw enable' "${CALLS}"; then
    pass "a rejected generic ssh rule also stops the firewall being enabled"
else
    fail "a rejected generic ssh rule also stops the firewall being enabled" "$(cat "${CALLS}")"
fi

echo
echo "== node exporter access does not count as being reachable =="

# Only the port 22 rules fail here. Metrics on 9100 do not let anyone log in, so they must not be
# what convinces the script it is safe to switch the firewall on.
FIREWALL_WHITELIST_IP_LIST="10.0.0.1"
FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=false
NODE_EXPORTER_USE_IP_WHITELISTS=true
# shellcheck disable=SC2329
ufw() {
    printf '%s\n' "ufw $*" >> "${CALLS}"
    case "$*" in
        *"port 22"*) return 1 ;;
        *) return 0 ;;
    esac
}
run_case
if ! grep -q 'ufw enable' "${CALLS}"; then
    pass "a working 9100 rule does not license enabling the firewall"
else
    fail "a working 9100 rule does not license enabling the firewall" "$(cat "${CALLS}")"
fi

echo
echo "== el_configurator.sh calls it, and nothing enables ufw behind its back =="

if grep -qE '^[[:space:]]*configure_ufw$' "${SCRIPT}"; then
    pass "the Debian firewall branch calls configure_ufw"
else
    fail "the Debian firewall branch calls configure_ufw"
fi

# Any ufw enable outside the function would reintroduce the ordering problem
outside=$(grep -n 'ufw enable' "${SCRIPT}" | awk -F: -v s="${start}" -v e="${end}" '$1 < s || $1 > e')
if [ -z "${outside}" ]; then
    pass "the only 'ufw enable' in the script is inside configure_ufw"
else
    fail "the only 'ufw enable' in the script is inside configure_ufw" "${outside}"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
