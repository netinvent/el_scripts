#!/usr/bin/env bash

# Tests for the firewalld narrowing in el_configurator.sh
#
# The kickstart opens ssh to everyone, and this script narrows it to a whitelist: bind the
# whitelisted sources to a permissive zone, then take ssh off the default zone. Only the second
# half used to be unconditional, so a whitelist that failed to bind produced a machine that had
# closed ssh to the world and opened it to nobody, discovered on first boot.
#
# The chosen behaviour is that the narrowing always happens, because a hardening script that
# silently leaves ssh open is worse, and that a whitelist which did not fully bind is reported
# loudly for the operator to deal with.
#
# This file sets the configuration globals the extracted function reads. The linter cannot see that
# code, so it reports them as unused, hence a file wide waiver.
# shellcheck disable=SC2034
#
# Usage: tests/test_configure_firewalld.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^configure_firewalld() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate configure_firewalld() in [${SCRIPT}]"
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

LOG_FILE=/dev/null
LOGGED_ERRORS=0
POST_INSTALL_SCRIPT_GOOD=true
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
        POST_INSTALL_SCRIPT_GOOD=false
        printf '%s\n' "${1}" >> "${ERRORS_TEXT}"
    fi
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

CALLS="${WORK}/calls"
BOUND="${WORK}/bound"
ERRORS_TEXT="${WORK}/errors"
# Space separated list of sources whose --add-source should not take effect
FW_REJECT=""

# Stand-in for firewall-offline-cmd, keeping just enough state to answer --query-source.
# It reproduces the behaviour that matters here: adding a source that is already bound fails, while
# querying it succeeds. Counting exit codes would call that a failure, which is why the real code
# asks for the resulting state instead.
# shellcheck disable=SC2329
firewall-offline-cmd() {
    local arg zone="" op="" val=""
    printf '%s\n' "$*" >> "${CALLS}"
    for arg in "$@"; do
        case "${arg}" in
            --zone=*)          zone="${arg#--zone=}" ;;
            --add-source=*)    op=add;   val="${arg#--add-source=}" ;;
            --query-source=*)  op=query; val="${arg#--query-source=}" ;;
        esac
    done
    case "${op}" in
        add)
            case " ${FW_REJECT} " in *" ${val} "*) return 1 ;; esac
            if grep -qxF "${zone} ${val}" "${BOUND}" 2>/dev/null; then
                return 1        # ALREADY_ENABLED
            fi
            printf '%s %s\n' "${zone}" "${val}" >> "${BOUND}"
            return 0
            ;;
        query)
            grep -qxF "${zone} ${val}" "${BOUND}" 2>/dev/null
            ;;
        *)
            return 0
            ;;
    esac
}

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

run_case() {
    : > "${CALLS}"
    : > "${ERRORS_TEXT}"
    [ "${1}" = keepstate ] || : > "${BOUND}"
    LOGGED_ERRORS=0
    configure_firewalld > /dev/null 2>&1
    return $?
}

ssh_removed() { grep -qx -- '--remove-service=ssh' "${CALLS}"; }

echo "Testing configure_firewalld from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== the happy path =="

FIREWALL_WHITELIST_IP_LIST="192.168.200.0/24:10.0.0.1"
FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=true
NODE_EXPORTER_USE_IP_WHITELISTS=true
FW_REJECT=""
run_case
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "every source bound: returns 0 and logs no ERROR"
else
    fail "every source bound: returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi
if [ "$(grep -c -- '--zone=trusted --add-source=' "${CALLS}")" -eq 2 ]; then
    pass "allow all ports mode binds the sources to the trusted zone"
else
    fail "allow all ports mode binds the sources to the trusted zone" "$(cat "${CALLS}")"
fi
if ssh_removed; then
    pass "ssh is removed from the default zone"
else
    fail "ssh is removed from the default zone" "$(cat "${CALLS}")"
fi

FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=false
run_case
if [ "$(grep -c -- '--zone=dmz --add-source=' "${CALLS}")" -eq 2 ] && grep -q -- '--zone=dmz --add-port=9100/tcp' "${CALLS}"; then
    pass "ssh only mode uses the dmz zone and opens the node exporter port"
else
    fail "ssh only mode uses the dmz zone and opens the node exporter port" "$(cat "${CALLS}")"
fi

echo
echo "== the narrowing happens even when the whitelist did not bind =="

FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=true
FW_REJECT="192.168.200.0/24 10.0.0.1"
run_case
rc=$?
if ssh_removed; then
    pass "no source bound: ssh is still removed, the machine is not left open"
else
    fail "no source bound: ssh is still removed" "$(cat "${CALLS}")"
fi
if [ "${rc}" -eq 1 ]; then
    pass "no source bound: returns 1"
else
    fail "no source bound: returns 1" "returned ${rc}"
fi
if [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "no source bound: logs an ERROR, so the banner and the metric go red"
else
    fail "no source bound: logs an ERROR"
fi
if grep -q 'console access' "${ERRORS_TEXT}" && grep -q '192.168.200.0/24' "${ERRORS_TEXT}"; then
    pass "no source bound: the ERROR says console access is needed and names the addresses"
else
    fail "no source bound: the ERROR is specific" "$(cat "${ERRORS_TEXT}")"
fi

echo
echo "== a partial failure is reported too =="

FW_REJECT="10.0.0.1"
run_case
rc=$?
if [ "${rc}" -eq 1 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "one of two bound: returns 1 and logs an ERROR"
else
    fail "one of two bound: returns 1 and logs an ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi
if grep -q '10.0.0.1' "${ERRORS_TEXT}" && ! grep -q 'Unbound:.*192.168.200.0/24' "${ERRORS_TEXT}"; then
    pass "the ERROR names only the address that failed"
else
    fail "the ERROR names only the address that failed" "$(cat "${ERRORS_TEXT}")"
fi
if ssh_removed; then
    pass "one of two bound: ssh is still removed"
else
    fail "one of two bound: ssh is still removed"
fi

echo
echo "== re-running does not invent a failure =="

# firewalld returns ALREADY_ENABLED, a non zero exit, for a source that is correctly bound. Counting
# exit codes would report every second run as broken.
FW_REJECT=""
run_case
run_case keepstate
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a second run over an already bound whitelist is clean"
else
    fail "a second run over an already bound whitelist is clean" "rc=${rc} errors=${LOGGED_ERRORS}" "$(cat "${ERRORS_TEXT}")"
fi

echo
echo "== no whitelist means no narrowing =="

FIREWALL_WHITELIST_IP_LIST=""
run_case
rc=$?
if [ "${rc}" -eq 0 ] && ! ssh_removed && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "with no whitelist, ssh is left alone and nothing is reported"
else
    fail "with no whitelist, ssh is left alone" "rc=${rc} errors=${LOGGED_ERRORS}" "$(cat "${CALLS}")"
fi

echo
echo "== el_configurator.sh wiring =="

if grep -qE '^[[:space:]]*configure_firewalld$' "${SCRIPT}"; then
    pass "the RHEL firewall branch calls configure_firewalld"
else
    fail "the RHEL firewall branch calls configure_firewalld"
fi

outside=$(grep -n 'firewall-offline-cmd' "${SCRIPT}" | awk -F: -v s="${start}" -v e="${end}" '$1 < s || $1 > e')
if [ -z "${outside}" ]; then
    pass "every firewall-offline-cmd call lives inside configure_firewalld"
else
    fail "every firewall-offline-cmd call lives inside configure_firewalld" "${outside}"
fi

# firewall-cmd would be wrong here: this runs in the anaconda %post chroot with firewalld installed
# but not running, which is exactly the case firewall-offline-cmd exists for
firewall_cmd_use=$(sed -n "${start},${end}p" "${SCRIPT}" | grep -vE '^[[:space:]]*#' | grep -nE '(^|[^-])firewall-cmd')
if [ -n "${firewall_cmd_use}" ]; then
    fail "the offline client is used, not firewall-cmd" "${firewall_cmd_use}"
else
    pass "the offline client is used, not firewall-cmd"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
