#!/usr/bin/env bash

# Tests for applying the fail2ban settings in el_configurator.sh
#
# The script writes fail2ban's jail settings, then used to only start fail2ban. A fail2ban that is
# already running, as on a rerun on an installed system, ignores a start, so it kept its old
# settings, and the bans that the firewalld reload just before had dropped stayed dropped. A running
# fail2ban is now restarted, which reads the settings and puts its bans back from its database.
#
# Whether fail2ban runs is asked through fail2ban-client, not systemctl: in the kickstart %post
# chroot, systemctl is-active ignores the command and answers 0.
#
# This file sets the configuration globals the extracted block reads. The linter cannot see that
# code, so it reports them as unused, hence a file wide waiver.
# shellcheck disable=SC2034
#
# Usage: tests/test_fail2ban_restart.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

# The block that writes the jail settings and starts fail2ban, from its "if" line to the matching "fi"
# shellcheck disable=SC2016
block_start=$(grep -nxF 'if [ "${__FAIL2BAN_INSTALLED}" = true ]; then' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${block_start}" ]; then
    echo "Cannot locate the fail2ban configuration block in [${SCRIPT}]"
    exit 2
fi
block_end=$(awk -v s="${block_start}" 'NR>s && /^fi$/ {print NR; exit}' "${SCRIPT}")

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
BLOCK="${WORK}/block"
CALLS="${WORK}/calls"
ERRORS_TEXT="${WORK}/errors"
# The jail files go under WORK rather than /etc
sed -n "${block_start},${block_end}p" "${SCRIPT}" | sed "s#/etc/fail2ban/#${WORK}/etc/fail2ban/#g" > "${BLOCK}"
mkdir -p "${WORK}/etc/fail2ban/jail.d"

LOG_FILE=/dev/null
FAIL2BAN_BANTIME=30m
FAIL2BAN_FINDTIME=2h
FAIL2BAN_MAXRETRY=3
FAIL2BAN_IGNORE_IP_LIST="10.99.0.1"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

# PING_RC is what fail2ban-client ping returns: 0 when fail2ban runs, 255 when its socket does not
# answer. RESTART_RC is what systemctl restart returns. Runs in a subshell, so that the stubs do not
# outlive it
run_block() {
    : > "${CALLS}"
    : > "${ERRORS_TEXT}"
    # The stubs are called from the sourced block, which the linter cannot see
    # shellcheck disable=SC2329
    (
        __FAIL2BAN_INSTALLED=true
        log() { [ "${2}" = "ERROR" ] && printf '%s\n' "${1}" >> "${ERRORS_TEXT}"; return 0; }
        set_conf_value() { echo "set_conf_value ${2}=${3}" >> "${CALLS}"; }
        systemctl() {
            echo "systemctl $*" >> "${CALLS}"
            [ "${1}" = restart ] && return "${RESTART_RC}"
            return 0
        }
        fail2ban-client() { echo "fail2ban-client $*" >> "${CALLS}"; return "${PING_RC}"; }
        # shellcheck disable=SC1090
        source "${BLOCK}"
    ) > /dev/null 2>&1
}

# Line number of the first call that is exactly $1 in CALLS, empty when there is none
call_line() { grep -nxF -- "${1}" "${CALLS}" | head -n 1 | cut -d: -f1; }

echo "Testing the fail2ban block of [${SCRIPT}] lines ${block_start}-${block_end}"
echo
echo "== a running fail2ban =="

PING_RC=0
RESTART_RC=0
run_block
last_setting=$(grep -n '^set_conf_value ' "${CALLS}" | tail -n 1 | cut -d: -f1)
restart_line=$(call_line "systemctl restart fail2ban")
if [ -n "${last_setting}" ] && [ -n "${restart_line}" ] && [ "${last_setting}" -lt "${restart_line}" ] && [ ! -s "${ERRORS_TEXT}" ]; then
    pass "is restarted after its settings are written, without an ERROR"
else
    fail "is restarted after its settings are written, without an ERROR" "$(cat "${CALLS}")" "$(cat "${ERRORS_TEXT}")"
fi
if [ -z "$(call_line "systemctl start fail2ban")" ] && [ -n "$(call_line "systemctl enable fail2ban")" ]; then
    pass "is enabled, and not merely started"
else
    fail "is enabled, and not merely started" "$(cat "${CALLS}")"
fi
if [ -n "$(call_line "fail2ban-client ping")" ]; then
    pass "is asked through fail2ban-client ping"
else
    fail "is asked through fail2ban-client ping" "$(cat "${CALLS}")"
fi
if [ -f "${WORK}/etc/fail2ban/jail.d/99-sshd-el.conf" ] && [ -f "${WORK}/etc/fail2ban/jail.d/99-default-el.conf" ]; then
    pass "the jail files are written (under the test directory)"
else
    fail "the jail files are written (under the test directory)" "$(ls -la "${WORK}/etc/fail2ban/jail.d")"
fi

RESTART_RC=1
run_block
if grep -q 'Failed to restart fail2ban' "${ERRORS_TEXT}"; then
    pass "a failed restart is an ERROR"
else
    fail "a failed restart is an ERROR" "$(cat "${CALLS}")"
fi
RESTART_RC=0

echo
echo "== a fail2ban that is not running, as in the kickstart =="

PING_RC=255
run_block
if [ -n "$(call_line "systemctl start fail2ban")" ] && [ -z "$(call_line "systemctl restart fail2ban")" ]; then
    pass "is started, not restarted"
else
    fail "is started, not restarted" "$(cat "${CALLS}")"
fi
PING_RC=0

echo
echo "== el_configurator.sh wiring =="

# systemctl is-active answers 0 in a chroot, which would restart a fail2ban that is not there
is_active_use=$(sed -n "${block_start},${block_end}p" "${SCRIPT}" | grep -vE '^[[:space:]]*#' | grep -n 'is-active')
if [ -z "${is_active_use}" ]; then
    pass "the block does not ask systemctl is-active"
else
    fail "the block does not ask systemctl is-active" "${is_active_use}"
fi

# The restart puts back the bans that the firewalld reload drops, so it has to come after it
# shellcheck disable=SC2016
fw_block_start=$(grep -nxF 'if is_enabled "${CONFIGURE_FIREWALL}"; then' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -n "${fw_block_start}" ] && [ "${fw_block_start}" -lt "${block_start}" ]; then
    pass "fail2ban is configured after the firewall"
else
    fail "fail2ban is configured after the firewall" "firewall block at line ${fw_block_start:-?}, fail2ban block at line ${block_start}"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
