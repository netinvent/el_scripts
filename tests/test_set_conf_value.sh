#!/usr/bin/env bash

# Unit tests for the set_conf_value / escape_bre helpers of el_configurator.sh
#
# set_conf_value applies nearly every hardening directive in the script, and its historical failure
# mode was silent: it could decide a setting was already present, change nothing, and still log
# success. These tests pin that behaviour down.
#
# The helpers are extracted from el_configurator.sh rather than sourced, because the script is a
# single self-contained file that executes on source.
#
# Usage: tests/test_set_conf_value.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

# Extract from 'escape_bre() {' down to the closing brace of set_conf_value
extract_start=$(grep -n '^escape_bre() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
set_conf_start=$(grep -n '^set_conf_value() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${extract_start}" ] || [ -z "${set_conf_start}" ]; then
    echo "Cannot locate escape_bre() / set_conf_value() in [${SCRIPT}]"
    exit 2
fi
extract_end=$(awk -v s="${set_conf_start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
if [ -z "${extract_end}" ]; then
    echo "Cannot find the end of set_conf_value() in [${SCRIPT}]"
    exit 2
fi

HELPERS=$(mktemp)
FIXTURES=$(mktemp -d)
trap 'rm -f "${HELPERS}"; rm -rf "${FIXTURES}"' EXIT

sed -n "${extract_start},${extract_end}p" "${SCRIPT}" > "${HELPERS}"

# Stubs for what the extracted helpers expect from the surrounding script.
# These are read by the extracted code, which the linter cannot see, hence the SC2034 waivers
# shellcheck disable=SC2034
LOG_FILE=/dev/null
# shellcheck disable=SC2034
POST_INSTALL_SCRIPT_GOOD=true
LOGGED_ERRORS=0
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
        # Mirrors the real log(): an ERROR is what flips the script's success banner
        # shellcheck disable=SC2034
        POST_INSTALL_SCRIPT_GOOD=false
    fi
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0

# check <label> <content before|@NOFILE> <content after> <expected rc> -- <set_conf_value args...>
check() {
    local label="${1}" before="${2}" after="${3}" want_rc="${4}"
    shift 5
    local file="${FIXTURES}/conf" rc got want
    if [ "${before}" = "@NOFILE" ]; then
        rm -f "${file}"
    else
        printf '%s' "${before}" > "${file}"
    fi
    LOGGED_ERRORS=0
    set_conf_value "${file}" "$@"
    rc=$?
    got=$(cat "${file}" 2>/dev/null)
    want=$(printf '%s' "${after}")
    if [ "${got}" = "${want}" ] && [ "${rc}" -eq "${want_rc}" ]; then
        PASSED=$((PASSED + 1))
        printf '  ok   %s\n' "${label}"
    else
        FAILED=$((FAILED + 1))
        printf '  FAIL %s\n' "${label}"
        printf '         want rc=%s content=%q\n' "${want_rc}" "${want}"
        printf '         got  rc=%s content=%q\n' "${rc}" "${got}"
    fi
}

echo "Testing set_conf_value from [${SCRIPT}] lines ${extract_start}-${extract_end}"
echo
echo "== a key must match on its own boundary =="

# A longer key sharing the prefix used to satisfy the search while failing the rewrite,
# so the directive was silently never written and no ERROR was raised
check "longer key with same prefix does not swallow the write" \
  'PermitRootLoginPolicy yes
' 'PermitRootLoginPolicy yes
PermitRootLogin no
' 0 -- "PermitRootLogin" "no" " "

check "longer key with same prefix, = separator" \
  'PortForwarding=yes
' 'PortForwarding=yes
Port=22
' 0 -- "Port" "22" "="

# An unescaped '.' in the name is a regex wildcard and used to overwrite unrelated lines
check "dot in a key name is matched literally, not as a wildcard" \
  'netXipv4Xip_forward = 0
' 'netXipv4Xip_forward = 0
net.ipv4.ip_forward=1
' 0 -- "net.ipv4.ip_forward" "1"

echo
echo "== values are written verbatim =="

# '&' means "the whole match" on the replacement side of sed's s///
check "ampersand in a value is written literally" \
  'Motd=old
' 'Motd=A&B
' 0 -- "Motd" "A&B"

check "backslash in a value is written literally" \
  'Path=old
' 'Path=C:\tmp
' 0 -- "Path" 'C:\tmp'

check "glob in a value stays literal (chrony include)" \
  '@NOFILE' 'include /etc/chrony/sources.d/*.conf
' 0 -- "include" "/etc/chrony/sources.d/*.conf" " "

check "value containing spaces (kernel.printk)" \
  '@NOFILE' 'kernel.printk=4 4 1 7
' 0 -- "kernel.printk" "4 4 1 7"

echo
echo "== the three separator styles =="

check "'=' separator, existing value padded with spaces" \
  'Storage = auto
Other=1
' 'Storage=persistent
Other=1
' 0 -- "Storage" "persistent" "="

check "' ' separator (sshd style)" \
  'X11Forwarding yes
UsePAM yes
' 'X11Forwarding no
UsePAM yes
' 0 -- "X11Forwarding" "no" " "

check "' = ' separator (fail2ban style)" \
  'bantime = 10m
' 'bantime = 30m
' 0 -- "bantime" "30m" " = "

echo
echo "== create, append and update =="

check "creates the file when it does not exist" \
  '@NOFILE' 'vm.swappiness=1
' 0 -- "vm.swappiness" "1"

check "appends when the key is absent" \
  'UsePAM yes
' 'UsePAM yes
MaxAuthTries 3
' 0 -- "MaxAuthTries" "3" " "

check "a commented-out key is left alone and the directive appended" \
  '#PermitRootLogin yes
' '#PermitRootLogin yes
PermitRootLogin no
' 0 -- "PermitRootLogin" "no" " "

check "an indented, still-active directive is updated in place" \
  '  X11Forwarding yes
' 'X11Forwarding no
' 0 -- "X11Forwarding" "no" " "

check "duplicate keys are all normalised to the wanted value" \
  'Port=22
Port=2222
' 'Port=22
Port=22
' 0 -- "Port" "22" "="

check "re-running leaves the file unchanged" \
  'MaxAuthTries 3
' 'MaxAuthTries 3
' 0 -- "MaxAuthTries" "3" " "

echo
echo "== real call sites from el_configurator.sh =="

check "two-word key (sudoers Defaults)" \
  'Defaults    env_reset
' 'Defaults    env_reset
Defaults logfile=/var/log/sudo.log
' 0 -- "Defaults logfile" "/var/log/sudo.log" "="

check "apt-style key with colons and a quoted value" \
  '@NOFILE' 'APT::Periodic::Unattended-Upgrade "1";
' 0 -- "APT::Periodic::Unattended-Upgrade" '"1";' " "

# $'...' keeps the trailing space visible: key + ' ' separator + empty value.
# modprobe accepts the trailing space.
check "empty value with ' ' separator (modprobe blacklist)" \
  '@NOFILE' $'blacklist squashfs \n' 0 -- "blacklist squashfs" "" " "

check "empty value is idempotent on a second run" \
  $'blacklist squashfs \n' $'blacklist squashfs \n' 0 -- "blacklist squashfs" "" " "

echo
echo "== a failed write is reported, not swallowed =="

LOGGED_ERRORS=0
write_rc=0
set_conf_value "${FIXTURES}/no_such_dir/conf" "Storage" "persistent" "=" > /dev/null 2>&1 || write_rc=$?
if [ "${write_rc}" -eq 1 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    PASSED=$((PASSED + 1))
    printf '  ok   an unwritable path returns 1 and logs an ERROR\n'
else
    FAILED=$((FAILED + 1))
    printf '  FAIL unwritable path: rc=%s errors=%s (wanted rc=1, errors>=1)\n' "${write_rc}" "${LOGGED_ERRORS}"
fi

rm -f "${FIXTURES}/rc_conf"
if set_conf_value "${FIXTURES}/rc_conf" "SomeKey" "1" > /dev/null 2>&1; then
    PASSED=$((PASSED + 1))
    printf '  ok   a successful write returns 0, so "|| log ERROR" call sites work\n'
else
    FAILED=$((FAILED + 1))
    printf '  FAIL a successful write did not return 0\n'
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
