#!/usr/bin/env bash

# Tests for the GRUB console argument rewrite in el_configurator.sh
#
# Enabling the serial console used to be a single greedy sed that discarded every kernel argument
# after the first console= one. That silently removed audit=1, which CIS and ANSSI both want, and
# net.ifnames=0, which renames the network interfaces on the next boot. These tests pin down that
# only the console arguments are touched.
#
# Usage: tests/test_grub_console_args.sh [path/to/el_configurator.sh]

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

grub_lines=$(extract_function set_grub_console_args)
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

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

GRUB="${WORK}/grub"
CONSOLE="console=tty0 console=ttyS0,115200,n8"

# check <label> <file content before> <expected GRUB_CMDLINE_LINUX line after>
check() {
    local label="${1}" before="${2}" want="${3}" got
    printf '%s' "${before}" > "${GRUB}"
    LOGGED_ERRORS=0
    set_grub_console_args "${GRUB}" "GRUB_CMDLINE_LINUX" "${CONSOLE}" > /dev/null
    got=$(grep -E '^GRUB_CMDLINE_LINUX=' "${GRUB}")
    if [ "${got}" = "${want}" ]; then
        pass "${label}"
    else
        fail "${label}" "want ${want}" "got  ${got}"
    fi
}

echo "Testing set_grub_console_args from [${SCRIPT}] lines ${grub_lines}"
echo
echo "== other kernel arguments survive =="

# The exact case from the finding
check "the regression case: nothing after console= is lost" \
  'GRUB_CMDLINE_LINUX="console=ttyS0 net.ifnames=0 biosdevname=0 audit=1"
' \
  'GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0 audit=1 console=tty0 console=ttyS0,115200,n8"'

check "arguments before an existing console= survive" \
  'GRUB_CMDLINE_LINUX="quiet splash console=ttyS0"
' \
  'GRUB_CMDLINE_LINUX="quiet splash console=tty0 console=ttyS0,115200,n8"'

check "several existing console= arguments are all replaced" \
  'GRUB_CMDLINE_LINUX="console=tty1 audit=1 console=ttyS1,9600 rootdelay=5"
' \
  'GRUB_CMDLINE_LINUX="audit=1 rootdelay=5 console=tty0 console=ttyS0,115200,n8"'

check "a value with no console= at all just gains the console arguments" \
  'GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192"
' \
  'GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192 console=tty0 console=ttyS0,115200,n8"'

check "an empty value gains only the console arguments" \
  'GRUB_CMDLINE_LINUX=""
' \
  'GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200,n8"'

check "arguments containing = and , are preserved verbatim" \
  'GRUB_CMDLINE_LINUX="rd.lvm.lv=vg0/root crashkernel=1G-4G:192M,4G-64G:256M audit=1"
' \
  'GRUB_CMDLINE_LINUX="rd.lvm.lv=vg0/root crashkernel=1G-4G:192M,4G-64G:256M audit=1 console=tty0 console=ttyS0,115200,n8"'

echo
echo "== the setting is found and created correctly =="

check "GRUB_CMDLINE_LINUX_DEFAULT is not mistaken for GRUB_CMDLINE_LINUX" \
  'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX="audit=1"
' \
  'GRUB_CMDLINE_LINUX="audit=1 console=tty0 console=ttyS0,115200,n8"'

printf 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\n' > "${GRUB}"
LOGGED_ERRORS=0
set_grub_console_args "${GRUB}" "GRUB_CMDLINE_LINUX" "${CONSOLE}" > /dev/null
if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"$' "${GRUB}"; then
    pass "the unrelated GRUB_CMDLINE_LINUX_DEFAULT line is left alone"
else
    fail "the unrelated GRUB_CMDLINE_LINUX_DEFAULT line is left alone" "$(cat "${GRUB}")"
fi
if grep -q '^GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200,n8"$' "${GRUB}"; then
    pass "a missing setting is created rather than skipped"
else
    fail "a missing setting is created rather than skipped" "$(cat "${GRUB}")"
fi

echo
echo "== rerunning changes nothing =="

printf 'GRUB_CMDLINE_LINUX="audit=1 console=ttyS0"\n' > "${GRUB}"
set_grub_console_args "${GRUB}" "GRUB_CMDLINE_LINUX" "${CONSOLE}" > /dev/null
first_run=$(cat "${GRUB}")
set_grub_console_args "${GRUB}" "GRUB_CMDLINE_LINUX" "${CONSOLE}" > /dev/null
if [ "${first_run}" = "$(cat "${GRUB}")" ]; then
    pass "a second run leaves the file identical"
else
    fail "a second run leaves the file identical" "first  ${first_run}" "second $(cat "${GRUB}")"
fi

echo
echo "== failures are reported =="

LOGGED_ERRORS=0
if set_grub_console_args "${WORK}/no_such_grub" "GRUB_CMDLINE_LINUX" "${CONSOLE}" > /dev/null 2>&1; then
    fail "a missing grub defaults file returns non-zero"
elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a missing grub defaults file returns non-zero and logs an ERROR"
else
    fail "a missing grub defaults file logs an ERROR"
fi

echo
echo "== the greedy sed is gone from el_configurator.sh =="

if grep -qE "sed -Ei .s#GRUB_CMDLINE_LINUX" "${SCRIPT}"; then
    fail "no greedy GRUB_CMDLINE_LINUX sed remains" \
         "$(grep -nE 'sed -Ei .s#GRUB_CMDLINE_LINUX' "${SCRIPT}")"
else
    pass "no greedy GRUB_CMDLINE_LINUX sed remains"
fi

if grep -qE 'set_grub_console_args /etc/default/grub' "${SCRIPT}"; then
    pass "the Debian branch calls set_grub_console_args"
else
    fail "the Debian branch calls set_grub_console_args"
fi

# The two seds this replaced had no error handling at all
if grep -A2 'set_grub_console_args /etc/default/grub' "${SCRIPT}" | grep -q 'log "Failed to set console arguments'; then
    pass "a failure to set the console arguments is logged"
else
    fail "a failure to set the console arguments is logged"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
