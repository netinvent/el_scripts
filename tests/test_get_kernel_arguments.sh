#!/usr/bin/env bash

# Unit tests for the get_kernel_arguments helper of el_configurator.sh
#
# Kernel arguments used to be handed to eval, which made any boot line arbitrary root code
# execution and glob-expanded unquoted values. These tests pin down that arguments are parsed
# and never executed, and that values survive intact.
#
# The helper is extracted from el_configurator.sh rather than sourced, because the script is a
# single self-contained file that executes on source.
#
# Usage: tests/test_get_kernel_arguments.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

extract_start=$(grep -n '^get_kernel_arguments() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${extract_start}" ]; then
    echo "Cannot locate get_kernel_arguments() in [${SCRIPT}]"
    exit 2
fi
extract_end=$(awk -v s="${extract_start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
if [ -z "${extract_end}" ]; then
    echo "Cannot find the end of get_kernel_arguments() in [${SCRIPT}]"
    exit 2
fi

HELPERS=$(mktemp)
FIXTURES=$(mktemp -d)
CANARY="${FIXTURES}/canary"
trap 'rm -f "${HELPERS}"; rm -rf "${FIXTURES}"' EXIT

sed -n "${extract_start},${extract_end}p" "${SCRIPT}" > "${HELPERS}"

# Stubs for what the extracted helper expects from the surrounding script.
# These are read by the extracted code, which the linter cannot see, hence the SC2034 waivers
# shellcheck disable=SC2034
LOG_FILE=/dev/null
# shellcheck disable=SC2034
POST_INSTALL_SCRIPT_GOOD=true
LOGGED_ERRORS=0
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
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; printf '         %s\n' "$@"; }

# parse <cmdline string> -- runs the helper against a fake /proc/cmdline
parse() {
    printf '%s\n' "${1}" > "${FIXTURES}/cmdline"
    LOGGED_ERRORS=0
    rm -f "${CANARY}"
    get_kernel_arguments "${FIXTURES}/cmdline"
}

# check_var <label> <cmdline> <variable> <expected value>
check_var() {
    local label="${1}" cmdline="${2}" var="${3}" want="${4}"
    unset "${var}"
    parse "${cmdline}"
    local got="${!var}"
    if [ "${got}" = "${want}" ]; then
        pass "${label}"
    else
        fail "${label}" "want ${var}=$(printf '%q' "${want}")" "got  ${var}=$(printf '%q' "${got}")"
    fi
}

# check_no_exec <label> <cmdline> -- the payload must not run and must not be lost silently
check_no_exec() {
    local label="${1}" cmdline="${2}"
    parse "${cmdline}"
    if [ -e "${CANARY}" ]; then
        fail "${label}" "the payload executed: canary file was created"
    else
        pass "${label}"
    fi
}

echo "Testing get_kernel_arguments from [${SCRIPT}] lines ${extract_start}-${extract_end}"
echo
echo "== kernel arguments are parsed, never executed =="

# These payloads deliberately contain no spaces. A kernel argument is a single whitespace
# delimited token, so a payload with spaces merely produces an eval syntax error and would
# make these tests pass for the wrong reason.
check_no_exec "command substitution in a value does not run" \
  "ro quiet NPF_BRAND_NAME=\$(id>${CANARY})"
check_no_exec "backtick substitution in a value does not run" \
  "ro quiet NPF_BRAND_NAME=\`id>${CANARY}\`"
check_no_exec "a semicolon does not start a second command" \
  "ro NPF_BRAND_NAME=x;id>${CANARY}"
check_no_exec "a redirection in a value does not truncate a file" \
  "ro NPF_BRAND_NAME=x>${CANARY}"

# The payload text must survive verbatim as data, not vanish.
# Single quotes are deliberate here: the point is that $(id) is never expanded, hence the SC2016 waiver
# shellcheck disable=SC2016
check_var "an injection attempt is kept as a literal string" \
  'ro NPF_BRAND_NAME=$(id)' "BRAND_NAME" '$(id)'

echo
echo "== values survive intact =="

check_var "plain value" \
  "ro quiet NPF_SCAP_PROFILE=anssi_bp28_intermediary" "SCAP_PROFILE" "anssi_bp28_intermediary"

check_var "value containing '=' is not truncated" \
  "NPF_SOME_TOKEN=abc=def" "SOME_TOKEN" "abc=def"

check_var "quoted value containing spaces" \
  'ro NPF_ISSUE_MESSAGE_EXTRA="- Private System" quiet' "ISSUE_MESSAGE_EXTRA" "- Private System"

check_var "colon separated list" \
  "NPF_FIREWALL_WHITELIST_IP_LIST=192.168.200.0/24:10.0.0.1" \
  "FIREWALL_WHITELIST_IP_LIST" "192.168.200.0/24:10.0.0.1"

check_var "empty value" \
  "NPF_NTP_SERVERS= quiet" "NTP_SERVERS" ""

check_var "boolean false" \
  "ro NPF_CONFIGURE_FAIL2BAN=false" "CONFIGURE_FAIL2BAN" "false"

echo
echo "== no glob expansion =="

# A bare '*' used to be expanded against the working directory by the unquoted array assignment
cd "${FIXTURES}" || exit 2
: > aaa.txt
: > bbb.txt
check_var "asterisk is kept literal, not expanded to filenames" \
  "ro NPF_BRAND_NAME=*" "BRAND_NAME" "*"
check_var "question mark is kept literal" \
  "ro NPF_BRAND_NAME=?" "BRAND_NAME" "?"
rm -f aaa.txt bbb.txt
cd - > /dev/null || exit 2

echo
echo "== several arguments on one line =="

unset BRAND_NAME SCAP_PROFILE CONFIGURE_WATCHDOG
parse 'BOOT_IMAGE=/vmlinuz ro NPF_BRAND_NAME="Net Perfect" quiet NPF_SCAP_PROFILE=false NPF_CONFIGURE_WATCHDOG=true rhgb'
if [ "${BRAND_NAME}" = "Net Perfect" ] && [ "${SCAP_PROFILE}" = "false" ] && [ "${CONFIGURE_WATCHDOG}" = "true" ]; then
    pass "three overrides on one line are all applied"
else
    fail "three overrides on one line are all applied" \
        "got BRAND_NAME=$(printf '%q' "${BRAND_NAME}") SCAP_PROFILE=$(printf '%q' "${SCAP_PROFILE}") CONFIGURE_WATCHDOG=$(printf '%q' "${CONFIGURE_WATCHDOG}")"
fi

unset BRAND_NAME
parse 'BOOT_IMAGE=/vmlinuz ro quiet rhgb crashkernel=auto'
if [ -z "${BRAND_NAME}" ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a line with no NPF_ arguments changes nothing and logs no error"
else
    fail "a line with no NPF_ arguments changes nothing" "BRAND_NAME=$(printf '%q' "${BRAND_NAME}") errors=${LOGGED_ERRORS}"
fi

echo
echo "== refused arguments are reported, not silently applied =="

saved_path="${PATH}"
parse "ro NPF_PATH=/tmp/evil"
if [ "${PATH}" = "${saved_path}" ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "an exported variable such as PATH cannot be overwritten"
else
    fail "an exported variable such as PATH cannot be overwritten" \
        "PATH changed=$([ "${PATH}" != "${saved_path}" ] && echo yes || echo no) errors=${LOGGED_ERRORS}"
fi
PATH="${saved_path}"

parse "ro NPF_9INVALID=x"
if [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "an invalid variable name is rejected with an ERROR"
else
    fail "an invalid variable name is rejected with an ERROR" "errors=${LOGGED_ERRORS}"
fi

LOGGED_ERRORS=0
if get_kernel_arguments "${FIXTURES}/does_not_exist" > /dev/null 2>&1; then
    fail "a missing cmdline file returns non-zero" "returned 0"
else
    if [ "${LOGGED_ERRORS}" -ge 1 ]; then
        pass "a missing cmdline file returns non-zero and logs an ERROR"
    else
        fail "a missing cmdline file logs an ERROR" "errors=${LOGGED_ERRORS}"
    fi
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
