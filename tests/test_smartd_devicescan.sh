#!/usr/bin/env bash

# Tests for configure_smartd_devicescan() in el_configurator.sh
#
# The DEVICESCAN entry used to be appended unconditionally, and the whole file was then run through
# "sort -u" so that re-running the script did not make it grow. That deduplicated, and it also
# sorted, which smartd.conf cannot survive. From smartd.conf(5):
#
#   DEFAULT      "all directives in this entry are set as defaults for the next device entries"
#   DEVICESCAN   smartd "will ignore any remaining lines in the configuration file"
#
# Both are position dependent. Sorting moved an operator's DEFAULT line below the /dev entries it
# was written above, so its directives silently stopped applying to them, and it alphabetised the
# comments away from whatever they documented.
#
# Usage: tests/test_smartd_devicescan.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^configure_smartd_devicescan() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate configure_smartd_devicescan() in [${SCRIPT}]"
    exit 2
fi
end=$(awk -v s="${start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")

WORK=$(mktemp -d)
HELPERS="${WORK}/smartd.sh"
CONF="${WORK}/smartd.conf"
trap 'rm -rf "${WORK}"' EXIT

# Read by the extracted function, which the linter cannot see, hence the SC2034 waivers
# shellcheck disable=SC2034
LOG_FILE=/dev/null
LOGGED_ERRORS=0
# shellcheck disable=SC2034
POST_INSTALL_SCRIPT_GOOD=true
LOGGED="${WORK}/logged.txt"
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
        # shellcheck disable=SC2034
        POST_INSTALL_SCRIPT_GOOD=false
    fi
    # Recorded so that a test can assert which check fired, not merely that something did. Several
    # of these failure paths end in the same return code by different routes
    printf '%s: %s\n' "${2:-INFO}" "${1}" >> "${LOGGED}"
    [ -n "${VERBOSE}" ] && printf '    log[%s]: %s\n' "${2:-INFO}" "${1}"
    return 0
}
logged() { grep -qF "${1}" "${LOGGED}" 2>/dev/null; }

sed -n "${start},${end}p" "${SCRIPT}" > "${HELPERS}"
# shellcheck disable=SC1090
source "${HELPERS}"

# The directive the function writes, read back out of the function itself so that these tests
# cannot drift from it
DIRECTIVE=$(sed -n 's/^ *local devicescan="\(.*\)"$/\1/p' "${HELPERS}")
if [ -z "${DIRECTIVE}" ]; then
    echo "Cannot read the DEVICESCAN directive out of the extracted function"
    exit 2
fi

PASSED=0
FAILED=0
SKIPPED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }
skip() { SKIPPED=$((SKIPPED + 1)); printf '  skip %s\n' "${1}"; }

# A realistic operator-written smartd.conf: a DEFAULT that applies to the two device entries under
# it, comments that explain the lines they sit above, and a stock DEVICESCAN at the end
write_conf() {
    cat > "${CONF}" <<'FIX'
# Sample configuration file for smartd.
#
# Directives here apply to the device entries below them.
DEFAULT -a -o on -S on
/dev/sda -d sat -s L/../../6/03
/dev/sdb -d sat
# Scan anything not named above
DEVICESCAN
FIX
}

# Position of the first line matching a fixed string, or 0
line_of() { grep -nFx "${1}" "${CONF}" 2>/dev/null | head -n 1 | cut -d: -f1; }
line_containing() { grep -nF "${1}" "${CONF}" 2>/dev/null | head -n 1 | cut -d: -f1; }

echo "Testing configure_smartd_devicescan from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== the operator's ordering survives, which is what sort -u destroyed =="

write_conf
LOGGED_ERRORS=0
configure_smartd_devicescan "${CONF}" > /dev/null
rc=$?

if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "returns 0 and logs no ERROR"
else
    fail "returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi

default_at=$(line_of 'DEFAULT -a -o on -S on')
sda_at=$(line_of '/dev/sda -d sat -s L/../../6/03')
sdb_at=$(line_of '/dev/sdb -d sat')
if [ -n "${default_at}" ] && [ -n "${sda_at}" ] && [ "${default_at}" -lt "${sda_at}" ] && [ "${default_at}" -lt "${sdb_at}" ]; then
    pass "DEFAULT stays above the device entries it sets defaults for"
else
    fail "DEFAULT stays above the device entries it sets defaults for" \
         "DEFAULT at ${default_at:-missing}, /dev/sda at ${sda_at:-missing}, /dev/sdb at ${sdb_at:-missing}" \
         "$(cat "${CONF}")"
fi

if [ "$(line_containing '# Directives here apply')" -lt "${default_at}" ]; then
    pass "comments stay above the lines they document"
else
    fail "comments stay above the lines they document" "$(cat "${CONF}")"
fi

if [ "$(line_of "${DIRECTIVE}")" = "$(wc -l < "${CONF}")" ]; then
    pass "our DEVICESCAN goes last, since it makes smartd stop reading the file"
else
    fail "our DEVICESCAN goes last" "$(cat -n "${CONF}")"
fi

if grep -qFx '# DEVICESCAN' "${CONF}"; then
    pass "the stock DEVICESCAN is commented out, only the first one is ever executed"
else
    fail "the stock DEVICESCAN is commented out" "$(cat "${CONF}")"
fi

echo
echo "== re-running changes nothing at all =="

after_first=$(cat "${CONF}")
LOGGED_ERRORS=0
configure_smartd_devicescan "${CONF}" > /dev/null
configure_smartd_devicescan "${CONF}" > /dev/null
rc=$?

if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a repeat run returns 0 and logs no ERROR"
else
    fail "a repeat run returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi

if [ "${after_first}" = "$(cat "${CONF}")" ]; then
    pass "two further runs leave the file byte for byte identical"
else
    fail "two further runs leave the file byte for byte identical" \
         "$(diff <(printf '%s\n' "${after_first}") "${CONF}")"
fi

if [ "$(grep -cFx "${DIRECTIVE}" "${CONF}")" -eq 1 ]; then
    pass "the directive is present exactly once"
else
    fail "the directive is present exactly once" "$(grep -nF 'DEVICESCAN' "${CONF}")"
fi

# The old code commented out its own entry on every run and appended a fresh one, so each pass left
# another "# DEVICESCAN -H ..." line behind. sort -u is what stopped that growing without bound
if [ "$(grep -cF '# DEVICESCAN -H' "${CONF}")" -eq 0 ]; then
    pass "no commented-out copy of our own directive accumulates"
else
    fail "no commented-out copy of our own directive accumulates" "$(grep -nF 'DEVICESCAN' "${CONF}")"
fi

echo
echo "== the entry is compared as a whole literal line =="

# Without -x, the commented copy below contains the directive as a substring, so the function would
# decide it is already configured and never write the active entry
write_conf
printf '# %s\n' "${DIRECTIVE}" >> "${CONF}"
LOGGED_ERRORS=0
configure_smartd_devicescan "${CONF}" > /dev/null
if grep -qFx "${DIRECTIVE}" "${CONF}"; then
    pass "a commented-out copy does not count as the entry being present"
else
    fail "a commented-out copy does not count as the entry being present" "$(cat "${CONF}")"
fi

# Synthetic, to pin the -F: the directive carries (, |, [5] and several dots. Read as an expression
# rather than as literal text it would match the near miss below, where every dot is an X and the
# bracket expression has become the single character it matches
write_conf
printf '%s\n' "$(printf '%s' "${DIRECTIVE}" | tr '.' 'X' | sed 's/\[5\]/5/')" >> "${CONF}"
LOGGED_ERRORS=0
configure_smartd_devicescan "${CONF}" > /dev/null
if grep -qFx "${DIRECTIVE}" "${CONF}"; then
    pass "a line that only matches as an expression does not count as the entry"
else
    fail "a line that only matches as an expression does not count as the entry" "$(cat "${CONF}")"
fi

echo
echo "== failures are reported =="

# The message matters, not just the return code. Without the missing-file check the call still
# fails, but further down at the sed, which reports something else entirely
LOGGED_ERRORS=0
: > "${LOGGED}"
if configure_smartd_devicescan "${WORK}/does-not-exist.conf" > /dev/null 2>&1; then
    fail "a missing configuration file returns non-zero"
elif [ "${LOGGED_ERRORS}" -ge 1 ] && logged "Cannot find smartd configuration file"; then
    pass "a missing configuration file is reported as missing, not as a failed edit"
else
    fail "a missing configuration file is reported as missing" "$(cat "${LOGGED}" 2>/dev/null)"
fi

write_conf
chmod 0444 "${CONF}" 2>/dev/null
if printf 'test\n' 2>/dev/null >> "${CONF}"; then
    # This filesystem does not enforce the mode, so the case cannot be reached here
    chmod 0644 "${CONF}" 2>/dev/null
    skip "an unwritable configuration file returns non-zero (mode not enforced on this filesystem)"
else
    LOGGED_ERRORS=0
    if configure_smartd_devicescan "${CONF}" > /dev/null 2>&1; then
        fail "an unwritable configuration file returns non-zero"
    elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
        pass "an unwritable configuration file returns non-zero and logs an ERROR"
    else
        fail "an unwritable configuration file logs an ERROR"
    fi
    chmod 0644 "${CONF}" 2>/dev/null
fi

# Exercise the read-back specifically. Every other failure here is caught by the sed or the append
# reporting its own error, so the only way to reach the read-back is an append that claims to have
# succeeded and wrote nothing. Shadowing the echo builtin produces exactly that: the shell still
# applies the redirection, so the file is touched, but no line is written and the status is 0
write_conf
: > "${LOGGED}"
LOGGED_ERRORS=0
echo() { return 0; }
configure_smartd_devicescan "${CONF}" > /dev/null 2>&1
rc=$?
unset -f echo
if [ "${rc}" -ne 0 ] && logged "did not land in"; then
    pass "an append that silently writes nothing is caught by the read-back"
else
    fail "an append that silently writes nothing is caught by the read-back" \
         "rc=${rc}, logged: $(cat "${LOGGED}" 2>/dev/null)"
fi

echo
echo "== nothing sorts a configuration file any more =="

code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")

if printf '%s\n' "${code_only}" | grep -qE 'sort -u'; then
    fail "no code line runs sort -u over a configuration file" \
         "$(printf '%s\n' "${code_only}" | grep -nE 'sort -u')"
else
    pass "no code line runs sort -u over a configuration file"
fi

# The helper existed only to feed that sort, and had exactly one caller
if grep -q 'uniq_filelines' "${SCRIPT}"; then
    fail "uniq_filelines is gone" "$(grep -n 'uniq_filelines' "${SCRIPT}" | head -3)"
else
    pass "uniq_filelines is gone"
fi

if grep -qE '^[[:space:]]*configure_smartd_devicescan "\$\{SMARTD_CONF_FILE\}"' "${SCRIPT}"; then
    pass "the smartd block calls the helper"
else
    fail "the smartd block calls the helper" "$(grep -n 'configure_smartd_devicescan' "${SCRIPT}")"
fi

# The paths are not symmetrical and are easy to transpose: EL builds smartmontools with
# --sysconfdir=/etc/smartmontools/, Debian ships /etc/smartd.conf
if grep -qE 'SMARTD_CONF_FILE=/etc/smartmontools/smartd\.conf' "${SCRIPT}" \
   && grep -qE 'SMARTD_CONF_FILE=/etc/smartd\.conf' "${SCRIPT}"; then
    pass "both distribution paths for smartd.conf are still set"
else
    fail "both distribution paths for smartd.conf are still set" "$(grep -n 'SMARTD_CONF_FILE=' "${SCRIPT}")"
fi

echo
printf 'passed %d, failed %d, skipped %d\n' "${PASSED}" "${FAILED}" "${SKIPPED}"
[ "${FAILED}" -eq 0 ]
