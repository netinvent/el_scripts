#!/usr/bin/env bash

# Tests for the systemd configuration drop-ins written by el_configurator.sh
#
# journald.conf and system.conf used to be edited in place, at a path that varied by release. On
# EL10 that path is /usr/lib/systemd, where the files belong to the systemd package: editing them
# there shows up in rpm -Va for good and is undone by the next systemd update, so persistent
# journal storage and the runtime watchdog would silently stop being configured.
#
# Drop-ins under /etc are the documented place for a local administrator to override vendor
# configuration and take precedence over the main file, whichever prefix the distribution uses.
#
# Usage: tests/test_systemd_dropins.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^write_systemd_dropin() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate write_systemd_dropin() in [${SCRIPT}]"
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
LOGGED_NOTICES=0
# shellcheck disable=SC2034
POST_INSTALL_SCRIPT_GOOD=true
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
        # shellcheck disable=SC2034
        POST_INSTALL_SCRIPT_GOOD=false
    fi
    # Counted apart from errors, because the difference between the two is the entire point of the
    # journal flush assertions below: an ERROR reddens the banner and the state metric, a NOTICE
    # leaves both alone
    [ "${2}" = "NOTICE" ] && LOGGED_NOTICES=$((LOGGED_NOTICES + 1))
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

# The function writes under /etc/systemd, which these tests must not touch. Redirect it into the
# work directory by shadowing mkdir and the shell's view of the path is not enough, so the helper
# is sourced with a patched prefix instead.
sed "s#/etc/systemd/#${WORK}/etc/systemd/#" "${HELPERS}" > "${HELPERS}.local"
# shellcheck disable=SC1090
source "${HELPERS}.local"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

echo "Testing write_systemd_dropin from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== a drop-in is written under /etc, not over the vendor file =="

LOGGED_ERRORS=0
write_systemd_dropin journald.conf Journal "Storage=persistent" > /dev/null
rc=$?
dropin="${WORK}/etc/systemd/journald.conf.d/99-el_configurator.conf"

if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "returns 0 and logs no ERROR"
else
    fail "returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi
if [ -f "${dropin}" ]; then
    pass "the file lands in journald.conf.d, which overrides the main file"
else
    fail "the file lands in journald.conf.d" "not found at ${dropin}"
fi
if grep -qx '\[Journal\]' "${dropin}" 2>/dev/null && grep -qx 'Storage=persistent' "${dropin}" 2>/dev/null; then
    pass "the section header and the setting are both written"
else
    fail "the section header and the setting are both written" "$(cat "${dropin}" 2>/dev/null)"
fi

LOGGED_ERRORS=0
write_systemd_dropin system.conf Manager "RuntimeWatchdogSec=60s" > /dev/null
wd="${WORK}/etc/systemd/system.conf.d/99-el_configurator.conf"
if grep -qx '\[Manager\]' "${wd}" 2>/dev/null && grep -qx 'RuntimeWatchdogSec=60s' "${wd}" 2>/dev/null; then
    pass "the watchdog drop-in uses the [Manager] section"
else
    fail "the watchdog drop-in uses the [Manager] section" "$(cat "${wd}" 2>/dev/null)"
fi

echo
echo "== more than one setting, and re-running =="

LOGGED_ERRORS=0
write_systemd_dropin journald.conf Journal "Storage=persistent" "SystemMaxUse=2G" > /dev/null
if grep -qx 'Storage=persistent' "${dropin}" && grep -qx 'SystemMaxUse=2G' "${dropin}"; then
    pass "several settings can be written at once"
else
    fail "several settings can be written at once" "$(cat "${dropin}")"
fi

write_systemd_dropin journald.conf Journal "Storage=persistent" > /dev/null
if [ "$(grep -c 'Storage=persistent' "${dropin}")" -eq 1 ]; then
    pass "a second run replaces the drop-in rather than appending to it"
else
    fail "a second run replaces the drop-in" "$(cat "${dropin}")"
fi

echo
echo "== failures are reported =="

LOGGED_ERRORS=0
if write_systemd_dropin journald.conf Journal > /dev/null 2>&1; then
    fail "calling with no setting returns non-zero"
elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "calling with no setting returns non-zero and logs an ERROR"
else
    fail "calling with no setting logs an ERROR"
fi

# Exercise the read-back. Occupying the drop-in path with a directory makes the redirect fail,
# which nothing else in this suite would notice: without the read-back the function would report
# success on a read only or full filesystem.
mkdir -p "${WORK}/etc/systemd/blocked.conf.d/99-el_configurator.conf"
LOGGED_ERRORS=0
if write_systemd_dropin blocked.conf Journal "Storage=persistent" > /dev/null 2>&1; then
    fail "a drop-in that could not be written returns non-zero" \
         "it reported success, so the settings are not read back after writing"
elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a drop-in that could not be written returns non-zero and logs an ERROR"
else
    fail "a drop-in that could not be written logs an ERROR"
fi

echo
echo "== the journal size cap is persistent and configurable =="

# journalctl --vacuum-size only trims what is on disk at that moment. Without SystemMaxUse the
# journal was free to grow straight back to journald's default, which is 10% of the filesystem.
if grep -qE '^JOURNAL_MAX_SIZE=' "${SCRIPT}"; then
    pass "JOURNAL_MAX_SIZE is a configuration option"
else
    fail "JOURNAL_MAX_SIZE is a configuration option"
fi

# The single quotes below are deliberate: these patterns match the literal ${...} text in the
# script and must not expand, hence the SC2016 waivers
# shellcheck disable=SC2016
if grep -q 'SystemMaxUse=${JOURNAL_MAX_SIZE}' "${SCRIPT}"; then
    pass "the cap is written as SystemMaxUse in the journald drop-in"
else
    fail "the cap is written as SystemMaxUse in the journald drop-in" \
         "$(grep -n 'SystemMaxUse' "${SCRIPT}")"
fi

# The old code hardcoded 2G in the vacuum call
if grep -qE 'vacuum-size=[0-9]' "${SCRIPT}"; then
    fail "the vacuum size is not hardcoded" "$(grep -nE 'vacuum-size=[0-9]' "${SCRIPT}")"
else
    pass "the vacuum size is not hardcoded"
fi

# shellcheck disable=SC2016
if grep -q 'journalctl --vacuum-size="${JOURNAL_MAX_SIZE}"' "${SCRIPT}"; then
    pass "the vacuum reuses the configured value"
else
    fail "the vacuum reuses the configured value" "$(grep -n 'vacuum-size' "${SCRIPT}")"
fi

# --vacuum-size rejects a percentage, so passing one through would log a spurious ERROR
# shellcheck disable=SC2016
journal_case=$(sed -n '/^case "\${JOURNAL_MAX_SIZE}" in/,/^esac$/p' "${SCRIPT}")
case "${journal_case}" in
    *'*%)'*) pass "a percentage skips the vacuum, which cannot take one" ;;
    *)       fail "a percentage skips the vacuum" "${journal_case}" ;;
esac
case "${journal_case}" in
    *"'')"*) pass "an empty value leaves journald's own default alone" ;;
    *)       fail "an empty value leaves journald's own default alone" ;;
esac

# The drop-in helper must accept the extra setting, which the multi-setting test above covers
LOGGED_ERRORS=0
write_systemd_dropin journald.conf Journal "Storage=persistent" "SystemMaxUse=500M" > /dev/null
if grep -qx 'SystemMaxUse=500M' "${dropin}" && grep -qx 'Storage=persistent' "${dropin}"; then
    pass "a configured size lands in the drop-in alongside Storage"
else
    fail "a configured size lands in the drop-in alongside Storage" "$(cat "${dropin}")"
fi

echo
echo "== el_configurator.sh no longer edits the vendor files =="

# Both settings used to be sed'ed into ${SYSTEMD_PREFIX}/..., which resolved to /usr/lib on EL10
if grep -qE 'sed .*(journald|system)\.conf' "${SCRIPT}"; then
    fail "no sed rewrites journald.conf or system.conf" \
         "$(grep -nE 'sed .*(journald|system)\.conf' "${SCRIPT}")"
else
    pass "no sed rewrites journald.conf or system.conf"
fi

if grep -q 'SYSTEMD_PREFIX' "${SCRIPT}"; then
    fail "the SYSTEMD_PREFIX release branching is gone" \
         "$(grep -n 'SYSTEMD_PREFIX' "${SCRIPT}" | head -3)"
else
    pass "the SYSTEMD_PREFIX release branching is gone"
fi

for expected in 'write_systemd_dropin journald.conf Journal' 'write_systemd_dropin system.conf Manager'; do
    if grep -q "${expected}" "${SCRIPT}"; then
        pass "called as: ${expected} ..."
    else
        fail "called as: ${expected} ..."
    fi
done

# Nothing should write into /usr/lib/systemd any more
if grep -qE '^[^#]*/usr/lib/systemd' "${SCRIPT}"; then
    fail "nothing writes under /usr/lib/systemd" \
         "$(grep -nE '^[^#]*/usr/lib/systemd' "${SCRIPT}" | head -3)"
else
    pass "nothing writes under /usr/lib/systemd"
fi

echo
echo "== the journal is flushed with journalctl, not by signalling a pid =="

# The flush used to be:
#     kill -USR1 "$(ps aux | grep '[s]ystemd-journald' | awk '{print $2}')"
# which only worked when that substitution produced exactly one pid. Quoted, no match handed kill a
# single empty argument and several matches handed it a single argument with a newline inside; both
# are rejected outright. Several is normal, not exotic: systemd-journald.service(8) says each
# journal namespace is "managed by its own instance of systemd-journald", so any unit carrying
# LogNamespace= adds one.

# Taken out of the script itself, so these assertions cannot drift away from the line they test
flush_line=$(grep -vE '^[[:space:]]*#' "${SCRIPT}" | grep -F 'journalctl --flush' | head -n 1)

if [ -n "${flush_line}" ]; then
    pass "the flush goes through journalctl --flush"
else
    fail "the flush goes through journalctl --flush" "no such line in ${SCRIPT}"
fi

# The old line had no error handling of any kind, so journalctl's own complaint went to whatever
# console the run happened to have rather than into the log with everything else
case "${flush_line}" in
    *'2>> "${LOG_FILE}"'*) pass "the flush sends its own error output to the log" ;;
    *) fail "the flush sends its own error output to the log" "${flush_line}" ;;
esac

code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")
if printf '%s\n' "${code_only}" | grep -qE 'kill -USR1'; then
    fail "no code line signals journald by pid" \
         "$(printf '%s\n' "${code_only}" | grep -nE 'kill -USR1')"
else
    pass "no code line signals journald by pid"
fi
if printf '%s\n' "${code_only}" | grep -qE 'ps aux \| grep'; then
    fail "no code line greps ps output for a pid" \
         "$(printf '%s\n' "${code_only}" | grep -nE 'ps aux \| grep')"
else
    pass "no code line greps ps output for a pid"
fi

if [ -n "${flush_line}" ]; then
    FLUSHBIN="${WORK}/flushbin"
    mkdir -p "${FLUSHBIN}"
    chmod +x "${FLUSHBIN}" 2>/dev/null
    saved_path="${PATH}"
    PATH="${FLUSHBIN}:${PATH}"

    printf '#!/bin/sh\nexit 0\n' > "${FLUSHBIN}/journalctl"
    chmod +x "${FLUSHBIN}/journalctl"
    LOGGED_ERRORS=0
    LOGGED_NOTICES=0
    eval "${flush_line}" > /dev/null 2>&1
    if [ "${LOGGED_ERRORS}" -eq 0 ] && [ "${LOGGED_NOTICES}" -eq 0 ]; then
        pass "a flush that works says nothing"
    else
        fail "a flush that works says nothing" "errors=${LOGGED_ERRORS} notices=${LOGGED_NOTICES}"
    fi

    # journald not being reachable, an installer chroot for instance, must not redden the run:
    # systemd-journal-flush.service performs the same flush on the next boot
    printf '#!/bin/sh\nexit 1\n' > "${FLUSHBIN}/journalctl"
    LOGGED_ERRORS=0
    LOGGED_NOTICES=0
    eval "${flush_line}" > /dev/null 2>&1
    if [ "${LOGGED_NOTICES}" -ge 1 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
        pass "a flush that fails is a NOTICE, so the success banner stays green"
    else
        fail "a flush that fails is a NOTICE and not an ERROR" \
             "errors=${LOGGED_ERRORS} notices=${LOGGED_NOTICES}"
    fi
    PATH="${saved_path}"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
