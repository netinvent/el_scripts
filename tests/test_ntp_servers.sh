#!/usr/bin/env bash

# Tests for the NTP server configuration in el_configurator.sh
#
# This used to write a chrony.conf into /etc/chrony/ on RHEL, a directory the RHEL chrony package
# does not own and chronyd never opens, so the configured time servers were silently ignored there.
# EL8, EL9 and EL10 all read /etc/chrony.conf; Debian keeps its config under /etc/chrony/ and ships
# a sources.d that its own sourcedir directive reads.
#
# server is a repeatable directive, so these tests also pin down that adding one never rewrites the
# pool or sourcedir lines that are already in the file.
#
# This file sets the configuration globals the extracted function reads. The linter cannot see that
# code, so it reports them as unused, hence a file wide waiver.
# shellcheck disable=SC2034
#
# Usage: tests/test_ntp_servers.sh [path/to/el_configurator.sh]

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

add_lines=$(extract_function configure_ntp_servers)
disable_lines=$(extract_function disable_existing_ntp_sources)
start="${add_lines%%-*}"
end="${add_lines##*-}"

LOG_FILE=/dev/null
LOGGED_ERRORS=0
POST_INSTALL_SCRIPT_GOOD=true
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
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

CONF="${WORK}/chrony.conf"

# The stock RHEL /etc/chrony.conf, near enough: a pool line, a sourcedir for DHCP supplied servers,
# and the usual housekeeping directives
RHEL_STOCK='pool 2.rocky.pool.ntp.org iburst
sourcedir /run/chrony-dhcp
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
keyfile /etc/chrony.keys
logdir /var/log/chrony
'

reset_conf() { printf '%s' "${1}" > "${CONF}"; LOGGED_ERRORS=0; }

echo "Testing the NTP setup in [${SCRIPT}]"
echo "  configure_ntp_servers          lines ${add_lines}"
echo "  disable_existing_ntp_sources   lines ${disable_lines}"
echo
echo "== servers are added without disturbing the rest of the file =="

NTP_SERVERS="192.168.200.254:10.0.0.1"
reset_conf "${RHEL_STOCK}"
configure_ntp_servers "${CONF}" > /dev/null
rc=$?

if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "returns 0 and logs no ERROR"
else
    fail "returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi
if grep -qx 'server 192.168.200.254 iburst' "${CONF}" && grep -qx 'server 10.0.0.1 iburst' "${CONF}"; then
    pass "both configured servers are present"
else
    fail "both configured servers are present" "$(cat "${CONF}")"
fi

# This is the trap that ruled out set_conf_value: it rewrites the first line matching a key, so
# asking it for "server" or "sourcedir" would eat these
if grep -qx 'sourcedir /run/chrony-dhcp' "${CONF}"; then
    pass "the DHCP sourcedir line is untouched"
else
    fail "the DHCP sourcedir line is untouched" "$(cat "${CONF}")"
fi
if grep -qx 'pool 2.rocky.pool.ntp.org iburst' "${CONF}"; then
    pass "the distribution pool line is untouched"
else
    fail "the distribution pool line is untouched" "$(cat "${CONF}")"
fi
survived=true
missing_line=""
while IFS= read -r stock_line; do
    [ -z "${stock_line}" ] && continue
    if ! grep -qxF -e "${stock_line}" -- "${CONF}"; then
        survived=false
        missing_line="${stock_line}"
    fi
done <<< "${RHEL_STOCK}"
if [ "${survived}" = true ]; then
    pass "every line of the original chrony.conf survived verbatim"
else
    fail "every line of the original chrony.conf survived verbatim" "lost: ${missing_line}"
fi
if [ "$(grep -c . "${CONF}")" -eq 9 ]; then
    pass "the file grew by exactly the two server lines"
else
    fail "the file grew by exactly the two server lines" "$(cat "${CONF}")"
fi

echo
echo "== re-running is a no-op =="

first_run=$(cat "${CONF}")
LOGGED_ERRORS=0
configure_ntp_servers "${CONF}" > /dev/null
rc=$?
if [ "${first_run}" = "$(cat "${CONF}")" ] && [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a second run leaves the file identical and reports success"
else
    fail "a second run leaves the file identical" "rc=${rc} errors=${LOGGED_ERRORS}" "$(diff <(printf '%s' "${first_run}") "${CONF}")"
fi

# A server already present by hand must not be duplicated either
reset_conf 'server 10.0.0.1 iburst
'
NTP_SERVERS="10.0.0.1"
configure_ntp_servers "${CONF}" > /dev/null
if [ "$(grep -c '^server 10.0.0.1 iburst$' "${CONF}")" -eq 1 ]; then
    pass "a server already in the file is not added twice"
else
    fail "a server already in the file is not added twice" "$(cat "${CONF}")"
fi

echo
echo "== the Debian sources file is created when missing =="

NTP_SERVERS="10.0.0.1"
SOURCES="${WORK}/sources.d/local-ntp-server.sources"
mkdir -p "${WORK}/sources.d"
rm -f "${SOURCES}"
LOGGED_ERRORS=0
configure_ntp_servers "${SOURCES}" > /dev/null
rc=$?
if [ "${rc}" -eq 0 ] && grep -qx 'server 10.0.0.1 iburst' "${SOURCES}" 2>/dev/null; then
    pass "a missing sources file is created with the server in it"
else
    fail "a missing sources file is created with the server in it" "rc=${rc}"
fi

echo
echo "== failures are reported, not swallowed =="

NTP_SERVERS="10.0.0.1"
LOGGED_ERRORS=0
if configure_ntp_servers "${WORK}/no_such_dir/chrony.conf" > /dev/null 2>&1; then
    fail "an unwritable path returns non-zero"
elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "an unwritable path returns non-zero and logs an ERROR"
else
    fail "an unwritable path logs an ERROR"
fi

NTP_SERVERS=""
reset_conf "${RHEL_STOCK}"
before=$(cat "${CONF}")
configure_ntp_servers "${CONF}" > /dev/null
if [ "${before}" = "$(cat "${CONF}")" ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "an empty NTP_SERVERS changes nothing"
else
    fail "an empty NTP_SERVERS changes nothing" "$(cat "${CONF}")"
fi

echo
echo "== REPLACE_EXISTING_NTP: the exclusive mode =="

# RHEL shape: servers go into the same file we are disabling sources in, and there is no sourcedir
# of ours to protect. /run/chrony-dhcp must go, or DHCP could keep injecting time servers.
NTP_SERVERS="192.168.200.254"
reset_conf "${RHEL_STOCK}"
disable_existing_ntp_sources "${CONF}" "" > /dev/null
configure_ntp_servers "${CONF}" > /dev/null
if ! grep -qx 'pool 2.rocky.pool.ntp.org iburst' "${CONF}"; then
    pass "RHEL: the distribution pool line is disabled"
else
    fail "RHEL: the distribution pool line is disabled" "$(cat "${CONF}")"
fi
if ! grep -qx 'sourcedir /run/chrony-dhcp' "${CONF}"; then
    pass "RHEL: the DHCP sourcedir is disabled, so DHCP cannot inject servers"
else
    fail "RHEL: the DHCP sourcedir is disabled" "$(cat "${CONF}")"
fi
if grep -qx 'server 192.168.200.254 iburst' "${CONF}"; then
    pass "RHEL: the configured server is present"
else
    fail "RHEL: the configured server is present" "$(cat "${CONF}")"
fi
if grep -q '^# Disabled by el_configurator' "${CONF}" && grep -q 'pool 2.rocky.pool.ntp.org' "${CONF}"; then
    pass "disabled lines are commented, not deleted"
else
    fail "disabled lines are commented, not deleted" "$(cat "${CONF}")"
fi
if grep -qx 'driftfile /var/lib/chrony/drift' "${CONF}" && grep -qx 'rtcsync' "${CONF}"; then
    pass "unrelated directives are left alone"
else
    fail "unrelated directives are left alone" "$(cat "${CONF}")"
fi

# Re-running the exclusive mode must not comment out the servers we just added and re-add them
before=$(cat "${CONF}")
LOGGED_ERRORS=0
disable_existing_ntp_sources "${CONF}" "" > /dev/null
configure_ntp_servers "${CONF}" > /dev/null
if [ "${before}" = "$(cat "${CONF}")" ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a second exclusive run leaves the file identical"
else
    fail "a second exclusive run leaves the file identical" "$(diff <(printf '%s' "${before}") "${CONF}")"
fi

# Debian shape: our servers live in a sources.d file that is read through a sourcedir directive, so
# that one sourcedir has to survive or we would switch off the servers we are configuring
DEBIAN_STOCK='confdir /etc/chrony/conf.d
sourcedir /run/chrony-dhcp
sourcedir /etc/chrony/sources.d
pool 2.debian.pool.ntp.org iburst
driftfile /var/lib/chrony/chrony.drift
'
reset_conf "${DEBIAN_STOCK}"
disable_existing_ntp_sources "${CONF}" "/etc/chrony/sources.d" > /dev/null
if grep -qx 'sourcedir /etc/chrony/sources.d' "${CONF}"; then
    pass "Debian: the sourcedir our own servers are read through is kept"
else
    fail "Debian: the sourcedir our own servers are read through is kept" "$(cat "${CONF}")"
fi
if ! grep -qx 'sourcedir /run/chrony-dhcp' "${CONF}"; then
    pass "Debian: the DHCP sourcedir is still disabled"
else
    fail "Debian: the DHCP sourcedir is still disabled" "$(cat "${CONF}")"
fi
if ! grep -qx 'pool 2.debian.pool.ntp.org iburst' "${CONF}"; then
    pass "Debian: the distribution pool line is disabled"
else
    fail "Debian: the distribution pool line is disabled" "$(cat "${CONF}")"
fi
if grep -qx 'confdir /etc/chrony/conf.d' "${CONF}"; then
    pass "Debian: confdir is not touched"
else
    fail "Debian: confdir is not touched" "$(cat "${CONF}")"
fi

# chrony directive names are not case sensitive
reset_conf 'Pool 2.rocky.pool.ntp.org iburst
  server 10.9.9.9 iburst
'
NTP_SERVERS="192.168.200.254"
disable_existing_ntp_sources "${CONF}" "" > /dev/null
if ! grep -qx 'Pool 2.rocky.pool.ntp.org iburst' "${CONF}" && ! grep -qx '  server 10.9.9.9 iburst' "${CONF}"; then
    pass "capitalised and indented directives are disabled too"
else
    fail "capitalised and indented directives are disabled too" "$(cat "${CONF}")"
fi

LOGGED_ERRORS=0
if disable_existing_ntp_sources "${WORK}/no_such_conf" "" > /dev/null 2>&1; then
    fail "a missing chrony.conf returns non-zero"
elif [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a missing chrony.conf returns non-zero and logs an ERROR"
else
    fail "a missing chrony.conf logs an ERROR"
fi

echo
echo "== el_configurator.sh points at the right file per distribution =="

if grep -qE '^REPLACE_EXISTING_NTP=(true|false)$' "${SCRIPT}"; then
    pass "REPLACE_EXISTING_NTP is a documented switch"
else
    fail "REPLACE_EXISTING_NTP is a documented switch"
fi
# Disabling has to run before the servers are added, or it would comment them straight back out.
# The single quotes are deliberate: these patterns match the literal ${...} text in the script,
# they are not meant to expand, hence the SC2016 waivers
# shellcheck disable=SC2016
disable_at=$(grep -n 'disable_existing_ntp_sources "\${chrony_main_conf}"' "${SCRIPT}" | head -n 1 | cut -d: -f1)
# shellcheck disable=SC2016
add_at=$(grep -n 'configure_ntp_servers "\${ntp_conf_file}"' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -n "${disable_at}" ] && [ -n "${add_at}" ] && [ "${disable_at}" -lt "${add_at}" ]; then
    pass "the disable step runs before the add step"
else
    fail "the disable step runs before the add step" "disable at ${disable_at:-none}, add at ${add_at:-none}"
fi
# Debian must hand over its sources dir so that sourcedir survives
# shellcheck disable=SC2016
if grep -q 'disable_existing_ntp_sources "\${chrony_main_conf}" "\${ntp_sources_dir}"' "${SCRIPT}"; then
    pass "the sourcedir to keep is passed through"
else
    fail "the sourcedir to keep is passed through"
fi

# RHEL 8, 9 and 10 all read /etc/chrony.conf and own no sources directory. Writing to
# /etc/chrony/chrony.conf there is what made this silently do nothing.
if grep -qE '^[[:space:]]*ntp_conf_file=/etc/chrony\.conf$' "${SCRIPT}"; then
    pass "the RHEL branch targets /etc/chrony.conf"
else
    fail "the RHEL branch targets /etc/chrony.conf" "$(grep -n 'ntp_conf_file=' "${SCRIPT}")"
fi
if grep -qE '^[[:space:]]*ntp_conf_file=/etc/chrony/sources\.d/' "${SCRIPT}"; then
    pass "the Debian branch targets /etc/chrony/sources.d"
else
    fail "the Debian branch targets /etc/chrony/sources.d" "$(grep -n 'ntp_conf_file=' "${SCRIPT}")"
fi
if grep -q 'set_conf_value "/etc/chrony/chrony.conf"' "${SCRIPT}"; then
    fail "the dead /etc/chrony/chrony.conf include is gone" \
         "$(grep -n 'set_conf_value "/etc/chrony/chrony.conf"' "${SCRIPT}")"
else
    pass "the dead /etc/chrony/chrony.conf include is gone"
fi
# set_conf_value rewrites a single valued key, which would collapse repeatable chrony directives
if sed -n "${start},${end}p" "${SCRIPT}" | grep -vE '^[[:space:]]*#' | grep -q 'set_conf_value'; then
    fail "set_conf_value is not used on chrony directives" \
         "$(sed -n "${start},${end}p" "${SCRIPT}" | grep -n 'set_conf_value')"
else
    pass "set_conf_value is not used on chrony directives"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
