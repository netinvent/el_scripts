#!/usr/bin/env bash

# Tests for check_internet() in el_configurator.sh
#
# The probe used to be:
#
#     curl -s --connect-timeout 5 -Lk "http://${host}"
#
# -k switches certificate validation off, and -L then follows redirects, so an http probe that
# redirected to https was completed with no verification at all. Every download this function gates
# goes over https, so probing http told us less than nothing about whether those would work.
#
# The host lists were also assigned as plain strings and then read as "${name[@]}". That happened to
# iterate correctly only because the expansion was unquoted and word split on the spaces; a host
# containing one would have silently become two.
#
# Usage: tests/test_check_internet.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^check_internet() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate check_internet() in [${SCRIPT}]"
    exit 2
fi
end=$(awk -v s="${start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")

WORK=$(mktemp -d)
BIN="${WORK}/bin"
CALLS="${WORK}/calls.log"
HELPERS="${WORK}/check_internet.sh"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${BIN}"

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

sed -n "${start},${end}p" "${SCRIPT}" > "${HELPERS}"

# Stubs. Each records its whole argument list and then succeeds or fails according to the
# CURL_RC / PING_RC the test sets, so the branch taken can be asserted rather than inferred.
for cmd in curl wget ping ip cat; do
    {
        echo "#!/bin/sh"
        echo "echo \"${cmd} \$*\" >> \"\${CALLS}\""
    } > "${BIN}/${cmd}"
    chmod +x "${BIN}/${cmd}"
done
{
    echo "#!/bin/sh"
    echo "echo \"curl \$*\" >> \"\${CALLS}\""
    echo "exit \${CURL_RC:-0}"
} > "${BIN}/curl"
{
    echo "#!/bin/sh"
    echo "echo \"wget \$*\" >> \"\${CALLS}\""
    echo "exit \${WGET_RC:-0}"
} > "${BIN}/wget"
{
    echo "#!/bin/sh"
    echo "echo \"ping \$*\" >> \"\${CALLS}\""
    echo "exit \${PING_RC:-0}"
} > "${BIN}/ping"
{
    echo "#!/bin/sh"
    echo "echo \"ip \$*\" >> \"\${CALLS}\""
} > "${BIN}/ip"
chmod +x "${BIN}/curl" "${BIN}/wget" "${BIN}/ping" "${BIN}/ip"
export CALLS CURL_RC WGET_RC PING_RC
PATH="${BIN}:${PATH}"

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

run() {
    CURL_RC="${1}"
    PING_RC="${2}"
    rm -f "${CALLS}"
    check_internet > /dev/null 2>&1
    RC=$?
}

echo "Testing check_internet from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== the probe is https, with verification left on =="

run 0 1
if [ "${RC}" -eq 0 ]; then
    pass "a working probe returns 0"
else
    fail "a working probe returns 0" "rc=${RC}"
fi

if grep -q 'https://' "${CALLS}"; then
    pass "the probe requests https"
else
    fail "the probe requests https" "$(cat "${CALLS}")"
fi

if grep -q 'http://' "${CALLS}"; then
    fail "the probe no longer requests plain http" "$(grep 'http://' "${CALLS}")"
else
    pass "the probe no longer requests plain http"
fi

# -k is --insecure. With it, the probe answers yes to a man in the middle
if grep -qE '(^| )-[A-Za-z]*k( |$)|--insecure' "${CALLS}"; then
    fail "certificate validation is not switched off" "$(cat "${CALLS}")"
else
    pass "certificate validation is not switched off"
fi

# -L completes an http to https redirect. Combined with -k that was a verified-by-nobody request,
# and for a reachability check a redirect response already proves the host answered
if grep -qE '(^| )-[A-Za-z]*L( |$)|--location' "${CALLS}"; then
    fail "the probe does not follow redirects" "$(cat "${CALLS}")"
else
    pass "the probe does not follow redirects"
fi

echo
echo "== every configured host is tried, and none of them is split =="

run 1 1
hosts_tried=$(grep -oE 'https://[^ ]+' "${CALLS}" | sed 's#https://##' | sort -u)
for h in one.one.one.one kernel.org github.com; do
    if printf '%s\n' "${hosts_tried}" | grep -qFx "${h}"; then
        pass "${h} is probed"
    else
        fail "${h} is probed" "tried: $(printf '%s' "${hosts_tried}" | tr '\n' ' ')"
    fi
done

if [ "$(printf '%s\n' "${hosts_tried}" | grep -c .)" -eq 3 ]; then
    pass "exactly the three configured hosts are probed, none split into fragments"
else
    fail "exactly the three configured hosts are probed" "$(printf '%s' "${hosts_tried}" | tr '\n' ' ')"
fi

# The ip_hosts list carries an IPv6 literal, which is the entry most likely to be mangled
if grep -qF '2606:4700:4700::1001' "${CALLS}"; then
    pass "the IPv6 fallback address survives intact"
else
    fail "the IPv6 fallback address survives intact" "$(grep ping "${CALLS}" | tr '\n' ' ')"
fi

echo
echo "== the fallbacks still work =="

run 1 0
if [ "${RC}" -eq 0 ]; then
    pass "a failed http probe still falls through to ping, as before"
else
    fail "a failed http probe still falls through to ping" "rc=${RC}"
fi

run 1 1
if [ "${RC}" -ne 0 ]; then
    pass "everything failing returns non-zero"
else
    fail "everything failing returns non-zero" "rc=${RC}"
fi

# Nothing here is an ERROR: no internet is a state this script copes with, not a failure of it
run 1 1
if [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a failed check logs no ERROR, since the script handles being offline"
else
    fail "a failed check logs no ERROR" "errors=${LOGGED_ERRORS}"
fi

echo
echo "== the host lists are real arrays =="

body=$(sed -n "${start},${end}p" "${SCRIPT}")

case "${body}" in
    *'fqdn_hosts=('*) pass "fqdn_hosts is declared as an array" ;;
    *) fail "fqdn_hosts is declared as an array" "$(printf '%s\n' "${body}" | grep -n 'fqdn_host')" ;;
esac
case "${body}" in
    *'ip_hosts=('*) pass "ip_hosts is declared as an array" ;;
    *) fail "ip_hosts is declared as an array" "$(printf '%s\n' "${body}" | grep -n 'ip_hosts')" ;;
esac

# An unquoted array expansion word splits again on whatever the elements contain, which is the
# behaviour the old string assignment was relying on by accident
if printf '%s\n' "${body}" | grep -qE '\$\{(fqdn_hosts|ip_hosts)\[@\]\}' \
   && ! printf '%s\n' "${body}" | grep -qE 'in \$\{(fqdn_hosts|ip_hosts)\[@\]\}'; then
    pass "the arrays are expanded quoted"
else
    fail "the arrays are expanded quoted" "$(printf '%s\n' "${body}" | grep -n '\[@\]')"
fi

echo
echo "== the script's own downloads verify what they fetch =="

# Only el_configurator's own code. The vendored node_exporter installer sits in a heredoc and is
# kept byte for byte identical to upstream, so its curl calls are deliberately left alone.
vend_start=$(grep -n "NODE_EXPORTER_INSTALLER_EOF' > " "${SCRIPT}" | head -n 1 | cut -d: -f1)
vend_end=$(awk -v s="${vend_start}" 'NR>s && /^NODE_EXPORTER_INSTALLER_EOF$/ {print NR; exit}' "${SCRIPT}")
own=$(awk -v a="${vend_start}" -v b="${vend_end}" 'NR < a || NR > b' "${SCRIPT}" | grep -vE '^[[:space:]]*#')

if [ -z "${vend_start}" ] || [ -z "${vend_end}" ]; then
    fail "the vendored installer block was located" "start=${vend_start} end=${vend_end}"
else
    pass "the vendored installer block was located, and is excluded from these checks"
fi

if printf '%s\n' "${own}" | grep -qE '\-\-insecure|\-\-no-check-certificate'; then
    fail "no download in this script disables certificate validation" \
         "$(printf '%s\n' "${own}" | grep -nE '\-\-insecure|\-\-no-check-certificate')"
else
    pass "no download in this script disables certificate validation"
fi

# Fetching to a file without --fail writes the server's error page out as if it were the payload.
#
# Both halves of this are matched with expressions rather than case globs, because f is routinely
# bundled into a short option group: the real call reads -sSfL, which no *-f* glob matches.
# The verdict is also given once, after the loop. An earlier version of this passed unconditionally
# at the end, so it reported success in the same breath as printing a failure.
writes_file='--output|( |^)-[A-Za-z]*[oO]( |$)'
has_fail='--fail|( |^)-[A-Za-z]*f'
offenders=""
while read -r line; do
    [ -z "${line}" ] && continue
    printf '%s\n' "${line}" | grep -qE -- "${writes_file}" || continue
    printf '%s\n' "${line}" | grep -qE -- "${has_fail}" && continue
    offenders="${offenders}  ${line}"
done <<< "$(printf '%s\n' "${own}" | grep -oE 'curl [^|;&]*')"

if [ -z "${offenders}" ]; then
    pass "every curl that writes a file uses --fail"
else
    fail "every curl that writes a file uses --fail" "${offenders}"
fi

echo
echo "== the array check is no longer suppressed in CI =="

# SC2068 was waived across the whole repository, which is what let the string-as-array read above go
# unnoticed. With the lists made into real arrays the waiver has no reason to stay, and leaving it
# would mean the next genuine array bug is silent too.
wf="$(dirname "${0}")/../.github/workflows/shellcheck.yml"
if [ -f "${wf}" ]; then
    if grep -qE '^[^#]*SHELLCHECK_OPTS.*SC2068' "${wf}"; then
        fail "CI no longer suppresses SC2068" "$(grep -n 'SHELLCHECK_OPTS' "${wf}")"
    else
        pass "CI no longer suppresses SC2068"
    fi
    if grep -qE '^[^#]*SHELLCHECK_OPTS.*SC2181' "${wf}"; then
        pass "SC2181 is still waived, a house style rather than a defect"
    else
        fail "SC2181 is still waived" "$(grep -n 'SHELLCHECK_OPTS' "${wf}")"
    fi
else
    fail "the shellcheck workflow was found" "no shellcheck.yml"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
