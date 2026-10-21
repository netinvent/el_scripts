#!/usr/bin/env bash

# Tests for run_closing_scap_scan() in el_configurator.sh
#
# The remediating oscap pass runs near the start of the script. Everything after it changes the
# machine, and several of those changes deliberately undo a profile rule: ALLOW_SUDO restores the
# sudo binary, the firewall work reopens what the profile closed, the sshd drop-in sets its own
# values. Those are decisions, and nothing here should treat them as failures.
#
# What a closing scan catches is the other kind, a step that quietly undoes a remediation nobody
# meant to touch. It cannot tell the two apart, so it never fails the run over a rule count: the
# counts go to the log and the report, and a number that moves between runs is the signal.
#
# Usage: tests/test_closing_scap_scan.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^run_closing_scap_scan() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate run_closing_scap_scan() in [${SCRIPT}]"
    exit 2
fi
end=$(awk -v s="${start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")

WORK=$(mktemp -d)
BIN="${WORK}/bin"
CALLS="${WORK}/calls.log"
HELPERS="${WORK}/scan.sh"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${BIN}"

# shellcheck disable=SC2034
LOG_FILE=/dev/null
LOGGED_ERRORS=0
LOGGED_NOTICES=0
LOGGED=""
# shellcheck disable=SC2034
POST_INSTALL_SCRIPT_GOOD=true
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
        # shellcheck disable=SC2034
        POST_INSTALL_SCRIPT_GOOD=false
    fi
    [ "${2}" = "NOTICE" ] && LOGGED_NOTICES=$((LOGGED_NOTICES + 1))
    LOGGED="${LOGGED}${1}
"
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}
# The function reads this to decide whether to run at all
is_enabled() {
    case "$(printf '%s' "${1}" | tr '[:upper:]' '[:lower:]')" in
        true|yes|y|on|1) return 0 ;;
        *) return 1 ;;
    esac
}

# /root and the textfile directory are not this suite's to touch
sed -n "${start},${end}p" "${SCRIPT}" \
    | sed -e "s#/root/openscap_report#${WORK}/root/openscap_report#g" \
          -e "s#/var/lib/node_exporter#${WORK}/var/lib/node_exporter#g" > "${HELPERS}"

# A stub that answers like oscap: a Result line per rule, and an exit code that says whether any
# rule failed rather than whether the tool worked
cat > "${BIN}/oscap" <<'STUB'
#!/bin/sh
echo "oscap $*" >> "${CALLS}"
i=0
while [ "${i}" -lt "${OSCAP_PASS:-0}" ]; do echo "Result  pass"; i=$((i + 1)); done
i=0
while [ "${i}" -lt "${OSCAP_FAIL:-0}" ]; do echo "Result  fail"; i=$((i + 1)); done
i=0
while [ "${i}" -lt "${OSCAP_OTHER:-0}" ]; do echo "Result  notchecked"; i=$((i + 1)); done
exit "${OSCAP_RC:-0}"
STUB
chmod +x "${BIN}/oscap"
for cmd in chown chmod; do
    {
        echo "#!/bin/sh"
        echo "echo \"${cmd} \$*\" >> \"\${CALLS}\""
        echo "exit 0"
    } > "${BIN}/${cmd}"
    chmod +x "${BIN}/${cmd}"
done
export CALLS OSCAP_PASS OSCAP_FAIL OSCAP_OTHER OSCAP_RC
PATH="${BIN}:${PATH}"

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

DS="${WORK}/ssg-ds.xml"
PROM="${WORK}/var/lib/node_exporter/textfile_collector/el_configurator_scap.prom"
: > "${DS}"

run() {
    rm -f "${CALLS}" "${PROM}"
    rm -rf "${WORK:?}/root"
    LOGGED_ERRORS=0
    LOGGED_NOTICES=0
    LOGGED=""
    OSCAP_PASS="${1:-0}"; OSCAP_FAIL="${2:-0}"; OSCAP_OTHER="${3:-0}"; OSCAP_RC="${4:-0}"
    run_closing_scap_scan > /dev/null 2>&1
    RC=$?
}

echo "Testing run_closing_scap_scan from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== it verifies, and never remediates =="

# shellcheck disable=SC2034
RUN_CLOSING_SCAP_SCAN=true
# shellcheck disable=SC2034
SCAP_PROFILE=anssi_bp28_high
# shellcheck disable=SC2034
SSG_DATASTREAM="${DS}"
# shellcheck disable=SC2034
NODE_EXPORTER_USER=prometheus
mkdir -p "${WORK}/var/lib/node_exporter/textfile_collector"

run 900 40 60 2
if [ "${RC}" -eq 0 ]; then
    pass "a scan that found failures still returns 0"
else
    fail "a scan that found failures still returns 0" "rc=${RC}"
fi

if grep -q -- '--remediate' "${CALLS}"; then
    fail "the closing scan does not remediate" "$(cat "${CALLS}")"
else
    pass "the closing scan does not remediate"
fi

# Fetching would make the count depend on whether the machine had internet that day, and the whole
# value here is that two runs are comparable
if grep -q -- '--fetch-remote-resources' "${CALLS}"; then
    fail "the closing scan does not fetch remote resources" "$(cat "${CALLS}")"
else
    pass "the closing scan does not fetch remote resources"
fi

if grep -q -- '--report ' "${CALLS}"; then
    pass "it writes a report to look at"
else
    fail "it writes a report to look at" "$(cat "${CALLS}")"
fi

echo
echo "== deliberate deviations are not treated as failures =="

# ALLOW_SUDO, the firewall work and the sshd drop-in all undo profile rules on purpose. A non-zero
# fail count is therefore the expected state, and must not redden the run.
run 900 40 60 2
if [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "failed rules log no ERROR, since several of them are this script's own decisions"
else
    fail "failed rules log no ERROR" "errors=${LOGGED_ERRORS}"
fi

case "${LOGGED}" in
    *"900 passed, 40 failed, 60 neither"*) pass "the counts are logged, which is what makes drift visible" ;;
    *) fail "the counts are logged" "${LOGGED}" ;;
esac

echo
echo "== oscap failing is different from rules failing =="

# 0 is everything passed, 2 is something did not. Anything else means the check produced no answer
run 900 40 60 0
if [ "${RC}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "exit 0, every rule passed, is not an error"
else
    fail "exit 0 is not an error" "rc=${RC} errors=${LOGGED_ERRORS}"
fi

run 0 0 0 1
if [ "${RC}" -ne 0 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "exit 1, oscap itself failing, is an ERROR"
else
    fail "exit 1 is an ERROR" "rc=${RC} errors=${LOGGED_ERRORS}"
fi

echo
echo "== it stays out of the way when it cannot help =="

# shellcheck disable=SC2034
RUN_CLOSING_SCAP_SCAN=false
run 900 40 60 2
if [ "${RC}" -eq 0 ] && [ ! -f "${CALLS}" ]; then
    pass "the flag turns it off without running oscap"
else
    fail "the flag turns it off" "rc=${RC} $(cat "${CALLS}" 2>/dev/null)"
fi
# shellcheck disable=SC2034
RUN_CLOSING_SCAP_SCAN=true

# shellcheck disable=SC2034
SCAP_PROFILE=false
run 900 40 60 2
if [ "${RC}" -eq 0 ] && [ ! -f "${CALLS}" ]; then
    pass "no profile means nothing to verify against"
else
    fail "no profile means nothing to verify against" "rc=${RC}"
fi
# shellcheck disable=SC2034
SCAP_PROFILE=anssi_bp28_high

# shellcheck disable=SC2034
SSG_DATASTREAM="${WORK}/absent-ds.xml"
run 900 40 60 2
if [ "${RC}" -eq 0 ] && [ "${LOGGED_NOTICES}" -ge 1 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "missing content is a NOTICE, not an ERROR, since offline installs are normal"
else
    fail "missing content is a NOTICE" "rc=${RC} notices=${LOGGED_NOTICES} errors=${LOGGED_ERRORS}"
fi
# shellcheck disable=SC2034
SSG_DATASTREAM="${DS}"

# hash -r matters here: bash remembers where it found oscap on the runs above, so type would keep
# answering yes for a binary that is no longer there and the call would fail at exec instead
mv "${BIN}/oscap" "${WORK}/oscap.hidden"
hash -r
run 900 40 60 2
mv "${WORK}/oscap.hidden" "${BIN}/oscap"
hash -r
if [ "${RC}" -eq 0 ] && [ "${LOGGED_NOTICES}" -ge 1 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a missing oscap is a NOTICE too"
else
    fail "a missing oscap is a NOTICE too" "rc=${RC} notices=${LOGGED_NOTICES} errors=${LOGGED_ERRORS}"
fi

echo
echo "== it is the last thing that looks at the machine =="

code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")

# Running it before the later steps would defeat the point, since those are the steps most likely to
# undo a remediation
scan_at=$(printf '%s\n' "${code_only}" | grep -n '^run_closing_scap_scan$' | head -1 | cut -d: -f1)
sudo_at=$(printf '%s\n' "${code_only}" | grep -n 'chmod 4111 /usr/bin/sudo' | head -1 | cut -d: -f1)
cleanup_at=$(printf '%s\n' "${code_only}" | grep -n '^cleanup_system ' | head -1 | cut -d: -f1)

if [ -n "${scan_at}" ] && [ -n "${sudo_at}" ] && [ "${scan_at}" -gt "${sudo_at}" ]; then
    pass "it runs after ALLOW_SUDO, one of the deviations it has to see"
else
    fail "it runs after ALLOW_SUDO" "scan at ${scan_at:-missing}, sudo at ${sudo_at:-missing}"
fi

if [ -n "${cleanup_at}" ] && [ "${scan_at}" -lt "${cleanup_at}" ]; then
    pass "and before the cleanup, so its report survives"
else
    fail "and before the cleanup" "scan at ${scan_at}, cleanup at ${cleanup_at:-missing}"
fi

if printf '%s\n' "${code_only}" | grep -qE '^RUN_CLOSING_SCAP_SCAN=true'; then
    pass "the flag defaults to on"
else
    fail "the flag defaults to on" "$(grep -n '^RUN_CLOSING_SCAP_SCAN=' "${SCRIPT}")"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
