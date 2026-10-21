#!/usr/bin/env bash

# Tests for the guarded sshd drop-in helpers of el_configurator.sh
#
# A bad value in /etc/ssh/sshd_config.d stops sshd from starting, and that is only discovered at
# the next reboot, by which time the machine is unreachable. These helpers install the drop-in and
# then check the whole configuration with sshd -t, rolling back if sshd would refuse it.
#
# The awkward case is a kickstart %post, where host keys do not exist yet and sshd -t cannot run at
# all. Rolling back there would silently drop the hardening on every kickstart install, so that
# case has to be told apart from a real syntax error. Both are tested here.
#
# Usage: tests/test_sshd_config_edit.sh [path/to/el_configurator.sh]

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

begin_lines=$(extract_function sshd_begin_edit)
commit_lines=$(extract_function sshd_commit_edit)
extract_function escape_bre > /dev/null
extract_function set_conf_value > /dev/null

# Stubs for what the extracted helpers expect from the surrounding script.
# These are read by the extracted code, which the linter cannot see, hence the SC2034 waivers
# shellcheck disable=SC2034
LOG_FILE=/dev/null
LOGGED_ERRORS=0
LOGGED_NOTICES=0
# shellcheck disable=SC2034
POST_INSTALL_SCRIPT_GOOD=true
log() {
    case "${2}" in
        ERROR)
            LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
            # shellcheck disable=SC2034
            POST_INSTALL_SCRIPT_GOOD=false
            ;;
        NOTICE) LOGGED_NOTICES=$((LOGGED_NOTICES + 1)) ;;
    esac
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

# Stand-in for sshd. SSHD_OUTPUT is what "sshd -t" prints; empty means the config is accepted.
# shellcheck disable=SC2329
sshd() { [ -n "${SSHD_OUTPUT}" ] && echo "${SSHD_OUTPUT}" >&2; [ -z "${SSHD_OUTPUT}" ]; }
SSHD_OUTPUT=""

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
SKIPPED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }
skip() { SKIPPED=$((SKIPPED + 1)); printf '  skip %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

# Some filesystems, notably a Windows checkout, ignore the group and other permission bits, which
# makes a mode assertion meaningless there. It still runs on the Linux CI runner.
chmod_is_honoured() {
    local probe="${WORK}/chmod_probe"
    : > "${probe}"
    chmod 0600 "${probe}" 2>/dev/null
    [ "$(stat -c %a "${probe}" 2>/dev/null)" = "600" ]
}

DROPIN_DIR="${WORK}/sshd_config.d"
DROPIN="${DROPIN_DIR}/99-el_configurator.conf"
mkdir -p "${DROPIN_DIR}"

reset_dropin() {
    rm -f "${DROPIN}"
    [ -n "${1}" ] && { printf '%s' "${1}" > "${DROPIN}"; chmod 0600 "${DROPIN}"; }
    LOGGED_ERRORS=0
    LOGGED_NOTICES=0
}

echo "Testing the sshd drop-in helpers in [${SCRIPT}]"
echo "  sshd_begin_edit   lines ${begin_lines}"
echo "  sshd_commit_edit  lines ${commit_lines}"
echo
echo "== a configuration sshd accepts is applied =="

reset_dropin ""
SSHD_OUTPUT=""
if sshd_begin_edit "${DROPIN}"; then
    set_conf_value "${SSHD_EDIT_FILE}" "MaxAuthTries" "3" " " > /dev/null
    set_conf_value "${SSHD_EDIT_FILE}" "X11Forwarding" "no" " " > /dev/null
    sshd_commit_edit
    rc=$?
else
    rc=99
fi

if [ "${rc}" -eq 0 ]; then
    pass "an accepted configuration returns 0"
else
    fail "an accepted configuration returns 0" "returned ${rc}"
fi
if grep -q '^MaxAuthTries 3$' "${DROPIN}" && grep -q '^X11Forwarding no$' "${DROPIN}"; then
    pass "both directives landed in the drop-in"
else
    fail "both directives landed in the drop-in" "$(cat "${DROPIN}" 2>/dev/null)"
fi
mode=$(stat -c %a "${DROPIN}" 2>/dev/null)
if ! chmod_is_honoured; then
    skip "the drop-in is created mode 0600" "this filesystem reports ${mode} for everything, checked on CI instead"
elif [ "${mode}" = "600" ]; then
    pass "the drop-in is created root readable only (${mode}), as CIS wants"
else
    fail "the drop-in is created mode 0600" "got ${mode}"
fi
if [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "an accepted configuration logs no ERROR"
else
    fail "an accepted configuration logs no ERROR" "errors=${LOGGED_ERRORS}"
fi

echo
echo "== a configuration sshd rejects is rolled back =="

reset_dropin 'MaxAuthTries 3
'
before_hash=$(sha256sum "${DROPIN}" | cut -d' ' -f1)
SSHD_OUTPUT="/etc/ssh/sshd_config.d/99-el_configurator.conf line 2: Bad configuration option: Nonsense"
if sshd_begin_edit "${DROPIN}"; then
    printf 'Nonsense yes\n' >> "${SSHD_EDIT_FILE}"
    sshd_commit_edit
    rc=$?
else
    rc=99
fi
SSHD_OUTPUT=""

if [ "${rc}" -eq 1 ]; then
    pass "a rejected configuration returns 1"
else
    fail "a rejected configuration returns 1" "returned ${rc}"
fi
if [ "${before_hash}" = "$(sha256sum "${DROPIN}" | cut -d' ' -f1)" ]; then
    pass "a rejected configuration restores the previous drop-in exactly"
else
    fail "a rejected configuration restores the previous drop-in exactly" "$(cat "${DROPIN}")"
fi
if [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a rejected configuration logs an ERROR"
else
    fail "a rejected configuration logs an ERROR"
fi

# When there was no drop-in to begin with, a rejected edit must not leave a broken one behind
reset_dropin ""
SSHD_OUTPUT="line 1: Bad configuration option: Nonsense"
if sshd_begin_edit "${DROPIN}"; then
    printf 'Nonsense yes\n' >> "${SSHD_EDIT_FILE}"
    sshd_commit_edit
fi
SSHD_OUTPUT=""
if [ ! -f "${DROPIN}" ]; then
    pass "a rejected first write leaves no drop-in behind"
else
    fail "a rejected first write leaves no drop-in behind" "$(cat "${DROPIN}")"
fi

echo
echo "== when sshd cannot be checked, hardening is kept rather than dropped =="

# In a kickstart %post the host keys do not exist yet, so sshd -t fails for a reason that has
# nothing to do with our configuration. Rolling back there would silently lose the hardening.
reset_dropin ""
SSHD_OUTPUT="sshd: no hostkeys available -- exiting."
if sshd_begin_edit "${DROPIN}"; then
    set_conf_value "${SSHD_EDIT_FILE}" "MaxAuthTries" "3" " " > /dev/null
    sshd_commit_edit
    rc=$?
else
    rc=99
fi
SSHD_OUTPUT=""

if [ "${rc}" -eq 0 ]; then
    pass "a missing host key is not treated as a rejected configuration"
else
    fail "a missing host key is not treated as a rejected configuration" "returned ${rc}"
fi
if grep -q '^MaxAuthTries 3$' "${DROPIN}" 2>/dev/null; then
    pass "the hardening is kept when sshd cannot be checked"
else
    fail "the hardening is kept when sshd cannot be checked" "drop-in: $(cat "${DROPIN}" 2>/dev/null)"
fi
if [ "${LOGGED_ERRORS}" -eq 0 ] && [ "${LOGGED_NOTICES}" -ge 1 ]; then
    pass "not being able to check is a NOTICE, not an ERROR, so the banner stays green"
else
    fail "not being able to check is a NOTICE, not an ERROR" \
         "errors=${LOGGED_ERRORS} notices=${LOGGED_NOTICES}"
fi

echo
echo "== the helpers refuse rather than guess =="

reset_dropin ""
if sshd_begin_edit "${WORK}/no_such_dir/sshd.conf" || [ "${LOGGED_ERRORS}" -lt 1 ]; then
    fail "a missing drop-in directory is refused with an ERROR"
else
    pass "a missing drop-in directory is refused with an ERROR"
fi

reset_dropin ""
saved_sshd=$(declare -f sshd)
unset -f sshd
# Unsetting the stub is not enough where a real sshd is installed, as on the GitHub runner or a
# Fedora host: type finds that one further down PATH. So the helper runs with a PATH that holds only
# the commands it uses past its sshd check. Those have to stay reachable, or a helper that lost the
# check would still fail on them and pass this test for the wrong reason.
NO_SSHD_BIN="${WORK}/bin_without_sshd"
mkdir -p "${NO_SSHD_BIN}"
for cmd in cat dirname mktemp rm; do
    printf '#!/bin/sh\nexec "%s" "$@"\n' "$(command -v "${cmd}")" > "${NO_SSHD_BIN}/${cmd}"
    chmod +x "${NO_SSHD_BIN}/${cmd}"
done
saved_path="${PATH}"
PATH="${NO_SSHD_BIN}"
sshd_begin_edit "${DROPIN}"
begin_rc=$?
PATH="${saved_path}"
if [ "${begin_rc}" -eq 0 ] || [ "${LOGGED_ERRORS}" -lt 1 ]; then
    fail "without sshd installed the helper refuses to edit"
else
    pass "without sshd installed the helper refuses to edit"
fi
eval "${saved_sshd}"

LOGGED_ERRORS=0
SSHD_EDIT_FILE=""
if sshd_commit_edit || [ "${LOGGED_ERRORS}" -lt 1 ]; then
    fail "committing with no edit in progress is refused with an ERROR"
else
    pass "committing with no edit in progress is refused with an ERROR"
fi

echo
echo "== the keepalive settings are one policy under one flag =="

# TCPKeepAlive no switches off TCP level probes because ClientAlive replaces them over the encrypted
# channel. Setting only the first leaves a machine with no liveness detection at all, which used to
# be reachable with CONFIGURE_SSHD_CLIENT_ALIVE=true and CONFIGURE_CIS_SSHD_SETTINGS=false.
sshd_block=$(sed -n '/^# All sshd directives go into one drop-in/,/^fi$/p' "${SCRIPT}")

# Both branches are anchored on the indented standalone if. The outer guard names both flags on one
# line, so a looser pattern matches it instead and captures the whole block.
#
# An extraction that matches nothing has to be a failure and not a pass. When these tests were
# written the conditions read [ "${FLAG}" != false ]; they now read is_enabled "${FLAG}", and until
# guard was added the two CIS assertions below went on passing against an empty string, having
# stopped checking anything at all.
client_alive_branch=$(printf '%s\n' "${sshd_block}" | sed -n '/^        if is_enabled "${CONFIGURE_SSHD_CLIENT_ALIVE}"; then/,/^        elif\|^        fi$/p')
cis_branch=$(printf '%s\n' "${sshd_block}" | sed -n '/^        if is_enabled "${CONFIGURE_CIS_SSHD_SETTINGS}"; then/,$p')

for name in client_alive_branch cis_branch; do
    if [ -n "${!name}" ]; then
        pass "the ${name%_branch} branch was located in the script"
    else
        fail "the ${name%_branch} branch was located in the script" \
             "the extraction matched nothing, so every assertion over it below is vacuous"
    fi
done

for setting in TCPKeepAlive ClientAliveInterval ClientAliveCountMax; do
    case "${client_alive_branch}" in
        *"\"${setting}\""*) pass "${setting} is under CONFIGURE_SSHD_CLIENT_ALIVE" ;;
        *)                  fail "${setting} is under CONFIGURE_SSHD_CLIENT_ALIVE" "${client_alive_branch}" ;;
    esac
done

# and no longer under the CIS flag, where the pairing could be broken apart
for setting in ClientAliveInterval ClientAliveCountMax; do
    if printf '%s\n' "${cis_branch}" | grep -vE '^[[:space:]]*#' | grep -q "\"${setting}\""; then
        fail "${setting} is no longer set under the CIS flag alone" \
             "the two flags can still be combined into a machine with no liveness detection"
    else
        pass "${setting} is no longer set under the CIS flag alone"
    fi
done

# Losing CIS 5.2.20 by turning the flag off should be said out loud, not left silent
case "${sshd_block}" in
    *'CIS 5.2.20 is not applied'*) pass "turning the flag off reports that CIS 5.2.20 is given up" ;;
    *)                             fail "turning the flag off reports that CIS 5.2.20 is given up" ;;
esac

echo
echo "== el_configurator.sh no longer writes sshd config unguarded =="

# Belt and braces for the mode: the behavioural check above is skipped on filesystems that ignore
# permission bits, so assert the call is there as well
if grep -qE 'chmod 0600 "\$\{SSHD_EDIT_TARGET\}"' "${SCRIPT}"; then
    pass "the commit sets mode 0600 on the target"
else
    fail "the commit sets mode 0600 on the target" "no chmod 0600 of SSHD_EDIT_TARGET found"
fi

if grep -qE '^[[:space:]]*set_conf_value[[:space:]]+/etc/ssh/' "${SCRIPT}"; then
    fail "no unvalidated set_conf_value on an sshd config remains" \
         "$(grep -nE '^[[:space:]]*set_conf_value[[:space:]]+/etc/ssh/' "${SCRIPT}")"
else
    pass "no unvalidated set_conf_value on an sshd config remains"
fi

# The distribution drop-in sorts before ours and sshd keeps the first value it obtains, so
# X11Forwarding has to be turned off there too. Losing this would silently un-harden CIS 5.2.12.
if grep -q '50-redhat.conf' "${SCRIPT}"; then
    pass "the distribution drop-in is still patched for CIS 5.2.12"
else
    fail "the distribution drop-in is still patched for CIS 5.2.12"
fi

echo
if [ "${SKIPPED}" -gt 0 ]; then
    printf 'passed %d, failed %d, skipped %d\n' "${PASSED}" "${FAILED}" "${SKIPPED}"
else
    printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
fi
[ "${FAILED}" -eq 0 ]
