#!/usr/bin/env bash

# Tests for get_el_version() in el_configurator.sh
#
# The script accepted Debian 11, but the SCAP content for bullseye carries only the older
# anssi_np_nt28_* profile names and no anssi_bp28_* at all, so the shipped SCAP_PROFILE default of
# anssi_bp28_high had nothing to match there and oscap failed. Confirmed against the profile lists
# in ComplianceAsCode/content at tag v0.1.73:
#
#   products/debian11/profiles  anssi_np_nt28_{minimal,average,high,restrictive}, standard, default
#   products/debian12/profiles  the same, plus anssi_bp28_{minimal,intermediary,enhanced,high}
#
# The README has only ever listed Debian 12 and 13, so the release list and the documentation
# disagreed. 11 is refused now, with a message saying why.
#
# These tests run the real function against fixture os-release files rather than reading the source.
#
# Usage: tests/test_release_detection.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^get_el_version() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate get_el_version() in [${SCRIPT}]"
    exit 2
fi
end=$(awk -v s="${start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")

WORK=$(mktemp -d)
HELPERS="${WORK}/get_el_version.sh"
trap 'rm -rf "${WORK}"' EXIT

# The function reads /etc/os-release directly, which these tests must not depend on. Point it at a
# fixture instead.
sed -n "${start},${end}p" "${SCRIPT}" | sed "s#/etc/os-release#\${OS_RELEASE}#g" > "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

# Each case runs in a subshell, because log_quit exits and the real one is kept, not stubbed: the
# whole point of several of these is that the script refuses to continue.
# shellcheck disable=SC2034
detect() {
    OS_RELEASE="${WORK}/os-release"
    printf '%s\n' "${1}" > "${OS_RELEASE}"
    RESULT=$(
        LOG_FILE=/dev/null
        POST_INSTALL_SCRIPT_GOOD=true
        LOGGED=""
        log() { LOGGED="${LOGGED}${1}"; printf '%s\n' "LOG[${2:-INFO}]:${1}"; }
        log_quit() { printf '%s\n' "QUIT:${1}"; exit 1; }
        OS_RELEASE="${OS_RELEASE}"
        # shellcheck disable=SC1090
        . "${HELPERS}"
        get_el_version
        printf '%s\n' "OK:${FLAVOR}:${RELEASE}"
    2>&1)
}

echo "Testing get_el_version from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== the supported releases are accepted =="

detect 'ID=debian
VERSION_ID="12"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"'
case "${RESULT}" in
    *OK:debian:12*) pass "Debian 12 is accepted as debian 12" ;;
    *) fail "Debian 12 is accepted as debian 12" "${RESULT}" ;;
esac

detect 'ID=debian
VERSION_ID="13"
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"'
case "${RESULT}" in
    *OK:debian:13*) pass "Debian 13 is accepted as debian 13" ;;
    *) fail "Debian 13 is accepted as debian 13" "${RESULT}" ;;
esac

detect 'ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.5"
PLATFORM_ID="platform:el9"'
case "${RESULT}" in
    *OK:rhel:9*) pass "AlmaLinux 9 is accepted as rhel 9" ;;
    *) fail "AlmaLinux 9 is accepted as rhel 9" "${RESULT}" ;;
esac

detect 'ID="rhel"
VERSION_ID="10.0"
PLATFORM_ID="platform:el10"'
case "${RESULT}" in
    *OK:rhel:10*) pass "RHEL 10 is accepted as rhel 10" ;;
    *) fail "RHEL 10 is accepted as rhel 10" "${RESULT}" ;;
esac

echo
echo "== Debian 11 is refused, and says why =="

detect 'ID=debian
VERSION_ID="11"
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"'
case "${RESULT}" in
    *OK:*) fail "Debian 11 does not reach the rest of the script" "${RESULT}" ;;
    *QUIT:*) pass "Debian 11 stops the run rather than half hardening the machine" ;;
    *) fail "Debian 11 stops the run" "${RESULT}" ;;
esac

# A bare "not compatible with release 0" would leave the operator guessing. The reason is the
# profile naming, and the message has to carry it.
case "${RESULT}" in
    *anssi_bp28*anssi_np_nt28*) pass "the refusal names both profile families, so the reason is clear" ;;
    *) fail "the refusal names both profile families" "${RESULT}" ;;
esac

# The reason is raised as an ERROR and the generic version check below it then stops the run, so
# both messages appear and POST_INSTALL_SCRIPT_GOOD goes false. Asserting the level rather than the
# exact stopping mechanism: which of the two lines quits is a style choice, that it is an error is not.
case "${RESULT}" in
    *"LOG[ERROR]:Debian 11 is not supported"*) pass "the reason is raised as an ERROR, not a passing remark" ;;
    *) fail "the reason is raised as an ERROR" "${RESULT}" ;;
esac

echo
echo "== an unknown release is still refused =="

# The version detection deliberately leaves RELEASE at 0 for anything it does not recognise, so the
# check below it is reachable. That is what separates this branch from the RHEL one.
detect 'ID=debian
VERSION_ID="14"
PRETTY_NAME="Debian GNU/Linux 14 (forky)"'
case "${RESULT}" in
    *QUIT:*) pass "an unrecognised Debian release stops the run" ;;
    *) fail "an unrecognised Debian release stops the run" "${RESULT}" ;;
esac

detect 'ID="rhel"
VERSION_ID="7.9"
PLATFORM_ID="platform:el7"'
case "${RESULT}" in
    *QUIT:*) pass "an unrecognised EL release stops the run" ;;
    *) fail "an unrecognised EL release stops the run" "${RESULT}" ;;
esac

detect 'ID=alpine
VERSION_ID="3.19"'
case "${RESULT}" in
    *QUIT:*) pass "an unrecognised distribution stops the run" ;;
    *) fail "an unrecognised distribution stops the run" "${RESULT}" ;;
esac

echo
echo "== the release list and the README agree =="

# The two drifted apart, which is the whole finding: the script took a release the documentation
# never claimed, and the shipped profile could not work on it.
readme="$(dirname "${0}")/../README.md"
if [ -f "${readme}" ]; then
    if grep -qE 'Debian 12 (&|and) 13' "${readme}"; then
        pass "the README still states Debian 12 and 13"
    else
        fail "the README still states Debian 12 and 13" "$(grep -n 'Debian 1' "${readme}" | head -3)"
    fi
    if grep -qE '^- Debian 11|Debian 11, 12' "${readme}"; then
        fail "the README does not claim Debian 11" "$(grep -n 'Debian 11' "${readme}" | head -3)"
    else
        pass "the README does not claim Debian 11"
    fi
else
    fail "the README was found" "no README.md beside the script"
fi

code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")
if printf '%s\n' "${code_only}" | grep -qE 'RELEASE=11'; then
    fail "the script no longer assigns release 11" "$(printf '%s\n' "${code_only}" | grep -n 'RELEASE=11')"
else
    pass "the script no longer assigns release 11"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
