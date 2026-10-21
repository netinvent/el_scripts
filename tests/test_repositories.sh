#!/usr/bin/env bash

# Tests for the CRB repository setup in el_configurator.sh
#
# The script used to run one hardcoded "dnf config-manager --set-enabled crb" for every EL release.
# That only ever worked on the EL9 clones: EL8 calls the repository powertools, subscribed RHEL uses
# a subscription-manager repository with an entirely different id, and EL10 ships dnf5, whose
# config-manager has no --set-enabled option at all.
#
# This file sets the configuration globals the extracted function reads. The linter cannot see that
# code, so it reports them as unused, hence a file wide waiver.
# shellcheck disable=SC2034
#
# Usage: tests/test_repositories.sh [path/to/el_configurator.sh]

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

is_enabled_lines=$(extract_function repository_is_enabled)
crb_lines=$(extract_function enable_crb_repository)
kernels_lines=$(extract_function dnf_remove_old_kernels)

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

CALLS="${WORK}/calls"
ENABLED="${WORK}/enabled"

# Stand-in for dnf. "repolist --enabled" answers from ${ENABLED}, in the two column layout dnf4
# prints; the enable paths append to it only when they are given the id that this fake system
# actually has, so a wrong repository name behaves the way the real tool would.
# shellcheck disable=SC2329
dnf() {
    printf 'dnf %s\n' "$*" >> "${CALLS}"
    case "${1}" in
        repolist)
            printf 'repo id                repo name\n'
            while IFS= read -r r; do [ -n "${r}" ] && printf '%s    Some Repo Name\n' "${r}"; done < "${ENABLED}"
            return 0
            ;;
        config-manager)
            case "${2}" in
                enable)             candidate="${3}" ;;   # dnf5 subcommand
                --set-enabled)      candidate="${3}" ;;   # dnf4 option
                --set-enabled=*)    candidate="${2#--set-enabled=}" ;;
                *) return 1 ;;
            esac
            # dnf5 has no --set-enabled: refuse it when the fake system is EL10
            if [ "${FAKE_DNF5}" = true ] && [ "${2}" = "--set-enabled" ]; then return 1; fi
            if [ "${FAKE_DNF5}" != true ] && [ "${2}" = "enable" ]; then return 1; fi
            case " ${AVAILABLE_REPOS} " in
                *" ${candidate} "*) printf '%s\n' "${candidate}" >> "${ENABLED}"; return 0 ;;
                *) return 1 ;;
            esac
            ;;
    esac
    return 0
}
# shellcheck disable=SC2329
subscription-manager() {
    printf 'subscription-manager %s\n' "$*" >> "${CALLS}"
    local repo="${3}"
    case " ${AVAILABLE_REPOS} " in
        *" ${repo} "*) printf '%s\n' "${repo}" >> "${ENABLED}"; return 0 ;;
        *) return 1 ;;
    esac
}
# uname -m is used to build the RHEL repository id
# shellcheck disable=SC2329
uname() { [ "${1}" = "-m" ] && { printf 'x86_64\n'; return 0; }; command uname "$@"; }

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

# scenario <DIST> <RELEASE> <dnf5?> <repos this system has> <repos already enabled>
scenario() {
    DIST="${1}"; RELEASE="${2}"; FAKE_DNF5="${3}"; AVAILABLE_REPOS="${4}"
    : > "${CALLS}"
    printf '%s\n' "${5}" | tr ' ' '\n' | grep -v '^$' > "${ENABLED}" 2>/dev/null || : > "${ENABLED}"
    LOGGED_ERRORS=0
    enable_crb_repository > /dev/null 2>&1
}

echo "Testing the CRB repository setup in [${SCRIPT}]"
echo "  repository_is_enabled   lines ${is_enabled_lines}"
echo "  enable_crb_repository   lines ${crb_lines}"
echo
echo "== the right repository name for the right release =="

scenario almalinux 8 false "powertools baseos appstream" ""
rc=$?
if [ "${rc}" -eq 0 ] && grep -q 'powertools' "${CALLS}"; then
    pass "EL8 clone: enables powertools, not crb"
else
    fail "EL8 clone: enables powertools, not crb" "rc=${rc}" "$(cat "${CALLS}")"
fi
if ! grep -qE '(^| )crb( |$)' "${CALLS}"; then
    pass "EL8 clone: never asks for a repository called crb"
else
    fail "EL8 clone: never asks for a repository called crb" "$(cat "${CALLS}")"
fi

scenario almalinux 9 false "crb baseos appstream" ""
rc=$?
if [ "${rc}" -eq 0 ] && grep -q -- '--set-enabled crb' "${CALLS}"; then
    pass "EL9 clone: enables crb with the dnf4 option"
else
    fail "EL9 clone: enables crb with the dnf4 option" "rc=${rc}" "$(cat "${CALLS}")"
fi

scenario almalinux 10 true "crb baseos appstream" ""
rc=$?
if [ "${rc}" -eq 0 ] && grep -q 'config-manager enable crb' "${CALLS}"; then
    pass "EL10 clone: uses the dnf5 enable subcommand, which is all dnf5 has"
else
    fail "EL10 clone: uses the dnf5 enable subcommand" "rc=${rc}" "$(cat "${CALLS}")"
fi
if ! grep -q -- '--set-enabled' "${CALLS}"; then
    pass "EL10 clone: never passes --set-enabled, which dnf5 removed"
else
    fail "EL10 clone: never passes --set-enabled" "$(cat "${CALLS}")"
fi

scenario rhel 9 false "codeready-builder-for-rhel-9-x86_64-rpms baseos" ""
rc=$?
if [ "${rc}" -eq 0 ] && grep -q 'subscription-manager repos --enable codeready-builder-for-rhel-9-x86_64-rpms' "${CALLS}"; then
    pass "subscribed RHEL: uses subscription-manager and the codeready-builder id"
else
    fail "subscribed RHEL: uses subscription-manager and the codeready-builder id" "rc=${rc}" "$(cat "${CALLS}")"
fi
if ! grep -q 'config-manager' "${CALLS}"; then
    pass "subscribed RHEL: does not try dnf config-manager"
else
    fail "subscribed RHEL: does not try dnf config-manager" "$(cat "${CALLS}")"
fi

echo
echo "== an already enabled repository is not a failure =="

# AlmaLinux 10 turns CRB on by default, so the common case must stay quiet
scenario almalinux 10 true "crb baseos" "crb"
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "already enabled: returns 0 and logs no ERROR"
else
    fail "already enabled: returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi
if ! grep -q 'config-manager' "${CALLS}"; then
    pass "already enabled: does not bother trying to enable it again"
else
    fail "already enabled: does not bother trying to enable it again" "$(cat "${CALLS}")"
fi

echo
echo "== a repository that really cannot be enabled is reported =="

scenario almalinux 9 false "baseos appstream" ""
rc=$?
if [ "${rc}" -eq 1 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "missing repository: returns 1 and logs an ERROR"
else
    fail "missing repository: returns 1 and logs an ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi

# The old behaviour, reproduced: asking for crb on an EL8 clone
scenario almalinux 8 false "powertools baseos" ""
if [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "EL8 clone with powertools present: no ERROR, unlike the old hardcoded crb"
else
    fail "EL8 clone with powertools present: no ERROR" "errors=${LOGGED_ERRORS}"
fi

echo
echo "== old kernel removal: an ordinary install is not a failure =="

# dnf repoquery prints nothing when there is no kernel old enough, and "dnf remove -y" with no
# package argument exits non zero. That combination used to paint every fresh install red.
KERNELS_TO_KEEP=2
# shellcheck disable=SC2329
dnf() {
    printf 'dnf %s\n' "$*" >> "${CALLS}"
    case "${1}" in
        repoquery) printf '%s' "${FAKE_OLD_KERNELS}"; return "${FAKE_REPOQUERY_RC:-0}" ;;
        remove)
            shift
            # -y is always passed, so anything less than two words means no package was given
            [ "$#" -lt 2 ] && return 1
            return "${FAKE_REMOVE_RC:-0}"
            ;;
    esac
    return 0
}

: > "${CALLS}"; LOGGED_ERRORS=0
FAKE_OLD_KERNELS=""; FAKE_REPOQUERY_RC=0; FAKE_REMOVE_RC=0
dnf_remove_old_kernels > /dev/null 2>&1
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "nothing to remove: returns 0 and logs no ERROR"
else
    fail "nothing to remove: returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi
if ! grep -q '^dnf remove' "${CALLS}"; then
    pass "nothing to remove: dnf remove is never called with an empty list"
else
    fail "nothing to remove: dnf remove is never called" "$(cat "${CALLS}")"
fi

: > "${CALLS}"; LOGGED_ERRORS=0
FAKE_OLD_KERNELS=$'kernel-core-5.14.0-1.el9.x86_64\nkernel-5.14.0-1.el9.x86_64'
dnf_remove_old_kernels > /dev/null 2>&1
rc=$?
if [ "${rc}" -eq 0 ] && grep -q 'dnf remove -y kernel-core' "${CALLS}"; then
    pass "kernels to remove: they are passed to dnf remove"
else
    fail "kernels to remove: they are passed to dnf remove" "rc=${rc}" "$(cat "${CALLS}")"
fi

: > "${CALLS}"; LOGGED_ERRORS=0
FAKE_OLD_KERNELS="kernel-core-5.14.0-1.el9.x86_64"; FAKE_REMOVE_RC=1
dnf_remove_old_kernels > /dev/null 2>&1
rc=$?
FAKE_REMOVE_RC=0
if [ "${rc}" -eq 1 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a removal that genuinely fails still returns 1 and logs an ERROR"
else
    fail "a removal that genuinely fails still returns 1 and logs an ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi

: > "${CALLS}"; LOGGED_ERRORS=0
FAKE_OLD_KERNELS=""; FAKE_REPOQUERY_RC=1
dnf_remove_old_kernels > /dev/null 2>&1
rc=$?
FAKE_REPOQUERY_RC=0
if [ "${rc}" -eq 1 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a failing repoquery is reported rather than read as nothing to do"
else
    fail "a failing repoquery is reported rather than read as nothing to do" "rc=${rc} errors=${LOGGED_ERRORS}"
fi

echo
echo "== el_configurator.sh wiring =="

if grep -qE '^[[:space:]]*enable_crb_repository$' "${SCRIPT}"; then
    pass "the EPEL section calls enable_crb_repository"
else
    fail "the EPEL section calls enable_crb_repository"
fi

if grep -qE '^[[:space:]]*dnf_remove_old_kernels$' "${SCRIPT}"; then
    pass "the kernel section calls dnf_remove_old_kernels"
else
    fail "the kernel section calls dnf_remove_old_kernels"
fi

# The original defect: piping repoquery straight into dnf remove
if grep -qE 'dnf remove -y \$\(' "${SCRIPT}"; then
    fail "no unguarded command substitution feeds dnf remove" \
         "$(grep -nE 'dnf remove -y \$\(' "${SCRIPT}")"
else
    pass "no unguarded command substitution feeds dnf remove"
fi

crb_start=${crb_lines%%-*}
crb_end=${crb_lines##*-}
outside=$(grep -n 'config-manager' "${SCRIPT}" | awk -F: -v a="${crb_start}" -v b="${crb_end}" '$1 < a || $1 > b')
if [ -z "${outside}" ]; then
    pass "no config-manager call survives outside the helper"
else
    fail "no config-manager call survives outside the helper" "${outside}"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
