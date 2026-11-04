#!/usr/bin/env bash

# Tests for remove_packages_if_unneeded() and the CIS 1.3.1.1 block of el_configurator.sh
#
# CIS 1.3.1.1 takes telnet and the inetd super servers off the machine. The first version ran
#   apt-get remove telnet inetd-utils      and      yum remove -y telnet inetd
# inetd-utils exists in neither Debian nor Ubuntu, and EL has no package called inetd, so apt-get
# stopped on the unknown name and removed nothing, and both logged an ERROR. Worse, a plain remove
# also takes along every installed package that depends on the ones named, and dnf then removes their
# now unused dependencies as well. A hardening step aimed at telnet could take an application with it.
#
# The package managers are stubbed over a small package database: STATUS holds the dpkg status of
# each installed package, and REQUIRED_BY the installed packages that depend on one.
#
# Usage: tests/test_remove_packages.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

HELPERS=$(mktemp)
WORK=$(mktemp -d)
CALLS="${WORK}/calls.log"
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

helper_lines=$(extract_function remove_packages_if_unneeded)

# Stubs for what the extracted helper expects from the surrounding script.
# These are read by the extracted code, which the linter cannot see, hence the SC2034 waivers
# shellcheck disable=SC2034
LOG_FILE=/dev/null
LOGGED_ERRORS=0
LOGGED_NOTICES=0
LOGGED=""
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
    LOGGED="${LOGGED}${1}
"
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

declare -A STATUS REQUIRED_BY

# The stubs below are called by the extracted function, not from this file, hence SC2329.
# dpkg-query -s prints a Status line for any package dpkg knows, removed ones included
# shellcheck disable=SC2329
dpkg-query() {
    [ "${1}" = -s ] || return 2
    if [ -z "${STATUS[${2}]}" ]; then
        echo "dpkg-query: package '${2}' is not installed" >&2
        return 1
    fi
    printf 'Package: %s\nStatus: %s\n' "${2}" "${STATUS[${2}]}"
}
# apt-get -s remove prints a Remv line for every package that would go, dependents included.
# The simulation runs inside a command substitution, so it records its call to a file
# shellcheck disable=SC2329
apt-get() {
    local simulate=false pkg dep
    echo "apt-get $*" >> "${CALLS}"
    [ "${1}" = -s ] && { simulate=true; shift; }
    [ "${1}" = remove ] || return 100
    shift
    [ "${1}" = -y ] && shift
    if [ "${simulate}" = true ]; then
        [ -n "${APT_SIMULATE_RC}" ] && return "${APT_SIMULATE_RC}"
        echo "NOTE: This is only a simulation!"
        for pkg in "$@"; do
            echo "Remv ${pkg} [1.0-1]"
            for dep in ${REQUIRED_BY[${pkg}]}; do echo "Remv ${dep} [1.0-1]"; done
        done
        return 0
    fi
    [ -n "${APT_REMOVE_RC}" ] && return "${APT_REMOVE_RC}"
    for pkg in "$@"; do STATUS[${pkg}]="deinstall ok config-files"; done
    return 0
}
# rpm -e refuses while an installed package outside the removal set requires one of the targets
# shellcheck disable=SC2329
rpm() {
    local test_only=false pkg dep
    echo "rpm $*" >> "${CALLS}"
    case "${1}" in
        -q) [ -n "${STATUS[${2}]}" ]; return ;;
        -e) shift ;;
        *) return 1 ;;
    esac
    [ "${1}" = --test ] && { test_only=true; shift; }
    for pkg in "$@"; do
        for dep in ${REQUIRED_BY[${pkg}]}; do
            case " $* " in
                *" ${dep} "*) ;;
                *) echo "error: Failed dependencies: ${pkg} is needed by ${dep}" >&2; return 1 ;;
            esac
        done
    done
    [ "${test_only}" = true ] && return 0
    [ -n "${RPM_REMOVE_RC}" ] && return "${RPM_REMOVE_RC}"
    for pkg in "$@"; do unset "STATUS[${pkg}]"; done
    return 0
}
# Neither may be used: both remove dependents, and dnf removes unused dependencies too
# shellcheck disable=SC2329
dnf() { echo "dnf $*" >> "${CALLS}"; return 0; }
# shellcheck disable=SC2329
yum() { echo "yum $*" >> "${CALLS}"; return 0; }

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

# run <flavor> <packages...>: resets the logs and calls the helper, leaving its exit code in RC
run() {
    # shellcheck disable=SC2034
    FLAVOR="${1}"
    shift
    : > "${CALLS}"
    LOGGED_ERRORS=0
    LOGGED_NOTICES=0
    LOGGED=""
    remove_packages_if_unneeded "$@" > /dev/null 2>&1
    RC=$?
}
calls() { cat "${CALLS}"; }
# The calls that actually change the machine, as opposed to queries and simulations
changes() { grep -E '^(apt-get remove|rpm -e [^-]|rpm -e$|dnf|yum)' "${CALLS}"; }
reset_db() { STATUS=(); REQUIRED_BY=(); APT_SIMULATE_RC=""; APT_REMOVE_RC=""; RPM_REMOVE_RC=""; }

echo "Testing remove_packages_if_unneeded from [${SCRIPT}] lines ${helper_lines}"
echo
echo "== Debian: only what is installed is removed =="

reset_db
run debian telnet inetutils-telnet telnet-ssl
if [ "${RC}" -eq 0 ] && [ ! -s "${CALLS}" ] && [ "${LOGGED_ERRORS}" -eq 0 ] && [ "${LOGGED_NOTICES}" -eq 0 ]; then
    pass "nothing installed returns 0 without calling apt-get, and logs no ERROR"
else
    fail "nothing installed returns 0 without calling apt-get" "rc=${RC} errors=${LOGGED_ERRORS} $(calls)"
fi

reset_db
STATUS[telnet]="deinstall ok config-files"
run debian telnet
if [ "${RC}" -eq 0 ] && [ ! -s "${CALLS}" ]; then
    pass "a package removed earlier, with only its configuration left, counts as not installed"
else
    fail "a package with only its configuration left counts as not installed" "rc=${RC} $(calls)"
fi

# Debian 12+ and Ubuntu 24.04 ship telnet as a transitional package that depends on inetutils-telnet
reset_db
STATUS[telnet]="install ok installed"
STATUS[inetutils-telnet]="install ok installed"
REQUIRED_BY[inetutils-telnet]="telnet"
run debian telnet inetutils-telnet telnet-ssl
if [ "${RC}" -eq 0 ] && [ "$(changes)" = "apt-get remove -y telnet inetutils-telnet" ]; then
    pass "a transitional package and its target go together, and the absent telnet-ssl is not named"
else
    fail "a transitional package and its target go together" "rc=${RC} $(calls)"
fi
if [ "${STATUS[telnet]}" = "deinstall ok config-files" ] && [ "${STATUS[inetutils-telnet]}" = "deinstall ok config-files" ]; then
    pass "both are gone afterwards"
else
    fail "both are gone afterwards" "telnet=${STATUS[telnet]} inetutils-telnet=${STATUS[inetutils-telnet]}"
fi

reset_db
STATUS[telnet]="hold ok installed"
run debian telnet
case "$(calls)" in
    *"apt-get -s remove telnet"*) pass "a held package counts as installed" ;;
    *) fail "a held package counts as installed" "$(calls)" ;;
esac

echo
echo "== Debian: nothing goes that something else needs =="

reset_db
STATUS[openbsd-inetd]="install ok installed"
STATUS[inetutils-ftpd]="install ok installed"
REQUIRED_BY[openbsd-inetd]="inetutils-ftpd"
run debian openbsd-inetd inetutils-inetd xinetd rlinetd
if [ "${RC}" -eq 1 ] && [ -z "$(changes)" ]; then
    pass "an inetd another installed package depends on is left in place"
else
    fail "an inetd another installed package depends on is left in place" "rc=${RC} $(calls)"
fi
case "${LOGGED}" in
    *"would also remove inetutils-ftpd"*) pass "the NOTICE names the package that is in the way" ;;
    *) fail "the NOTICE names the package that is in the way" "${LOGGED}" ;;
esac
if [ "${LOGGED_NOTICES}" -ge 1 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "keeping a needed package is a NOTICE, not an ERROR"
else
    fail "keeping a needed package is a NOTICE, not an ERROR" "notices=${LOGGED_NOTICES} errors=${LOGGED_ERRORS}"
fi

# The same pair as above, split across two calls: the target alone would drag the transitional along
reset_db
STATUS[telnet]="install ok installed"
STATUS[inetutils-telnet]="install ok installed"
REQUIRED_BY[inetutils-telnet]="telnet"
run debian inetutils-telnet
if [ "${RC}" -eq 1 ] && [ -z "$(changes)" ]; then
    pass "a package whose removal would take a dependent along is not removed"
else
    fail "a package whose removal would take a dependent along is not removed" "rc=${RC} $(calls)"
fi

echo
echo "== Debian: failures are reported =="

reset_db
STATUS[telnet]="install ok installed"
APT_SIMULATE_RC=100
run debian telnet
if [ "${RC}" -eq 1 ] && [ "${LOGGED_ERRORS}" -ge 1 ] && [ -z "$(changes)" ]; then
    pass "a failed simulation is an ERROR, and nothing is removed blind"
else
    fail "a failed simulation is an ERROR, and nothing is removed blind" "rc=${RC} errors=${LOGGED_ERRORS} $(calls)"
fi

reset_db
STATUS[telnet]="install ok installed"
APT_REMOVE_RC=100
run debian telnet
if [ "${RC}" -eq 1 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a failed removal is an ERROR"
else
    fail "a failed removal is an ERROR" "rc=${RC} errors=${LOGGED_ERRORS}"
fi

echo
echo "== EL: rpm -e, which removes exactly what it is given =="

reset_db
STATUS[telnet]=installed
run rhel telnet
if [ "${RC}" -eq 0 ] && [ "$(changes)" = "rpm -e telnet" ] && [ -z "${STATUS[telnet]}" ]; then
    pass "an installed telnet nothing requires is removed with rpm -e, never dnf or yum"
else
    fail "an installed telnet nothing requires is removed with rpm -e" "rc=${RC} $(calls)"
fi

reset_db
STATUS[xinetd]=installed
STATUS[tang-xinetd]=installed
REQUIRED_BY[xinetd]="tang-xinetd"
run rhel xinetd
if [ "${RC}" -eq 1 ] && [ -z "$(changes)" ] && [ -n "${STATUS[xinetd]}" ]; then
    pass "an xinetd another installed package requires is left in place"
else
    fail "an xinetd another installed package requires is left in place" "rc=${RC} $(calls)"
fi
if [ "${LOGGED_NOTICES}" -ge 1 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "and that is a NOTICE, not an ERROR"
else
    fail "and that is a NOTICE, not an ERROR" "notices=${LOGGED_NOTICES} errors=${LOGGED_ERRORS}"
fi

reset_db
run rhel telnet-server
if [ "${RC}" -eq 0 ] && [ -z "$(changes)" ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "nothing installed returns 0 without removing anything"
else
    fail "nothing installed returns 0 without removing anything" "rc=${RC} $(calls)"
fi

reset_db
STATUS[telnet]=installed
RPM_REMOVE_RC=1
run rhel telnet
if [ "${RC}" -eq 1 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a failed rpm -e is an ERROR"
else
    fail "a failed rpm -e is an ERROR" "rc=${RC} errors=${LOGGED_ERRORS}"
fi

echo
echo "== the CIS 1.3.1.1 block uses the helper, in the right order =="

cis_block=$(awk 'index($0, "# Apply CIS 1.3.1.1") == 1 {f = 1} f && index($0, "# Apply CIS 1.5") == 1 {exit} f {print}' "${SCRIPT}")
cis_code=$(printf '%s\n' "${cis_block}" | grep -vE '^[[:space:]]*#')

if printf '%s\n' "${cis_code}" | grep -qE 'inetd-utils|(apt-get|yum|dnf) remove'; then
    fail "no direct remove and no inetd-utils, which no distribution ships" \
         "$(printf '%s\n' "${cis_code}" | grep -nE 'inetd-utils|(apt-get|yum|dnf) remove')"
else
    pass "no direct remove and no inetd-utils, which no distribution ships"
fi

# One call per group: a transitional package split from its target would block both
if printf '%s\n' "${cis_code}" | grep -qE 'remove_packages_if_unneeded telnet inetutils-telnet( |$)'; then
    pass "Debian's telnet and inetutils-telnet are removed in one call"
else
    fail "Debian's telnet and inetutils-telnet are removed in one call" "${cis_code}"
fi
if printf '%s\n' "${cis_code}" | grep -qE 'remove_packages_if_unneeded telnetd inetutils-telnetd( |$)'; then
    pass "and so are telnetd and inetutils-telnetd"
else
    fail "and so are telnetd and inetutils-telnetd" "${cis_code}"
fi

# inetutils-telnetd depends on inetutils-inetd | inet-superserver, so with the servers still there
# the inetd group would be blocked by them
servers_at=$(printf '%s\n' "${cis_code}" | grep -n 'remove_packages_if_unneeded telnetd ' | head -1 | cut -d: -f1)
inetd_at=$(printf '%s\n' "${cis_code}" | grep -n 'remove_packages_if_unneeded openbsd-inetd' | head -1 | cut -d: -f1)
if [ -n "${servers_at}" ] && [ -n "${inetd_at}" ] && [ "${servers_at}" -lt "${inetd_at}" ]; then
    pass "the telnet servers go before the inetd they depend on"
else
    fail "the telnet servers go before the inetd they depend on" "servers ${servers_at:-missing}, inetd ${inetd_at:-missing}"
fi

el_server_at=$(printf '%s\n' "${cis_code}" | grep -n 'remove_packages_if_unneeded telnet-server' | head -1 | cut -d: -f1)
el_xinetd_at=$(printf '%s\n' "${cis_code}" | grep -n 'remove_packages_if_unneeded xinetd$' | head -1 | cut -d: -f1)
if [ -n "${el_server_at}" ] && [ -n "${el_xinetd_at}" ] && [ "${el_server_at}" -lt "${el_xinetd_at}" ]; then
    pass "on EL telnet-server goes before xinetd too"
else
    fail "on EL telnet-server goes before xinetd too" "server ${el_server_at:-missing}, xinetd ${el_xinetd_at:-missing}"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
