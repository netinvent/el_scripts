#!/usr/bin/env bash

# Tests for the pinned SCAP Security Guide package install in el_configurator.sh
#
# These .debs are pulled out of the Debian pool rather than installed with apt, because Debian's
# stable suites trail one release for SCAP content. A pool .deb carries no signature dpkg can
# check, so the pinned sha256 values are the only thing between a tampered download and maintainer
# scripts running as root. These tests make sure a bad download can never reach apt-get.
#
# Usage: tests/test_ssg_debian_packages.sh [path/to/el_configurator.sh]

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
    # The packages are downloaded to /opt/ssg, which only root can create. They go to the work
    # directory instead, so the suite runs as a normal user, the GitHub runner included
    sed -n "${first},${last}p" "${SCRIPT}" | sed "s#/opt/ssg#${WORK}/opt/ssg#g" >> "${HELPERS}"
    echo "${first}-${last}"
}

pinned_lines=$(extract_function install_ssg_debian_packages)
content_lines=$(extract_function install_ssg_content)

# Stubs for what the extracted helper expects from the surrounding script.
# These are read by the extracted code, which the linter cannot see, hence the SC2034 waivers
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
# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

echo "Testing the ssg install in [${SCRIPT}]"
echo "  install_ssg_debian_packages  lines ${pinned_lines}"
echo "  install_ssg_content          lines ${content_lines}"
echo

# ---------------------------------------------------------------------------
# Behavioural tests, with curl / wget / apt-get stubbed out
# ---------------------------------------------------------------------------
# Read by the extracted function, which the linter cannot see, hence the SC2034 waiver
# shellcheck disable=SC2034
SSG_DEBIAN_POOL_URL="https://example.invalid/pool"
# apt-get is invoked inside a subshell, so the stub records to a file rather than a variable
APT_LOG="${WORK}/apt_calls"
CURL_URLS=""

# The three stubs below are called by the extracted function, not from this file, hence SC2329
# Writes ${PAYLOAD} instead of whatever the pool would have served
# shellcheck disable=SC2329
curl() {
    local out="" url=""
    while [ $# -gt 0 ]; do
        case "${1}" in
            --output) out="${2}"; shift 2 ;;
            -*) shift ;;
            *) url="${1}"; shift ;;
        esac
    done
    CURL_URLS="${CURL_URLS} ${url}"
    [ "${CURL_FAILS}" = true ] && return 22
    printf '%s' "${PAYLOAD}" > "${out}"
    return 0
}
# shellcheck disable=SC2329
apt-get() { printf ' %s' "$*" >> "${APT_LOG}"; return 0; }
# shellcheck disable=SC2329
wget() { return 1; }

run_case() {
    : > "${APT_LOG}"
    CURL_URLS=""
    LOGGED_ERRORS=0
    install_ssg_debian_packages > /dev/null 2>&1
    return $?
}

apt_calls() { cat "${APT_LOG}" 2>/dev/null; }

good_payload="the real package bytes"
good_hash=$(printf '%s' "${good_payload}" | sha256sum | cut -d' ' -f1)

echo "== a download that does not match its pinned hash is never installed =="

SSG_DEBIAN_PACKAGES="${good_hash}  ssg-base_0.1.80-1_all.deb"
PAYLOAD="tampered package bytes"
CURL_FAILS=false
run_case
rc=$?
if [ "${rc}" -eq 1 ]; then
    pass "a tampered download makes the function return 1"
else
    fail "a tampered download makes the function return 1" "returned ${rc}"
fi
if [ -z "$(apt_calls)" ]; then
    pass "a tampered download never reaches apt-get"
else
    fail "a tampered download never reaches apt-get" "apt-get was called with:$(apt_calls)"
fi
if [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a tampered download logs an ERROR"
else
    fail "a tampered download logs an ERROR"
fi

echo
echo "== a download that matches its pinned hash is installed =="

PAYLOAD="${good_payload}"
run_case
rc=$?
if [ "${rc}" -eq 0 ]; then
    pass "a matching download makes the function return 0"
else
    fail "a matching download makes the function return 0" "returned ${rc}"
fi
case "$(apt_calls)" in
    *"./ssg-base_0.1.80-1_all.deb"*)
        pass "the package is handed to apt-get as a local file, so dependencies resolve" ;;
    *)
        fail "the package is handed to apt-get as a local file" "apt-get got:$(apt_calls)" ;;
esac

echo
echo "== other failure paths never install anything =="

CURL_FAILS=true
run_case
rc=$?
if [ "${rc}" -eq 1 ] && [ -z "$(apt_calls)" ]; then
    pass "a failed download returns 1 and installs nothing"
else
    fail "a failed download returns 1 and installs nothing" "rc=${rc} apt:$(apt_calls)"
fi
CURL_FAILS=false

saved_packages="${SSG_DEBIAN_PACKAGES}"
SSG_DEBIAN_PACKAGES=""
run_case
rc=$?
if [ "${rc}" -eq 1 ] && [ -z "$(apt_calls)" ]; then
    pass "an empty pin list returns 1 and installs nothing"
else
    fail "an empty pin list returns 1 and installs nothing" "rc=${rc} apt:$(apt_calls)"
fi
SSG_DEBIAN_PACKAGES="${saved_packages}"

unset -f curl wget
run_case
rc=$?
if [ "${rc}" -eq 1 ] && [ -z "$(apt_calls)" ]; then
    pass "no downloader available returns 1 and installs nothing"
else
    fail "no downloader available returns 1 and installs nothing" "rc=${rc} apt:$(apt_calls)"
fi

echo
echo "== the distribution is preferred, the pinned download is only a fallback =="

# install_ssg_content asks the machine whether the datastream it needs actually turned up, rather
# than deciding from the release number. Debian's archive trails one release for SCAP content, but
# the day it catches up this fallback has to stop firing on its own.
PINNED_RAN="${WORK}/pinned_ran"
# shellcheck disable=SC2329
install_ssg_debian_packages() { : > "${PINNED_RAN}"; return "${PINNED_RC:-0}"; }
DATASTREAM="${WORK}/ssg-debian13-ds.xml"

content_case() {
    rm -f "${PINNED_RAN}" "${DATASTREAM}"
    : > "${APT_LOG}"
    LOGGED_ERRORS=0
    [ "${1}" = distro_provides ] && : > "${DATASTREAM}"
    # The stubbed apt-get cannot create files, so a "pinned download succeeds" case seeds the
    # datastream through the stub above
    if [ "${1}" = pinned_provides ]; then
        install_ssg_debian_packages() { : > "${PINNED_RAN}"; : > "${DATASTREAM}"; return 0; }
    fi
    install_ssg_content "${DATASTREAM}" > /dev/null 2>&1
}

content_case distro_provides
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -f "${PINNED_RAN}" ]; then
    pass "when the distribution provides the datastream, the pinned download is skipped"
else
    fail "when the distribution provides the datastream, the pinned download is skipped" \
         "rc=${rc} pinned_ran=$([ -f "${PINNED_RAN}" ] && echo yes || echo no)"
fi

content_case pinned_provides
rc=$?
if [ "${rc}" -eq 0 ] && [ -f "${PINNED_RAN}" ]; then
    pass "when the distribution lacks it, the pinned download runs and satisfies it"
else
    fail "when the distribution lacks it, the pinned download runs and satisfies it" \
         "rc=${rc} pinned_ran=$([ -f "${PINNED_RAN}" ] && echo yes || echo no)"
fi

# Restore the plain stub, which never creates the datastream
# shellcheck disable=SC2329
install_ssg_debian_packages() { : > "${PINNED_RAN}"; return "${PINNED_RC:-0}"; }

content_case distro_lacks
rc=$?
if [ "${rc}" -eq 1 ] && [ -f "${PINNED_RAN}" ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "when neither source provides it, the function returns 1 and logs an ERROR"
else
    fail "when neither source provides it, the function returns 1 and logs an ERROR" \
         "rc=${rc} errors=${LOGGED_ERRORS}"
fi

PINNED_RC=1
content_case distro_lacks
rc=$?
PINNED_RC=0
if [ "${rc}" -eq 1 ]; then
    pass "a failing pinned download propagates as a failure"
else
    fail "a failing pinned download propagates as a failure" "rc=${rc}"
fi

# A distribution that has no ssg packages at all must not by itself trip the failure banner,
# because the pinned fallback is the supported way out of that
content_case distro_provides
if [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a successful run logs no ERROR, so the success banner is not tripped"
else
    fail "a successful run logs no ERROR" "errors=${LOGGED_ERRORS}"
fi

if grep -qE 'RELEASE.*-ge 12.*then' "${SCRIPT}" && grep -B2 -A2 'RELEASE.*-ge 12' "${SCRIPT}" | grep -q ssg; then
    fail "the ssg path no longer branches on the release number" \
         "$(grep -n 'RELEASE.*-ge 12' "${SCRIPT}")"
else
    pass "the ssg path no longer branches on the release number"
fi

echo
echo "== the pins committed in el_configurator.sh are well formed =="

pool_url=$(grep -m1 '^SSG_DEBIAN_POOL_URL=' "${SCRIPT}" | cut -d'"' -f2)
case "${pool_url}" in
    https://*) pass "the pool URL is https (${pool_url})" ;;
    *) fail "the pool URL is https" "got [${pool_url}]" ;;
esac

pins=$(sed -n "/^SSG_DEBIAN_PACKAGES=\$(cat << 'EOF'/,/^EOF\$/p" "${SCRIPT}" | grep -E '^[0-9a-f]{64}  ')
pin_count=$(printf '%s\n' "${pins}" | grep -c . )
if [ "${pin_count}" -ge 1 ]; then
    pass "the pin block parses (${pin_count} packages pinned)"
else
    fail "the pin block parses" "no lines matching '<64 hex>  <file>' found"
fi

malformed=$(printf '%s\n' "${pins}" | grep -vE '^[0-9a-f]{64}  [a-z0-9.+-]+_[0-9][0-9a-z.+~-]*_all\.deb$' | grep -c . )
if [ "${malformed}" -eq 0 ]; then
    pass "every pin is a 64 hex sha256 followed by a versioned .deb filename"
else
    fail "every pin is a 64 hex sha256 followed by a versioned .deb filename" "${malformed} malformed line(s)"
fi

for expected in ssg-base ssg-debian ssg-applications ssg-debderived; do
    if printf '%s\n' "${pins}" | grep -q "  ${expected}_"; then
        pass "${expected} is pinned"
    else
        fail "${expected} is pinned"
    fi
done

if grep -qE '^[[:space:]]*(curl|wget).*http://.*scap-security-guide' "${SCRIPT}"; then
    fail "no plain http download of ssg packages remains" \
         "$(grep -nE '^[[:space:]]*(curl|wget).*http://.*scap-security-guide' "${SCRIPT}")"
else
    pass "no plain http download of ssg packages remains"
fi

if grep -qE '^[[:space:]]*dpkg -i .*ssg-' "${SCRIPT}"; then
    fail "no unverified 'dpkg -i' of an ssg package remains" \
         "$(grep -nE '^[[:space:]]*dpkg -i .*ssg-' "${SCRIPT}")"
else
    pass "no unverified 'dpkg -i' of an ssg package remains"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
