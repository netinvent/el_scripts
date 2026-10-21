#!/usr/bin/env bash

# Checks on the node_exporter installer vendored into el_configurator.sh
#
# The installer used to be piped from raw.githubusercontent.com straight into a root shell, so
# whoever controlled that repository controlled root on every machine provisioned afterwards.
# It is now embedded verbatim. These checks keep it honest:
#   - the embedded copy still hashes to the sha256 recorded in its provenance comment
#   - it is still valid sh and still verifies what it downloads
#   - nothing in el_configurator.sh pipes remote content into a shell again
#
# Usage: tests/test_vendored_node_exporter_installer.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"
DELIMITER=NODE_EXPORTER_INSTALLER_EOF

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

EMBEDDED=$(mktemp)
trap 'rm -f "${EMBEDDED}"' EXIT

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

echo "Checking the vendored installer in [${SCRIPT}]"
echo

awk -v d="${DELIMITER}" '
    $0 ~ "cat << .?" d ".? > " { f = 1; next }
    $0 == d { f = 0 }
    f { print }
' "${SCRIPT}" > "${EMBEDDED}"

echo "== the embedded copy is intact =="

if [ -s "${EMBEDDED}" ]; then
    pass "the installer heredoc was found and is not empty ($(wc -l < "${EMBEDDED}") lines)"
else
    fail "the installer heredoc was found and is not empty" "extracted nothing between the ${DELIMITER} markers"
    printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
    exit 1
fi

# The provenance comment records what was vendored. If someone edits the embedded copy without
# updating that comment, or updates the comment without re-vendoring, this disagrees.
recorded_hash=$(grep -m1 -oE '^[[:space:]]*#[[:space:]]+sha256[[:space:]]+[0-9a-f]{64}' "${SCRIPT}" | grep -oE '[0-9a-f]{64}')
actual_hash=$(sha256sum "${EMBEDDED}" | cut -d' ' -f1)

if [ -z "${recorded_hash}" ]; then
    fail "the provenance comment records a sha256" "no '# sha256 <64 hex>' line found in ${SCRIPT}"
elif [ "${recorded_hash}" = "${actual_hash}" ]; then
    pass "the embedded copy matches the recorded sha256"
else
    fail "the embedded copy matches the recorded sha256" \
         "recorded ${recorded_hash}" \
         "actual   ${actual_hash}" \
         "Either the embedded installer was edited, or the provenance comment is stale."
fi

check_provenance_field() {
    if grep -qE "^[[:space:]]*#[[:space:]]*${2}" "${SCRIPT}"; then
        pass "the provenance comment records ${1}"
    else
        fail "the provenance comment records ${1}" "no line matching /${2}/"
    fi
}
check_provenance_field "the upstream repository" 'Upstream:[[:space:]]*https://github\.com/'
check_provenance_field "the pinned upstream commit" 'commit[[:space:]]+[0-9a-f]{40}'

# Resolved against the repository, not against the script under test, so that passing an
# arbitrary path for the script still checks the license that ships with this repo
if [ -f "$(dirname "${0}")/../LICENSES/node_exporter_installer.MIT" ]; then
    pass "the upstream MIT license is shipped alongside, as that license requires"
else
    fail "the upstream MIT license is shipped alongside" "LICENSES/node_exporter_installer.MIT is missing"
fi

echo
echo "== the embedded copy still does its job =="

if sh -n "${EMBEDDED}" 2>/dev/null; then
    pass "the embedded installer is valid sh"
else
    fail "the embedded installer is valid sh" "$(sh -n "${EMBEDDED}" 2>&1 | head -3)"
fi

# The installer's whole security value is that it checks the release archive against the
# sha256sums.txt published with that release. Losing that would be silent.
if grep -q 'sha256sums.txt' "${EMBEDDED}" && grep -q 'HASH_ARCHIVE_EXPECTED' "${EMBEDDED}"; then
    pass "the installer still verifies the downloaded archive against sha256sums.txt"
else
    fail "the installer still verifies the downloaded archive against sha256sums.txt"
fi

if grep -qE 'GITHUB_URL=https://github\.com/prometheus/node_exporter/releases' "${EMBEDDED}"; then
    pass "the installer still pulls node_exporter from the official prometheus releases"
else
    fail "the installer still pulls node_exporter from the official prometheus releases"
fi

echo
echo "== nothing pipes remote content into a shell =="

# Matches: curl/wget ... | [env assignments ...] sh|bash , across the whole configurator.
# This is the pattern the vendoring exists to eliminate; catch it if it ever comes back.
pipe_hits=$(grep -nE '(curl|wget)[^|]*\|[^|]*[[:space:]](sh|bash)([[:space:]]|$)' "${SCRIPT}" \
            | grep -v '^[[:space:]]*[0-9]*:[[:space:]]*#' || true)
if [ -z "${pipe_hits}" ]; then
    pass "no 'curl|wget ... | sh' pipeline anywhere in el_configurator.sh"
else
    fail "no 'curl|wget ... | sh' pipeline anywhere in el_configurator.sh" "${pipe_hits}"
fi

if grep -q 'raw.githubusercontent.com/carlocorradini' "${SCRIPT}"; then
    if grep -E 'raw\.githubusercontent\.com/carlocorradini' "${SCRIPT}" | grep -qvE '^[[:space:]]*#'; then
        fail "the upstream installer URL is only referenced in comments" \
             "$(grep -nE 'raw\.githubusercontent\.com/carlocorradini' "${SCRIPT}" | grep -vE ':[[:space:]]*#')"
    else
        pass "the upstream installer URL is only referenced in comments"
    fi
else
    pass "the upstream installer URL is only referenced in comments"
fi

echo
echo "== the unit's excess privileges are trimmed by a drop-in =="

# The override lives in a drop-in rather than in the vendored installer, so that the embedded copy
# stays diffable against upstream and re-running the installer cannot undo it.
harden_start=$(grep -n '^harden_node_exporter_service() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -n "${harden_start}" ]; then
    pass "harden_node_exporter_service exists"
else
    fail "harden_node_exporter_service exists"
fi

harden_end=$(awk -v s="${harden_start:-1}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
harden_body=$(sed -n "${harden_start:-1},${harden_end:-1}p" "${SCRIPT}")

case "${harden_body}" in
    *"/etc/systemd/system/node_exporter.service.d"*)
        pass "it writes a systemd drop-in, it does not patch the vendored unit" ;;
    *)
        fail "it writes a systemd drop-in" ;;
esac

for setting in 'Delegate=no' 'LimitCORE=0' 'LimitNPROC=512' 'TasksMax=512' 'NoNewPrivileges=true'; do
    case "${harden_body}" in
        *"${setting}"*) pass "drop-in sets ${setting}" ;;
        *)              fail "drop-in sets ${setting}" ;;
    esac
done

# The three infinity limits and the delegation come from the upstream unit and must not survive.
# Comment lines are dropped first, because the function explains what it is undoing and naming
# LimitCORE=infinity in prose must not read as setting it.
harden_settings=$(printf '%s\n' "${harden_body}" | grep -vE '^[[:space:]]*#')
for leftover in 'Delegate=yes' 'LimitNPROC=infinity' 'LimitCORE=infinity' 'TasksMax=infinity'; do
    case "${harden_settings}" in
        *"${leftover}"*) fail "the drop-in does not re-assert ${leftover}" ;;
        *)               pass "the drop-in does not re-assert ${leftover}" ;;
    esac
done

if grep -qE '^[[:space:]]*harden_node_exporter_service$' "${SCRIPT}"; then
    pass "the node_exporter section calls it"
else
    fail "the node_exporter section calls it"
fi

# The upstream unit is still what the vendored installer writes, untouched
embedded_unit=$(awk '/create_systemd_service_file\(\) \{/,/^}/' "${SCRIPT}")
case "${embedded_unit}" in
    *'LimitCORE=infinity'*) pass "the vendored installer itself is left unmodified" ;;
    *)                      fail "the vendored installer itself is left unmodified" "its unit was edited in place, which breaks the upstream diff" ;;
esac

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
