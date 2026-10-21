#!/usr/bin/env bash

# Tests for is_enabled(), boolean_value() and validate_boolean_options() in el_configurator.sh
#
# The true/false options used to be tested three different ways:
#
#   [ "${X}" != false ]   twenty-six call sites. Anything but the lowercase word enabled the block
#   [ "${X}" = true ]     two call sites. Only the lowercase word enabled it
#   [ "${X}" == true ]    three call sites, same meaning as the second
#
# The three agree on exactly two values, true and false, and disagree on every other spelling. So
# one setting meant opposite things in different parts of the same run, silently:
#
#   ALLOW_SUDO=yes                            left sudo locked down, because that one is = true
#   FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=yes narrowed the whitelist to ssh for the same reason
#   ALLOW_UNPROTECTED_FS_SYMLINKS=No          switched fs.protected_symlinks off, because != false
#                                             compares against a lowercase literal and No is not it
#
# Usage: tests/test_boolean_options.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

WORK=$(mktemp -d)
HELPERS="${WORK}/bool.sh"
trap 'rm -rf "${WORK}"' EXIT

# shellcheck disable=SC2034
LOG_FILE=/dev/null
LOGGED_ERRORS=0
QUIT_MESSAGE=""
QUIT_CALLED=false
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
# The real one exits. Recorded instead, so that the message can be asserted and the suite survives
log_quit() {
    QUIT_CALLED=true
    QUIT_MESSAGE="${1}"
    log "${1}" "${2}"
    return 1
}

# Pull out the option list and the three functions
{
    sed -n '/^BOOLEAN_OPTIONS=(/,/^)$/p' "${SCRIPT}"
    for fn in is_enabled boolean_value validate_boolean_options; do
        s=$(grep -n "^${fn}() {" "${SCRIPT}" | head -n 1 | cut -d: -f1)
        if [ -z "${s}" ]; then
            echo "Cannot locate ${fn}() in [${SCRIPT}]" >&2
            exit 2
        fi
        e=$(awk -v s="${s}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
        sed -n "${s},${e}p" "${SCRIPT}"
    done
} > "${HELPERS}"

if ! grep -q '^BOOLEAN_OPTIONS=(' "${HELPERS}"; then
    echo "Cannot locate the BOOLEAN_OPTIONS list in [${SCRIPT}]"
    exit 2
fi
# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

echo "Testing the boolean option helpers from [${SCRIPT}]"
echo
echo "== the two spellings that already worked still mean what they meant =="

# Every configuration file in the field holds one of these two, so they must not move
for v in true false; do
    TESTOPT="${v}"
    if is_enabled "${TESTOPT}"; then got=on; else got=off; fi
    want=off; [ "${v}" = true ] && want=on
    if [ "${got}" = "${want}" ]; then
        pass "${v} is ${want}, unchanged from before"
    else
        fail "${v} is ${want}" "got ${got}"
    fi
done

echo
echo "== the spellings that used to mean two things at once now mean one =="

# on: every reasonable way of writing yes
for v in yes YES Yes y Y on ON 1 TRUE True tRuE; do
    TESTOPT="${v}"
    if is_enabled "${TESTOPT}"; then
        pass "[${v}] is on"
    else
        fail "[${v}] is on" "read as off"
    fi
done

# off: every reasonable way of writing no. Under the old != false test all of these ran the block
for v in no NO No n N off OFF 0 FALSE False fAlSe; do
    TESTOPT="${v}"
    if is_enabled "${TESTOPT}"; then
        fail "[${v}] is off" "read as on, which is what != false used to do"
    else
        pass "[${v}] is off"
    fi
done

echo
echo "== a value nothing can read stops the run before anything is changed =="

# The alternative is guessing, and the safe guess differs per option: for CONFIGURE_FIREWALL the
# cautious reading is on, for ALLOW_UNPROTECTED_FS_SYMLINKS it is off
set_all_valid() {
    local n
    for n in "${BOOLEAN_OPTIONS[@]}"; do
        eval "${n}=false"
    done
}

set_all_valid
QUIT_CALLED=false
LOGGED_ERRORS=0
validate_boolean_options
if [ "${QUIT_CALLED}" = false ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "an entirely valid configuration passes silently"
else
    fail "an entirely valid configuration passes silently" "${QUIT_MESSAGE}"
fi

set_all_valid
CONFIGURE_FIREWALL=maybe
QUIT_CALLED=false
validate_boolean_options
if [ "${QUIT_CALLED}" = true ]; then
    pass "an unreadable value stops the run"
else
    fail "an unreadable value stops the run"
fi
case "${QUIT_MESSAGE}" in
    *CONFIGURE_FIREWALL*maybe*) pass "the message names the option and shows its value" ;;
    *) fail "the message names the option and shows its value" "${QUIT_MESSAGE}" ;;
esac

set_all_valid
CONFIGURE_FIREWALL=maybe
CONFIGURE_TUNED=perhaps
QUIT_CALLED=false
validate_boolean_options
case "${QUIT_MESSAGE}" in
    *CONFIGURE_FIREWALL*CONFIGURE_TUNED*)
        pass "every bad option is reported at once, not one run at a time" ;;
    *)
        fail "every bad option is reported at once" "${QUIT_MESSAGE}" ;;
esac

set_all_valid
CONFIGURE_FIREWALL=""
QUIT_CALLED=false
validate_boolean_options
if [ "${QUIT_CALLED}" = true ]; then
    pass "an empty value is refused rather than read as one thing or the other"
else
    fail "an empty value is refused"
fi

echo
echo "== boolean_value hands a literal word to code that compares for itself =="

TESTOPT=yes
if [ "$(boolean_value "${TESTOPT}")" = true ]; then
    pass "an on value becomes the literal word true"
else
    fail "an on value becomes the literal word true" "got [$(boolean_value "${TESTOPT}")]"
fi
TESTOPT=No
if [ "$(boolean_value "${TESTOPT}")" = false ]; then
    pass "an off value becomes the literal word false"
else
    fail "an off value becomes the literal word false" "got [$(boolean_value "${TESTOPT}")]"
fi

# The vendored node_exporter installer runs its own [ "$X" != true ] test, which this script cannot
# change without diverging from upstream, so the value handed over has to be normalised first
if grep -q 'INSTALL_NODE_EXPORTER_SKIP_FIREWALL="\$(boolean_value "\${NODE_EXPORTER_SKIP_FIREWALL}")"' "${SCRIPT}"; then
    pass "the vendored installer is handed a normalised word, not the raw option"
else
    fail "the vendored installer is handed a normalised word" \
         "$(grep -n 'INSTALL_NODE_EXPORTER_SKIP_FIREWALL=' "${SCRIPT}")"
fi

echo
echo "== the option list matches what the configuration block declares =="

# Two lists that must not drift. Anything declared but unlisted escapes validation entirely, and
# anything listed but undeclared is validated as empty and would stop every run
declared=$(grep -oE '^[A-Z_]+=(true|false)' "${SCRIPT}" | cut -d= -f1 | grep -v '^POST_INSTALL_SCRIPT_GOOD$' | sort -u)
listed=$(printf '%s\n' "${BOOLEAN_OPTIONS[@]}" | sort -u)

missing=$(comm -23 <(printf '%s\n' "${declared}") <(printf '%s\n' "${listed}"))
extra=$(comm -13 <(printf '%s\n' "${declared}") <(printf '%s\n' "${listed}"))

if [ -z "${missing}" ]; then
    pass "every declared option is in BOOLEAN_OPTIONS"
else
    fail "every declared option is in BOOLEAN_OPTIONS" "not listed: $(echo "${missing}" | tr '\n' ' ')"
fi
if [ -z "${extra}" ]; then
    pass "BOOLEAN_OPTIONS lists nothing that is not declared"
else
    fail "BOOLEAN_OPTIONS lists nothing that is not declared" "not declared: $(echo "${extra}" | tr '\n' ' ')"
fi

echo
echo "== every option is actually read somewhere =="

# An option declared and listed but never read is dead weight. Only a ${...} expansion counts here,
# which is deliberate: a call site reverted to is_enabled NAME would read as unread and fail, and
# that form is what made every option invisible to shellcheck in the first place.
unread=""
while read -r opt; do
    [ -z "${opt}" ] && continue
    uses=$(grep -vE '^[[:space:]]*#' "${SCRIPT}" \
           | grep -cE "\\$\{${opt}\}")
    [ "${uses}" -eq 0 ] && unread="${unread} ${opt}"
done <<< "${listed}"

if [ -z "${unread}" ]; then
    pass "every option in BOOLEAN_OPTIONS is read by the script"
else
    fail "every option in BOOLEAN_OPTIONS is read by the script" "never read:${unread}"
fi

# Both call forms parse, and only one is right. is_enabled CONFIGURE_TUNED passes the literal string
# "CONFIGURE_TUNED", which lowercases to nothing the case matches, so it returns 1 and the block is
# silently skipped. shellcheck cannot see it either, because the option stays used at its other call
# sites. Nothing else catches this, so it is checked directly.
bare=$(grep -vE '^[[:space:]]*#' "${SCRIPT}" \
       | grep -nE '(is_enabled|boolean_value) [A-Z_]+')
if [ -z "${bare}" ]; then
    pass "no call site passes an option name where a value is meant"
else
    fail "no call site passes an option name where a value is meant" "${bare}"
fi

# Passing the value means shellcheck sees each option assigned and used, so none of them needs a
# disable any more. One reappearing would mean a call site went back to passing the name, or that
# something genuinely unused is being hidden.
if grep -q 'disable=SC2034' "${SCRIPT}"; then
    fail "no option needs an SC2034 directive any more" \
         "$(grep -n 'disable=SC2034' "${SCRIPT}" | head -3)"
else
    pass "no option needs an SC2034 directive any more"
fi

echo
echo "== no option is read the old way any more =="

code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")
old=""
while read -r opt; do
    [ -z "${opt}" ] && continue
    if printf '%s\n' "${code_only}" | grep -qE "\\[ \"\\\$\\{${opt}\\}\" [!=]=? (true|false) \\]"; then
        old="${old} ${opt}"
    fi
done <<< "${listed}"

if [ -z "${old}" ]; then
    pass "no option is still compared against a literal true or false"
else
    fail "no option is still compared against a literal true or false" "still compared:${old}"
fi

# validate_boolean_options has to run after get_kernel_arguments, which can set these options from
# the boot line, and before anything on the machine is changed
entry=$(printf '%s\n' "${code_only}" | grep -nE '^(get_kernel_arguments|validate_boolean_options|get_el_version)$' | head -3)
case "$(printf '%s' "${entry}" | tr '\n' ' ')" in
    *get_kernel_arguments*validate_boolean_options*get_el_version*)
        pass "validation runs after the boot line is read and before anything is configured" ;;
    *)
        fail "validation runs after the boot line is read and before anything is configured" "${entry}" ;;
esac

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
