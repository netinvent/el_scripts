#!/usr/bin/env bash

# Tests for the /etc/profile.d shell timeout scripts written by el_configurator.sh
#
# The generated tmout.sh used to dispatch on $0:
#
#     if [ "$0" = "tcsh" ]; then set autologout=10
#     elif [ "$0" = "bash" ]; then typeset -xr TMOUT=600
#     else export TMOUT=600; readonly TMOUT; export TMOUT; fi
#
# Neither of the first two branches can run where it matters. A login shell is invoked with a
# leading dash, as -bash, so it never equals bash; bash -c does equal it, but bash -c does not read
# /etc/profile.d at all. And no csh reads a .sh file. Every real login therefore took the else, and
# that branch assigns to TMOUT unconditionally, so any further source of /etc/profile printed
# "TMOUT: readonly variable".
#
# Where each family looks, from the packaging:
#
#   EL       /etc/profile        for i in /etc/profile.d/*.sh /etc/profile.d/sh.local
#            /etc/csh.cshrc      foreach i ( /etc/profile.d/*.csh )
#            /etc/csh.login      the same loop again
#   Debian   /etc/profile        run-parts --regex '^[a-zA-Z0-9_][a-zA-Z0-9._-]*\.sh$' /etc/profile.d
#            /etc/csh.cshrc      sources /etc/csh/cshrc.d/*, and never reads /etc/profile.d at all
#
# So the two files cohabit: on EL the sh loop globs *.sh and the csh loop globs *.csh, which is how
# the setup package already ships lang.sh beside lang.csh, and on Debian the run-parts regex will
# not match a .csh at all. The csh file has to follow the distribution to the right directory.
#
# These tests extract the generated files from the heredocs and run them, rather than reading the
# script for the right strings.
#
# Usage: tests/test_shell_timeout.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

WORK=$(mktemp -d)
SH="${WORK}/tmout.sh"
CSH="${WORK}/tmout.csh"
trap 'rm -rf "${WORK}"' EXIT

# Pull each heredoc body out of the script. The terminator is EOF at column 0, and the opening line
# may be indented, since the csh one sits inside an if.
# Matched with index rather than a regex, because the csh target is written through a variable and
# "${CSH_TMOUT_FILE}" is full of characters a regex would read as syntax
extract() {
    awk -v want="${1}" '
        index($0, "cat << ") && index($0, want) { f = 1; next }
        f && /^EOF$/ { exit }
        f { print }
    ' "${SCRIPT}"
}
extract '/etc/profile.d/tmout.sh' > "${SH}"
# The csh file goes to a path chosen at runtime, because the two families do not read the same
# directory: EL runs foreach i ( /etc/profile.d/*.csh ) from /etc/csh.cshrc and /etc/csh.login,
# while Debian's /etc/csh.cshrc sources /etc/csh/cshrc.d/* and never looks at /etc/profile.d.
extract "CSH_TMOUT_FILE" > "${CSH}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

if [ ! -s "${SH}" ]; then
    echo "Could not extract /etc/profile.d/tmout.sh from [${SCRIPT}]"
    exit 2
fi

# Run the extracted file the way a login shell would: $0 is -bash, and nothing else is read.
# LC_ALL=C because the checks below look for bash's English "readonly variable", and a French bash
# says "variable en lecture seule", which would let the error through unseen
as_login_shell() {
    LC_ALL=C bash -c 'exec -a "-bash" bash --norc --noprofile -c "$1"' _ "${1}" 2>&1
}

echo "Testing the generated shell timeout scripts from [${SCRIPT}]"
echo
echo "== the timeout is applied, and it is not removable =="

out=$(as_login_shell ". ${SH}; echo \"TMOUT=[\$TMOUT]\"")
case "${out}" in
    *'TMOUT=[600]'*) pass "a login shell gets TMOUT=600" ;;
    *) fail "a login shell gets TMOUT=600" "${out}" ;;
esac

out=$(as_login_shell ". ${SH}; ( TMOUT=0 ) 2>/dev/null && echo WRITABLE || echo READONLY")
case "${out}" in
    *READONLY*) pass "TMOUT is readonly, so a user cannot raise or clear it" ;;
    *) fail "TMOUT is readonly" "${out}" ;;
esac

# An exported TMOUT is not a readonly one, so a value carried in from the environment must lose
out=$(as_login_shell "export TMOUT=0; . ${SH}; echo \"TMOUT=[\$TMOUT]\"")
case "${out}" in
    *'TMOUT=[600]'*) pass "a hostile TMOUT inherited from the environment is overridden" ;;
    *) fail "a hostile TMOUT inherited from the environment is overridden" "${out}" ;;
esac

echo
echo "== sourcing it more than once says nothing =="

# This is the regression. /etc/profile can be read again in a shell that already ran this, and the
# old unconditional assignment answered with "TMOUT: readonly variable" every time
out=$(as_login_shell ". ${SH}; . ${SH}; . ${SH}; echo \"TMOUT=[\$TMOUT]\"")
case "${out}" in
    *'readonly variable'*|*'read-only'*)
        fail "three sources in one shell print nothing" "${out}" ;;
    *'TMOUT=[600]'*)
        pass "three sources in one shell print nothing, and TMOUT still stands" ;;
    *)
        fail "three sources in one shell leave TMOUT set" "${out}" ;;
esac

# Same under a plain POSIX shell, which is the other thing that reads /etc/profile.d/*.sh
out=$(sh -c ". ${SH}; . ${SH}; echo \"TMOUT=[\$TMOUT]\"" 2>&1)
case "${out}" in
    *'readonly'*|*'read-only'*) fail "re-sourcing under sh prints nothing" "${out}" ;;
    *'TMOUT=[600]'*) pass "re-sourcing under sh prints nothing either" ;;
    *) fail "re-sourcing under sh leaves TMOUT set" "${out}" ;;
esac

echo
echo "== the dead \$0 dispatch is gone =="

# $0 for a login shell is -bash, never bash, so this comparison selected nothing in production
if grep -qE '"\$0" = "(bash|tcsh)"' "${SH}"; then
    fail "no branch compares \$0 against a bare shell name" "$(cat "${SH}")"
else
    pass "no branch compares \$0 against a bare shell name"
fi

# csh syntax in a file only ever read by sh and bash
if grep -q 'autologout' "${SH}"; then
    fail "no csh syntax is left in the .sh file" "$(grep -n autologout "${SH}")"
else
    pass "no csh syntax is left in the .sh file"
fi

echo
echo "== csh gets its own file, which is the only one tcsh reads =="

if [ -s "${CSH}" ]; then
    pass "a tmout.csh is generated"
else
    fail "a tmout.csh is generated" "nothing extracted"
fi

if grep -q 'autologout' "${CSH}" 2>/dev/null; then
    pass "it sets autologout, which is the csh equivalent"
else
    fail "it sets autologout" "$(cat "${CSH}" 2>/dev/null)"
fi

# autologout counts minutes, TMOUT counts seconds. 10 and 600 have to stay the same policy
sh_seconds=$(grep -oE 'TMOUT=[0-9]+' "${SH}" | head -1 | cut -d= -f2)
csh_minutes=$(grep -oE 'autologout=[0-9]+' "${CSH}" 2>/dev/null | head -1 | cut -d= -f2)
if [ -n "${sh_seconds}" ] && [ -n "${csh_minutes}" ] && [ "$((csh_minutes * 60))" -eq "${sh_seconds}" ]; then
    pass "both files express the same timeout, ${sh_seconds}s and ${csh_minutes}min"
else
    fail "both files express the same timeout" "sh=${sh_seconds}s csh=${csh_minutes}min"
fi

if grep -q 'set -r autologout' "${CSH}" 2>/dev/null; then
    pass "autologout is set readonly too"
else
    fail "autologout is set readonly too" "$(cat "${CSH}" 2>/dev/null)"
fi

# Re-sourcing a csh file that already set a readonly variable errors the same way
if grep -qE 'if *\( *! *\$\?autologout *\)' "${CSH}" 2>/dev/null; then
    pass "the csh file is guarded against being sourced twice"
else
    fail "the csh file is guarded against being sourced twice" "$(cat "${CSH}" 2>/dev/null)"
fi

# Written whether or not a csh is installed right now. Gating it on the shell being present at
# install time means a machine that gains tcsh later never gets the timeout, and the file costs
# nothing on a machine that never does.
code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")
if printf '%s\n' "${code_only}" | grep -qE 'type (tcsh|csh) >'; then
    fail "the csh file is written unconditionally, not gated on a csh being installed" \
         "$(printf '%s\n' "${code_only}" | grep -nE 'type (tcsh|csh) >')"
else
    pass "the csh file is written unconditionally, not gated on a csh being installed"
fi

echo
echo "== the csh file goes where each family actually looks =="

# EL: /etc/csh.cshrc and /etc/csh.login both run foreach i ( /etc/profile.d/*.csh ), which is why
# the setup package ships lang.sh and lang.csh side by side there
if printf '%s\n' "${code_only}" | grep -qE 'CSH_TMOUT_FILE=/etc/profile\.d/tmout\.csh'; then
    pass "on EL it goes to /etc/profile.d/tmout.csh"
else
    fail "on EL it goes to /etc/profile.d/tmout.csh" "$(grep -n 'CSH_TMOUT_FILE=' "${SCRIPT}")"
fi

# Debian: /etc/csh.cshrc sources /etc/csh/cshrc.d/* and never reads /etc/profile.d, so a .csh
# dropped there is silently ignored
if printf '%s\n' "${code_only}" | grep -qE 'CSH_TMOUT_FILE=/etc/csh/cshrc\.d/'; then
    pass "on Debian it goes to /etc/csh/cshrc.d, which is the only place tcsh reads there"
else
    fail "on Debian it goes to /etc/csh/cshrc.d" "$(grep -n 'CSH_TMOUT_FILE=' "${SCRIPT}")"
fi

# The tcsh package only reads that directory, it does not create it
if printf '%s\n' "${code_only}" | grep -qE 'mkdir -p /etc/csh/cshrc\.d'; then
    pass "the Debian directory is created, since the tcsh package only reads it"
else
    fail "the Debian directory is created" "$(grep -n 'cshrc.d' "${SCRIPT}")"
fi

# Both files live in the same directory on EL, so they have to be able to. They can: the sh loop
# globs *.sh and the csh loop globs *.csh, and upstream already ships lang.sh beside lang.csh
if printf '%s\n' "${code_only}" | grep -qE '> /etc/profile\.d/tmout\.sh'; then
    pass "the sh file keeps its own name, distinct from the csh one"
else
    fail "the sh file keeps its own name" "$(grep -n 'tmout' "${SCRIPT}")"
fi

echo
echo "== plain su gets the timeout too, on Debian =="

# su, sudo su and sudo -s start a non-login interactive bash. On Debian that shell reads
# /etc/bash.bashrc and ~/.bashrc and never /etc/profile.d, so the script hooks tmout.sh into
# /etc/bash.bashrc. The block is pulled out of the script and run against a copy of that file.
hook_block=$(awk '
    $0 == "if [ \"${FLAVOR}\" = \"debian\" ]; then" { start = NR; buf = $0; next }
    start && NR == start + 1 && !index($0, "TMOUT_HOOK=") { start = 0 }
    start { buf = buf "\n" $0; if ($0 == "fi") { print buf; exit } }
' "${SCRIPT}")
BASHRC="${WORK}/bash.bashrc"
printf '%s\n' "${hook_block}" \
    | sed -e "s#/etc/bash\.bashrc#${BASHRC}#g" -e "s#/etc/profile\.d/tmout\.sh#${SH}#g" > "${WORK}/hook_block.sh"

# The head of Debian's own file, which returns early for non-interactive shells. The final newline
# is left out on purpose, the way a hand edited file can end. The ${PS1-} is file content, not
# something to expand here
# shellcheck disable=SC2016
seed_bashrc() {
    printf '%s\n%s\n%s' '# System-wide .bashrc file for interactive bash(1) shells.' \
        '[ -z "${PS1-}" ] && return' 'shopt -s checkwinsize' > "${BASHRC}"
}
# Runs the extracted block the way the script does, with log and LOG_FILE stubbed. FLAVOR,
# LOG_FILE and log are read by the sourced block, which the linter cannot see
# shellcheck disable=SC2034,SC2329
run_hook_block() {
    ( FLAVOR="${1}"; LOG_FILE=/dev/null; log() { :; }; . "${WORK}/hook_block.sh" )
}
hook_count() { grep -cF "${SH}" "${BASHRC}" 2>/dev/null; }

if grep -q 'TMOUT_HOOK=' "${WORK}/hook_block.sh"; then
    pass "the Debian bash.bashrc block was located in the script"
else
    fail "the Debian bash.bashrc block was located in the script" "nothing extracted"
fi

seed_bashrc
run_hook_block debian
if [ "$(hook_count)" -eq 1 ] && grep -qx 'shopt -s checkwinsize' "${BASHRC}"; then
    pass "the hook is appended once, and the last line of a file without a final newline survives"
else
    fail "the hook is appended once, and the last line survives" "$(cat "${BASHRC}")"
fi

run_hook_block debian
if [ "$(hook_count)" -eq 1 ]; then
    pass "a second run does not add it again"
else
    fail "a second run does not add it again" "$(cat "${BASHRC}")"
fi

# This is the su case itself: a non-login interactive bash whose only startup file is bash.bashrc
out=$(HISTFILE=/dev/null bash --rcfile "${BASHRC}" -i \
    -c 'echo "TMOUT=[${TMOUT}]"; ( TMOUT=0 ) 2>/dev/null && echo WRITABLE || echo READONLY' 2>&1 < /dev/null)
case "${out}" in
    *'TMOUT=[600]'*READONLY*) pass "a non-login interactive shell, as su starts, gets TMOUT=600 readonly" ;;
    *) fail "a non-login interactive shell, as su starts, gets TMOUT=600 readonly" "${out}" ;;
esac

# Debian's /etc/profile reads /etc/bash.bashrc before /etc/profile.d, so a login shell now sources
# tmout.sh twice. PS1 is set because that is what lets the file go past its early return
out=$(as_login_shell "PS1='\$ '; . ${BASHRC}; . ${SH}; echo \"TMOUT=[\$TMOUT]\"")
case "${out}" in
    *'readonly variable'*|*'read-only'*) fail "a login shell reading both stays silent" "${out}" ;;
    *'TMOUT=[600]'*) pass "a login shell reading both bash.bashrc and profile.d stays silent" ;;
    *) fail "a login shell reading both keeps TMOUT set" "${out}" ;;
esac

# EL's /etc/bashrc already reads /etc/profile.d for non-login shells, so its file is left alone
rm -f "${BASHRC}"
run_hook_block rhel
if [ ! -e "${BASHRC}" ]; then
    pass "on EL bash.bashrc is not touched"
else
    fail "on EL bash.bashrc is not touched" "$(cat "${BASHRC}")"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
