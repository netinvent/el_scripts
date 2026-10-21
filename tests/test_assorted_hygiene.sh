#!/usr/bin/env bash

# Tests for the assorted items collected as L9 in the review
#
# None of these is a single mechanism, so this suite reads the script rather than running extracted
# functions. Every check excludes comment lines, because most of these items are also *described* in
# comments right next to the code that no longer does them.
#
# Usage: tests/test_assorted_hygiene.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

# The vendored node_exporter installer is kept byte for byte identical to upstream, so its own
# habits are not this script's to fix
vend_start=$(grep -n "NODE_EXPORTER_INSTALLER_EOF' > " "${SCRIPT}" | head -n 1 | cut -d: -f1)
vend_end=$(awk -v s="${vend_start}" 'NR>s && /^NODE_EXPORTER_INSTALLER_EOF$/ {print NR; exit}' "${SCRIPT}")
if [ -z "${vend_start}" ] || [ -z "${vend_end}" ]; then
    echo "Could not locate the vendored installer block in [${SCRIPT}]"
    exit 2
fi
own=$(awk -v a="${vend_start}" -v b="${vend_end}" 'NR < a || NR > b' "${SCRIPT}" | grep -vE '^[[:space:]]*#')

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

has() { printf '%s\n' "${own}" | grep -qE "${1}"; }
show() { printf '%s\n' "${own}" | grep -nE "${1}" | head -3; }

echo "Testing the assorted hygiene items from [${SCRIPT}]"
echo
echo "== package management goes through the scriptable interface =="

# apt(8) documents its own CLI as not stable between releases and tells you not to script it.
# apt-get is the one with the compatibility promise.
if has '\bapt (install|update|upgrade|dist-upgrade|autoremove|purge|remove)\b'; then
    fail "no bare apt subcommand is used for scripting" "$(show '\bapt (install|update|upgrade|dist-upgrade|autoremove|purge|remove)\b')"
else
    pass "no bare apt subcommand is used for scripting"
fi

if has 'apt-get install -y'; then
    pass "installs go through apt-get"
else
    fail "installs go through apt-get"
fi

# apt-get update takes no confirmation, so -y there was noise
if has 'apt-get update .*-y|apt-get update -y'; then
    fail "apt-get update is not passed a pointless -y" "$(show 'apt-get update')"
else
    pass "apt-get update is not passed a pointless -y"
fi

echo
echo "== the RHEL release check has no unreachable arm =="

# The version detection above it already log_quit on anything that is not 8, 9 or 10, so a second
# test of the same three could only ever be true, and its else named Debian inside the RHEL branch
if has 'Debian or alive|Debian or alike'; then
    fail "the RHEL branch no longer log_quits with a Debian message" "$(show 'Debian or ali')"
else
    pass "the RHEL branch no longer log_quits with a Debian message"
fi

# The Debian and Ubuntu branches are deliberately shaped differently: they leave RELEASE at 0 for an
# unknown version rather than quitting inside the detection, so their check really is reachable
if has 'Not compatible with \$\{DIST\} release'; then
    pass "the Debian and Ubuntu branches keep their reachable version check"
else
    fail "the Debian and Ubuntu branches keep their reachable version check"
fi

echo
echo "== the RHEL serial console does not undo its own work =="

# --update-bls-cmdline rewrites the boot loader entries from GRUB_CMDLINE_LINUX in
# /etc/default/grub, which carries no console arguments here, so it undid the grubby call above it.
# Red Hat patched grub2-mkconfig to leave the BLS cmdline alone by default for that reason.
if has '\-\-update-bls-cmdline'; then
    fail "grub2-mkconfig is not asked to rewrite the BLS command line" "$(show 'update-bls-cmdline')"
else
    pass "grub2-mkconfig is not asked to rewrite the BLS command line"
fi

# EL9 unified both firmwares on /boot/grub2/grub.cfg and left a configfile stub in the ESP, so
# writing a full configuration there would clobber the stub. Only EL8 UEFI needs the ESP path.
if has 'grub2-mkconfig -o "\$\{grub_cfg\}"'; then
    pass "the grub configuration path is resolved rather than hardcoded"
else
    fail "the grub configuration path is resolved rather than hardcoded" "$(show 'grub2-mkconfig')"
fi

if has 'RELEASE\}" -eq 8 \] && \[ -d /sys/firmware/efi'; then
    pass "the ESP path is used only on EL8 UEFI, where the real configuration lives there"
else
    fail "the ESP path is used only on EL8 UEFI" "$(show 'firmware/efi')"
fi

# The message named the wrong thing entirely: this call sets kernel arguments, not a getty, and the
# same string was used for both. Counted rather than matched against the grubby line, because the
# call is now split over a continuation and the message sits on the second half of it, so grepping
# the grubby line for the message can never match whatever the message says.
getty_total=$(printf '%s\n' "${own}" | grep -c 'Enabling serial getty failed')
getty_on_unit=$(printf '%s\n' "${own}" | grep 'Enabling serial getty failed' | grep -c 'systemctl enable serial-getty')
if [ "${getty_total}" -eq 1 ] && [ "${getty_on_unit}" -eq 1 ]; then
    pass "the getty message is used once, on the call that enables the getty"
else
    fail "the getty message is used once, on the call that enables the getty" \
         "${getty_total} uses, ${getty_on_unit} of them on the systemctl call" \
         "$(show 'Enabling serial getty failed')"
fi

if has 'Failed to add console arguments to the kernel command line'; then
    pass "the grubby failure names the kernel command line instead"
else
    fail "the grubby failure names the kernel command line instead" "$(show 'grubby')"
fi

echo
echo "== errors reach the log =="

# stdout here is the package manager's progress output, stderr is the reason it failed
if has 'install -y [a-z_-]+ >> "\$\{LOG_FILE\}"'; then
    fail "no install redirects stdout where it means stderr" "$(show 'install -y [a-z_-]+ >> ')"
else
    pass "no install redirects stdout where it means stderr"
fi

offenders=""
while read -r line; do
    [ -z "${line}" ] && continue
    case "${line}" in
        *'${LOG_FILE}'*) ;;
        *) offenders="${offenders}  ${line}" ;;
    esac
done <<< "$(printf '%s\n' "${own}" | grep -oE '(dnf|apt-get) install -y [^|]*')"
if [ -z "${offenders}" ]; then
    pass "every package install sends its errors to the log"
else
    fail "every package install sends its errors to the log" "${offenders}"
fi

echo
echo "== nothing changes the working directory behind the rest of the script =="

# cd /opt || log ... carried on after a failed cd, and on success moved the working directory for
# everything that came after it. Nothing in that block used a relative path, so it simply went.
if has '^\s*cd /'; then
    fail "no bare cd changes the working directory for later code" "$(show '^\s*cd /')"
else
    pass "no bare cd changes the working directory for later code"
fi

# The two cd calls that remain are inside subshells, where the change cannot escape
if has '\(cd "\$\{ssg_dir\}" &&'; then
    pass "the ssg unpacking still cds inside a subshell, where it is contained"
else
    fail "the ssg unpacking still cds inside a subshell"
fi

echo
echo "== the login banners survive the SCAP profile =="

# A profile carrying a banner rule rewrites /etc/issue and /etc/issue.net during remediation, so
# branding written before that ran was replaced by the profile default
issue_at=$(printf '%s\n' "${own}" | grep -n 'cat << EOF > /etc/issue$' | head -1 | cut -d: -f1)
scap_at=$(printf '%s\n' "${own}" | grep -n 'oscap xccdf eval' | tail -1 | cut -d: -f1)
if [ -n "${issue_at}" ] && [ -n "${scap_at}" ] && [ "${issue_at}" -gt "${scap_at}" ]; then
    pass "/etc/issue is written after remediation, not before it"
else
    fail "/etc/issue is written after remediation" "issue at ${issue_at:-missing}, last oscap eval at ${scap_at:-missing}"
fi

issuenet_at=$(printf '%s\n' "${own}" | grep -n 'cat << EOF > /etc/issue.net' | head -1 | cut -d: -f1)
if [ -n "${issuenet_at}" ] && [ "${issuenet_at}" -gt "${scap_at}" ]; then
    pass "/etc/issue.net is written after remediation too"
else
    fail "/etc/issue.net is written after remediation too" "issue.net at ${issuenet_at:-missing}"
fi

# It has to stay ahead of the sshd Banner directive that points at it
banner_at=$(printf '%s\n' "${own}" | grep -n '"Banner" "/etc/issue.net"' | head -1 | cut -d: -f1)
if [ -n "${banner_at}" ] && [ "${issuenet_at}" -lt "${banner_at}" ]; then
    pass "and still ahead of the sshd Banner directive that points at it"
else
    fail "and still ahead of the sshd Banner directive" "issue.net at ${issuenet_at}, Banner at ${banner_at:-missing}"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
