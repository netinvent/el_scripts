#!/usr/bin/env bash

# Tests for is_virtual() in el_configurator.sh
#
# IS_VIRTUAL decides whether smartmontools and the smartmon prometheus collectors are installed,
# which tuned profile is applied, and whether qemu-guest-agent is installed together with the
# virt_qemu_ga_read_nonsecurity_files SELinux boolean. A physical machine wrongly detected as
# virtual therefore loses disk failure monitoring and gains a guest agent it has no use for.
#
# Two ways that used to happen:
#
#   VIRT_BRAND_NAME was pasted into a grep alternation. Blank it, which is the natural thing to do
#   for anyone who is not the vendor named in the default, and the pattern ends in an empty branch.
#   An empty branch matches every line, so every physical machine reported as virtual.
#
#   The search ran over the whole dmidecode output. That includes DMI type 4, Processor
#   Information, whose flags read "VME (Virtual mode extension)" and "Enhanced Virtualization" on
#   ordinary physical CPUs, and DMI type 11, OEM Strings, which vendors fill with arbitrary text
#   including the names of hypervisors a physical server is certified for.
#
# The dmidecode stub below filters by -t the way the real one does, so removing the type
# restriction from the script really does reproduce the false positive rather than merely failing
# a string match on the source.
#
# Usage: tests/test_is_virtual.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

start=$(grep -n '^is_virtual() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ]; then
    echo "Cannot locate is_virtual() in [${SCRIPT}]"
    exit 2
fi
end=$(awk -v s="${start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")

WORK=$(mktemp -d)
BIN="${WORK}/bin"
CALLS="${WORK}/calls.log"
HELPERS="${WORK}/is_virtual.sh"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${BIN}"

# Read by the extracted function, which the linter cannot see, hence the SC2034 waivers
# shellcheck disable=SC2034
LOG_FILE=/dev/null
LOGGED_ERRORS=0
# shellcheck disable=SC2034
POST_INSTALL_SCRIPT_GOOD=true
# shellcheck disable=SC2034
FLAVOR=rhel
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
        # shellcheck disable=SC2034
        POST_INSTALL_SCRIPT_GOOD=false
    fi
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

sed -n "${start},${end}p" "${SCRIPT}" > "${HELPERS}"

# A stub that honours -t the way the real dmidecode does: the argument is a comma separated list of
# DMI type numbers and the output is the union of those records. With no -t it dumps everything,
# which is what the unhardened code asked for.
cat > "${BIN}/dmidecode" <<'STUB'
#!/bin/sh
echo "dmidecode $*" >> "${CALLS}"
types=""
while [ $# -gt 0 ]; do
    case "$1" in
        -t) types="$2"; shift 2 ;;
        *)  shift ;;
    esac
done
[ -n "${DMI_EMPTY}" ] && exit 0
if [ -z "${types}" ]; then
    cat "${DMI_FIXTURE}"
else
    awk -v want="${types}" '
        BEGIN { RS = ""; n = split(want, a, ","); for (i = 1; i <= n; i++) keep[a[i]] = 1 }
        {
            if (match($0, /DMI type [0-9]+/)) {
                t = substr($0, RSTART + 9, RLENGTH - 9)
                if (t in keep) print $0 "\n"
            }
        }
    ' "${DMI_FIXTURE}"
fi
exit 0
STUB
cat > "${BIN}/lsmod" <<'STUB'
#!/bin/sh
cat "${LSMOD_FIXTURE}"
STUB
for cmd in dnf apt apt-get; do
    {
        echo "#!/bin/sh"
        echo "echo \"${cmd} \$*\" >> \"\${CALLS}\""
        echo "exit 0"
    } > "${BIN}/${cmd}"
    chmod +x "${BIN}/${cmd}"
done
chmod +x "${BIN}/dmidecode" "${BIN}/lsmod"
export CALLS DMI_FIXTURE LSMOD_FIXTURE DMI_EMPTY
PATH="${BIN}:${PATH}"

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

# ---- fixtures ----

# A physical Dell server. Two traps are planted in it, both in DMI tables that have nothing to do
# with whether the machine is virtual: the processor flags carry the two strings the original
# script's own comment warned about, and the OEM strings name a hypervisor the box is certified
# for, which is a normal thing for a server vendor to write there.
cat > "${WORK}/dmi_physical.txt" <<'FIX'
# dmidecode 3.5
Getting SMBIOS data from sysfs.
SMBIOS 3.3.0 present.

Handle 0x0000, DMI type 0, 26 bytes
BIOS Information
	Vendor: Dell Inc.
	Version: 1.10.2

Handle 0x0100, DMI type 1, 27 bytes
System Information
	Manufacturer: Dell Inc.
	Product Name: PowerEdge R750
	Serial Number: 7X2K9L3

Handle 0x0200, DMI type 2, 15 bytes
Base Board Information
	Manufacturer: Dell Inc.
	Product Name: 0PJ80M

Handle 0x0400, DMI type 4, 48 bytes
Processor Information
	Manufacturer: Intel(R) Corporation
	Version: Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz
	Flags:
		VME (Virtual mode extension)
		Enhanced Virtualization

Handle 0x0B00, DMI type 11, 5 bytes
OEM Strings
	String 1: Dell System
	String 2: VMware ESXi Ready Node
	String 3: Certified for Hyper-V
FIX

# The same physical server, branded by the vendor this script was written for
sed 's/Product Name: PowerEdge R750/Product Name: NetPerfect Appliance 200/' \
    "${WORK}/dmi_physical.txt" > "${WORK}/dmi_branded.txt"

# A near miss on that brand. The extra character is what a regular expression dot would consume,
# so this is the fixture that tells -F apart from a plain regex match: searching it for
# "Net.Perfect" finds nothing as a fixed string and finds NetXPerfect as a regex. Against the
# fixture above, which has no character between Net and Perfect, both readings fail to match and
# the distinction would go untested
sed 's/Product Name: PowerEdge R750/Product Name: NetXPerfect Appliance 200/' \
    "${WORK}/dmi_physical.txt" > "${WORK}/dmi_branded_x.txt"

cat > "${WORK}/dmi_vmware.txt" <<'FIX'
Handle 0x0000, DMI type 0, 26 bytes
BIOS Information
	Vendor: Phoenix Technologies LTD

Handle 0x0100, DMI type 1, 27 bytes
System Information
	Manufacturer: VMware, Inc.
	Product Name: VMware Virtual Platform
FIX

cat > "${WORK}/dmi_kvm.txt" <<'FIX'
Handle 0x0000, DMI type 0, 26 bytes
BIOS Information
	Vendor: SeaBIOS

Handle 0x0100, DMI type 1, 27 bytes
System Information
	Manufacturer: Red Hat
	Product Name: KVM
FIX

# Hyper-V signs itself in the BIOS record, DMI type 0, not in System Information
cat > "${WORK}/dmi_hyperv.txt" <<'FIX'
Handle 0x0000, DMI type 0, 26 bytes
BIOS Information
	Vendor: Microsoft Corporation
	Version: Hyper-V UEFI Release v4.1

Handle 0x0100, DMI type 1, 27 bytes
System Information
	Manufacturer: Microsoft Corporation
	Product Name: Virtual Machine
FIX

cat > "${WORK}/dmi_vbox.txt" <<'FIX'
Handle 0x0100, DMI type 1, 27 bytes
System Information
	Manufacturer: innotek GmbH
	Product Name: VirtualBox
FIX

cat > "${WORK}/lsmod_physical.txt" <<'FIX'
Module                  Size  Used by
megaraid_sas          188416  3
tg3                   208896  0
ext4                  978944  1
FIX

cat > "${WORK}/lsmod_virtio.txt" <<'FIX'
Module                  Size  Used by
virtio_net             57344  0
virtio_pci             24576  0
net_failover           24576  1 virtio_net
FIX

# Synthetic, to pin the anchoring: no module is named virtio, but the Used by column mentions one.
# The old unanchored grep read the whole line and so matched here.
cat > "${WORK}/lsmod_usedby.txt" <<'FIX'
Module                  Size  Used by
net_failover           24576  1 virtio_net
megaraid_sas          188416  3
FIX

run_detect() {
    LSMOD_FIXTURE="${WORK}/${1}"
    DMI_FIXTURE="${WORK}/${2}"
    VIRT_BRAND_NAME="${3-NetPerfect}"
    IS_VIRTUAL=
    LOGGED_ERRORS=0
    rm -f "${CALLS}"
    is_virtual > /dev/null 2>&1
}

assert_virtual() {
    if [ "${IS_VIRTUAL}" = true ]; then pass "${1}"; else fail "${1}" "IS_VIRTUAL=${IS_VIRTUAL}"; fi
}
assert_physical() {
    if [ "${IS_VIRTUAL}" = false ]; then pass "${1}"; else fail "${1}" "IS_VIRTUAL=${IS_VIRTUAL}"; fi
}

echo "Testing is_virtual from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== an empty VIRT_BRAND_NAME must not match every machine =="

# This is the headline defect. Pasting the variable into the alternation left a trailing empty
# branch when it was blank, and an empty branch matches any line at all
run_detect lsmod_physical.txt dmi_physical.txt ""
assert_physical "a physical machine with VIRT_BRAND_NAME empty is still physical"

run_detect lsmod_physical.txt dmi_vmware.txt ""
assert_virtual "a VMware guest with VIRT_BRAND_NAME empty is still virtual"

echo
echo "== the DMI search is scoped to the tables that identify the machine =="

run_detect lsmod_physical.txt dmi_physical.txt
assert_physical "processor flags and OEM strings do not make a physical server virtual"

if grep -q 'dmidecode -t 0,1,2' "${CALLS}" 2>/dev/null; then
    pass "dmidecode is asked for DMI types 0, 1 and 2 only"
else
    fail "dmidecode is asked for DMI types 0, 1 and 2 only" "$(cat "${CALLS}" 2>/dev/null)"
fi

# Type 4 is Processor Information and type 11 is OEM Strings. Neither says anything about
# virtualisation, and both are attacker- or vendor-controlled text in this context
for t in 4 11; do
    if grep -qE "dmidecode -t [0-9,]*\\b${t}\\b" "${CALLS}" 2>/dev/null; then
        fail "DMI type ${t} is not read" "$(cat "${CALLS}")"
    else
        pass "DMI type ${t} is not read"
    fi
done

echo
echo "== real hypervisors are still detected =="

run_detect lsmod_physical.txt dmi_vmware.txt
assert_virtual "VMware is detected from System Information"

run_detect lsmod_physical.txt dmi_kvm.txt
assert_virtual "KVM is detected from System Information"

run_detect lsmod_physical.txt dmi_hyperv.txt
assert_virtual "Hyper-V is detected from the BIOS record, so DMI type 0 is still read"

run_detect lsmod_physical.txt dmi_vbox.txt
assert_virtual "VirtualBox is detected from the innotek manufacturer"

echo
echo "== the brand name is matched on its own, as a fixed string =="

run_detect lsmod_physical.txt dmi_branded.txt "NetPerfect"
assert_virtual "a branded appliance is detected through VIRT_BRAND_NAME"

# A brand name is operator supplied text, so a regular expression character in it must not widen
# the search. Read as a regex, "Net.Perfect" matches the NetXPerfect in this fixture through the
# any-character dot; read as a fixed string it matches nothing
run_detect lsmod_physical.txt dmi_branded_x.txt "Net.Perfect"
assert_physical "a dot in VIRT_BRAND_NAME is a literal dot, not any character"

# The same fixture with the literal name still has to be found, so the test above cannot be passing
# merely because the brand search is broken outright
run_detect lsmod_physical.txt dmi_branded_x.txt "NetXPerfect"
assert_virtual "the literal brand name in that same fixture is still detected"

run_detect lsmod_physical.txt dmi_physical.txt "NetPerfect"
assert_physical "a set brand name that is absent leaves the machine physical"

echo
echo "== the virtio check reads module names, not the whole line =="

run_detect lsmod_virtio.txt dmi_physical.txt
assert_virtual "virtio modules mark the machine virtual"

run_detect lsmod_usedby.txt dmi_physical.txt
assert_physical "virtio appearing only in the Used by column does not count"

if grep -q 'dmidecode' "${CALLS}" 2>/dev/null; then
    pass "the physical case falls through to dmidecode"
else
    fail "the physical case falls through to dmidecode"
fi

echo
echo "== failures are reported rather than assumed =="

DMI_EMPTY=1
run_detect lsmod_physical.txt dmi_physical.txt
DMI_EMPTY=
if [ "${IS_VIRTUAL}" = false ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "an empty dmidecode read logs an ERROR and does not claim to have detected anything"
else
    fail "an empty dmidecode read logs an ERROR" "IS_VIRTUAL=${IS_VIRTUAL} errors=${LOGGED_ERRORS}"
fi

mv "${BIN}/dmidecode" "${WORK}/dmidecode.hidden"
run_detect lsmod_physical.txt dmi_physical.txt
mv "${WORK}/dmidecode.hidden" "${BIN}/dmidecode"
if [ "${IS_VIRTUAL}" = false ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a missing dmidecode logs an ERROR and falls back to physical"
else
    fail "a missing dmidecode logs an ERROR" "IS_VIRTUAL=${IS_VIRTUAL} errors=${LOGGED_ERRORS}"
fi

# The install attempt used to swallow its own failure. Both branches are checked separately: an
# alternation across the two passes as soon as either one still logs, which hides a regression in
# the other
for mgr in dnf apt-get; do
    if grep -qE "${mgr} install -y dmidecode .*\\|\\| log" "${SCRIPT}"; then
        pass "a failed dmidecode install is logged on ${mgr}"
    else
        fail "a failed dmidecode install is logged on ${mgr}" \
             "$(grep -n "${mgr} install -y dmidecode" "${SCRIPT}")"
    fi
done

echo
echo "== the old unsafe forms are gone from the source =="

code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")

if printf '%s\n' "${code_only}" | grep -qE 'lsmod \| grep virtio'; then
    fail "the unanchored lsmod grep is gone"
else
    pass "the unanchored lsmod grep is gone"
fi

if printf '%s\n' "${code_only}" | grep -qE '^\s*dmidecode \| grep'; then
    fail "the unscoped dmidecode pipe is gone"
else
    pass "the unscoped dmidecode pipe is gone"
fi

# The variable inside the alternation is the empty-branch bug itself
if printf '%s\n' "${code_only}" | grep -qE 'Red Hat.*\$\{VIRT_BRAND_NAME\}'; then
    fail "VIRT_BRAND_NAME is no longer part of the hypervisor alternation" \
         "$(printf '%s\n' "${code_only}" | grep -n 'VIRT_BRAND_NAME')"
else
    pass "VIRT_BRAND_NAME is no longer part of the hypervisor alternation"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
