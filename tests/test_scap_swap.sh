#!/usr/bin/env bash

# Tests for add_scap_swap / remove_scap_swap, and for how the oscap exit code is read
#
# Reported from a fresh Debian 12 install with 4 GB of memory:
#
#   el_configurator.sh: line 1830:  3089 Killed   oscap xccdf eval --profile anssi_bp28_high ...
#
# Killed is SIGKILL, which the kernel OOM killer sends. Several rules in anssi_bp28_high walk the
# whole filesystem, their OVAL objects carrying recurse_direction="down" with max_depth="-1", and
# the result is held in memory. The same rules are behind the DEBIAN_12_SKIP_RULES note already in
# the script, where a larger machine grinds instead of dying.
#
# Two things came out of that. Swap covers the peak for the length of the run. And the exit code has
# to be read properly: a killed process answers 137, the old test looked only for 1, so the run
# reported success and printed the green banner on a half remediated machine.
#
# Usage: tests/test_scap_swap.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

WORK=$(mktemp -d)
BIN="${WORK}/bin"
CALLS="${WORK}/calls.log"
HELPERS="${WORK}/swap.sh"
MEMINFO="${WORK}/meminfo"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${BIN}"

# shellcheck disable=SC2034
LOG_FILE=/dev/null
LOGGED_ERRORS=0
LOGGED_NOTICES=0
LOGGED=""
# shellcheck disable=SC2034
POST_INSTALL_SCRIPT_GOOD=true
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
        # shellcheck disable=SC2034
        POST_INSTALL_SCRIPT_GOOD=false
    fi
    [ "${2}" = "NOTICE" ] && LOGGED_NOTICES=$((LOGGED_NOTICES + 1))
    LOGGED="${LOGGED}${1}
"
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

extract_fn() {
    local s e
    s=$(grep -n "^${1}() {" "${SCRIPT}" | head -n 1 | cut -d: -f1)
    if [ -z "${s}" ]; then
        echo "Cannot locate ${1}() in [${SCRIPT}]" >&2
        exit 2
    fi
    e=$(awk -v s="${s}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
    sed -n "${s},${e}p" "${SCRIPT}"
}

# The probe walks real system directories, and these tests must not write to them, so the candidate
# list is rewritten into the sandbox. The literal list is asserted separately further down, so the
# rewrite here and the script cannot drift apart without a test saying so.
# /proc/meminfo is the machine's, and these tests need to pretend to be a small one.
C1="${WORK}/c1"
C2="${WORK}/c2"
C3="${WORK}/c3"
{
    extract_fn make_scap_swap_file
    extract_fn add_scap_swap
    extract_fn remove_scap_swap
} | sed -e "s#/proc/meminfo#${MEMINFO}#g" \
        -e "s#candidates=(/var/tmp /var / /home /srv /opt)#candidates=(${C1} ${C2} ${C3})#" \
    > "${HELPERS}"

if ! grep -q "candidates=(${C1} ${C2} ${C3})" "${HELPERS}"; then
    echo "The candidate list in ${SCRIPT} is not the literal these tests rewrite, so the probe would"
    echo "run against real system directories. Update the sed above to match, then re-run."
    exit 2
fi

# Stubs. mkswap, swapon and swapoff cannot run here, and dd is real so the file size can be checked.
for cmd in mkswap swapon swapoff chattr; do
    {
        echo "#!/bin/sh"
        echo "echo \"${cmd} \$*\" >> \"\${CALLS}\""
        # A glob lets one call fail while the same command succeeds elsewhere, which is what a
        # filesystem that turns down a swap file looks like to the probe
        echo "case \"\$*\" in \${${cmd}_FAIL_GLOB:-__never_matches__}) exit 1 ;; esac"
        echo "exit \${${cmd}_RC:-0}"
    } > "${BIN}/${cmd}"
    chmod +x "${BIN}/${cmd}"
done

# df is stubbed so each test can describe a filesystem layout. The script calls df -PTm <dir> and
# reads $1 device, $2 type and $5 available in MB, so the stub has to put them in those columns:
# getting that wrong is the whole reason the real call is a single df rather than three.
# A directory absent from the table makes df fail, which is what an unmounted path would do.
DF_TABLE="${WORK}/df_table"
cat > "${BIN}/df" <<'DFEOF'
#!/bin/sh
dir=""
for a in "$@"; do
    case "$a" in -*) ;; *) dir="$a" ;; esac
done
while read -r d fstype avail device; do
    [ "$d" = "$dir" ] || continue
    # A leftover swap file takes room away from its own filesystem, which is the whole reason the
    # script clears leftovers before it measures anything
    if [ -n "${LEFTOVER_COST}" ] && [ -e "${d}/el_configurator_scap.swap" ]; then
        avail=$((avail - LEFTOVER_COST))
    fi
    echo "Filesystem Type 1048576-blocks Used Available Capacity Mounted-on"
    echo "$device $fstype 999999 0 $avail 1% $d"
    exit 0
done < "${DF_TABLE}"
exit 1
DFEOF
chmod +x "${BIN}/df"

# dd stays real by default, so the swap file is genuinely written and can be checked for holes.
# DD_FAKE makes it record the arguments and touch the file instead, for the tests about how big a
# swap file the probe decided on, which are in the gigabytes and would take minutes to write.
REAL_DD=$(command -v dd)
cat > "${BIN}/dd" <<'DDEOF'
#!/bin/sh
echo "dd $*" >> "${CALLS}"
if [ -z "${DD_FAKE}" ]; then
    exec "${REAL_DD}" "$@"
fi
of=""
for a in "$@"; do
    case "$a" in of=*) of="${a#of=}" ;; esac
done
: > "${of}"
DDEOF
chmod +x "${BIN}/dd"

export CALLS DF_TABLE REAL_DD DD_FAKE LEFTOVER_COST mkswap_RC swapon_RC swapoff_RC chattr_RC
export mkswap_FAIL_GLOB swapon_FAIL_GLOB swapoff_FAIL_GLOB chattr_FAIL_GLOB
PATH="${BIN}:${PATH}"

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

SWAPFILE="${WORK}/swapdir/el_configurator_scap.swap"

# mem_mb swap_mb
set_memory() {
    printf 'MemTotal:       %d kB\nSwapTotal:      %d kB\n' "$(( ${1} * 1024 ))" "$(( ${2} * 1024 ))" > "${MEMINFO}"
}

# Describes the sandbox filesystems for one test: each argument is "dir fstype availMB device"
set_filesystems() {
    : > "${DF_TABLE}"
    while [ $# -gt 0 ]; do
        echo "${1}" >> "${DF_TABLE}"
        shift
    done
}

reset() {
    rm -rf "${WORK:?}/swapdir" "${WORK:?}/c1" "${WORK:?}/c2" "${WORK:?}/c3"
    rm -f "${CALLS}"
    LOGGED_ERRORS=0
    LOGGED_NOTICES=0
    LOGGED=""
    mkswap_RC=0; swapon_RC=0; swapoff_RC=0; chattr_RC=0
    mkswap_FAIL_GLOB=""; swapon_FAIL_GLOB=""; swapoff_FAIL_GLOB=""; chattr_FAIL_GLOB=""
    DD_FAKE=""
    LEFTOVER_COST=""
    # shellcheck disable=SC2034
    SCAP_SWAP_ACTIVE_FILE=""
    # shellcheck disable=SC2034
    SCAP_SWAP_FILE="${SWAPFILE}"
    # Small, so the tests do not write gigabytes. The size logic is the same at any number.
    # shellcheck disable=SC2034
    SCAP_SWAP_SIZE_MB=2
    set_filesystems "${WORK}/swapdir ext4 20000 /dev/sda1"
}

# Prepares the three probe candidates as real directories, and describes them to the df stub.
# Each argument is "fstype availMB device", in candidate order.
set_candidates() {
    # shellcheck disable=SC2034
    SCAP_SWAP_FILE=""
    : > "${DF_TABLE}"
    local n=0 dir spec
    for spec in "$@"; do
        n=$((n + 1))
        eval "dir=\${C${n}}"
        mkdir -p "${dir}"
        echo "${dir} ${spec}" >> "${DF_TABLE}"
    done
}
echo "Testing the OpenSCAP swap helpers from [${SCRIPT}]"
echo
echo "== a small machine gets swap for the run =="

reset
set_memory 4096 0
add_scap_swap; rc=$?

if [ "${rc}" -eq 0 ]; then
    pass "returns 0 on the 4 GB machine this was reported from"
else
    fail "returns 0 on a 4 GB machine" "rc=${rc} ${LOGGED}"
fi
if [ -f "${SWAPFILE}" ]; then
    pass "a swap file is created"
else
    fail "a swap file is created"
fi

# A file with holes is refused by swapon on XFS, which is what RHEL installs by default, so the
# bytes have to actually be written rather than fallocated
size=$(stat -c %s "${SWAPFILE}" 2>/dev/null)
if [ "${size}" = "$((2 * 1024 * 1024))" ]; then
    pass "it is fully written, not a sparse file swapon would refuse"
else
    fail "it is fully written" "got ${size:-unknown} bytes, wanted $((2 * 1024 * 1024))"
fi

for want in mkswap swapon; do
    if grep -q "^${want} " "${CALLS}"; then
        pass "${want} is run on it"
    else
        fail "${want} is run on it" "$(cat "${CALLS}" 2>/dev/null)"
    fi
done

echo
echo "== a machine that does not need it is left alone =="

reset
set_memory 16384 0
add_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ ! -e "${SWAPFILE}" ] && [ ! -f "${CALLS}" ]; then
    pass "16 GB of memory means no swap file and nothing run"
else
    fail "16 GB of memory means no swap file" "rc=${rc} $(cat "${CALLS}" 2>/dev/null)"
fi

# Swap the machine already has counts towards the total
reset
set_memory 4096 8192
add_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ ! -e "${SWAPFILE}" ]; then
    pass "existing swap counts, so a machine with plenty is not given more"
else
    fail "existing swap counts" "rc=${rc}"
fi

reset
set_memory 4096 0
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=0
add_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ ! -e "${SWAPFILE}" ] && [ ! -f "${CALLS}" ]; then
    pass "size 0 turns it off entirely"
else
    fail "size 0 turns it off entirely" "rc=${rc}"
fi

echo
echo "== it is temporary, and only ever its own file =="

reset
set_memory 4096 0
add_scap_swap > /dev/null
rm -f "${CALLS}"
remove_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ ! -e "${SWAPFILE}" ]; then
    pass "the file is swapped off and deleted afterwards"
else
    fail "the file is swapped off and deleted afterwards" "rc=${rc}"
fi
if grep -q "^swapoff .*el_configurator_scap.swap" "${CALLS}"; then
    pass "swapoff names only the file this script made"
else
    fail "swapoff names only the file this script made" "$(cat "${CALLS}" 2>/dev/null)"
fi

# Pulling swap out from under a system that is using it is worse than leaving a file behind
reset
set_memory 4096 0
add_scap_swap > /dev/null
swapoff_RC=1
remove_scap_swap; rc=$?
if [ "${rc}" -ne 0 ] && [ -e "${SWAPFILE}" ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a failed swapoff leaves the file rather than deleting swap still in use"
else
    fail "a failed swapoff leaves the file" "rc=${rc}"
fi
swapoff_RC=0

reset
remove_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ ! -f "${CALLS}" ]; then
    pass "removing swap that was never added does nothing"
else
    fail "removing swap that was never added does nothing" "rc=${rc}"
fi

# A run that was interrupted leaves a file behind, and the next one has to cope with it
reset
set_memory 4096 0
mkdir -p "$(dirname "${SWAPFILE}")"
printf 'leftover' > "${SWAPFILE}"
add_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ "$(stat -c %s "${SWAPFILE}" 2>/dev/null)" = "$((2 * 1024 * 1024))" ]; then
    pass "a leftover file from an interrupted run is replaced, not appended to"
else
    fail "a leftover file is replaced" "rc=${rc}"
fi

echo
echo "== a filesystem short of room gets a smaller swap file =="

# The machine this came from has 4 GB of memory and an ANSSI partition layout, where the partition
# with the most room may still not have the whole 4096MB going spare. Half a swap file carries the
# run further than none, so the size is cut to what fits rather than the filesystem being passed up.
reset
set_memory 4096 0
set_filesystems "${WORK}/swapdir ext4 2600 /dev/sda1"
DD_FAKE=1
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=4096
add_scap_swap; rc=$?
if [ "${rc}" -eq 0 ]; then
    pass "a filesystem too small for the full size is still used"
else
    fail "a filesystem too small for the full size is still used" "rc=${rc} ${LOGGED}"
fi
# 2600 free, 256 held back so the partition is not filled to the brim, leaves 2344
if grep -q "count=2344 " "${CALLS}" 2>/dev/null; then
    pass "and the swap file is cut down to what fits, less the margin"
else
    fail "and the swap file is cut down to what fits" "$(cat "${CALLS}" 2>/dev/null)"
fi
case "${LOGGED}" in
    *"reduced from 4096MB"*) pass "and the log says it was reduced, and from what" ;;
    *) fail "and the log says it was reduced" "${LOGGED}" ;;
esac

echo
echo "== it refuses rather than half doing it =="

# Under the floor the write costs more minutes than the swap is worth
reset
set_memory 4096 0
set_filesystems "${WORK}/swapdir ext4 1200 /dev/sda1"
DD_FAKE=1
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=4096
add_scap_swap; rc=$?
if [ "${rc}" -ne 0 ] && [ "${LOGGED_ERRORS}" -ge 1 ] && [ ! -e "${SWAPFILE}" ]; then
    pass "less room than the floor is an ERROR, and nothing is left behind"
else
    fail "less room than the floor is an ERROR" "rc=${rc} errors=${LOGGED_ERRORS} ${LOGGED}"
fi
if [ ! -f "${CALLS}" ]; then
    pass "and it decides that before writing anything"
else
    fail "and it decides that before writing anything" "$(cat "${CALLS}")"
fi

# A size smaller than the floor was asked for as it stands, so the floor must not veto it. This is
# the case every other test in this file runs under, and it would fail silently the wrong way.
reset
set_memory 4096 0
add_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ -e "${SWAPFILE}" ]; then
    pass "a SCAP_SWAP_SIZE_MB under the floor is honoured, since nothing had to be cut"
else
    fail "a SCAP_SWAP_SIZE_MB under the floor is honoured" "rc=${rc} ${LOGGED}"
fi
reset
set_memory 4096 0
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=lots
add_scap_swap; rc=$?
if [ "${rc}" -ne 0 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "a size that is not a number is refused"
else
    fail "a size that is not a number is refused" "rc=${rc}"
fi

reset
set_memory 4096 0
mkswap_RC=1
add_scap_swap; rc=$?
if [ "${rc}" -ne 0 ] && [ ! -e "${SWAPFILE}" ]; then
    pass "a failed mkswap cleans the file up"
else
    fail "a failed mkswap cleans the file up" "rc=${rc}"
fi
mkswap_RC=0

reset
set_memory 4096 0
swapon_RC=1
add_scap_swap; rc=$?
if [ "${rc}" -ne 0 ] && [ ! -e "${SWAPFILE}" ]; then
    pass "a failed swapon cleans the file up"
else
    fail "a failed swapon cleans the file up" "rc=${rc}"
fi
swapon_RC=0

echo
echo "== the oscap exit code is read properly =="

code_only=$(grep -vE '^[[:space:]]*#' "${SCRIPT}")

# This is the bug the report exposed. 137 is SIGKILL, and it is not 1, so a test for 1 alone sent a
# killed remediation down the success path and the run ended with a green banner.
if printf '%s\n' "${code_only}" | grep -qE 'if \[ \$\? -eq 1 \]; then'; then
    fail "no oscap branch tests only for exit 1" \
         "$(printf '%s\n' "${code_only}" | grep -nE 'if \[ \$\? -eq 1 \]; then')"
else
    pass "no oscap branch tests only for exit 1"
fi

# 0 is clean, 2 is "some rule failed" which is normal for a profile this script deviates from
branches=$(printf '%s\n' "${code_only}" | grep -cE '\[ "\$\{scap_rc\}" -ne 0 \] && \[ "\$\{scap_rc\}" -ne 2 \]')
if [ "${branches}" -eq 2 ]; then
    pass "both the online and offline branches accept 0 and 2 and nothing else"
else
    fail "both branches accept 0 and 2 and nothing else" "found ${branches}, expected 2"
fi

if printf '%s\n' "${code_only}" | grep -q 'OpenSCAP exited ${scap_rc}'; then
    pass "the failure says which code it got, so a 137 is recognisable in the log"
else
    fail "the failure says which code it got"
fi

echo
echo "== the swap wraps the whole remediation =="

on_count=$(printf '%s\n' "${code_only}" | grep -cE '^ +add_scap_swap')
off_count=$(printf '%s\n' "${code_only}" | grep -c '^ *remove_scap_swap$')
if [ "${on_count}" -eq 2 ]; then
    pass "swap is added on both the online and offline paths"
else
    fail "swap is added on both paths" "found ${on_count}"
fi
if [ "${off_count}" -eq 1 ]; then
    pass "and taken away once, after both of them"
else
    fail "and taken away once, after both of them" "found ${off_count}"
fi

first_on=$(printf '%s\n' "${code_only}" | grep -nE '^ +add_scap_swap' | head -1 | cut -d: -f1)
eval_at=$(printf '%s\n' "${code_only}" | grep -n 'oscap xccdf eval.*--remediate' | head -1 | cut -d: -f1)
off_at=$(printf '%s\n' "${code_only}" | grep -n '^ *remove_scap_swap$' | head -1 | cut -d: -f1)
if [ -n "${first_on}" ] && [ -n "${eval_at}" ] && [ -n "${off_at}" ] \
   && [ "${first_on}" -lt "${eval_at}" ] && [ "${eval_at}" -lt "${off_at}" ]; then
    pass "on before the remediation, off after it"
else
    fail "on before the remediation, off after it" \
         "on ${first_on:-missing}, eval ${eval_at:-missing}, off ${off_at:-missing}"
fi

# Adding it to fstab would make it permanent, which is the opposite of what this is for
if printf '%s\n' "${code_only}" | grep -qE 'fstab.*swap|swap.*fstab'; then
    fail "the swap file never reaches fstab" \
         "$(printf '%s\n' "${code_only}" | grep -nE 'fstab')"
else
    pass "the swap file never reaches fstab"
fi
echo
echo "== the probe picks the filesystem with the most room =="

# On an ANSSI layout /var/tmp is a partition of its own and frequently the smallest thing on the
# machine, which is what sent the reported run into the OOM killer with nowhere to put swap.
reset
set_memory 4096 0
set_candidates "ext4 2000 /dev/sda1" "ext4 9000 /dev/sdb1" "ext4 5000 /dev/sdc1"
DD_FAKE=1
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=4096
add_scap_swap; rc=$?

if [ "${rc}" -eq 0 ] && [ -e "${C2}/el_configurator_scap.swap" ]; then
    pass "the roomiest candidate wins, not the first one listed"
else
    fail "the roomiest candidate wins" "rc=${rc} ${LOGGED}"
fi
if [ ! -e "${C1}/el_configurator_scap.swap" ] && [ ! -e "${C3}/el_configurator_scap.swap" ]; then
    pass "and the others are left alone"
else
    fail "and the others are left alone"
fi
# 9000 free is more than 4096 + 256, so nothing is cut down here
if grep -q "count=4096 " "${CALLS}" 2>/dev/null; then
    pass "and it gets the full size, since the room is there"
else
    fail "and it gets the full size" "$(cat "${CALLS}" 2>/dev/null)"
fi
if [ "${SCAP_SWAP_ACTIVE_FILE}" = "${C2}/el_configurator_scap.swap" ]; then
    pass "the path that was actually used is recorded"
else
    fail "the path that was actually used is recorded" "[${SCAP_SWAP_ACTIVE_FILE}]"
fi

# Which is the whole point of recording it: the configured path is no longer where the file is
remove_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ ! -e "${C2}/el_configurator_scap.swap" ] && [ -z "${SCAP_SWAP_ACTIVE_FILE}" ]; then
    pass "and remove_scap_swap takes away that file, wherever the probe put it"
else
    fail "remove_scap_swap takes away that file" "rc=${rc} active=[${SCAP_SWAP_ACTIVE_FILE}]"
fi

# Nothing was made, so nothing may be taken away, and swapoff must not be run on a guess
reset
remove_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ ! -f "${CALLS}" ]; then
    pass "a run that made no swap file removes nothing"
else
    fail "a run that made no swap file removes nothing" "rc=${rc} $(cat "${CALLS}" 2>/dev/null)"
fi

echo
echo "== a filesystem that cannot hold a swap file is passed over =="

# A swap file needs the filesystem to map its blocks, through its own swap_activate or through
# bmap. tmpfs has neither, and the kernel turns it down with "swapfile has holes" rather than
# anything that names the real problem, so it is filtered out before a gigabyte is written to it.
reset
set_memory 4096 0
set_candidates "ext4 5000 /dev/sda1" "tmpfs 90000 tmpfs" "ext4 3000 /dev/sdc1"
DD_FAKE=1
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=4096
add_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ -e "${C1}/el_configurator_scap.swap" ]; then
    pass "the roomiest candidate is skipped when it is tmpfs, and the next one used"
else
    fail "the roomiest candidate is skipped when it is tmpfs" "rc=${rc} ${LOGGED}"
fi
if [ ! -e "${C2}/el_configurator_scap.swap" ]; then
    pass "and nothing at all is written to it"
else
    fail "and nothing at all is written to it"
fi

# One of each family in turn, as the roomiest candidate, so a hole in the list shows up as that
# type winning. Running the whole probe once per name costs more than it proves, so the rest of
# the list is checked by reading it, below.
bad_used=""
for bad in tmpfs overlay nfs zfs vfat; do
    reset
    set_memory 4096 0
    set_candidates "ext4 3000 /dev/sda1" "${bad} 90000 somedev"
    DD_FAKE=1
    # shellcheck disable=SC2034
    SCAP_SWAP_SIZE_MB=2000
    add_scap_swap > /dev/null 2>&1
    [ -e "${C2}/el_configurator_scap.swap" ] && bad_used="${bad_used} ${bad}"
done
if [ -z "${bad_used}" ]; then
    pass "none of tmpfs, overlay, nfs, zfs or vfat is ever used"
else
    fail "a filesystem that cannot hold a swap file was used" "${bad_used}"
fi

# And the rest of the list is still named. A type quietly dropped from it would only show up on the
# machine that has that filesystem, which is the worst place to find out.
denyline=$(grep -F "''|tmpfs|" "${SCRIPT}" | head -1)
if [ -z "${denyline}" ]; then
    fail "the list of filesystems that cannot hold a swap file is where these tests expect it"
else
    missing=""
    for bad in tmpfs ramfs devtmpfs overlay overlayfs squashfs iso9660 autofs nfs nfs4 cifs                smbfs smb3 fuse fuseblk zfs vfat exfat msdos; do
        case "${denyline}" in
            *"|${bad}|"*|*"|${bad})"*) ;;
            *) missing="${missing} ${bad}" ;;
        esac
    done
    if [ -z "${missing}" ]; then
        pass "and every type the script means to turn down is still named in the list"
    else
        fail "a type has gone missing from the list" "${missing}"
    fi
    # The same matching against a line that is deliberately missing one entry, or the loop above
    # would pass for free if its pattern were wrong
    probe_missing=""
    for bad in tmpfs zfs; do
        case "''|tmpfs|ramfs)" in
            *"|${bad}|"*|*"|${bad})"*) ;;
            *) probe_missing="${probe_missing} ${bad}" ;;
        esac
    done
    if [ "${probe_missing}" = " zfs" ]; then
        pass "and that check does notice one being dropped"
    else
        fail "and that check does notice one being dropped" "reported [${probe_missing}], wanted [ zfs]"
    fi

    # btrfs must not be in there: the script has its own handling for it, setting no copy on write
    # before writing, and denying the type outright would make that dead code
    case "${denyline}" in
        *"|btrfs|"*|*"|btrfs)"*) fail "btrfs is not turned down, it is handled" ;;
        *) pass "btrfs is not turned down, it is handled" ;;
    esac
fi

# The positive control for the loop above: an ordinary type in the same position is used, so the
# loop is proving the deny list rather than that the second candidate is never reachable
reset
set_memory 4096 0
set_candidates "ext4 3000 /dev/sda1" "xfs 90000 /dev/sdb1"
DD_FAKE=1
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=2000
add_scap_swap > /dev/null 2>&1
if [ -e "${C2}/el_configurator_scap.swap" ]; then
    pass "an ordinary filesystem in that same position is used"
else
    fail "an ordinary filesystem in that same position is used" "${LOGGED}"
fi

echo
echo "== a candidate that turns the file down falls through to the next =="

reset
set_memory 4096 0
set_candidates "ext4 3000 /dev/sda1" "ext4 9000 /dev/sdb1"
DD_FAKE=1
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=2000
# The roomiest one accepts the file and then refuses to swap it on, which no amount of measuring
# beforehand can predict. Btrfs on a snapshot subvolume does exactly this.
swapon_FAIL_GLOB="${C2}/*"
add_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ -e "${C1}/el_configurator_scap.swap" ]; then
    pass "the next roomiest is used when swapon refuses the first"
else
    fail "the next roomiest is used when swapon refuses the first" "rc=${rc} ${LOGGED}"
fi
if [ ! -e "${C2}/el_configurator_scap.swap" ]; then
    pass "and the file it left behind is cleaned up"
else
    fail "and the file it left behind is cleaned up"
fi
# A recoverable failure must not mark the whole post install bad, only the final give up may
if [ "${LOGGED_ERRORS}" -eq 0 ] && [ "${LOGGED_NOTICES}" -ge 1 ]; then
    pass "and it is a NOTICE, so POST_INSTALL_SCRIPT_GOOD survives a filesystem saying no"
else
    fail "a recoverable failure is a NOTICE" "errors=${LOGGED_ERRORS} notices=${LOGGED_NOTICES}"
fi

# When every candidate refuses, that is a real failure
reset
set_memory 4096 0
set_candidates "ext4 3000 /dev/sda1" "ext4 9000 /dev/sdb1"
DD_FAKE=1
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=2000
swapon_RC=1
add_scap_swap; rc=$?
if [ "${rc}" -ne 0 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "every candidate refusing is an ERROR"
else
    fail "every candidate refusing is an ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi
if [ ! -e "${C1}/el_configurator_scap.swap" ] && [ ! -e "${C2}/el_configurator_scap.swap" ]; then
    pass "and no half made swap file is left on any of them"
else
    fail "and no half made swap file is left on any of them"
fi

echo
echo "== the same filesystem is not measured twice =="

# /var and /var/tmp are usually one filesystem, and so are / and /home. Ranked twice, it would be
# beaten by itself, and the second copy is unreachable anyway.
reset
set_memory 4096 0
set_candidates "ext4 3000 /dev/sda1" "ext4 3000 /dev/sda1"
DD_FAKE=1
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=2000
add_scap_swap
if [ -e "${C1}/el_configurator_scap.swap" ] && [ ! -e "${C2}/el_configurator_scap.swap" ]; then
    pass "two candidates on one device are used once, the first one seen"
else
    fail "two candidates on one device are used once"
fi

echo
echo "== leftovers go before anything is measured =="

# A gigabyte of zeroes from an interrupted run makes its filesystem look fuller than it is, so a
# candidate could be passed over on the strength of the file this run is about to replace
# c2 has more room than c1, but only once its leftover is out of the way: measured with the
# leftover still there it looks like the smaller of the two, and c1 would win instead.
reset
set_memory 4096 0
set_candidates "ext4 3000 /dev/sda1" "ext4 4000 /dev/sdb1"
echo leftover > "${C2}/el_configurator_scap.swap"
LEFTOVER_COST=2000
DD_FAKE=1
# shellcheck disable=SC2034
SCAP_SWAP_SIZE_MB=2000
add_scap_swap; rc=$?
if grep -q "^swapoff ${C2}/el_configurator_scap.swap\$" "${CALLS}" 2>/dev/null; then
    pass "a leftover is swapped off before being removed, in case it is still on"
else
    fail "a leftover is swapped off before being removed" "$(cat "${CALLS}" 2>/dev/null)"
fi
if [ "${rc}" -eq 0 ] && [ -e "${C2}/el_configurator_scap.swap" ]; then
    pass "and its filesystem is measured with the leftover already gone"
else
    fail "and its filesystem is measured with the leftover already gone"          "rc=${rc}, the smaller candidate won because the leftover was still counted"
fi
if grep -q "count=2000 " "${CALLS}" 2>/dev/null; then
    pass "and it gets the full size rather than what was left around the leftover"
else
    fail "and it gets the full size" "$(cat "${CALLS}" 2>/dev/null)"
fi

echo
echo "== an explicit SCAP_SWAP_FILE pins the location =="

reset
set_memory 4096 0
mkdir -p "${C1}" "${C2}" "${C3}"
add_scap_swap; rc=$?
if [ "${rc}" -eq 0 ] && [ -e "${SWAPFILE}" ]; then
    pass "the configured path is used as given"
else
    fail "the configured path is used as given" "rc=${rc} ${LOGGED}"
fi
if [ ! -e "${C1}/el_configurator_scap.swap" ] && [ ! -e "${C2}/el_configurator_scap.swap" ] \
   && [ ! -e "${C3}/el_configurator_scap.swap" ]; then
    pass "and nothing is probed"
else
    fail "and nothing is probed"
fi

echo
echo "== the list the script probes is the one these tests rewrite =="

# Everything above runs against a rewritten candidate list. Without this the tests would keep
# passing while the script probed somewhere else entirely.
if grep -q 'candidates=(/var/tmp /var / /home /srv /opt)' "${SCRIPT}"; then
    pass "the probe order in the script is the literal these tests substitute"
else
    fail "the probe order in the script is the literal these tests substitute" \
         "$(grep -n 'candidates=(' "${SCRIPT}")"
fi

# /tmp is deliberately absent: it is tmpfs as often as not, and systemd-tmpfiles cleans what is
# left of it out from under long running processes
if printf '%s\n' "$(grep 'candidates=(' "${SCRIPT}")" | grep -qE '[( ]/tmp[ )]'; then
    fail "/tmp is not among the candidates" "$(grep -n 'candidates=(' "${SCRIPT}")"
else
    pass "/tmp is not among the candidates"
fi

# The check above must be able to see a /tmp that is really there, or it passes for free
if printf '%s\n' 'candidates=(/var/tmp /tmp /var)' | grep -qE '[( ]/tmp[ )]'; then
    pass "and that check would notice one being added"
else
    fail "and that check would notice one being added"
fi

if extract_fn remove_scap_swap | grep -q 'SCAP_SWAP_ACTIVE_FILE'; then
    pass "remove_scap_swap goes by the file that was made, not by the configured path"
else
    fail "remove_scap_swap goes by the file that was made"
fi

echo
echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
