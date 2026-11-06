#!/usr/bin/env bash

# Tests for the profile file support of el_configurator.sh: --profile-file, how a profile is read
# and checked, validate_value_options and sshd_check_keyword
#
# A profile replaces an edited copy of the script, so it carries the same weight: it decides how the
# machine is hardened. These tests pin down that it is read as data and never executed, that only
# the settings of the block at the top are accepted, that a file root does not own is refused, and
# that without a profile nothing changes.
#
# The helpers are extracted from el_configurator.sh rather than sourced, because the script is a
# single self-contained file that executes on source.
#
# This file sets the configuration globals the extracted functions read. The linter cannot see that
# code, so it reports them as unused, hence a file wide waiver.
# shellcheck disable=SC2034
#
# Usage: tests/test_profile_file.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

HELPERS=$(mktemp)
WORK=$(mktemp -d)
# The trust check refuses /tmp, which everyone may write to, so files that have to pass it live here
TRUSTED_WORK=$(mktemp -d "${HOME}/.el_configurator_test.XXXXXX") || exit 2
TRUSTED_WORK=$(readlink -f "${TRUSTED_WORK}")
chmod 0755 "${TRUSTED_WORK}"
trap 'rm -f "${HELPERS}"; rm -rf "${WORK}" "${TRUSTED_WORK}"' EXIT

extract_function() {
    local first last
    first=$(grep -n "^${1}() {" "${SCRIPT}" | head -n 1 | cut -d: -f1)
    if [ -z "${first}" ]; then
        echo "Cannot locate ${1}() in [${SCRIPT}]"
        exit 2
    fi
    last=$(awk -v s="${first}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
    sed -n "${first},${last}p" "${SCRIPT}" >> "${HELPERS}"
}

sed -n '/^PROFILE_SETTINGS=(/,/^)$/p' "${SCRIPT}" >> "${HELPERS}"
for fn in check_profile_file_trust parse_profile_value set_profile_setting parse_profile_text load_profile \
        validate_value_options sshd_check_keyword; do
    extract_function "${fn}"
done

LOG_FILE=/dev/null
LOG_TEXT="${WORK}/log"
QUIT_TEXT="${WORK}/quit"
POST_INSTALL_SCRIPT_GOOD=true
log() {
    printf '%s: %s\n' "${2:-INFO}" "${1}" >> "${LOG_TEXT}"
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}
# The real one exits, and so does this one: every case that can stop runs in a subshell, and the
# message is kept in a file for the parent to read
log_quit() {
    printf '%s\n' "${1}" > "${QUIT_TEXT}"
    log "${1}" "${2}"
    exit 1
}

# The tests run as an ordinary user, whose files root does not own. With FAKE_ROOT=true the owner
# that check_profile_file_trust reads becomes root, and everything else it checks stays real
FAKE_ROOT=false
# shellcheck disable=SC2329
stat() {
    if [ "${FAKE_ROOT}" = true ] && [ "${1}" = "-c" ] && [ "${2}" = '%u %a' ]; then
        command stat "$@" | sed 's/^[0-9][0-9]* /0 /'
    else
        command stat "$@"
    fi
}

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

# parse <profile text>: parses in a subshell, prints the settings named in SHOW afterwards
# Returns the subshell's status; the quit message, if any, is in QUIT_TEXT
SHOW=""
parse() {
    : > "${QUIT_TEXT}"
    : > "${LOG_TEXT}"
    (
        parse_profile_text "test.profile" "${1}"
        for name in ${SHOW}; do
            printf '%s=[%s]\n' "${name}" "${!name}"
        done
    )
}

# refused <label> <profile text> <part of the expected message>
refused() {
    local label="${1}" text="${2}" want="${3}" rc
    parse "${text}" > /dev/null
    rc=$?
    if [ "${rc}" -ne 0 ] && grep -qF -- "${want}" "${QUIT_TEXT}"; then
        pass "${label}"
    else
        fail "${label}" "rc=${rc}, wanted a stop saying [${want}], got [$(cat "${QUIT_TEXT}")]"
    fi
}

echo "Testing profile files in [${SCRIPT}]"
echo
echo "== PROFILE_SETTINGS matches the block at the top of the script =="

# Two lists that must not drift. A setting declared but unlisted cannot be set from a profile, and
# a listed name that is not a setting would let a profile set a variable the block never meant to
# expose
block_end=$(grep -n '^LOG_FILE=' "${SCRIPT}" | head -n 1 | cut -d: -f1)
declared=$(sed -n "1,${block_end}p" "${SCRIPT}" | grep -oE '^[A-Z_][A-Z0-9_]*=' | tr -d '=' \
    | grep -vx -e SCRIPT_BUILD -e LOG_FILE | sort -u)
listed=$(printf '%s\n' "${PROFILE_SETTINGS[@]}" | sort -u)
if [ "${declared}" = "${listed}" ]; then
    pass "every setting of the block is listed, and nothing else"
else
    fail "every setting of the block is listed, and nothing else" \
        "not listed: $(comm -23 <(echo "${declared}") <(echo "${listed}") | tr '\n' ' ')" \
        "not declared: $(comm -13 <(echo "${declared}") <(echo "${listed}") | tr '\n' ' ')"
fi
if [ "$(printf '%s\n' "${PROFILE_SETTINGS[@]}" | sort | uniq -d)" = "" ]; then
    pass "no setting is listed twice"
else
    fail "no setting is listed twice" "$(printf '%s\n' "${PROFILE_SETTINGS[@]}" | sort | uniq -d)"
fi

echo
echo "== a profile copied from the block gives the values of the block =="

# Everything from the first setting to the last, as an operator would copy it. The one line that
# derives a value from another one cannot be data, so it is left out, and load_profile covers it
block_text=$(sed -n '/^BRAND_NAME=/,/^CLEANUP_MODE=/p' "${SCRIPT}" | grep -v '^FAIL2BAN_IGNORE_IP_LIST=')
SHOW="$(printf '%s\n' "${PROFILE_SETTINGS[@]}" | grep -vx FAIL2BAN_IGNORE_IP_LIST | tr '\n' ' ')"
from_profile=$(parse "${block_text}")
rc=$?
# The block itself, run as bash, which is what the script does
from_bash=$(
    # shellcheck disable=SC1090
    source <(printf '%s\n' "${block_text}")
    for name in ${SHOW}; do
        printf '%s=[%s]\n' "${name}" "${!name}"
    done
)
if [ "${rc}" -eq 0 ] && [ -n "${from_profile}" ] && [ "${from_profile}" = "${from_bash}" ]; then
    pass "every value, the multi line ones included, is what bash makes of the block"
else
    fail "every value is what bash makes of the block" "rc=${rc} [$(cat "${QUIT_TEXT}")]" \
        "$(diff <(echo "${from_bash}") <(echo "${from_profile}") | head -n 20)"
fi

echo
echo "== values are read as bash would assign them =="

SHOW="BRAND_NAME ISSUE_MESSAGE_EXTRA SCAP_PROFILE NTP_SERVERS FIREWALL_OPEN_PORTS"
got=$(parse "    BRAND_NAME=\"My Brand\"   # indented, with a comment
ISSUE_MESSAGE_EXTRA='- Private \$ystem'
SCAP_PROFILE=false # off
NTP_SERVERS=
FIREWALL_OPEN_PORTS=51820/udp")
want="BRAND_NAME=[My Brand]
ISSUE_MESSAGE_EXTRA=[- Private \$ystem]
SCAP_PROFILE=[false]
NTP_SERVERS=[]
FIREWALL_OPEN_PORTS=[51820/udp]"
if [ "${got}" = "${want}" ]; then
    pass "double, single quoted and plain values, comments and indentation"
else
    fail "double, single quoted and plain values, comments and indentation" "got:" "${got}"
fi

SHOW="REMOTE_LOGIN_BANNER"
got=$(parse "REMOTE_LOGIN_BANNER=\$(cat << 'EOF'
  Indented \\ kept, \$HOME and \$(id) kept as text

EOF
)")
want="REMOTE_LOGIN_BANNER=[  Indented \\ kept, \$HOME and \$(id) kept as text]"
if [ "${got}" = "${want}" ]; then
    pass "a block keeps its lines as they are, and loses its trailing newlines like \$(...)"
else
    fail "a block keeps its lines as they are" "got:" "${got}"
fi

CANARY="${WORK}/canary"
SHOW="BRAND_NAME"
got=$(parse "BRAND_NAME='\$(touch ${CANARY})'")
if [ ! -e "${CANARY}" ] && [ "${got}" = "BRAND_NAME=[\$(touch ${CANARY})]" ]; then
    pass "a single quoted command substitution stays text and never runs"
else
    fail "a single quoted command substitution stays text and never runs" "got: ${got}"
fi

echo
echo "== what a profile may not hold =="

refused "a name outside the block" "PATH=/tmp" "PATH is not a setting"
refused "LOG_FILE, which the run needs before the profile" "LOG_FILE=/tmp/log" "LOG_FILE is not a setting"
refused "SCRIPT_BUILD" "SCRIPT_BUILD=1" "SCRIPT_BUILD is not a setting"
refused "a setting given twice" "BRAND_NAME=a
BRAND_NAME=b" "BRAND_NAME is set twice"
refused "a block and a line for the same setting" "MOTD_MSG=\$(cat << 'EOF'
x
EOF
)
MOTD_MSG=y" "MOTD_MSG is set twice"
# The profile lines are meant literally, hence the single quotes
# shellcheck disable=SC2016
refused "a double quoted expansion" 'BRAND_NAME="${HOME}"' "the value of BRAND_NAME must be"
refused "a command substitution" "BRAND_NAME=\$(touch ${CANARY})" "the value of BRAND_NAME must be"
# shellcheck disable=SC2016
refused "a backtick" 'BRAND_NAME=`id`' "the value of BRAND_NAME must be"
refused "an unquoted value with a space" 'BRAND_NAME=a b' "the value of BRAND_NAME must be"
refused "a command" "touch ${CANARY}" "neither a comment, a setting"
refused "export" "export BRAND_NAME=a" "neither a comment, a setting"
refused "a block with an unquoted delimiter, which bash would expand" "MOTD_MSG=\$(cat << EOF
x
EOF
)" "the value of MOTD_MSG must be"
refused "a block without its delimiter" "MOTD_MSG=\$(cat << 'EOF'
x" "no line 'EOF' ends MOTD_MSG"
refused "a block without its closing parenthesis" "MOTD_MSG=\$(cat << 'EOF'
x
EOF" "no line ) ends MOTD_MSG"
refused "a block followed by something else than )" "MOTD_MSG=\$(cat << 'EOF'
x
EOF
BRAND_NAME=a" "expected ) to end MOTD_MSG"
refused "a Windows line ending" $'BRAND_NAME=a\r' "Windows line ending"
if [ ! -e "${CANARY}" ]; then
    pass "none of these ran anything"
else
    fail "none of these ran anything" "${CANARY} exists"
fi

echo
echo "== which files are trusted =="

# trust <label> <expect 0 or 1> <path> <part of the expected message, for a refusal>
trust() {
    local label="${1}" want_rc="${2}" path="${3}" want="${4}" rc
    : > "${LOG_TEXT}"
    check_profile_file_trust "${path}"
    rc=$?
    if [ "${rc}" -eq "${want_rc}" ] && { [ -z "${want}" ] || grep -qF -- "${want}" "${LOG_TEXT}"; }; then
        pass "${label}"
    else
        fail "${label}" "rc=${rc}, log: $(cat "${LOG_TEXT}")"
    fi
}

PROFILE_FILE_MAX_SIZE=1048576
GOOD="${TRUSTED_WORK}/good.profile"
printf 'BRAND_NAME=Test\n' > "${GOOD}"
chmod 0644 "${GOOD}"

FAKE_ROOT=false
trust "a file owned by an ordinary user is refused" 1 "${GOOD}" "must belong to root"
FAKE_ROOT=true
trust "the same file owned by root, in directories only root writes, is accepted" 0 "${GOOD}" ""
trust "a relative path is refused" 1 "good.profile" "give an absolute path"
ln -s "${GOOD}" "${TRUSTED_WORK}/link.profile"
trust "a symlink is refused" 1 "${TRUSTED_WORK}/link.profile" "must not contain symlinks"
trust "a path with .. is refused" 1 "${TRUSTED_WORK}/../$(basename "${TRUSTED_WORK}")/good.profile" "must not contain symlinks"
trust "a missing file is refused" 1 "${TRUSTED_WORK}/missing.profile" ""
chmod 0666 "${GOOD}"
trust "a file others may write is refused" 1 "${GOOD}" "writable by root only"
chmod 0644 "${GOOD}"
chmod 0775 "${TRUSTED_WORK}"
trust "a directory above it others may write is refused" 1 "${GOOD}" "${TRUSTED_WORK} must belong to root"
chmod 0755 "${TRUSTED_WORK}"
mkdir -p "${WORK}/in_tmp"
printf 'BRAND_NAME=Test\n' > "${WORK}/in_tmp/x.profile"
trust "a file below /tmp is refused, since everyone may write there" 1 "${WORK}/in_tmp/x.profile" "writable by root only"

echo
echo "== load_profile =="

# load <path or empty>: runs load_profile in a subshell with that --profile-file, prints SHOW
load() {
    : > "${QUIT_TEXT}"
    : > "${LOG_TEXT}"
    (
        PROFILE_FILE="${1}"
        load_profile
        for name in ${SHOW}; do
            printf '%s=[%s]\n' "${name}" "${!name}"
        done
    )
}

BRAND_NAME=NetPerfect
SCAP_PROFILE=anssi_bp28_high
FIREWALL_WHITELIST_IP_LIST=""
FAIL2BAN_IGNORE_IP_LIST=""
SHOW="BRAND_NAME SCAP_PROFILE"
got=$(load "")
rc=$?
if [ "${rc}" -eq 0 ] && [ "${got}" = "BRAND_NAME=[NetPerfect]
SCAP_PROFILE=[anssi_bp28_high]" ] && [ ! -s "${LOG_TEXT}" ]; then
    pass "no --profile-file: the settings of the script, and nothing is read or logged"
else
    fail "no --profile-file: the settings of the script, and nothing is read or logged" "rc=${rc} got=${got}" "$(cat "${LOG_TEXT}")"
fi

printf 'BRAND_NAME=Given\n' > "${TRUSTED_WORK}/given.profile"
chmod 0644 "${TRUSTED_WORK}/given.profile"
got=$(load "${TRUSTED_WORK}/given.profile")
rc=$?
if [ "${rc}" -eq 0 ] && [ "${got}" = "BRAND_NAME=[Given]
SCAP_PROFILE=[anssi_bp28_high]" ] && grep -q "Loading profile given from ${TRUSTED_WORK}/given.profile (sha256 " "${LOG_TEXT}"; then
    pass "--profile-file overrides what it sets, the script's settings apply to the rest, and its hash is logged"
else
    fail "--profile-file overrides what it sets, the script's settings apply to the rest" "rc=${rc} got=${got}" "$(cat "${LOG_TEXT}")"
fi

FAKE_ROOT=false
got=$(load "${TRUSTED_WORK}/given.profile")
rc=$?
if [ "${rc}" -ne 0 ] && grep -q 'refused, nothing has been changed' "${QUIT_TEXT}"; then
    pass "a profile that fails the trust check stops the run, rather than being skipped"
else
    fail "a profile that fails the trust check stops the run" "rc=${rc} got=${got}"
fi
FAKE_ROOT=true

printf 'FIREWALL_WHITELIST_IP_LIST=192.0.2.0/24\n' > "${TRUSTED_WORK}/whitelist.profile"
chmod 0644 "${TRUSTED_WORK}/whitelist.profile"
SHOW="FIREWALL_WHITELIST_IP_LIST FAIL2BAN_IGNORE_IP_LIST"
got=$(load "${TRUSTED_WORK}/whitelist.profile")
if [ "${got}" = "FIREWALL_WHITELIST_IP_LIST=[192.0.2.0/24]
FAIL2BAN_IGNORE_IP_LIST=[192.0.2.0/24]" ]; then
    pass "FAIL2BAN_IGNORE_IP_LIST follows the whitelist, as in the block, when the profile leaves it out"
else
    fail "FAIL2BAN_IGNORE_IP_LIST follows the whitelist" "got: ${got}"
fi
printf 'FIREWALL_WHITELIST_IP_LIST=192.0.2.0/24\nFAIL2BAN_IGNORE_IP_LIST=10.99.0.1\n' > "${TRUSTED_WORK}/whitelist.profile"
got=$(load "${TRUSTED_WORK}/whitelist.profile")
if [ "${got}" = "FIREWALL_WHITELIST_IP_LIST=[192.0.2.0/24]
FAIL2BAN_IGNORE_IP_LIST=[10.99.0.1]" ]; then
    pass "a FAIL2BAN_IGNORE_IP_LIST the profile sets is kept"
else
    fail "a FAIL2BAN_IGNORE_IP_LIST the profile sets is kept" "got: ${got}"
fi

printf 'BRAND_NAME=a\0b\n' > "${TRUSTED_WORK}/nul.profile"
chmod 0644 "${TRUSTED_WORK}/nul.profile"
load "${TRUSTED_WORK}/nul.profile" > /dev/null
rc=$?
if [ "${rc}" -ne 0 ] && grep -q 'NUL bytes' "${QUIT_TEXT}"; then
    pass "a file with a NUL byte is refused"
else
    fail "a file with a NUL byte is refused" "rc=${rc} [$(cat "${QUIT_TEXT}")]"
fi

printf 'BRAND_NAME=a\n' > "${TRUSTED_WORK}/bad-name.profile"
chmod 0644 "${TRUSTED_WORK}/bad-name.profile"
load "${TRUSTED_WORK}/bad-name.profile" > /dev/null
rc=$?
if [ "${rc}" -ne 0 ] && grep -q 'its name must be' "${QUIT_TEXT}"; then
    pass "a file name that is not letters, digits or _ is refused"
else
    fail "a file name that is not letters, digits or _ is refused" "rc=${rc} [$(cat "${QUIT_TEXT}")]"
fi
FAKE_ROOT=false

echo
echo "== validate_value_options =="

# The defaults of the block, as the script would have them
defaults() {
    eval "$(sed -n '/^BRAND_NAME=/,/^CLEANUP_MODE=/p' "${SCRIPT}" | grep -E '^(SSHD_|FIREWALL_|FAIL2BAN_)[A-Z_]*=' | grep -v '^FAIL2BAN_IGNORE_IP_LIST=')"
}

# values <label> <expect 0 or 1> <NAME=value>...: sets the values over the defaults, then validates
values() {
    local label="${1}" want_rc="${2}" rc
    shift 2
    : > "${QUIT_TEXT}"
    (
        defaults
        for assignment in "$@"; do
            printf -v "${assignment%%=*}" '%s' "${assignment#*=}"
        done
        validate_value_options
    ) > /dev/null
    rc=$?
    if [ "${rc}" -eq "${want_rc}" ]; then
        pass "${label}"
    else
        fail "${label}" "rc=${rc} [$(cat "${QUIT_TEXT}")]"
    fi
}

values "the defaults of the block are valid" 0
values "the bastion design's values are valid" 0 \
    SSHD_PERSOURCE_PENALTY_EXEMPT_LIST=10.99.0.1 SSHD_MAX_STARTUPS=50:30:200 SSHD_MAX_AUTH_TRIES=6 SSHD_LOGIN_GRACE_TIME=1m30s \
    FIREWALL_SSH_INTERFACE=wg0 FIREWALL_SSH_INTERFACE_SOURCES=10.99.0.1 FIREWALL_OPEN_PORTS=51820/udp \
    FAIL2BAN_MAXRETRY=10 FAIL2BAN_FINDTIME=10m FAIL2BAN_BANTIME=1h
values "lists with several entries and CIDR, and a port range" 0 \
    SSHD_PERSOURCE_PENALTY_EXEMPT_LIST=10.99.0.1:192.0.2.0/24 FIREWALL_SSH_INTERFACE=wg0 \
    FIREWALL_SSH_INTERFACE_SOURCES=10.99.0.1:10.99.0.2 FIREWALL_OPEN_PORTS=51820/udp:60000-60010/udp
values "a bantime of -1, which bans for good" 0 FAIL2BAN_BANTIME=-1
values "a single MaxStartups number" 0 SSHD_MAX_STARTUPS=100
values "MaxAuthTries 0" 1 SSHD_MAX_AUTH_TRIES=0
values "MaxStartups with two fields" 1 SSHD_MAX_STARTUPS=10:30
values "a LoginGraceTime with a unit sshd does not know" 1 SSHD_LOGIN_GRACE_TIME=60x
values "an IPv6 address, which a colon separated list cannot hold" 1 SSHD_PERSOURCE_PENALTY_EXEMPT_LIST=fd00::1
values "a quote in a source, which would rewrite the rich rule" 1 \
    FIREWALL_SSH_INTERFACE=wg0 'FIREWALL_SSH_INTERFACE_SOURCES=10.99.0.1" accept rule family="ipv4'
values "sources without an interface" 1 FIREWALL_SSH_INTERFACE_SOURCES=10.99.0.1
values "an interface name with a space" 1 "FIREWALL_SSH_INTERFACE=wg 0"
values "an interface name longer than the kernel allows" 1 FIREWALL_SSH_INTERFACE=abcdefghijklmnop
values "a port without a protocol" 1 FIREWALL_OPEN_PORTS=51820
values "a port with an unknown protocol" 1 FIREWALL_OPEN_PORTS=51820/icmp
values "a maxretry that is not a number" 1 FAIL2BAN_MAXRETRY=three
values "a findtime of -1" 1 FAIL2BAN_FINDTIME=-1
values "an empty bantime" 1 FAIL2BAN_BANTIME=

: > "${QUIT_TEXT}"
( defaults; SSHD_MAX_AUTH_TRIES=x; FAIL2BAN_MAXRETRY=y; validate_value_options ) > /dev/null
if grep -q 'SSHD_MAX_AUTH_TRIES=\[x\]' "${QUIT_TEXT}" && grep -q 'FAIL2BAN_MAXRETRY=\[y\]' "${QUIT_TEXT}"; then
    pass "every bad value is reported at once"
else
    fail "every bad value is reported at once" "$(cat "${QUIT_TEXT}")"
fi

echo
echo "== sshd_check_keyword =="

# check_keyword <label> <expected status> <what the stub sshd prints>
check_keyword() {
    local label="${1}" want_rc="${2}" rc
    SSHD_OUTPUT="${3}"
    # Called by the extracted sshd_check_keyword, which the linter cannot see
    # shellcheck disable=SC2329
    sshd() { printf '%s\n' "${SSHD_OUTPUT}" >&2; return 1; }
    : > "${LOG_TEXT}"
    sshd_check_keyword PerSourcePenaltyExemptList 10.99.0.1
    rc=$?
    unset -f sshd
    if [ "${rc}" -eq "${want_rc}" ]; then
        pass "${label}"
    else
        fail "${label}" "rc=${rc}"
    fi
}

check_keyword "accepted: sshd goes on to look for host keys" 0 "sshd: no hostkeys available -- exiting."
check_keyword "accepted on Debian, where the privilege separation directory comes next" 0 "Missing privilege separation directory: /run/sshd"
check_keyword "an older sshd that does not know the keyword" 1 "command-line: line 0: Bad configuration option: PerSourcePenaltyExemptList"
check_keyword "an sshd built without it" 1 "command-line line 0: Unsupported option \"PerSourcePenaltyExemptList\""
check_keyword "a value sshd refuses" 2 "command-line line 0: Invalid PerSourcePenaltyExemptList address"

SSHD_BIN=$(command -v sshd || ls /usr/sbin/sshd 2>/dev/null)
if [ -n "${SSHD_BIN}" ]; then
    # shellcheck disable=SC2329
    sshd() { "${SSHD_BIN}" "$@"; }
    sshd_check_keyword NoSuchKeywordAtAll 1
    rc=$?
    if [ "${rc}" -eq 1 ]; then
        pass "the real sshd: an unknown keyword reads as unknown"
    else
        fail "the real sshd: an unknown keyword reads as unknown" "rc=${rc}"
    fi
    sshd_check_keyword MaxStartups 10:30:60
    rc=$?
    if [ "${rc}" -eq 0 ]; then
        pass "the real sshd: a known keyword reads as accepted, without host keys"
    else
        fail "the real sshd: a known keyword reads as accepted" "rc=${rc}"
    fi
    unset -f sshd
else
    echo "  skip no sshd here, the real sshd is not tried"
fi

echo
echo "== the command line =="

# These stop before the first log line, so they are safe to run as anyone, anywhere
out=$(bash "${SCRIPT}" --help 2>&1)
rc=$?
if [ "${rc}" -eq 0 ] && [[ "${out}" == *"--profile-file=PATH"* ]] && [[ "${out}" != *"INFO:"* ]]; then
    pass "--help prints the usage and logs nothing"
else
    fail "--help prints the usage and logs nothing" "rc=${rc}" "${out}"
fi
out=$(bash "${SCRIPT}" --profile-file 2>&1)
rc=$?
if [ "${rc}" -eq 2 ] && [[ "${out}" == *"unknown argument [--profile-file]"* ]] && [[ "${out}" != *"INFO:"* ]]; then
    pass "--profile-file without =PATH is refused before anything is logged"
else
    fail "--profile-file without =PATH is refused before anything is logged" "rc=${rc}" "${out}"
fi
out=$(bash "${SCRIPT}" --profile-file=/a --profile-file=/b 2>&1)
rc=$?
if [ "${rc}" -eq 2 ] && [[ "${out}" == *"given twice"* ]]; then
    pass "--profile-file given twice is refused"
else
    fail "--profile-file given twice is refused" "rc=${rc}" "${out}"
fi

echo
echo "== el_configurator.sh wiring =="

entry=$(sed -n '/^## Script entry point/,$p' "${SCRIPT}" | grep -nE '^(load_profile|get_kernel_arguments|validate_boolean_options|validate_value_options|get_el_version)$' | cut -d: -f2 | tr '\n' ' ')
if [ "${entry}" = "load_profile get_kernel_arguments validate_boolean_options validate_value_options get_el_version " ]; then
    pass "the profile is read first, kernel arguments override it, then everything is validated"
else
    fail "the profile is read first, kernel arguments override it, then everything is validated" "order: ${entry}"
fi
first_log=$(grep -n '^log "Starting EL configurator' "${SCRIPT}" | cut -d: -f1)
parse_call=$(grep -n '^parse_arguments "\$@"$' "${SCRIPT}" | cut -d: -f1)
if [ -n "${parse_call}" ] && [ -n "${first_log}" ] && [ "${parse_call}" -lt "${first_log}" ]; then
    pass "the command line is read before the first log line"
else
    fail "the command line is read before the first log line" "parse_arguments at ${parse_call:-?}, first log at ${first_log:-?}"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
