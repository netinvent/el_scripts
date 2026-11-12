#!/usr/bin/env bash

# Tests for the firewalld narrowing in el_configurator.sh
#
# The kickstart opens ssh to everyone, and this script narrows it to a whitelist: bind the
# whitelisted sources to a permissive zone, then take ssh off the default zone. Only the second
# half used to be unconditional, so a whitelist that failed to bind produced a machine that had
# closed ssh to the world and opened it to nobody, discovered on first boot.
#
# The chosen behaviour is that the narrowing always happens, because a hardening script that
# silently leaves ssh open is worse, and that a whitelist which did not fully bind is reported
# loudly for the operator to deal with.
#
# This file sets the configuration globals the extracted function reads. The linter cannot see that
# code, so it reports them as unused, hence a file wide waiver.
# shellcheck disable=SC2034
#
# Usage: tests/test_configure_firewalld.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

# configure_firewalld and the two helpers right above it, which open ports and set up the ssh
# interface. start is the first helper, end the end of configure_firewalld
start=$(grep -n '^configure_firewalld_open_ports() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
main_start=$(grep -n '^configure_firewalld() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${start}" ] || [ -z "${main_start}" ] || ! grep -q '^configure_firewalld_ssh_interface() {' "${SCRIPT}"; then
    echo "Cannot locate configure_firewalld() and its helpers in [${SCRIPT}]"
    exit 2
fi
end=$(awk -v s="${main_start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")

HELPERS=$(mktemp)
WORK=$(mktemp -d)
trap 'rm -f "${HELPERS}"; rm -rf "${WORK}"' EXIT
sed -n "${start},${end}p" "${SCRIPT}" > "${HELPERS}"

# The function reads its options through is_enabled, so that helper has to come along too. Without
# it the call is an unknown command, exits 127, and every option silently reads as off, which looks
# exactly like a configuration failure rather than a missing helper.
ie_start=$(grep -n '^is_enabled() {' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${ie_start}" ]; then
    echo "Cannot locate is_enabled() in [${SCRIPT}]"
    exit 2
fi
ie_end=$(awk -v s="${ie_start}" 'NR>=s && /^\}$/ {print NR; exit}' "${SCRIPT}")
sed -n "${ie_start},${ie_end}p" "${SCRIPT}" >> "${HELPERS}"

LOG_FILE=/dev/null
LOGGED_ERRORS=0
POST_INSTALL_SCRIPT_GOOD=true
log() {
    if [ "${2}" = "ERROR" ]; then
        LOGGED_ERRORS=$((LOGGED_ERRORS + 1))
        POST_INSTALL_SCRIPT_GOOD=false
        printf '%s\n' "${1}" >> "${ERRORS_TEXT}"
    fi
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

CALLS="${WORK}/calls"
BOUND="${WORK}/bound"
ERRORS_TEXT="${WORK}/errors"
# Space separated list of sources whose --add-source should not take effect
FW_REJECT=""

# Stand-in for firewall-offline-cmd, keeping just enough state to answer --query-source.
# It reproduces the behaviour that matters here: adding a source that is already bound fails, while
# querying it succeeds. Counting exit codes would call that a failure, which is why the real code
# asks for the resulting state instead.
#
# Ports, services, rich rules and interfaces are kept in ITEMS as zone|kind|value, the default zone
# being public, and zones made with --new-zone in ZONES. An add into a zone that does not exist fails,
# as does an add or a remove whose value contains FW_REJECT_ITEM. Removing what is not there fails.
# The default zone's target is kept in TARGET, default when empty; FW_REJECT_TARGET makes setting it
# fail.
ITEMS="${WORK}/items"
ZONES="${WORK}/zones"
TARGET="${WORK}/target"
FW_REJECT_ITEM=""
FW_REJECT_TARGET=""
# shellcheck disable=SC2329
firewall-offline-cmd() {
    local arg zone="" op="" val="" kind=""
    printf '%s\n' "$*" >> "${CALLS}"
    for arg in "$@"; do
        case "${arg}" in
            --zone=*)          zone="${arg#--zone=}" ;;
            --add-source=*)    op=add;   val="${arg#--add-source=}" ;;
            --query-source=*)  op=query; val="${arg#--query-source=}" ;;
            --get-zones)       op=get_zones ;;
            --new-zone=*)      op=new_zone; val="${arg#--new-zone=}" ;;
            --delete-zone=*)   op=delete_zone; val="${arg#--delete-zone=}" ;;
            --add-port=*|--add-service=*|--add-rich-rule=*|--change-interface=*)
                op=add_item; kind="${arg%%=*}"; kind="${kind#--add-}"; kind="${kind#--change-}"; val="${arg#*=}" ;;
            --query-port=*|--query-service=*|--query-rich-rule=*|--query-interface=*)
                op=query_item; kind="${arg%%=*}"; kind="${kind#--query-}"; val="${arg#*=}" ;;
            --remove-rich-rule=*)
                op=remove_item; kind=rich-rule; val="${arg#*=}" ;;
            --set-target=*)    op=set_target; val="${arg#--set-target=}" ;;
            --get-target)      op=get_target ;;
        esac
    done
    case "${op}" in
        set_target)
            [ -n "${FW_REJECT_TARGET}" ] && return 1
            printf '%s\n' "${val}" > "${TARGET}"
            return 0
            ;;
        get_target)
            if [ -s "${TARGET}" ]; then cat "${TARGET}"; else echo default; fi
            return 0
            ;;
        remove_item)
            grep -qxF "${zone:-public}|${kind}|${val}" "${ITEMS}" 2>/dev/null || return 1     # NOT_ENABLED
            if [ -n "${FW_REJECT_ITEM}" ] && [[ "${val}" == *"${FW_REJECT_ITEM}"* ]]; then
                return 1
            fi
            grep -vxF "${zone:-public}|${kind}|${val}" "${ITEMS}" > "${ITEMS}.new"; mv "${ITEMS}.new" "${ITEMS}"
            return 0
            ;;
        get_zones)
            printf 'block dmz drop external home internal public trusted work'
            [ -s "${ZONES}" ] && printf ' %s' "$(tr '\n' ' ' < "${ZONES}")"
            echo
            return 0
            ;;
        new_zone)
            grep -qxF "${val}" "${ZONES}" 2>/dev/null && return 1     # NAME_CONFLICT
            printf '%s\n' "${val}" >> "${ZONES}"
            return 0
            ;;
        delete_zone)
            grep -qxF "${val}" "${ZONES}" 2>/dev/null || return 1     # INVALID_ZONE
            grep -vxF "${val}" "${ZONES}" > "${ZONES}.new"; mv "${ZONES}.new" "${ZONES}"
            grep -v "^${val}|" "${ITEMS}" > "${ITEMS}.new" 2>/dev/null; mv "${ITEMS}.new" "${ITEMS}"
            return 0
            ;;
        add_item)
            case "${zone:-public}" in
                block|dmz|drop|external|home|internal|public|trusted|work) ;;
                *) grep -qxF "${zone}" "${ZONES}" 2>/dev/null || return 1 ;;
            esac
            if [ -n "${FW_REJECT_ITEM}" ] && [[ "${val}" == *"${FW_REJECT_ITEM}"* ]]; then
                return 1
            fi
            grep -qxF "${zone:-public}|${kind}|${val}" "${ITEMS}" 2>/dev/null && return 1    # ALREADY_ENABLED
            printf '%s|%s|%s\n' "${zone:-public}" "${kind}" "${val}" >> "${ITEMS}"
            return 0
            ;;
        query_item)
            grep -qxF "${zone:-public}|${kind}|${val}" "${ITEMS}" 2>/dev/null
            return $?
            ;;
    esac
    case "${op}" in
        add)
            case " ${FW_REJECT} " in *" ${val} "*) return 1 ;; esac
            if grep -qxF "${zone} ${val}" "${BOUND}" 2>/dev/null; then
                return 1        # ALREADY_ENABLED
            fi
            printf '%s %s\n' "${zone}" "${val}" >> "${BOUND}"
            return 0
            ;;
        query)
            grep -qxF "${zone} ${val}" "${BOUND}" 2>/dev/null
            ;;
        *)
            return 0
            ;;
    esac
}

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

run_case() {
    : > "${CALLS}"
    : > "${ERRORS_TEXT}"
    if [ "${1}" != keepstate ]; then
        : > "${BOUND}"
        : > "${ITEMS}"
        : > "${ZONES}"
        : > "${TARGET}"
    fi
    LOGGED_ERRORS=0
    configure_firewalld > /dev/null 2>&1
    return $?
}

ssh_removed() { grep -qx -- '--remove-service=ssh' "${CALLS}"; }

echo "Testing configure_firewalld from [${SCRIPT}] lines ${start}-${end}"
echo
echo "== the happy path =="

FIREWALL_WHITELIST_IP_LIST="192.168.200.0/24:10.0.0.1"
FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=true
NODE_EXPORTER_USE_IP_WHITELISTS=true
FW_REJECT=""
run_case
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "every source bound: returns 0 and logs no ERROR"
else
    fail "every source bound: returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi
if [ "$(grep -c -- '--zone=trusted --add-source=' "${CALLS}")" -eq 2 ]; then
    pass "allow all ports mode binds the sources to the trusted zone"
else
    fail "allow all ports mode binds the sources to the trusted zone" "$(cat "${CALLS}")"
fi
if ssh_removed; then
    pass "ssh is removed from the default zone"
else
    fail "ssh is removed from the default zone" "$(cat "${CALLS}")"
fi

FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=false
run_case
if [ "$(grep -c -- '--zone=dmz --add-source=' "${CALLS}")" -eq 2 ] && grep -q -- '--zone=dmz --add-port=9100/tcp' "${CALLS}"; then
    pass "ssh only mode uses the dmz zone and opens the node exporter port"
else
    fail "ssh only mode uses the dmz zone and opens the node exporter port" "$(cat "${CALLS}")"
fi

echo
echo "== the narrowing happens even when the whitelist did not bind =="

FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=true
FW_REJECT="192.168.200.0/24 10.0.0.1"
run_case
rc=$?
if ssh_removed; then
    pass "no source bound: ssh is still removed, the machine is not left open"
else
    fail "no source bound: ssh is still removed" "$(cat "${CALLS}")"
fi
if [ "${rc}" -eq 1 ]; then
    pass "no source bound: returns 1"
else
    fail "no source bound: returns 1" "returned ${rc}"
fi
if [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "no source bound: logs an ERROR, so the banner and the metric go red"
else
    fail "no source bound: logs an ERROR"
fi
if grep -q 'console access' "${ERRORS_TEXT}" && grep -q '192.168.200.0/24' "${ERRORS_TEXT}"; then
    pass "no source bound: the ERROR says console access is needed and names the addresses"
else
    fail "no source bound: the ERROR is specific" "$(cat "${ERRORS_TEXT}")"
fi

echo
echo "== a partial failure is reported too =="

FW_REJECT="10.0.0.1"
run_case
rc=$?
if [ "${rc}" -eq 1 ] && [ "${LOGGED_ERRORS}" -ge 1 ]; then
    pass "one of two bound: returns 1 and logs an ERROR"
else
    fail "one of two bound: returns 1 and logs an ERROR" "rc=${rc} errors=${LOGGED_ERRORS}"
fi
if grep -q '10.0.0.1' "${ERRORS_TEXT}" && ! grep -q 'Unbound:.*192.168.200.0/24' "${ERRORS_TEXT}"; then
    pass "the ERROR names only the address that failed"
else
    fail "the ERROR names only the address that failed" "$(cat "${ERRORS_TEXT}")"
fi
if ssh_removed; then
    pass "one of two bound: ssh is still removed"
else
    fail "one of two bound: ssh is still removed"
fi

echo
echo "== re-running does not invent a failure =="

# firewalld returns ALREADY_ENABLED, a non zero exit, for a source that is correctly bound. Counting
# exit codes would report every second run as broken.
FW_REJECT=""
run_case
run_case keepstate
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "a second run over an already bound whitelist is clean"
else
    fail "a second run over an already bound whitelist is clean" "rc=${rc} errors=${LOGGED_ERRORS}" "$(cat "${ERRORS_TEXT}")"
fi

echo
echo "== no whitelist means no narrowing =="

FIREWALL_WHITELIST_IP_LIST=""
run_case
rc=$?
if [ "${rc}" -eq 0 ] && ! ssh_removed && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "with no whitelist, ssh is left alone and nothing is reported"
else
    fail "with no whitelist, ssh is left alone" "rc=${rc} errors=${LOGGED_ERRORS}" "$(cat "${CALLS}")"
fi

has_item() { grep -qxF "${1}" "${ITEMS}"; }
SSH_RULE='el-ssh|rich-rule|rule family="ipv4" source address="10.99.0.1" service name="ssh" accept'

echo
echo "== an ssh interface, a whitelist and open ports =="

FIREWALL_WHITELIST_IP_LIST="192.0.2.0/24"
FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=false
NODE_EXPORTER_USE_IP_WHITELISTS=false
FIREWALL_SSH_INTERFACE=wg0
FIREWALL_SSH_INTERFACE_SOURCES="10.99.0.1"
FIREWALL_OPEN_PORTS="51820/udp"
FW_REJECT=""
FW_REJECT_ITEM=""
run_case
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "all three: returns 0 and logs no ERROR"
else
    fail "all three: returns 0 and logs no ERROR" "rc=${rc} errors=${LOGGED_ERRORS}" "$(cat "${ERRORS_TEXT}")"
fi
if has_item 'el-ssh|interface|wg0' && has_item "${SSH_RULE}" && ! has_item 'el-ssh|service|ssh'; then
    pass "the interface gets its own zone, with ssh from its source only"
else
    fail "the interface gets its own zone, with ssh from its source only" "$(cat "${ITEMS}")"
fi
if ! grep -q -- '--add-source=10.99.0.1' "${CALLS}"; then
    pass "the interface's source is not a zone source, which would let it in on every interface"
else
    fail "the interface's source is not a zone source" "$(cat "${CALLS}")"
fi
if has_item 'public|port|51820/udp'; then
    pass "the open port is in the default zone"
else
    fail "the open port is in the default zone" "$(cat "${ITEMS}")"
fi
if ssh_removed && [ "$(grep -c -- '--zone=dmz --add-source=192.0.2.0/24' "${CALLS}")" -eq 1 ]; then
    pass "the whitelist still narrows the default zone as before"
else
    fail "the whitelist still narrows the default zone as before" "$(cat "${CALLS}")"
fi

run_case keepstate
rc=$?
if [ "${rc}" -eq 0 ] && [ "${LOGGED_ERRORS}" -eq 0 ] && grep -qx -- '--delete-zone=el-ssh' "${CALLS}" \
        && [ "$(grep -cxF "${SSH_RULE}" "${ITEMS}")" -eq 1 ]; then
    pass "a second run rebuilds the zone, cleanly"
else
    fail "a second run rebuilds the zone, cleanly" "rc=${rc} errors=${LOGGED_ERRORS}" "$(cat "${ERRORS_TEXT}")" "$(cat "${ITEMS}")"
fi

FIREWALL_SSH_INTERFACE_SOURCES=""
run_case
if has_item 'el-ssh|service|ssh' && ! grep -q 'rich-rule' "${ITEMS}"; then
    pass "without sources, the zone allows ssh from anyone on the interface"
else
    fail "without sources, the zone allows ssh from anyone on the interface" "$(cat "${ITEMS}")"
fi

echo
echo "== an ssh interface alone narrows the default zone too =="

FIREWALL_WHITELIST_IP_LIST=""
FIREWALL_SSH_INTERFACE_SOURCES="10.99.0.1"
FIREWALL_OPEN_PORTS=""
run_case
rc=$?
if [ "${rc}" -eq 0 ] && ssh_removed && has_item "${SSH_RULE}" && [ "${LOGGED_ERRORS}" -eq 0 ]; then
    pass "no whitelist, an interface: ssh leaves the default zone, the interface keeps it"
else
    fail "no whitelist, an interface: ssh leaves the default zone" "rc=${rc} errors=${LOGGED_ERRORS}" "$(cat "${CALLS}")"
fi

FW_REJECT_ITEM="10.99.0.1"
run_case
rc=$?
if [ "${rc}" -eq 1 ] && ssh_removed && grep -q 'source 10.99.0.1' "${ERRORS_TEXT}"; then
    pass "a rule that did not land: still narrowed, returns 1, and the ERROR names the source"
else
    fail "a rule that did not land: still narrowed, returns 1, and the ERROR names the source" "rc=${rc}" "$(cat "${ERRORS_TEXT}")"
fi
FW_REJECT_ITEM=""

echo
echo "== open ports alone change nothing else =="

FIREWALL_SSH_INTERFACE=""
FIREWALL_SSH_INTERFACE_SOURCES=""
FIREWALL_OPEN_PORTS="51820/udp:60000-60010/udp"
run_case
rc=$?
if [ "${rc}" -eq 0 ] && has_item 'public|port|51820/udp' && has_item 'public|port|60000-60010/udp' && ! ssh_removed; then
    pass "ports open, and with no whitelist and no interface ssh is left alone"
else
    fail "ports open, and ssh is left alone" "rc=${rc}" "$(cat "${CALLS}")"
fi

FW_REJECT_ITEM="60000"
run_case
rc=$?
if [ "${rc}" -eq 1 ] && grep -q '60000-60010/udp' "${ERRORS_TEXT}" && has_item 'public|port|51820/udp'; then
    pass "a port that did not open: returns 1 and the ERROR names it"
else
    fail "a port that did not open: returns 1 and the ERROR names it" "rc=${rc}" "$(cat "${ERRORS_TEXT}")"
fi
FW_REJECT_ITEM=""
FIREWALL_OPEN_PORTS=""

echo
echo "== the default zone's target =="

ND_RULES=(
    'public|rich-rule|rule family="ipv6" icmp-type name="neighbour-solicitation" accept'
    'public|rich-rule|rule family="ipv6" icmp-type name="neighbour-advertisement" accept'
    'public|rich-rule|rule family="ipv6" icmp-type name="router-advertisement" accept'
    'public|rich-rule|rule family="ipv6" source address="fe80::/10" icmp-type name="mld-listener-query" accept'
)
PING_RULE='public|rich-rule|rule icmp-type name="echo-request" accept'
has_nd_rules() { local r; for r in "${ND_RULES[@]}"; do has_item "${r}" || return 1; done; return 0; }
has_no_icmp_rules() { ! grep -q 'icmp-type' "${ITEMS}"; }
target_is() { [ "$(cat "${TARGET}" 2>/dev/null)" = "${1}" ]; }

FIREWALL_DEFAULT_ZONE_TARGET=""
FIREWALL_DEFAULT_ZONE_ALLOW_PING=false
run_case
if ! grep -q -- '--set-target\|--get-target\|rich-rule' "${CALLS}"; then
    pass "left empty, the target and the ICMP rules are not touched"
else
    fail "left empty, the target and the ICMP rules are not touched" "$(cat "${CALLS}")"
fi

FIREWALL_DEFAULT_ZONE_TARGET=DROP
run_case
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && target_is DROP && has_nd_rules && ! has_item "${PING_RULE}"; then
    pass "DROP: the target is set, IPv6 neighbour discovery stays allowed, ping does not"
else
    fail "DROP: the target is set, IPv6 neighbour discovery stays allowed, ping does not" "rc=${rc}" "$(cat "${ITEMS}")" "$(cat "${ERRORS_TEXT}")"
fi

FIREWALL_DEFAULT_ZONE_ALLOW_PING=true
run_case keepstate
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && target_is DROP && has_nd_rules && has_item "${PING_RULE}"; then
    pass "DROP with FIREWALL_DEFAULT_ZONE_ALLOW_PING on a rerun: ping is allowed as well"
else
    fail "DROP with FIREWALL_DEFAULT_ZONE_ALLOW_PING on a rerun: ping is allowed as well" "rc=${rc}" "$(cat "${ITEMS}")" "$(cat "${ERRORS_TEXT}")"
fi

FIREWALL_DEFAULT_ZONE_ALLOW_PING=false
run_case keepstate
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && has_nd_rules && ! has_item "${PING_RULE}"; then
    pass "turning FIREWALL_DEFAULT_ZONE_ALLOW_PING off again takes the ping rule away"
else
    fail "turning FIREWALL_DEFAULT_ZONE_ALLOW_PING off again takes the ping rule away" "rc=${rc}" "$(cat "${ITEMS}")" "$(cat "${ERRORS_TEXT}")"
fi

FIREWALL_DEFAULT_ZONE_TARGET=default
FIREWALL_DEFAULT_ZONE_ALLOW_PING=true
run_case keepstate
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && target_is default && has_no_icmp_rules; then
    pass "default puts firewalld's own target back and takes every ICMP rule away, ping's included"
else
    fail "default puts firewalld's own target back and takes every ICMP rule away, ping's included" "rc=${rc}" "$(cat "${ITEMS}")" "$(cat "${ERRORS_TEXT}")"
fi

FIREWALL_DEFAULT_ZONE_TARGET=REJECT
FIREWALL_DEFAULT_ZONE_ALLOW_PING=false
run_case
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && target_is '%%REJECT%%' && has_nd_rules && ! has_item "${PING_RULE}"; then
    pass "REJECT: set under the name firewalld stores, %%REJECT%%, with the ICMPv6 rules DROP gets, and no ping"
else
    fail "REJECT: set under the name firewalld stores, %%REJECT%%, with the ICMPv6 rules DROP gets, and no ping" "rc=${rc}" "$(cat "${TARGET}")" "$(cat "${ITEMS}")" "$(cat "${ERRORS_TEXT}")"
fi

FIREWALL_DEFAULT_ZONE_TARGET=DROP
FIREWALL_DEFAULT_ZONE_ALLOW_PING=true
run_case keepstate
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && target_is DROP && has_nd_rules && has_item "${PING_RULE}"; then
    pass "from REJECT to DROP with ping allowed on a rerun"
else
    fail "from REJECT to DROP with ping allowed on a rerun" "rc=${rc}" "$(cat "${TARGET}")" "$(cat "${ITEMS}")" "$(cat "${ERRORS_TEXT}")"
fi
FIREWALL_DEFAULT_ZONE_ALLOW_PING=false

FIREWALL_DEFAULT_ZONE_TARGET=DROP
FW_REJECT_TARGET=yes
run_case
rc=$?
if [ "${rc}" -eq 1 ] && grep -q 'target DROP not set' "${ERRORS_TEXT}"; then
    pass "a target that did not take: returns 1 and the ERROR says so"
else
    fail "a target that did not take: returns 1 and the ERROR says so" "rc=${rc}" "$(cat "${ERRORS_TEXT}")"
fi
FW_REJECT_TARGET=""

FIREWALL_DEFAULT_ZONE_ALLOW_PING=true
run_case
FIREWALL_DEFAULT_ZONE_ALLOW_PING=false
FW_REJECT_ITEM="echo-request"
run_case keepstate
rc=$?
if [ "${rc}" -eq 1 ] && grep -q 'left over rule icmp-type name="echo-request" accept' "${ERRORS_TEXT}"; then
    pass "a ping rule that would not go: returns 1 and the ERROR names it"
else
    fail "a ping rule that would not go: returns 1 and the ERROR names it" "rc=${rc}" "$(cat "${ERRORS_TEXT}")"
fi
FW_REJECT_ITEM=""

FIREWALL_WHITELIST_IP_LIST="192.0.2.0/24"
FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=false
run_case
rc=$?
if [ "${rc}" -eq 0 ] && target_is DROP && grep -qxF 'dmz 192.0.2.0/24' "${BOUND}" && ssh_removed; then
    pass "DROP together with a whitelist: the narrowing happens as before"
else
    fail "DROP together with a whitelist: the narrowing happens as before" "rc=${rc}" "$(cat "${CALLS}")"
fi
FIREWALL_WHITELIST_IP_LIST=""
FIREWALL_DEFAULT_ZONE_TARGET=""

echo
echo "== the default zone's target, against the real firewall-offline-cmd =="

# The stand-in above cannot tell whether firewalld takes these target names and rich rules, nor
# whether a rule queries back in the form it was added. In a mount namespace of an unprivileged user
# namespace, a scratch /etc/firewalld lets the real offline client run without touching this
# machine's configuration. Machines without firewalld, and kernels or runners that forbid this, skip
# the section
if command -v firewall-offline-cmd > /dev/null 2>&1 && [ -d /etc/firewalld ] && command -v unshare > /dev/null 2>&1 \
        && unshare -rm sh -c 'mount -t tmpfs none /etc/firewalld' > /dev/null 2>&1; then
    real=$(unshare -rm bash -s "${HELPERS}" << 'NS' 2>&1
mount -t tmpfs none /etc/firewalld || exit 1
LOG_FILE=/dev/null
log() { [ "${2}" = "ERROR" ] && echo "ERROR: ${1}"; return 0; }
# shellcheck disable=SC1090
source "${1}"
step() {
    FIREWALL_DEFAULT_ZONE_TARGET="${1}"
    FIREWALL_DEFAULT_ZONE_ALLOW_PING="${2}"
    configure_firewalld_default_zone_target
    echo "== ${1} ping=${2} rc=$? target=$(firewall-offline-cmd --get-target 2> /dev/null)"
    firewall-offline-cmd --list-rich-rules 2> /dev/null | sort
}
step DROP false
step REJECT true
step DROP false
step default false
NS
)
    # The rules of a step, as firewalld lists them
    rules_of() { printf '%s\n' "${real}" | sed -n "/^== ${1}\$/,/^==/p" | grep '^rule '; }
    expected_nd=$(printf '%s\n' \
        'rule family="ipv6" icmp-type name="neighbour-advertisement" accept' \
        'rule family="ipv6" icmp-type name="neighbour-solicitation" accept' \
        'rule family="ipv6" icmp-type name="router-advertisement" accept' \
        'rule family="ipv6" source address="fe80::/10" icmp-type name="mld-listener-query" accept' | sort)
    if printf '%s\n' "${real}" | grep -qxF '== DROP ping=false rc=0 target=DROP' \
            && [ "$(rules_of 'DROP ping=false rc=0 target=DROP' | head -n 4)" = "${expected_nd}" ] \
            && ! printf '%s\n' "${real}" | grep -q '^ERROR'; then
        pass "DROP: firewalld takes the target, and lists the ICMPv6 rules exactly as the script queries them"
    else
        fail "DROP: firewalld takes the target, and lists the ICMPv6 rules exactly as the script queries them" "${real}"
    fi
    if printf '%s\n' "${real}" | grep -qxF '== REJECT ping=true rc=0 target=%%REJECT%%' \
            && printf '%s\n' "${real}" | sed -n '/^== REJECT/,/^== DROP/p' | grep -qxF 'rule icmp-type name="echo-request" accept'; then
        pass "REJECT with ping allowed: firewalld takes %%REJECT%%, and the ping rule"
    else
        fail "REJECT with ping allowed: firewalld takes %%REJECT%%, and the ping rule" "${real}"
    fi
    if [ "$(printf '%s\n' "${real}" | grep -c '^== DROP ping=false rc=0 target=DROP$')" -eq 2 ] \
            && ! printf '%s\n' "${real}" | sed -n '/^== REJECT/,$p' | sed -n '/^== DROP/,/^== default/p' | grep -q 'echo-request'; then
        pass "back to DROP without ping: firewalld lets the ping rule go"
    else
        fail "back to DROP without ping: firewalld lets the ping rule go" "${real}"
    fi
    if printf '%s\n' "${real}" | grep -qxF '== default ping=false rc=0 target=default' \
            && ! printf '%s\n' "${real}" | sed -n '/^== default/,$p' | grep -q '^rule '; then
        pass "default: firewalld's own target is back, with no rule left"
    else
        fail "default: firewalld's own target is back, with no rule left" "${real}"
    fi
else
    echo "  skip no firewall-offline-cmd, or no unprivileged mount namespace, on this machine"
fi

echo
echo "== applying the configuration =="

# firewall-offline-cmd only writes the configuration, so a firewalld that is already running, as on a
# rerun on an installed system, keeps its old rules unless it reloads. One that is not running, as
# in the kickstart %post chroot, is started instead. This runs the script's own firewall block, from
# its "if is_enabled" line to the matching "fi", with configure_firewalld and the commands stubbed
# shellcheck disable=SC2016
fw_block_start=$(grep -nxF 'if is_enabled "${CONFIGURE_FIREWALL}"; then' "${SCRIPT}" | head -n 1 | cut -d: -f1)
if [ -z "${fw_block_start}" ]; then
    echo "Cannot locate the CONFIGURE_FIREWALL block in [${SCRIPT}]"
    exit 2
fi
fw_block_end=$(awk -v s="${fw_block_start}" 'NR>s && /^fi$/ {print NR; exit}' "${SCRIPT}")
FW_BLOCK="${WORK}/fw_block"
APPLY_CALLS="${WORK}/apply_calls"
sed -n "${fw_block_start},${fw_block_end}p" "${SCRIPT}" > "${FW_BLOCK}"

# FW_STATE_RC is what firewall-cmd --state returns: 0 when firewalld runs, 252 (NOT_RUNNING) when not.
# Runs in a subshell, so that the stubs do not outlive it
run_fw_block() {
    : > "${APPLY_CALLS}"
    : > "${ERRORS_TEXT}"
    # The stubs are called from the sourced block, which the linter cannot see
    # shellcheck disable=SC2329
    (
        CONFIGURE_FIREWALL=true
        FLAVOR=rhel
        dnf() { return 0; }
        configure_firewalld() { echo "configure_firewalld" >> "${APPLY_CALLS}"; }
        systemctl() { echo "systemctl $*" >> "${APPLY_CALLS}"; return 0; }
        firewall-cmd() {
            echo "firewall-cmd $*" >> "${APPLY_CALLS}"
            case "${1}" in
                --state)  return "${FW_STATE_RC}" ;;
                --reload) return "${FW_RELOAD_RC}" ;;
            esac
            return 0
        }
        # shellcheck disable=SC1090
        source "${FW_BLOCK}"
    ) > /dev/null 2>&1
}

# Line number of the first call matching $1 in APPLY_CALLS, empty when there is none
call_line() { grep -nxF -- "${1}" "${APPLY_CALLS}" | head -n 1 | cut -d: -f1; }

FW_STATE_RC=0
FW_RELOAD_RC=0
run_fw_block
config_line=$(call_line "configure_firewalld")
reload_line=$(call_line "firewall-cmd --reload")
if [ -n "${config_line}" ] && [ -n "${reload_line}" ] && [ "${config_line}" -lt "${reload_line}" ] && [ ! -s "${ERRORS_TEXT}" ]; then
    pass "a running firewalld reloads after the configuration is written"
else
    fail "a running firewalld reloads after the configuration is written" "$(cat "${APPLY_CALLS}")" "$(cat "${ERRORS_TEXT}")"
fi
if [ -z "$(call_line "systemctl start firewalld")" ] && [ -n "$(call_line "systemctl enable firewalld")" ]; then
    pass "a running firewalld is enabled, and not started again"
else
    fail "a running firewalld is enabled, and not started again" "$(cat "${APPLY_CALLS}")"
fi

FW_RELOAD_RC=1
run_fw_block
if grep -q 'Failed to reload firewalld' "${ERRORS_TEXT}"; then
    pass "a failed reload is an ERROR"
else
    fail "a failed reload is an ERROR" "$(cat "${APPLY_CALLS}")"
fi
FW_RELOAD_RC=0

FW_STATE_RC=252
run_fw_block
if [ -n "$(call_line "systemctl start firewalld")" ] && [ -z "$(call_line "firewall-cmd --reload")" ] && [ -n "$(call_line "configure_firewalld")" ]; then
    pass "a firewalld that is not running, as in the kickstart, is started instead of reloaded"
else
    fail "a firewalld that is not running, as in the kickstart, is started instead of reloaded" "$(cat "${APPLY_CALLS}")"
fi
FW_STATE_RC=0

echo
echo "== el_configurator.sh wiring =="

if grep -qE '^[[:space:]]*configure_firewalld$' "${SCRIPT}"; then
    pass "the RHEL firewall branch calls configure_firewalld"
else
    fail "the RHEL firewall branch calls configure_firewalld"
fi

outside=$(grep -n 'firewall-offline-cmd' "${SCRIPT}" | awk -F: -v s="${start}" -v e="${end}" '$1 < s || $1 > e')
if [ -z "${outside}" ]; then
    pass "every firewall-offline-cmd call lives inside configure_firewalld"
else
    fail "every firewall-offline-cmd call lives inside configure_firewalld" "${outside}"
fi

# firewall-cmd would be wrong here: this runs in the anaconda %post chroot with firewalld installed
# but not running, which is exactly the case firewall-offline-cmd exists for
firewall_cmd_use=$(sed -n "${start},${end}p" "${SCRIPT}" | grep -vE '^[[:space:]]*#' | grep -nE '(^|[^-])firewall-cmd')
if [ -n "${firewall_cmd_use}" ]; then
    fail "the offline client is used, not firewall-cmd" "${firewall_cmd_use}"
else
    pass "the offline client is used, not firewall-cmd"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
