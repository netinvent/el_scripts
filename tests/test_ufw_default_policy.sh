#!/usr/bin/env bash

# Tests for FIREWALL_DEFAULT_ZONE_TARGET on ufw in el_configurator.sh
#
# ufw already drops what no rule allows, but its own before.rules answer ping. With DROP, ping is
# dropped by ufw's after.init hook, a file Debian creates once from a template and never replaces,
# so no update undoes it. These tests check that the hook is only taken over while it is that
# template or already the script's, never an administrator's own, that allowing ping again puts the
# template back, and, where the kernel lets an unprivileged user build a network namespace, that the
# hook really puts its rule ahead of ufw's and takes it away again.
#
# This file sets the configuration globals the extracted function reads. The linter cannot see that
# code, so it reports them as unused, hence a file wide waiver.
# shellcheck disable=SC2034
#
# Usage: tests/test_ufw_default_policy.sh [path/to/el_configurator.sh]

SCRIPT="${1:-$(dirname "${0}")/../el_configurator.sh}"

if [ ! -f "${SCRIPT}" ]; then
    echo "Cannot find el_configurator.sh at [${SCRIPT}]"
    exit 2
fi

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
BIN="${WORK}/bin"
HELPERS="${WORK}/helpers.sh"
HOOK="${WORK}/etc/ufw/after.init"
TEMPLATE="${WORK}/usr/share/ufw/after.init"
POLICY="${WORK}/etc/default/ufw"
CALLS="${WORK}/calls"
ERRORS_TEXT="${WORK}/errors"
mkdir -p "${BIN}" "${WORK}/etc/ufw" "${WORK}/usr/share/ufw" "${WORK}/etc/default"

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

# The paths go under WORK, and the hook it writes finds the iptables stubs first
extract_fn configure_ufw_default_policy > "${WORK}/fn.sh" || exit 2
extract_fn is_enabled > "${WORK}/is_enabled.sh" || exit 2
sed -e "s#/etc/ufw/#${WORK}/etc/ufw/#g" \
    -e "s#/usr/share/ufw/#${WORK}/usr/share/ufw/#g" \
    -e "s#/etc/default/ufw#${POLICY}#g" \
    -e "s#^PATH=/usr/sbin:#PATH=${BIN}:/usr/sbin:#" \
    "${WORK}/fn.sh" "${WORK}/is_enabled.sh" > "${HELPERS}"

LOG_FILE=/dev/null
log() {
    [ "${2}" = "ERROR" ] && printf '%s\n' "${1}" >> "${ERRORS_TEXT}"
    [ -n "${VERBOSE}" ] && echo "    log[${2:-INFO}]: ${1}"
    return 0
}

# iptables and ip6tables stubs, which the written hook runs. Each records its call. A chain is there
# unless IPT_NO_CHAIN or IP6T_NO_CHAIN is set, a rule is never there yet, and a delete finds nothing
for cmd in iptables ip6tables; do
    cat > "${BIN}/${cmd}" << STUB
#!/bin/sh
echo "${cmd} \$*" >> "${CALLS}"
case " \$* " in
    *" -L "*) [ "${cmd}" = iptables ] && [ -n "\${IPT_NO_CHAIN}" ] && exit 1
              [ "${cmd}" = ip6tables ] && [ -n "\${IP6T_NO_CHAIN}" ] && exit 1
              exit 0 ;;
    *" -C "*|*" -D "*) exit 1 ;;
esac
exit 0
STUB
    chmod +x "${BIN}/${cmd}"
done
export CALLS IPT_NO_CHAIN IP6T_NO_CHAIN

UFW_DEFAULT_RC=0
# The script calls ufw by absolute path, see test_configure_ufw.sh
if ! eval 'function /sbin/ufw() { echo "ufw $*" >> "${CALLS}"; return "${UFW_DEFAULT_RC}"; }' 2> /dev/null; then
    echo "Cannot stub /sbin/ufw on this shell, these tests would not exercise the real code path"
    exit 2
fi

# shellcheck disable=SC1090
source "${HELPERS}"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "${1}"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "${1}"; shift; [ $# -gt 0 ] && printf '         %s\n' "$@"; }

MARKER="# el_configurator: refuses ping for FIREWALL_DEFAULT_ZONE_TARGET"
printf '#!/bin/sh\n# ufw template\nexit 0\n' > "${TEMPLATE}"

# fresh: the machine as Debian leaves it, the template copied to /etc/ufw, not executable
fresh() {
    cp "${TEMPLATE}" "${HOOK}"
    chmod 640 "${HOOK}"
    printf 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\n' > "${POLICY}"
}

run() {
    : > "${CALLS}"
    : > "${ERRORS_TEXT}"
    configure_ufw_default_policy > /dev/null 2>&1
}

echo "Testing configure_ufw_default_policy from [${SCRIPT}]"
echo
echo "== DROP without ping =="

FIREWALL_DEFAULT_ZONE_TARGET=DROP
FIREWALL_DEFAULT_ZONE_ALLOW_PING=false
fresh
run
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && grep -qxF "${MARKER}" "${HOOK}" && [ -x "${HOOK}" ]; then
    pass "ufw's template is replaced by the hook, executable"
else
    fail "ufw's template is replaced by the hook, executable" "rc=${rc}" "$(cat "${ERRORS_TEXT}")" "$(ls -l "${HOOK}")"
fi
if grep -q -- '^iptables -w -I ufw-before-input 1 ! -i lo -p icmp --icmp-type echo-request -j DROP$' "${CALLS}" \
        && grep -q -- '^ip6tables -w -I ufw6-before-input 1 ! -i lo -p icmpv6 --icmpv6-type echo-request -j DROP$' "${CALLS}"; then
    pass "the hook is run at once, dropping ping first in ufw's IPv4 and IPv6 chains"
else
    fail "the hook is run at once, dropping ping first in ufw's IPv4 and IPv6 chains" "$(cat "${CALLS}")"
fi
if ! grep -q '^ufw ' "${CALLS}"; then
    pass "a default incoming policy that is already deny is left alone, without reloading ufw"
else
    fail "a default incoming policy that is already deny is left alone, without reloading ufw" "$(cat "${CALLS}")"
fi

# An earlier version of the script's hook, which records being stopped before it is replaced. Its $1
# is for that hook to expand
# shellcheck disable=SC2016
printf '#!/bin/sh\n%s\n# old version\necho "old hook $1" >> "%s"\nexit 0\n' "${MARKER}" "${CALLS}" > "${HOOK}"
chmod 750 "${HOOK}"
run
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && ! grep -q 'old version' "${HOOK}" && grep -qxF "${MARKER}" "${HOOK}" \
        && [ "$(head -n 1 "${CALLS}")" = "old hook stop" ]; then
    pass "a hook of the script's own is stopped, then rewritten, on a rerun"
else
    fail "a hook of the script's own is stopped, then rewritten, on a rerun" "rc=${rc}" "$(cat "${CALLS}")" "$(cat "${ERRORS_TEXT}")"
fi

printf '#!/bin/sh\n# the administrator'"'"'s own\n' > "${HOOK}"
cp "${HOOK}" "${WORK}/own"
run
rc=$?
if [ "${rc}" -eq 1 ] && grep -q "administrator's own hook" "${ERRORS_TEXT}" && cmp -s "${HOOK}" "${WORK}/own" && ! grep -q 'tables' "${CALLS}"; then
    pass "an administrator's own hook is left alone, with an ERROR"
else
    fail "an administrator's own hook is left alone, with an ERROR" "rc=${rc}" "$(cat "${ERRORS_TEXT}")"
fi

rm -f "${HOOK}"
run
rc=$?
if [ "${rc}" -eq 0 ] && grep -qxF "${MARKER}" "${HOOK}"; then
    pass "a missing hook is written"
else
    fail "a missing hook is written" "rc=${rc}" "$(cat "${ERRORS_TEXT}")"
fi

fresh
mv "${TEMPLATE}" "${WORK}/template.away"
rm -f "${HOOK}"
run
rc=$?
if [ "${rc}" -eq 1 ] && grep -q 'may not run' "${ERRORS_TEXT}" && [ ! -e "${HOOK}" ]; then
    pass "without ufw's template, which says this ufw may not run hooks, nothing is written, with an ERROR"
else
    fail "without ufw's template, nothing is written, with an ERROR" "rc=${rc}" "$(cat "${ERRORS_TEXT}")"
fi
mv "${WORK}/template.away" "${TEMPLATE}"

fresh
IP6T_NO_CHAIN=yes
run
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && ! grep -q '^ip6tables -w -I' "${CALLS}" && grep -q '^iptables -w -I' "${CALLS}"; then
    pass "with IPv6 off in ufw, its missing chain is skipped rather than failing the hook"
else
    fail "with IPv6 off in ufw, its missing chain is skipped rather than failing the hook" "rc=${rc}" "$(cat "${CALLS}")" "$(cat "${ERRORS_TEXT}")"
fi
IP6T_NO_CHAIN=""

echo
echo "== the default incoming policy =="

fresh
printf 'DEFAULT_INPUT_POLICY="REJECT"\n' > "${POLICY}"
run
if grep -qx 'ufw default deny incoming' "${CALLS}" && [ ! -s "${ERRORS_TEXT}" ]; then
    pass "a policy changed from ufw's deny is set back"
else
    fail "a policy changed from ufw's deny is set back" "$(cat "${CALLS}")"
fi
UFW_DEFAULT_RC=1
run
rc=$?
if [ "${rc}" -eq 1 ] && grep -q 'Failed to set ufw' "${ERRORS_TEXT}"; then
    pass "a policy ufw would not set is an ERROR"
else
    fail "a policy ufw would not set is an ERROR" "rc=${rc}" "$(cat "${ERRORS_TEXT}")"
fi
UFW_DEFAULT_RC=0

echo
echo "== REJECT =="

FIREWALL_DEFAULT_ZONE_TARGET=DROP
FIREWALL_DEFAULT_ZONE_ALLOW_PING=false
fresh
run
FIREWALL_DEFAULT_ZONE_TARGET=REJECT
run
rc=$?
if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && grep -qx 'ufw default reject incoming' "${CALLS}" && grep -qx 'target=REJECT' "${HOOK}"; then
    pass "ufw's incoming policy becomes reject, and the hook refuses ping the REJECT way"
else
    fail "ufw's incoming policy becomes reject, and the hook refuses ping the REJECT way" "rc=${rc}" "$(cat "${CALLS}")" "$(cat "${ERRORS_TEXT}")"
fi
drop_out=$(grep -n -- '^iptables -w -D ufw-before-input ! -i lo -p icmp --icmp-type echo-request -j DROP$' "${CALLS}" | head -n 1 | cut -d: -f1)
reject_in=$(grep -n -- '^iptables -w -I ufw-before-input 1 ! -i lo -p icmp --icmp-type echo-request -j REJECT --reject-with icmp-admin-prohibited$' "${CALLS}" | head -n 1 | cut -d: -f1)
if [ -n "${drop_out}" ] && [ -n "${reject_in}" ] && [ "${drop_out}" -lt "${reject_in}" ] \
        && grep -q -- '^ip6tables -w -I ufw6-before-input 1 ! -i lo -p icmpv6 --icmpv6-type echo-request -j REJECT --reject-with icmp6-adm-prohibited$' "${CALLS}"; then
    pass "from DROP to REJECT: the previous hook takes its DROP rule out before the REJECT rules go in"
else
    fail "from DROP to REJECT: the previous hook takes its DROP rule out before the REJECT rules go in" "$(cat "${CALLS}")"
fi
printf 'IPV6=yes\nDEFAULT_INPUT_POLICY="REJECT"\n' > "${POLICY}"
run
if ! grep -q '^ufw ' "${CALLS}"; then
    pass "a reject policy already in place is left alone"
else
    fail "a reject policy already in place is left alone" "$(cat "${CALLS}")"
fi
FIREWALL_DEFAULT_ZONE_TARGET=DROP

echo
echo "== ping allowed again, or default =="

for setting in "DROP true" "default false"; do
    FIREWALL_DEFAULT_ZONE_TARGET="${setting% *}"
    FIREWALL_DEFAULT_ZONE_ALLOW_PING="${setting#* }"
    fresh
    FIREWALL_DEFAULT_ZONE_TARGET=DROP FIREWALL_DEFAULT_ZONE_ALLOW_PING=false run
    run
    rc=$?
    if [ "${rc}" -eq 0 ] && [ ! -s "${ERRORS_TEXT}" ] && cmp -s "${HOOK}" "${TEMPLATE}" && [ ! -x "${HOOK}" ] \
            && grep -q '^iptables -w -D ufw-before-input' "${CALLS}"; then
        pass "${setting% *} with FIREWALL_DEFAULT_ZONE_ALLOW_PING=${setting#* }: the rule leaves the running firewall, the template is back, not executable"
    else
        fail "${setting% *} with FIREWALL_DEFAULT_ZONE_ALLOW_PING=${setting#* }: the rule leaves the running firewall, the template is back" "rc=${rc}" "$(cat "${CALLS}")" "$(cat "${ERRORS_TEXT}")"
    fi
done

fresh
run
if cmp -s "${HOOK}" "${TEMPLATE}" && ! grep -q 'tables' "${CALLS}"; then
    pass "a hook that is not the script's is not touched when ping is allowed"
else
    fail "a hook that is not the script's is not touched when ping is allowed" "$(cat "${CALLS}")"
fi

echo
echo "== the hook against real chains =="

# The hook as the script writes it, without the test's PATH, for each target
hook_real="${WORK}/hook_real.sh"
sed -n "/^    hook_text=\$(cat << 'EOF'\$/,/^EOF\$/p" "${SCRIPT}" | sed '1d;$d' > "${hook_real}"
if grep -qxF "${MARKER}" "${hook_real}" && grep -qx 'target=@TARGET@' "${hook_real}"; then
    pass "the hook text holds the marker the script looks for, and the target it fills in"
else
    fail "the hook text holds the marker the script looks for, and the target it fills in" "$(head -12 "${hook_real}")"
fi
sed 's/^target=@TARGET@$/target=REJECT/' "${hook_real}" > "${WORK}/hook_reject.sh"
sed -i 's/^target=@TARGET@$/target=DROP/' "${hook_real}"

# In a network namespace of an unprivileged user namespace, iptables works on chains of its own.
# Kernels or runners that forbid this skip the section rather than fail it
if command -v unshare > /dev/null 2>&1 && command -v iptables > /dev/null 2>&1 \
        && unshare -rn iptables -w -n -L INPUT > /dev/null 2>&1; then
    real=$(unshare -rn sh -s "${hook_real}" "${WORK}/hook_reject.sh" << 'NS' 2>&1
hook="$1"
hook_reject="$2"
iptables -w -N ufw-before-input
iptables -w -A ufw-before-input -i lo -j ACCEPT
iptables -w -A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
ip6tables -w -N ufw6-before-input
ip6tables -w -A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j ACCEPT
sh "${hook}" start && sh "${hook}" start && echo "started twice"
iptables -w -S ufw-before-input
ip6tables -w -S ufw6-before-input
echo "-- stopped"
sh "${hook}" stop
iptables -w -S ufw-before-input
ip6tables -w -S ufw6-before-input
echo "-- REJECT"
sh "${hook_reject}" start
iptables -w -S ufw-before-input
ip6tables -w -S ufw6-before-input
echo "-- REJECT stopped"
sh "${hook_reject}" stop
iptables -w -S ufw-before-input
ip6tables -w -S ufw6-before-input
echo "-- without IPv6"
ip6tables -w -F ufw6-before-input
ip6tables -w -X ufw6-before-input
sh "${hook}" start && echo "started without IPv6"
NS
)
    started=$(printf '%s\n' "${real}" | sed -n '1,/^-- stopped$/p')
    stopped=$(printf '%s\n' "${real}" | sed -n '/^-- stopped$/,/^-- REJECT$/p')
    rejecting=$(printf '%s\n' "${real}" | sed -n '/^-- REJECT$/,/^-- REJECT stopped$/p')
    reject_stopped=$(printf '%s\n' "${real}" | sed -n '/^-- REJECT stopped$/,/^-- without IPv6$/p')
    if printf '%s\n' "${started}" | grep -q '^started twice$' \
            && [ "$(printf '%s\n' "${started}" | grep -c -- '-j DROP$')" -eq 2 ] \
            && [ "$(printf '%s\n' "${started}" | grep -- '^-A ufw-before-input' | head -n 1)" = "-A ufw-before-input ! -i lo -p icmp -m icmp --icmp-type 8 -j DROP" ] \
            && [ "$(printf '%s\n' "${started}" | grep -- '^-A ufw6-before-input' | head -n 1)" = "-A ufw6-before-input ! -i lo -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j DROP" ]; then
        pass "started twice: one rule per family, ahead of ufw's own rules accepting ping"
    else
        fail "started twice: one rule per family, ahead of ufw's own rules accepting ping" "${real}"
    fi
    if ! printf '%s\n' "${stopped}" | grep -q -- '-j DROP$' \
            && [ "$(printf '%s\n' "${stopped}" | grep -c -- '-j ACCEPT$')" -eq 3 ]; then
        pass "stopped: the rules are gone, ufw's own are left"
    else
        fail "stopped: the rules are gone, ufw's own are left" "${real}"
    fi
    if [ "$(printf '%s\n' "${rejecting}" | grep -- '^-A ufw-before-input' | head -n 1)" = "-A ufw-before-input ! -i lo -p icmp -m icmp --icmp-type 8 -j REJECT --reject-with icmp-admin-prohibited" ] \
            && [ "$(printf '%s\n' "${rejecting}" | grep -- '^-A ufw6-before-input' | head -n 1)" = "-A ufw6-before-input ! -i lo -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j REJECT --reject-with icmp6-adm-prohibited" ] \
            && ! printf '%s\n' "${reject_stopped}" | grep -q -- '-j REJECT'; then
        pass "REJECT: ping refused administratively prohibited, ahead of ufw's rules, and taken away on stop"
    else
        fail "REJECT: ping refused administratively prohibited, ahead of ufw's rules, and taken away on stop" "${real}"
    fi
    if printf '%s\n' "${real}" | grep -q '^started without IPv6$'; then
        pass "without ufw's IPv6 chain the hook still starts, so ufw does too"
    else
        fail "without ufw's IPv6 chain the hook still starts, so ufw does too" "${real}"
    fi
else
    echo "  skip this kernel or runner gives no unprivileged network namespace with iptables"
fi

echo
echo "== el_configurator.sh wiring =="

if sed -n '/^configure_ufw() {/,/^}$/p' "${SCRIPT}" | grep -A3 'ufw enable' | grep -q 'configure_ufw_default_policy'; then
    pass "configure_ufw applies the target right after enabling ufw"
else
    fail "configure_ufw applies the target right after enabling ufw"
fi

echo
printf 'passed %d, failed %d\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
