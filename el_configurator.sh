#!/usr/bin/env bash

# Security & basic setup configuration script from NetPerfect
# Works with RHEL / AlmaLinux / RockyLinux / CentOS EL8, EL9 and EL10
# Works with Debian 12
# Works with Debian 13, scap profiles available since ssg 0.1.80 which ships ssg-debian13-ds.xml
# Works with Ubuntu 22.04 tls, although scap support needs to be disabled as of 16-12-2025

SCRIPT_BUILD="2026081901"

# Note that all variables can be overridden by kernel arguments
# Example: Override BRAND_NAME with kernel argument: NPF_BRAND_NAME=MyBrand

BRAND_NAME=NetPerfect # Name which will be displayed in /etc/issue
VIRT_BRAND_NAME=NetPerfect # String that will be searched in SMBIOS to detect virtual machines
ISSUE_MESSAGE_EXTRA="- Private System" # Will be displayed with BRAND_NAME in /etc/issue.net
BRAND_VER=5.1

REMOTE_LOGIN_BANNER=$(cat << 'EOF'
 ___________________________________________________
/ UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED  \
|                                                   |
| You must have explicit, authorized permission     |
| to access or configure this device. Unauthorized  |
| attempts and actions to access or use this system |
| may result in civil and/or criminal penalties.    |
| All activities performed on this device are       |
| logged and monitored.                             |
\                                                   /
 ---------------------------------------------------
EOF
)

MOTD_MSG=$(cat << 'EOF'
         \   ^__^
          \  (oo)\_______
             (__)\       )\/\
                 ||----w |
                 ||     ||
___MOTD_STATUS_DO_NOT_DELETE___
 
EOF
)


# Select SCAP PROFILE, choosing "" or false disables scap profile, which is a requirement for ubuntu
# Get profile list with oscap info "/usr/share/xml/scap/ssg/content/ssg-${DIST}${RELEASE}-ds.xml"
# where flavor in rhel,debian and release = major os version
# See https://www.open-scap.org/download/
SCAP_PROFILE=anssi_bp28_high
#SCAP_PROFILE=anssi_bp28_intermediary
#SCAP_PROFILE=false

# SCAP Security Guide packages for Debian 12+.
# Debian's own suites trail one release for SCAP content: bookworm ships ssg 0.1.65, which carries
# no debian12 datastream, and trixie ships 0.1.76, which carries no debian13 one. So the packages
# have to be pulled from the archive pool rather than installed with apt.
# A .deb taken out of the pool carries no signature apt can check, which is why every file below is
# pinned to the sha256 Debian publishes for it and verified before anything is installed.
# To move to a newer release, replace every line below with the values from
# https://packages.debian.org/sid/all/<package>/download
SSG_DEBIAN_POOL_URL="https://deb.debian.org/debian/pool/main/s/scap-security-guide"
SSG_DEBIAN_PACKAGES=$(cat << 'EOF'
fdb92f480cd782fde407123bd3d20860d9d4e26faa21eca738cb7cf78ebf6204  ssg-base_0.1.80-1_all.deb
aa72d05f04dd9a5f5da961a255ed643aa6b08c07f17579a7091d19ae3e2b931c  ssg-debian_0.1.80-1_all.deb
735682488025215454e3e82ab9a6f2965d1c1e5bd5ed64219a1fdfc71617facd  ssg-applications_0.1.80-1_all.deb
a8e4e4424364b1caae12a2a9ae412bea3f79493c2ec1d2ebaa5f8e92f53d8cda  ssg-debderived_0.1.80-1_all.deb
EOF
)

# By default, ANSSI profiles disables sudo (which is a good thing, but el10 also disables root account by default, so we need at least a root account or sudo working)
ALLOW_SUDO=false

# Setup SELinux on Debian
SETUP_SELINUX_DEBIAN=false

# Configure serial terminal
CONFIGURE_SERIAL_TERMINAL=true

# Add resize_term and resize_term2 scripts to /etc/profile.d
CONFIGURE_TERMINAL_RESIZER=true

# Install and configure node_exporter
CONFIGURE_NODE_EXPORTER=true
# See below for firewall settings

# Setup python smartmontools / nvme tooling for prometheus on physical systems
CONFIGURE_NODE_EXPORTER_PYTHON_EXTENSIONS=true

# Make sure system automatically installs security updates
CONFIGURE_AUTOMATIC_UPDATES=true

# Enable system watchdog
CONFIGURE_WATCHDOG=true

# Use specific network schedulers (bbr + cake)
CONFIGURE_NETWORK_SCHEDULING=true

# Add client keep alives to sshd
CONFIGURE_SSHD_CLIENT_ALIVE=true

# Configure SSH CIS settings
CONFIGURE_CIS_SSHD_SETTINGS=true

# Implement tuned profiles
CONFIGURE_TUNED=true

# Install and configure firewall
CONFIGURE_FIREWALL=true

# Configure semicolon separated list of NTP servers
#NTP_SERVERS="192.168.200.254:10.0.0.1"
NTP_SERVERS=""

# Add NTP servers or replace existing default OS settings
REPLACE_EXISTING_NTP=false

# Optional whitelist IPs / CIDR for firewall, semicolon separated
#FIREWALL_WHITELIST_IP_LIST="192.168.200.0/24:10.0.0.1"
FIREWALL_WHITELIST_IP_LIST=""
FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS=true # Allow all ports for whitelisted IPs, if not enabled, only ssh is allowed

NODE_EXPORTER_USE_IP_WHITELISTS=true # Use firewall whitelists for node exporter if they're defined, unless all ports are whitelisted
NODE_EXPORTER_SKIP_FIREWALL=true # Do not open node_exporter port in firewall for everyone
# Pin the node_exporter release to install, eg v1.8.2, so that installs are reproducible
# Left empty, the latest release is resolved from the GitHub API at install time
NODE_EXPORTER_VERSION=""

# Install and configure fail2ban
CONFIGURE_FAIL2BAN=true

# Optional whitelist IPs / CIDR for Fail2ban
# Attention, when overriding this via a kernel argument, you'll need to override this value too
FAIL2BAN_IGNORE_IP_LIST="${FIREWALL_WHITELIST_IP_LIST}"

# Keep ipv4 forwarding active (necessary for container setups and most routing setups)
KEEP_IPV4_FORWARDING=false

# Keep arp_filter disabled (may cause network issues with some cloud provider VMs)
# Setting this to false enhances security, but may cause network issues like sporadic loss of network
KEEP_ARP_FILTER_DISABLED=true

# Optional allow non protected fs symlinks
# Will be necessary for docker to write to /dev/stdout via mount --bind links
ALLOW_UNPROTECTED_FS_SYMLINKS=false

# Apparmor disable runc profile in order to allow docker/podman to run on Debian machines with OpenSCAP
# This is not an ideal fix from a security perspective
DISABLE_APPARMOR_RUNC_PROFILE=true

VM_SWAPPINESS_VALUE=1 # Set vm.swappiness value to this

# Number of kernels to keep on the system, older ones will be removed (flattens false positives in SIEMs)
#   RHEL 8-10    dnf's installonly_limit caps future installs, and the surplus kernels already on
#                disk are removed straight away
#   Debian 13    apt applies APT::NeverAutoRemove::KernelCount on autoremove. Apt always keeps the
#                running kernel and the latest one, so any value below 2 is ignored
#   Debian 12    Value is wrtitten but old apt doesn't honour it
KERNELS_TO_KEEP=2

LOG_FILE=/root/.el-configurator.log

log() {
    __log_line="${1}"
    __log_level="${2:-INFO}"

    __log_line="${__log_level}: ${__log_line}"
    echo "${__log_line}" >> "${LOG_FILE}"
    echo "${__log_line}"

    if [ "${__log_level}" = "ERROR" ]; then
        POST_INSTALL_SCRIPT_GOOD=false
    fi
}

log_quit() {
    log "${1}" "${2}"
    log "Exiting script"
    exit 1
}

log "Starting EL configurator post install build ${SCRIPT_BUILD} at $(date)"
[ -z "${BASH_VERSION}" ] && log_quit "This script must be run with bash"


get_kernel_arguments() {
    # This allows to set variables from kernel arguments
    # kernel argument NPF_VARIABLE_NAME=value sets VARIABLE_NAME with value
    # A value containing spaces must be quoted, eg NPF_BRAND_NAME="My Brand"
    # A value may contain '=' signs, eg NPF_SOME_TOKEN=abc=def

    local cmdline_file="${1:-/proc/cmdline}"
    local kernel_arg_prefix="NPF_"
    local kernel_args remaining matched argument_name argument_value attributes
    # <prefix>NAME=VALUE where VALUE is either "quoted, possibly containing spaces" or a bare token.
    # The name is captured loosely here so that a malformed one can be reported rather than skipped.
    local kernel_arg_regex="(^|[[:space:]])${kernel_arg_prefix}([^=[:space:]]+)=(\"[^\"]*\"|[^[:space:]]*)"

    if [ ! -f "${cmdline_file}" ]; then
        log "Cannot find kernel arguments from ${cmdline_file}" "ERROR"
        return 1
    fi

    kernel_args=$(cat "${cmdline_file}")
    log "Current kernel arguments: ${kernel_args}"

    remaining="${kernel_args}"
    while [[ "${remaining}" =~ ${kernel_arg_regex} ]]; do
        matched="${BASH_REMATCH[0]}"
        argument_name="${BASH_REMATCH[2]}"
        argument_value="${BASH_REMATCH[3]}"
        # Consume what we matched, so the next iteration looks at the rest of the line.
        # The quotes around ${matched} keep it a literal, not a glob pattern.
        remaining="${remaining#*"${matched}"}"

        # Drop the surrounding quotes of a quoted value
        if [ "${argument_value:0:1}" = '"' ]; then
            argument_value="${argument_value:1:${#argument_value}-2}"
        fi

        if ! [[ "${argument_name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            log "Ignoring kernel argument ${kernel_arg_prefix}${argument_name}: not a valid variable name" "ERROR"
            continue
        fi

        # Refuse to overwrite exported variables, so that a boot line cannot repoint PATH, IFS or LD_*
        attributes=$(declare -p "${argument_name}" 2>/dev/null)
        attributes="${attributes#declare -}"
        attributes="${attributes%% *}"
        case "${attributes}" in
            *x*)
                log "Ignoring kernel argument ${kernel_arg_prefix}${argument_name}: would overwrite environment variable ${argument_name}" "ERROR"
                continue
                ;;
        esac

        if printf -v "${argument_name}" '%s' "${argument_value}" 2>> "${LOG_FILE}"; then
            log "Retrieved variable from kernel arguments: ${argument_name}=${argument_value}"
        else
            log "Cannot set variable ${argument_name} from kernel arguments" "ERROR"
        fi
    done
}

# This is a duplicate from the Python script, but since we don't inherit pre settings, we need to redeclare it
# Physical machine can return
# VME (Virtual mode extension)
# Enhanced Virtualization

is_virtual() {
    lsmod | grep virtio > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        IS_VIRTUAL=true
        log "Detected this machine as virtual using virtio drivers"
    else

        # Hence we need to detect specific products
        if ! type -p dmidecode > /dev/null 2>&1; then
            log "dmidecode not found, trying to install it"
            if [ "${FLAVOR}" = "rhel" ]; then
                dnf install -y dmidecode
            else
                apt install -y dmidecode
            fi
        fi
        if ! type -p dmidecode > /dev/null 2>&1; then
            log "Cannot find dmidecode, let's assume this is a physical machine" "ERROR"
            IS_VIRTUAL=false
        else
            # Special diag for kvm machines
            dmidecode | grep -i "kvm\|qemu\|vmware\|hyper-v\|virtualbox\|innotek\|Manufacturer: Red Hat\|${VIRT_BRAND_NAME}" > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                IS_VIRTUAL=true
                log "Detected this machine as virtual using hypervisor search"
            else
                IS_VIRTUAL=false
                log "Detected this machine as physical"
            fi
        fi
    fi
}

get_el_version() {
    if [ -f /etc/os-release ]; then
    # DIST must contain "rhel", "almalinux", "debian", "ubuntu" or alike
    # FLAVOR will contain "rhel" or "debian"
	# The following awk line has been tested on almalinux 8, almalinux 9, rhel 10, almalinux 10, debian 12, debian 13 and ubuntu 22
        DIST=$(awk '{ if ($1~/^ID=/) { sub("ID=","", $0); gsub("\"","", $0); print tolower($0) }}' /etc/os-release)
        RELEASE=0
        if grep 'ID="rhel"' /etc/os-release > /dev/null || grep 'ID_LIKE="*rhel*' /etc/os-release > /dev/null; then
            FLAVOR=rhel
	    if grep -e 'PLATFORM_ID=".*el10' /etc/os-release > /dev/null; then
                RELEASE=10
		        SYSTEMD_PREFIX=/usr/lib/systemd
            elif grep -e 'PLATFORM_ID=".*el9' /etc/os-release > /dev/null; then
                RELEASE=9
		        SYSTEMD_PREFIX=/etc/systemd
            elif grep -e 'PLATFORM_ID=".*el8' /etc/os-release > /dev/null; then
                RELEASE=8
		        SYSTEMD_PREFIX=/etc/systemd
            else
                log_quit "RHEL or alike release not compatible: dist=${DIST},flavor=${FLAVOR},release=${RELEASE}"
            fi
            if [ "${RELEASE}" -eq 8 ] || [ "${RELEASE}" -eq 9 ] || [ "${RELEASE}" -eq 10 ]; then
                log "Found Linux ${DIST} release ${RELEASE}"
            else
                log_quit "Debian or alive release not compatible: dist=${DIST},flavor=${FLAVOR},release=${RELEASE}"
            fi
        elif grep 'ID=*debian*' /etc/os-release > /dev/null; then
            FLAVOR=debian
            if grep -e 'VERSION_ID="11' /etc/os-release > /dev/null; then
                RELEASE=11
		        SYSTEMD_PREFIX=/etc/systemd
            elif grep -e 'VERSION_ID="12' /etc/os-release > /dev/null; then
                RELEASE=12
		        SYSTEMD_PREFIX=/etc/systemd
            elif grep -e 'VERSION_ID="13' /etc/os-release > /dev/null; then
                RELEASE=13
		        SYSTEMD_PREFIX=/etc/systemd
            fi
            if [ "${RELEASE}" -eq 11 ] || [ "${RELEASE}" -eq 12 ] || [ "${RELEASE}" -eq 13 ]; then
                log "Found Linux ${DIST} release ${RELEASE}"
            else
                log_quit "Not compatible with ${DIST} release ${RELEASE} "
            fi
        elif grep 'ID=*ubuntu*' /etc/os-release > /dev/null; then
            FLAVOR=debian
            if grep -e 'VERSION_ID="20' /etc/os-release > /dev/null; then
                RELEASE=20
                SYSTEMD_PREFIX=/etc/systemd
            elif grep -e 'VERSION_ID="22' /etc/os-release > /dev/null; then
                RELEASE=22
                SYSTEMD_PREFIX=/etc/systemd
            fi
            if [ "${RELEASE}" -ge 20 ]; then
                log "Found Linux ${DIST} release ${RELEASE}, limited compatibility"
            else
                log_quit "Not compatible with ${DIST} release ${RELEASE} "
            fi
        else
            log_quit "Cannot determine OS flavor from /etc/os-release"
        fi
    else
        log_quit "No /etc/os-release file found"
    fi
}


# We need a dns hostname in order to validate that we got internet before using internet related functions
# Also, we need to make sure 
check_internet() {
    fqdn_host="one.one.one.one kernel.org github.com"
    ip_hosts="2606:4700:4700::1001 8.8.8.8 9.9.9.9"
    for host in ${fqdn_host[@]}; do
        if type curl > /dev/null 2>&1; then
            curl -s --connect-timeout 5 -Lk "http://${host}" > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                log "FQDN curl HTTP request to ${host} works."
                return 0
            else
                log "FQDN curl HTTP request to ${host} failed."
            fi
        elif type wget > /dev/null 2>&1; then
            wget -q --timeout=5 -O /dev/null "http://${host}" > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                log "FQDN wget HTTP request to ${host} works."
                return 0
            else
                log "FQDN wget HTTP request to ${host} failed."
            fi
        else
            log "No curl nor wget available to test internet connectivity to ${host}" "INFO"
        fi
        ping -4 -c2 "${host}" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            log "FQDN IPv4 echo request to ${host} works."
            return 0
        else
            log "FQDN IPv4 echo request to ${host} failed."
        fi
        ping -6 -c2 "${host}" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            log "FQDN IPv6 echo request to ${host} works."
            return 0
        else
            log "FQDN IPv6 echo request to ${host} failed."
        fi
    done
    log "Looks like we cannot access internet via hostnames. Let's try IPs"
    for host in ${ip_hosts[@]}; do
        ping -c2 "${host}" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            log "IP check to ${host} works, but dns resolution doesn't seem to."
            return 1
        fi
    done
    ip_result=$(ip a)
    route_result=$(ip route)
    resolv=$(cat /etc/resolv.conf)
    log "Internet check failed. Please find output of diag commands:" "NOTICE"
    log "ip a:\n${ip_result}\n\n"
    log "ip route:\n${route_result}\n\n"
    log "resolv.conf content:\n${resolv}\n\n"

    return 1
}

escape_bre() {
    # Escapes basic regular expression metacharacters so that a key is matched literally
    # Without this, a name like net.ipv4.ip_forward would also match netXipv4Xip_forward
    local __escaped="${1}"
    __escaped="${__escaped//\\/\\\\}"
    __escaped="${__escaped//./\\.}"
    __escaped="${__escaped//\*/\\*}"
    __escaped="${__escaped//\[/\\[}"
    __escaped="${__escaped//\]/\\]}"
    __escaped="${__escaped//^/\\^}"
    __escaped="${__escaped//\$/\\$}"
    printf '%s' "${__escaped}"
}

set_conf_value() {
    # Updates a line in a configuration file
    # name=value or name    =   value (gets rewritten to name=value) if separator = '='
    # name value if separator = ' '
    # name = value if separator = ' = '
    # Every write is read back before returning, so a directive that did not land raises an ERROR
    # instead of being reported as applied

    # This is only used for single values in a file
    # Do not use if files contain multiple entries with the same name

    # Returns 0 when the file holds the requested value, 1 otherwise
    local file="${1}"
    local name="${2}"
    local value="${3}"
    local separator="${4:-=}"
    # sed separator $'\001' (SOH) is chosen since it's unlikely to be used in a configuration file
    # sed separator can be changed to any other character as long as it's not used
    # if not used, we'll go for the SOH character
    local sed_separator="${5:-false}"
    if [ "${sed_separator}" = false ]; then
        sed_separator=$(echo -en "\001")
    fi

    local expected_line="${name}${separator}${value}"
    local separator_core key_re replacement current

    # Neither of these can be expressed through sed without corrupting the target file
    case "${name}${value}" in
        *"${sed_separator}"*)
            log "Cannot set [${name}] in file [${file}]: name or value contains the sed separator." "ERROR"
            return 1
            ;;
    esac
    case "${expected_line}" in
        *$'\n'*)
            log "Cannot set [${name}] in file [${file}]: name or value contains a newline." "ERROR"
            return 1
            ;;
    esac

    # The separator may carry decorative spaces (' = '), but what delimits the key in the file is its
    # core character. When that core is empty (separator is ' '), whitespace delimits the key instead.
    separator_core="${separator//[[:space:]]/}"
    if [ -n "${separator_core}" ]; then
        key_re="^[[:space:]]*$(escape_bre "${name}")[[:space:]]*$(escape_bre "${separator_core}")"
    else
        key_re="^[[:space:]]*$(escape_bre "${name}")[[:space:]]"
    fi

    if [ ! -f "${file}" ]; then
        log "Creating file [${file}] with conf [${name}] set to [${value}]." "INFO"
        echo "${expected_line}" > "${file}" 2>> "${LOG_FILE}"
    # The key boundary in key_re is what stops "PermitRootLoginPolicy" from satisfying a search for
    # "PermitRootLogin", which used to leave sed with nothing to replace and the setting unwritten
    elif grep -q -e "${key_re}" -- "${file}" 2>/dev/null; then
        log "Updating conf [${name}] to [${value}] in file [${file}]." "INFO"
        # On the replacement side of s///, & means "the whole match" and \ starts an escape
        replacement="${expected_line//\\/\\\\}"
        replacement="${replacement//&/\\&}"
        # Using -i.eltmp for BSD compat
        sed -i.eltmp "s${sed_separator}${key_re}.*${sed_separator}${replacement}${sed_separator}" "${file}" >> "${LOG_FILE}" 2>&1
        # Remove temp file if exists
        rm -f "${file}.eltmp" > /dev/null 2>&1
    else
        log "Creating conf [${name}] set to [${value}] in file [${file}]." "INFO"
        echo "${expected_line}" >> "${file}" 2>> "${LOG_FILE}"
    fi

    # Read back what we asked for. A grep that matched a longer key, a value mangled by sed, or a file
    # we could not write all land here instead of passing as success
    if grep -q -F -x -e "${expected_line}" -- "${file}" 2>/dev/null; then
        return 0
    fi
    current=$(grep -e "${key_re}" -- "${file}" 2>/dev/null | head -n 1)
    log "Cannot set [${name}] to [${value}] in file [${file}]." "ERROR"
    log "Current value is [${current}]" "NOTICE"
    return 1
}

install_ssg_content() {
    # Installs the SCAP Security Guide content for the release being hardened.
    #
    # The distribution packages are preferred, because apt verifies their signatures for us.
    # Debian freezes its archive at release while SCAP content for a release lands upstream
    # afterwards, so the shipped ssg usually covers the previous release rather than this one:
    # as of 2026-08, bookworm ships 0.1.65 with no debian12 datastream and trixie ships 0.1.76
    # with no debian13 one. Only when the datastream we actually need is missing do we fall back
    # to the pinned download, so that fallback stops happening on its own once Debian catches up.
    #
    # Argument is the datastream the rest of the script will hand to oscap
    # Returns 0 when that datastream is present, 1 otherwise
    local datastream="${1}"

    log "Installing ssg openscap data from the distribution"
    # Not an ERROR: the pinned packages below are the supported way out of this
    apt-get install -y ssg-base ssg-debderived ssg-debian ssg-applications 2>> "${LOG_FILE}" \
        || log "Distribution ssg packages are unavailable, will try the pinned ones"

    if [ -f "${datastream}" ]; then
        log "Distribution ssg provides ${datastream}"
        return 0
    fi

    log "Distribution ssg does not provide ${datastream}, falling back to pinned ssg packages"
    install_ssg_debian_packages || return 1

    if [ -f "${datastream}" ]; then
        log "Pinned ssg packages provide ${datastream}"
        return 0
    fi
    log "Still no ${datastream} after installing the pinned ssg packages" "ERROR"
    return 1
}

install_ssg_debian_packages() {
    # Downloads the pinned SCAP Security Guide packages, verifies each one against the sha256
    # Debian publishes for it, and only then installs them.
    # dpkg cannot check a signature on a .deb pulled out of the pool, so those checksums are the
    # only thing standing between a tampered download and maintainer scripts running as root.
    # A checksum mismatch aborts the install rather than degrading to an unverified one.
    # Returns 0 when every package is installed, 1 otherwise
    local ssg_dir package_file package_files download_rc install_rc

    if [ -z "${SSG_DEBIAN_PACKAGES}" ]; then
        log "No ssg packages are pinned, cannot install SCAP content" "ERROR"
        return 1
    fi

    ssg_dir=$(mktemp -d) || {
        log "Cannot create temporary directory for ssg packages" "ERROR"
        return 1
    }
    printf '%s\n' "${SSG_DEBIAN_PACKAGES}" > "${ssg_dir}/SHA256SUMS"

    package_files=""
    download_rc=0
    while read -r _ package_file; do
        [ -z "${package_file}" ] && continue
        log "Downloading ${package_file}"
        if type curl > /dev/null 2>&1; then
            # --fail matters here: without it curl saves an HTTP error page as if it were the .deb
            curl -sSfL --connect-timeout 30 --output "${ssg_dir}/${package_file}" "${SSG_DEBIAN_POOL_URL}/${package_file}" 2>> "${LOG_FILE}" || download_rc=1
        elif type wget > /dev/null 2>&1; then
            wget -q --timeout=30 -O "${ssg_dir}/${package_file}" "${SSG_DEBIAN_POOL_URL}/${package_file}" 2>> "${LOG_FILE}" || download_rc=1
        else
            log "No curl nor wget available to download ssg packages" "ERROR"
            download_rc=1
        fi
        [ "${download_rc}" -ne 0 ] && break
        package_files="${package_files} ./${package_file}"
    done << EOF
${SSG_DEBIAN_PACKAGES}
EOF

    if [ "${download_rc}" -ne 0 ]; then
        log "Cannot download ssg packages, SCAP content will be missing" "ERROR"
        rm -rf "${ssg_dir}"
        return 1
    fi

    if ! (cd "${ssg_dir}" && sha256sum -c SHA256SUMS) >> "${LOG_FILE}" 2>&1; then
        log "Checksum verification failed for ssg packages, refusing to install them. See log file" "ERROR"
        rm -rf "${ssg_dir}"
        return 1
    fi
    log "All ssg packages match their pinned sha256"

    # apt-get resolves the dependencies between these packages, dpkg -i would need the right order
    # We actually want word splitting here
    # shellcheck disable=SC2086
    (cd "${ssg_dir}" && apt-get install -y ${package_files}) 2>> "${LOG_FILE}"
    install_rc=$?
    rm -rf "${ssg_dir}"
    if [ "${install_rc}" -ne 0 ]; then
        log "Cannot install ssg packages" "ERROR"
        return 1
    fi
    return 0
}

sudoers_begin_edit() {
    # Starts an edit of the sudoers file on a private copy, and puts the path of that copy in
    # SUDOERS_EDIT_FILE. Change that copy, then call sudoers_commit_edit to validate and apply it.
    #
    # A global is used rather than printing the path, because log() writes to stdout and also sets
    # POST_INSTALL_SCRIPT_GOOD, both of which a command substitution would swallow.
    #
    # Optional argument is the sudoers file, defaults to /etc/sudoers (used by tests)
    # Returns 0 when the copy is ready, 1 otherwise
    SUDOERS_EDIT_TARGET="${1:-/etc/sudoers}"
    SUDOERS_EDIT_FILE=""

    if [ ! -f "${SUDOERS_EDIT_TARGET}" ]; then
        log "No ${SUDOERS_EDIT_TARGET} to edit" "ERROR"
        return 1
    fi
    if ! type visudo > /dev/null 2>&1; then
        # Refusing beats editing sudoers with no way to check the result
        log "visudo is not available, refusing to modify ${SUDOERS_EDIT_TARGET} unchecked" "ERROR"
        return 1
    fi

    SUDOERS_EDIT_FILE=$(mktemp) || {
        log "Cannot create a temporary copy of ${SUDOERS_EDIT_TARGET}" "ERROR"
        SUDOERS_EDIT_FILE=""
        return 1
    }
    if ! cat "${SUDOERS_EDIT_TARGET}" > "${SUDOERS_EDIT_FILE}" 2>> "${LOG_FILE}"; then
        log "Cannot copy ${SUDOERS_EDIT_TARGET}" "ERROR"
        rm -f "${SUDOERS_EDIT_FILE}"
        SUDOERS_EDIT_FILE=""
        return 1
    fi
    return 0
}

sudoers_commit_edit() {
    # Validates the copy started by sudoers_begin_edit and only then puts it in place.
    #
    # sudo refuses to run at all when sudoers has a syntax error, and the ANSSI profile disables the
    # root account on EL10, so an unchecked edit here can lock a machine out for good. Everything is
    # validated together, so a rejected edit leaves the original completely untouched.
    #
    # The content is written through the existing file rather than moved over it, which keeps its
    # inode, permissions and SELinux context exactly as they were.
    # Returns 0 when the edit is live, 1 when it was rejected
    local commit_rc=0

    if [ -z "${SUDOERS_EDIT_FILE}" ] || [ ! -f "${SUDOERS_EDIT_FILE}" ]; then
        log "No sudoers edit in progress to commit" "ERROR"
        return 1
    fi

    if ! visudo -cf "${SUDOERS_EDIT_FILE}" >> "${LOG_FILE}" 2>&1; then
        log "visudo rejected the new ${SUDOERS_EDIT_TARGET}, keeping the current one. See log file" "ERROR"
        commit_rc=1
    elif ! cat "${SUDOERS_EDIT_FILE}" > "${SUDOERS_EDIT_TARGET}" 2>> "${LOG_FILE}"; then
        log "Cannot write ${SUDOERS_EDIT_TARGET}" "ERROR"
        commit_rc=1
    else
        log "Updated ${SUDOERS_EDIT_TARGET}, validated by visudo"
    fi

    rm -f "${SUDOERS_EDIT_FILE}" > /dev/null 2>&1
    SUDOERS_EDIT_FILE=""
    return "${commit_rc}"
}

sshd_begin_edit() {
    # Starts an edit of an sshd configuration file on a private copy, and puts the path of that
    # copy in SSHD_EDIT_FILE. Change that copy, then call sshd_commit_edit to install and check it.
    #
    # A global is used rather than printing the path, because log() writes to stdout and also sets
    # POST_INSTALL_SCRIPT_GOOD, both of which a command substitution would swallow.
    #
    # Optional argument is the file to edit, defaults to our own drop-in
    # Returns 0 when the copy is ready, 1 otherwise
    SSHD_EDIT_TARGET="${1:-/etc/ssh/sshd_config.d/99-el_configurator.conf}"
    SSHD_EDIT_FILE=""

    if ! type sshd > /dev/null 2>&1; then
        log "sshd is not installed, skipping ${SSHD_EDIT_TARGET}" "ERROR"
        return 1
    fi
    if [ ! -d "$(dirname "${SSHD_EDIT_TARGET}")" ]; then
        log "No $(dirname "${SSHD_EDIT_TARGET}") directory, cannot write ${SSHD_EDIT_TARGET}" "ERROR"
        return 1
    fi

    SSHD_EDIT_FILE=$(mktemp) || {
        log "Cannot create a temporary copy of ${SSHD_EDIT_TARGET}" "ERROR"
        SSHD_EDIT_FILE=""
        return 1
    }
    # Seed the copy from the current file when there is one, so an edit adds to it instead of
    # replacing it. A missing target simply starts empty.
    if [ -f "${SSHD_EDIT_TARGET}" ] && ! cat "${SSHD_EDIT_TARGET}" > "${SSHD_EDIT_FILE}" 2>> "${LOG_FILE}"; then
        log "Cannot copy ${SSHD_EDIT_TARGET}" "ERROR"
        rm -f "${SSHD_EDIT_FILE}"
        SSHD_EDIT_FILE=""
        return 1
    fi
    return 0
}

sshd_commit_edit() {
    # Installs the copy started by sshd_begin_edit, then checks the resulting configuration with
    # sshd -t and rolls back if sshd would refuse to start.
    #
    # sshd is checked after installing rather than before, because a drop-in is only meaningful as
    # part of the whole configuration: checking the fragment on its own would miss a value that
    # conflicts with another drop-in.
    #
    # Returns 0 when the configuration is in place, 1 when it was rolled back
    local sshd_backup sshd_had_target=false sshd_check commit_rc=0

    if [ -z "${SSHD_EDIT_FILE}" ] || [ ! -f "${SSHD_EDIT_FILE}" ]; then
        log "No sshd edit in progress to commit" "ERROR"
        return 1
    fi

    sshd_backup=$(mktemp) || {
        log "Cannot create a backup of ${SSHD_EDIT_TARGET}" "ERROR"
        rm -f "${SSHD_EDIT_FILE}"
        SSHD_EDIT_FILE=""
        return 1
    }
    if [ -f "${SSHD_EDIT_TARGET}" ]; then
        cat "${SSHD_EDIT_TARGET}" > "${sshd_backup}" 2>> "${LOG_FILE}"
        sshd_had_target=true
    fi

    if ! cat "${SSHD_EDIT_FILE}" > "${SSHD_EDIT_TARGET}" 2>> "${LOG_FILE}"; then
        log "Cannot write ${SSHD_EDIT_TARGET}" "ERROR"
        rm -f "${SSHD_EDIT_FILE}" "${sshd_backup}"
        SSHD_EDIT_FILE=""
        return 1
    fi
    # CIS wants sshd_config and the files it includes readable by root only
    chmod 0600 "${SSHD_EDIT_TARGET}" 2>> "${LOG_FILE}" || log "Cannot chmod 0600 ${SSHD_EDIT_TARGET}" "ERROR"

    sshd_check=$(sshd -t 2>&1)
    if [ -z "${sshd_check}" ]; then
        log "Updated ${SSHD_EDIT_TARGET}, validated by sshd -t"
    elif echo "${sshd_check}" | grep -i -e 'host key' -e 'hostkey' > /dev/null 2>&1; then
        # Host keys are generated on first boot, so in a kickstart %post there are none yet and
        # sshd -t cannot run. Rolling back here would silently drop the hardening on every
        # kickstart install, which is worse than not being able to check it.
        log "Cannot check ${SSHD_EDIT_TARGET} yet, sshd has no host keys in this environment. Keeping it" "NOTICE"
        log "sshd -t said: ${sshd_check}" "NOTICE"
    else
        log "sshd rejected the configuration, rolling ${SSHD_EDIT_TARGET} back: ${sshd_check}" "ERROR"
        if [ "${sshd_had_target}" = true ]; then
            cat "${sshd_backup}" > "${SSHD_EDIT_TARGET}" 2>> "${LOG_FILE}" || log "Cannot restore ${SSHD_EDIT_TARGET}" "ERROR"
        else
            rm -f "${SSHD_EDIT_TARGET}" 2>> "${LOG_FILE}" || log "Cannot remove ${SSHD_EDIT_TARGET}" "ERROR"
        fi
        commit_rc=1
    fi

    rm -f "${SSHD_EDIT_FILE}" "${sshd_backup}" > /dev/null 2>&1
    SSHD_EDIT_FILE=""
    return "${commit_rc}"
}

set_grub_console_args() {
    # Replaces the console arguments of a GRUB_CMDLINE_LINUX style setting, leaving every other
    # kernel argument exactly where it was.
    #
    # This used to be a single greedy sed, which silently discarded everything after the first
    # console= argument. Starting from
    #   GRUB_CMDLINE_LINUX="console=ttyS0 net.ifnames=0 biosdevname=0 audit=1"
    # it produced
    #   GRUB_CMDLINE_LINUX=" console=tty0 console=ttyS0,115200,n8 "
    # dropping audit=1, which CIS and ANSSI both want, and net.ifnames=0, which renames the network
    # interfaces on the next boot.
    #
    # Arguments: grub defaults file, setting name, console arguments to set
    # Returns 0 when the setting holds the wanted value, 1 otherwise
    local grub_file="${1}"
    local setting="${2}"
    local console_args="${3}"
    local current_line current_value kept_args arg
    local grub_args=()

    if [ ! -f "${grub_file}" ]; then
        log "No ${grub_file}, cannot set ${setting}" "ERROR"
        return 1
    fi

    current_line=$(grep -E "^[[:space:]]*${setting}[[:space:]]*=" "${grub_file}" 2>/dev/null | head -n 1)
    # Everything after the first '=', with the surrounding quotes taken off. A missing setting
    # simply leaves this empty, and the value is created from scratch further down.
    current_value="${current_line#*=}"
    current_value="${current_value%\"}"
    current_value="${current_value#\"}"

    # read -a splits on whitespace without globbing, unlike an unquoted expansion
    read -r -a grub_args <<< "${current_value}"
    kept_args=""
    for arg in "${grub_args[@]}"; do
        [ -z "${arg}" ] && continue
        # Only the console arguments are replaced, everything else is carried over untouched
        case "${arg}" in
            console=*) continue ;;
        esac
        kept_args="${kept_args}${kept_args:+ }${arg}"
    done
    kept_args="${kept_args}${kept_args:+ }${console_args}"

    log "Setting ${setting} to [${kept_args}] in ${grub_file}"
    set_conf_value "${grub_file}" "${setting}" "\"${kept_args}\"" "="
}

dnf_remove_old_kernels() {
    # Removes the kernels older than the last KERNELS_TO_KEEP, on RHEL and clones.
    #
    # The list is captured before anything is removed, because a freshly installed machine has
    # nothing old enough and "dnf remove -y" with no package argument exits non zero. Feeding the
    # query straight into dnf meant an ordinary install logged an ERROR, printed the FAILURE banner
    # and published el_configurator_state 1, so the healthy case looked like a failed hardening run.
    # That is how operators learn to ignore a red signal.
    #
    # Returns 0 when there was nothing to do or the removal worked, 1 otherwise
    local old_kernels

    if ! old_kernels=$(dnf repoquery --installonly --latest-limit=-"${KERNELS_TO_KEEP}" 2>> "${LOG_FILE}"); then
        log "Cannot list the kernels to remove" "ERROR"
        return 1
    fi
    if [ -z "${old_kernels}" ]; then
        log "No kernel older than the last ${KERNELS_TO_KEEP} to remove"
        return 0
    fi

    # repoquery returns one package per line, flattened here so the log entry stays on one line
    log "Removing kernels older than the last ${KERNELS_TO_KEEP}: ${old_kernels//$'\n'/ }"
    # We actually want word splitting here
    # shellcheck disable=SC2086
    if ! dnf remove -y ${old_kernels} 2>> "${LOG_FILE}"; then
        log "Failed to remove old kernels" "ERROR"
        return 1
    fi
    return 0
}

harden_node_exporter_service() {
    # Trims the systemd unit the vendored installer writes.
    #
    # That unit is shaped for a container runtime installer rather than a metrics exporter: it
    # delegates a cgroup subtree and lifts the process, task and core dump limits entirely.
    # LimitCORE=infinity also pulls against the CIS 1.5.1 and 1.5.2 core dump controls this script
    # applies elsewhere, so the machine ends up asking for two different things at once.
    #
    # This is written as a drop-in rather than patched into the vendored installer, for three
    # reasons: the embedded copy stays byte for byte identical to upstream and so stays diffable
    # against it, re-running the installer cannot quietly undo the change, and the override is
    # visible as our own decision instead of hidden in someone else's code.
    #
    # Explicit values are used rather than empty assignments, because resetting a Limit directive to
    # its default with an empty string is not documented behaviour.
    #
    # The service still runs as root. Moving it to a user of its own needs the systemd and logind
    # collectors to keep reaching D-Bus and the textfile collector directory to stay readable by
    # that user, which wants a test boot rather than a configuration line.
    # Returns 0 when the drop-in is in place, 1 otherwise
    local dropin_dir="/etc/systemd/system/node_exporter.service.d"
    local dropin="${dropin_dir}/99-el_configurator.conf"

    if [ ! -d "${dropin_dir}" ]; then
        mkdir -p "${dropin_dir}" 2>> "${LOG_FILE}" || {
            log "Cannot create ${dropin_dir}" "ERROR"
            return 1
        }
    fi

    cat << 'EOF' > "${dropin}" 2>> "${LOG_FILE}"
# Written by el_configurator. The unit this overrides comes from the vendored node_exporter
# installer, which inherits its shape from a container runtime installer.
[Service]
# A metrics exporter has no cgroup subtree to manage
Delegate=no
# No core dumps, matching CIS 1.5.1 and 1.5.2, which the unit otherwise contradicts
LimitCORE=0
# Generous for a Go binary, which needs threads rather than processes, but no longer unlimited
LimitNPROC=512
TasksMax=512
# Cannot gain privileges through execve, even while still running as root
NoNewPrivileges=true
EOF

    if [ ! -s "${dropin}" ]; then
        log "Cannot write ${dropin}" "ERROR"
        return 1
    fi
    log "Restricted the node_exporter service through ${dropin}"

    # Starting and reloading do not work in the install environment, so these are not errors there
    systemctl daemon-reload 2>> "${LOG_FILE}" || log "Cannot reload systemd, the node_exporter limits apply on next boot"
    systemctl restart node_exporter 2>> "${LOG_FILE}" || log "Cannot restart node_exporter, the new limits apply on next boot"
    return 0
}

repository_is_enabled() {
    # Asks dnf whether a repository is currently enabled.
    #
    # Only the first field of each line is compared, which is the repo id, because dnf4 and dnf5
    # print different columns after it and dnf5 adds a status column of its own. The header line
    # starts with "repo", so it cannot collide with a real id.
    #
    # Arguments: the repository id
    # Returns 0 when the repository is enabled, 1 otherwise
    local repository="${1}"

    [ -z "${repository}" ] && return 1
    dnf repolist --enabled 2>/dev/null | awk '{print $1}' | grep -qxF -e "${repository}"
}

enable_crb_repository() {
    # Enables the repository that EPEL packages routinely depend on. Its name, and the way to turn
    # it on, both change across the releases this script supports:
    #
    #   AlmaLinux / Rocky / CentOS 8      powertools
    #   AlmaLinux / Rocky / CentOS 9, 10  crb
    #   subscribed RHEL                   codeready-builder-for-rhel-<release>-<arch>-rpms, and it
    #                                     is a subscription-manager repository, not a dnf one
    #
    # On top of that, EL10 ships dnf5, whose config-manager dropped --set-enabled in favour of an
    # enable subcommand. Hardcoding "dnf config-manager --set-enabled crb" therefore only ever
    # worked on the EL9 clones, and failed silently everywhere else.
    #
    # The outcome is read back from dnf rather than taken from an exit code, so a repository that is
    # already on, which is the default on AlmaLinux 10 since 2025-09-09, is not called a failure.
    # Returns 0 when the repository ends up enabled, 1 otherwise
    local crb_repo

    if [ "${DIST}" = "rhel" ]; then
        crb_repo="codeready-builder-for-rhel-${RELEASE}-$(uname -m)-rpms"
    elif [ "${RELEASE}" -eq 8 ]; then
        crb_repo="powertools"
    else
        crb_repo="crb"
    fi

    if repository_is_enabled "${crb_repo}"; then
        log "Repository ${crb_repo} is already enabled"
        return 0
    fi

    log "Enabling repository ${crb_repo}"
    if [ "${DIST}" = "rhel" ]; then
        subscription-manager repos --enable "${crb_repo}" >> "${LOG_FILE}" 2>&1
    elif [ "${RELEASE}" -ge 10 ]; then
        # dnf5
        dnf config-manager enable "${crb_repo}" >> "${LOG_FILE}" 2>&1
    else
        dnf config-manager --set-enabled "${crb_repo}" >> "${LOG_FILE}" 2>&1
    fi

    if repository_is_enabled "${crb_repo}"; then
        log "Enabled repository ${crb_repo}"
        return 0
    fi
    log "Cannot enable repository ${crb_repo}, EPEL packages that depend on it may fail to install" "ERROR"
    return 1
}

disable_existing_ntp_sources() {
    # Comments out the time sources the distribution configured, so that only NTP_SERVERS is left.
    #
    # Three kinds of line are turned off: pool, server, and any sourcedir other than the one this
    # script writes into. That last exception matters: on Debian our own servers are read through
    # sourcedir /etc/chrony/sources.d, so disabling every sourcedir would switch off the very
    # servers we are configuring. On RHEL there is no such exception, we write to chrony.conf
    # directly, and the sourcedir that does get disabled is /run/chrony-dhcp, which is the point,
    # since a DHCP server could otherwise keep injecting time sources.
    #
    # Lines are commented rather than deleted, so the original configuration stays readable.
    # Servers this script itself configures are left alone, otherwise a second run would comment
    # them out and then add them back.
    #
    # Arguments: the main chrony configuration file, and the sourcedir to keep (may be empty)
    # Returns 0 on success, 1 otherwise
    local chrony_conf="${1}"
    local keep_sourcedir="${2}"
    local tmp_conf line directive rest sourcedir_path keep_line ntp_server
    local disabled=0
    local ntp_server_array=()

    if [ ! -f "${chrony_conf}" ]; then
        log "No ${chrony_conf}, cannot replace the existing NTP sources" "ERROR"
        return 1
    fi

    IFS=':' read -r -a ntp_server_array <<< "${NTP_SERVERS}"

    tmp_conf=$(mktemp) || {
        log "Cannot create a temporary copy of ${chrony_conf}" "ERROR"
        return 1
    }

    while IFS= read -r line || [ -n "${line}" ]; do
        # First word of the line, leading whitespace ignored. chrony directive names are not case
        # sensitive, so compare in lower case.
        read -r directive rest <<< "${line}"
        directive=$(printf '%s' "${directive}" | tr '[:upper:]' '[:lower:]')
        keep_line=true
        case "${directive}" in
            pool)
                keep_line=false
                ;;
            server)
                keep_line=false
                for ntp_server in "${ntp_server_array[@]}"; do
                    if [ -n "${ntp_server}" ] && [ "${line}" = "server ${ntp_server} iburst" ]; then
                        keep_line=true
                        break
                    fi
                done
                ;;
            sourcedir)
                sourcedir_path="${rest%%[[:space:]]*}"
                if [ -z "${keep_sourcedir}" ] || [ "${sourcedir_path}" != "${keep_sourcedir}" ]; then
                    keep_line=false
                fi
                ;;
        esac
        if [ "${keep_line}" = true ]; then
            printf '%s\n' "${line}" >> "${tmp_conf}"
        else
            printf '# Disabled by el_configurator, REPLACE_EXISTING_NTP is set: %s\n' "${line}" >> "${tmp_conf}"
            disabled=$((disabled + 1))
        fi
    done < "${chrony_conf}"

    # Written through the existing file rather than moved over it, which keeps its inode and so its
    # permissions and SELinux context
    if ! cat "${tmp_conf}" > "${chrony_conf}" 2>> "${LOG_FILE}"; then
        log "Cannot write ${chrony_conf}" "ERROR"
        rm -f "${tmp_conf}"
        return 1
    fi
    rm -f "${tmp_conf}"

    log "Disabled ${disabled} distribution time source line(s) in ${chrony_conf}"
    return 0
}

configure_ntp_servers() {
    # Adds the configured NTP servers to chrony's configuration.
    #
    # The paths are not interchangeable between distributions, and using the Debian ones on RHEL is
    # why this silently did nothing there for a long time. RHEL 8, 9 and 10 all read
    # /etc/chrony.conf, and their chrony package owns no sources directory at all: there is no
    # /etc/chrony/ and no /etc/chrony.d/. Debian keeps its configuration under /etc/chrony/ and
    # ships /etc/chrony/sources.d with a sourcedir directive already pointing at it.
    #
    # server is a repeatable directive, so set_conf_value is deliberately not used here. That helper
    # models a single valued key: it would rewrite the first matching line, which on RHEL means
    # collapsing the pool lines, or worse the sourcedir that feeds DHCP supplied time servers.
    # Lines are appended only when absent instead, which also makes a second run a no-op.
    #
    # Arguments: the chrony file to add the servers to
    # Returns 0 when every configured server is present in that file, 1 otherwise
    local ntp_file="${1}"
    local ntp_server ntp_line
    local missing=0
    local ntp_server_array=()

    if [ -z "${NTP_SERVERS}" ]; then
        return 0
    fi
    if [ ! -f "${ntp_file}" ] && [ ! -d "$(dirname "${ntp_file}")" ]; then
        log "Neither ${ntp_file} nor its directory exist, cannot configure NTP" "ERROR"
        return 1
    fi

    IFS=':' read -r -a ntp_server_array <<< "${NTP_SERVERS}"
    for ntp_server in "${ntp_server_array[@]}"; do
        [ -z "${ntp_server}" ] && continue
        ntp_line="server ${ntp_server} iburst"
        if grep -qFx -e "${ntp_line}" -- "${ntp_file}" 2>/dev/null; then
            log "NTP server ${ntp_server} is already configured in ${ntp_file}"
            continue
        fi
        echo "${ntp_line}" >> "${ntp_file}" 2>> "${LOG_FILE}"
        # Read back rather than trusting the redirection, so a read only or full filesystem is
        # reported instead of passing as configured
        if grep -qFx -e "${ntp_line}" -- "${ntp_file}" 2>/dev/null; then
            log "Added NTP server ${ntp_server} to ${ntp_file}"
        else
            log "Cannot add NTP server ${ntp_server} to ${ntp_file}" "ERROR"
            missing=$((missing + 1))
        fi
    done

    [ "${missing}" -eq 0 ]
}

configure_firewalld() {
    # Narrows firewalld to the configured whitelist, on RHEL and clones.
    #
    # The kickstart opens ssh to everyone with "firewall --enabled --service ssh", and this narrows
    # it: the whitelisted sources are bound to a permissive zone, then ssh and cockpit are taken off
    # the default zone so that nobody else reaches them.
    #
    # Every call is firewall-offline-cmd rather than firewall-cmd because this runs in the anaconda
    # %post chroot, where firewalld is installed but not running.
    #
    # The narrowing happens whether or not the sources bound. A hardening script that quietly leaves
    # ssh open to the world because one whitelist entry was malformed is worse than one that closes
    # it and says so. What did not bind is checked against the resulting configuration and reported
    # through the log, the failure banner and the prometheus state metric, for the operator to deal
    # with.
    #
    # Returns 0 when every whitelisted source is bound, 1 otherwise
    local whitelist_ip firewalld_zone
    local bound=0 expected=0
    local unbound=""
    local firewall_whitelist_ip_array=()

    if [ "${FIREWALL_WHITELIST_IP_LIST}" = "" ]; then
        # Nothing to narrow to. The kickstart's own "firewall --service ssh" is left standing.
        log "No firewall whitelist configured, leaving the default firewalld zone as it is"
        return 0
    fi

    IFS=':' read -r -a firewall_whitelist_ip_array <<< "${FIREWALL_WHITELIST_IP_LIST}"
    if [ "${FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS}" == true ]; then
        firewalld_zone=trusted
        log "Adding whitelisted IPs to firewalld in trusted zone"
    else
        firewalld_zone=dmz
        log "Adding generic ssh permission for whitelisted IPs to firewalld"
    fi

    for whitelist_ip in "${firewall_whitelist_ip_array[@]}"; do
        expected=$((expected + 1))
        # Deliberately not treating a non zero exit here as the failure: re-running this script
        # gives ALREADY_ENABLED for a source that is correctly bound, which used to log an ERROR on
        # every second run. What the configuration ends up holding is what matters, so ask it.
        firewall-offline-cmd --zone="${firewalld_zone}" --add-source="${whitelist_ip}" >> "${LOG_FILE}" 2>&1
        if firewall-offline-cmd --zone="${firewalld_zone}" --query-source="${whitelist_ip}" > /dev/null 2>&1; then
            bound=$((bound + 1))
        else
            unbound="${unbound}${unbound:+ }${whitelist_ip}"
        fi
    done

    if [ "${firewalld_zone}" = dmz ] && [ "${NODE_EXPORTER_USE_IP_WHITELISTS}" != false ]; then
        log "Adding node exporter whitelisted IPs to firewalld dmz zone"
        firewall-offline-cmd --zone=dmz --add-port=9100/tcp 2>> "${LOG_FILE}" || log "Failed to add node exporter to firewalld dmz zone" "ERROR"
    fi

    # Since we allow ip whitelists for all, we should disable ssh & cockpit allowance for everyone else
    # Using --zone=public here with firewall-offline-cmd results in "Can't use lokkit options with other options" error
    # Fortunately, the default zone is public
    firewall-offline-cmd --remove-service=ssh 2>> "${LOG_FILE}" || log "Failed to remove ssh from public zone in firewalld" "ERROR"
    firewall-offline-cmd --remove-service=cockpit 2>> "${LOG_FILE}" || log "Failed to remove cockpit from public zone in firewalld" "ERROR"

    if [ "${bound}" -eq "${expected}" ]; then
        log "Firewalld narrowed to ${bound} whitelisted source(s) in zone ${firewalld_zone}"
        return 0
    fi
    if [ "${bound}" -eq 0 ]; then
        log "None of the ${expected} whitelisted source(s) bound to firewalld zone ${firewalld_zone}, and ssh is now off the default zone: this machine will need console access. Unbound: ${unbound}" "ERROR"
    else
        log "Only ${bound} of ${expected} whitelisted source(s) bound to firewalld zone ${firewalld_zone}, and ssh is now off the default zone. Unbound: ${unbound}" "ERROR"
    fi
    return 1
}

configure_ufw() {
    # Sets up ufw from the configured whitelists, on Debian and derivatives.
    #
    # Rules go in before the firewall is switched on. ufw accepts them while it is inactive and
    # applies them when enabled, whereas enabling first leaves a window in which the default deny
    # policy is live with nothing allowed through, which drops the ssh session this script may well
    # be running in, and strands the machine if the run stops there.
    #
    # ufw_reachable counts only the rules that actually grant access to the machine, so a whitelist
    # ufw rejected outright cannot end with a firewall nobody can get past.
    #
    # Returns 0 when the firewall is enabled, 1 when it was deliberately left off
    local whitelist_ip
    local ufw_reachable=0
    local firewall_whitelist_ip_array=()

    if [ "${FIREWALL_WHITELIST_IP_LIST}" != "" ]; then
        IFS=':' read -r -a firewall_whitelist_ip_array <<< "${FIREWALL_WHITELIST_IP_LIST}"
        if [ "${FIREWALL_ALLOW_ALL_PORTS_ON_WHITELISTS}" == true ]; then
            log "Adding whitelisted IPs to ufw"
            for whitelist_ip in "${firewall_whitelist_ip_array[@]}"; do
                if /sbin/ufw allow from "${whitelist_ip}" 2>> "${LOG_FILE}"; then
                    ufw_reachable=$((ufw_reachable + 1))
                else
                    log "Failed to add ${whitelist_ip} to ufw whitelist" "ERROR"
                fi
            done
        else
            log "Adding generic ssh permission for whitelisted IPs to ufw"
            for whitelist_ip in "${firewall_whitelist_ip_array[@]}"; do
                if /sbin/ufw allow from "${whitelist_ip}" to any port 22 proto tcp 2>> "${LOG_FILE}"; then
                    ufw_reachable=$((ufw_reachable + 1))
                else
                    log "Failed to add ${whitelist_ip} to ufw ssh whitelist" "ERROR"
                fi
            done
            if [ "${NODE_EXPORTER_USE_IP_WHITELISTS}" != false ]; then
                log "Adding node exporter whitelisted IPs to ufw"
                # Metrics do not make the machine reachable, so these do not count
                for whitelist_ip in "${firewall_whitelist_ip_array[@]}"; do
                    /sbin/ufw allow from "${whitelist_ip}" to any port 9100 proto tcp 2>> "${LOG_FILE}" || log "Failed to add ${whitelist_ip} to ufw node exporter whitelist" "ERROR"
                done
            fi
        fi
    else
        log "Adding generic SSH port permission to ufw so we can work"
        if /sbin/ufw allow ssh 2>> "${LOG_FILE}"; then
            ufw_reachable=$((ufw_reachable + 1))
        else
            log "Failed to allow ssh in ufw" "ERROR"
        fi
    fi

    if [ "${ufw_reachable}" -eq 0 ]; then
        # An unfirewalled machine you can still log into beats a firewalled one you cannot. This
        # only happens when every rule was rejected, which means the whitelist itself is wrong.
        log "No ufw rule granting access was accepted, leaving the firewall disabled rather than locking this machine out. Check FIREWALL_WHITELIST_IP_LIST" "ERROR"
        return 1
    fi

    log "Enabling ufw with ${ufw_reachable} rule(s) granting access"
    systemctl enable ufw 2>> "${LOG_FILE}" || log "Failed to enable ufw service" "ERROR"
    systemctl start ufw 2>> "${LOG_FILE}" || log "Failed to start ufw" "ERROR"
    echo y | /sbin/ufw enable 2>> "${LOG_FILE}" || log "Failed to enable ufw" "ERROR"
    return 0
}

uniq_filelines() {
    filename="${1:-false}"

    if [ -f "${filename}" ]; then
        sort -u "${filename}" -o "${filename}" || log "Cannot make lines in file [${filename}] unique." "ERROR"
    fi
}

## Script entry point
POST_INSTALL_SCRIPT_GOOD=true

# Make debian dpkg happy when running via su
export PATH=$PATH:/sbin:/usr/sbin

get_kernel_arguments
get_el_version
is_virtual

if [ ${IS_VIRTUAL} = true ]; then
    EL_NAME=VMv${BRAND_VER}
else
    EL_NAME=PMv${BRAND_VER}
fi
cat << EOF > /etc/issue
${BRAND_NAME} ${EL_NAME}

IPv4 \4
IPv6 \6

EOF

# Apply CIS 1.7.3 Add /etc/issue.net file or remote login banners with minimal sys info
cat << EOF > /etc/issue.net
${BRAND_NAME} ${ISSUE_MESSAGE_EXTRA}
${REMOTE_LOGIN_BANNER}
EOF

check_internet
if [ $? -eq 0 ]; then
    if ! type curl > /dev/null 2>&1 && ! type wget > /dev/null 2>&1; then
        log "Let's try to download curl"
        if [ "${FLAVOR}" = "rhel" ]; then
            dnf install -y curl 2>> "${LOG_FILE}" || log "curl is missing and cannot be installed" "ERROR"
        elif [ "${FLAVOR}" = "debian" ]; then
            apt install -y curl 2>> "${LOG_FILE}" || log "curl is missing and cannot be installed" "ERROR"
        fi
    fi

    log "Updating system"
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf update -y 2>> "${LOG_FILE}" || log "Failed to update system" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        apt update -y 2>> "${LOG_FILE}" || log "Failed to update system" "ERROR"
        apt dist-upgrade -y 2>> "${LOG_FILE}" || log "Failed to update system" "ERROR"
    fi
fi

if [ "${SCAP_PROFILE}" != false ]; then  
    # Datastream oscap will be pointed at, eg /usr/share/xml/scap/ssg/content/ssg-debian13-ds.xml
    SSG_DATASTREAM="/usr/share/xml/scap/ssg/content/ssg-${DIST}${RELEASE}-ds.xml"
    # Disable --fetch-remote-resources on machines without internet
    if [ ! -d /root/openscap_report ]; then
        mkdir /root/openscap_report 2>> "${LOG_FILE}" || log "Failed to create /root/openscap_report directory" "ERROR"
    fi

    check_internet
    if [ $? -eq 0 ]; then
        # Let's reinstall openscap in case we're running this script on a non prepared machine
        if [ "${FLAVOR}" = "rhel" ]; then
            dnf install -y openscap scap-security-guide 2>> "${LOG_FILE}" || log "OpenSCAP is missing and cannot be installed" "ERROR"
        # Limit to debian only, no ubuntu support for openscap, so we need to check for DIST instead of simply FLAVOR to be debian
        elif [ "${FLAVOR}" = "debian" ] && [ "${DIST}" = "debian" ]; then
            log "Installing openscap utils"
            apt install -y openscap-utils 2>> "${LOG_FILE}" || log "OpenSCAP is missing and cannot be installed" "ERROR"
            install_ssg_content "${SSG_DATASTREAM}" || log "SCAP content is unavailable, remediation cannot run" "ERROR"
        else
            log_quit "Cannot setup OpenSCAP on this system"
        fi
        log "Setting up scap profile ${SCAP_PROFILE} with remote resources"

        # Note: on certain debian 12 setups, oscap is stuck forever with anssi_bp_28_high profile when doing FS checks
        # In that case, one can exclude the specific rules that are causing the issue until a stable SSG gets released
        #DEBIAN_12_SKIP_RULES="--skip-rule xccdf_org.ssgproject.content_rule_dir_perms_world_writable_sticky_bits --skip-rule xccdf_org.ssgproject.content_rule_dir_perms_world_writable_root_owned --skip-rule xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_world_writable --skip-rule xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned --skip-rule xccdf_org.ssgproject.content_rule_no_files_unowned_by_user --skip-rule xccdf_org.ssgproject.content_rule_accounts_users_home_files_groupownership --skip-rule xccdf_org.ssgproject.content_rule_accounts_users_home_files_ownership --skip-rule xccdf_org.ssgproject.content_rule_accounts_users_home_files_permissions
        #oscap xccdf eval --profile ${SCAP_PROFILE} ${DEBIAN_12_SKIP_RULES} --fetch-remote-resources --report "/root/openscap_report/${SCAP_PROFILE}_report_$(date '+%Y-%m-%d').html" --remediate "${SSG_DATASTREAM}" > /root/openscap_report/actions.log 2>&1
        
        oscap xccdf eval --profile ${SCAP_PROFILE} --fetch-remote-resources --report "/root/openscap_report/${SCAP_PROFILE}_report_$(date '+%Y-%m-%d').html" --remediate "${SSG_DATASTREAM}" > /root/openscap_report/actions.log 2>&1
        # exit code 2 means rules have been partially applied, which can be normal
        if [ $? -eq 1 ]; then
            log "OpenSCAP failed. See /root/openscap_report/actions.log" "ERROR"
        else
            log "Generating scap results with remote resources"
            oscap xccdf generate guide --fetch-remote-resources --profile ${SCAP_PROFILE} "${SSG_DATASTREAM}" > "/root/openscap_report/${SCAP_PROFILE}_guide_$(date '+%Y-%m-%d').html" 2>> "${LOG_FILE}"
            [ $? -ne 0 ] && log "OpenSCAP results failed. See log file" "ERROR"
        fi
    else
        log "Setting up scap profile ${SCAP_PROFILE} without internet"
        oscap xccdf eval --profile ${SCAP_PROFILE} --report "/root/openscap_report/${SCAP_PROFILE}_report_$(date '+%Y-%m-%d').html" --remediate "${SSG_DATASTREAM}" > /root/openscap_report/actions.log 2>&1
        if [ $? -eq 1 ]; then
            log "OpenSCAP failed. See /root/openscap_report/actions.log" "ERROR"
        else
            log "Generating scap results without internet"
            oscap xccdf generate guide --profile ${SCAP_PROFILE} "${SSG_DATASTREAM}" > "/root/openscap_report/${SCAP_PROFILE}_guide_$(date '+%Y-%m-%d').html" 2>> "${LOG_FILE}"
            [ $? -ne 0 ] && log "OpenSCAP results failed. See log file" "ERROR"
        fi
    fi

    # Fix firewall cannot load after anssi_bp28_high
    if [ "${SCAP_PROFILE}" = "anssi_bp28_high" ] && [ "${FLAVOR}" = "rhel" ]; then
        log "Fixing firewalld cannot load after anssi_bp28_high profile on ${FLAVOR}"
        setsebool -P secure_mode_insmod=off || log "Cannot set secure_mode_insmod to off" "ERROR"
    fi

    # Fix ssh logins don't work with RHEL 9.6 and RHEL 10 after anssi_bp28_high
    if [ "${SCAP_PROFILE}" = "anssi_bp28_high" ] && [ "${FLAVOR}" = "rhel" ] && [ "${RELEASE}" -ge 9 ]; then
        log "Fixing sshd not working after anssi_bp28_high profile on ${FLAVOR} ${RELEASE}"
        setsebool -P polyinstantiation_enabled 1 || log "Cannot configure SELinux polyinstantiation_enabled to 1" "ERROR"
    fi
else
    log "No SCAP profile selected. Skipping SCAP profile setup"
fi

if [ "${SETUP_SELINUX_DEBIAN}" != false ] && [ "${FLAVOR}" = "debian" ]; then
    log "Setting up SELinux on ${FLAVOR}"
    apt install -y selinux-basics selinux-policy-default auditd policycoreutils-python-utils 2>> "${LOG_FILE}" || log "Failed to install selinux tools" "ERROR"
    log "Activating SELinux"
    selinux-activate 2>> "${LOG_FILE}" || log "Failed to activate SELinux" "ERROR"
    log "Setting up SELinux to enforcing"
    selinux-config-enforcing 2>> "${LOG_FILE}" || log "Failed to set SELinux to enforcing" "ERROR"
fi

# Don't fetch dnf epel packages since it's not sure we get internet
# Setup EPEL and packages
check_internet
if [ $? -eq 0 ]; then
    log "Install available with internet. setting up additional packages."
    if  [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y tar >> "${LOG_FILE}" || log "Cannot install tar" "ERROR"
        dnf install -y epel-release 2>> "${LOG_FILE}" || log "Failed to install epel-release, some tools like fail2ban will not be installed" "ERROR"
        # We need to update after installing epel-release since it will update various packages
        dnf update -y 2>> "${LOG_FILE}" || log "Failed to update system after epel-release install" "ERROR"
        # The following packages are epel dependent
        # WIP: RHEL 10 has no atop package at the moment
        if [ "${RELEASE}" -eq 10 ]; then
            available_packages="htop nmon iftop iptraf"
        else
            available_packages="htop atop nmon iftop iptraf"
        fi
        # We actually want word splitting here
        # shellcheck disable=SC2086
        dnf install -y ${available_packages} 2>> "${LOG_FILE}" || log "Failed to install additional tools ${available_packages}" "ERROR"
        enable_crb_repository
        if [ "${CONFIGURE_AUTOMATIC_UPDATES}" != false ]; then
            dnf install -y dnf-automatic 2>> "${LOG_FILE}" || log "Failed to install dnf-automatic" "ERROR"
        fi
        if [ "${CONFIGURE_TUNED}" != false ]; then
            dnf install -y tuned 2>> "${LOG_FILE}" || log "Failed to install tuned" "ERROR"
        fi
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y tar 2>> "${LOG_FILE}" || log "Cannot install tar" "ERROR"
        apt install -y htop atop nmon iftop iptraf-ng  tar 2>> "${LOG_FILE}" || log "Failed to install additional tools" "ERROR"
        if [ "${CONFIGURE_AUTOMATIC_UPDATES}" != false ]; then
            apt install -y unattended-upgrades 2>> "${LOG_FILE}" || log "Failed to install unattended-upgrades" "ERROR"
        fi
        if [ "${CONFIGURE_TUNED}" != false ]; then
            apt install -y tuned 2>> "${LOG_FILE}" || log "Failed to install tuned" "ERROR"
        fi
    fi
else
    log "No epel available without internet. Didn't install additional packages."
fi

if [ ${IS_VIRTUAL} != true ]; then
    log "Setting up disk SMART tooling"
    # Make sure we install smartmontools even if already present
    SMARTD_SYSTEMD_SERVICE=smartd
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y smartmontools nvme-cli 2>> "${LOG_FILE}" || log "Failed to install smartmontools" "ERROR"
        SMARTD_CONF_FILE=/etc/smartmontools/smartd.conf
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y smartmontools nvme-cli 2>> "${LOG_FILE}" || log "Failed to install smartmontools" "ERROR"
        SMARTD_CONF_FILE=/etc/smartd.conf
        # Override smartd service name for debian 13+ which became smartmontools instead of smartd
        if [ "${RELEASE}" -ge 13 ]; then
            SMARTD_SYSTEMD_SERVICE=smartmontools
        fi
    fi

    if [ ! -f "${SMARTD_CONF_FILE}" ]; then
        log "Cannot find smartd configuration file at ${SMARTD_CONF_FILE}" "ERROR"
    fi
    # Deactivate any existing DEVICESCAN entries since only the first one gets executed
    sed -i 's/^DEVICESCAN/# DEVICESCAN/g' "${SMARTD_CONF_FILE}" >> "${LOG_FILE}" 2>&1
    # Add our basic devicescan entry
    echo "DEVICESCAN -H -l error -f -C 197+ -U 198+ -t -l selftest -I 194 -n sleep,7,q -s (S/../.././10|L/../../[5]/13)" >> "${SMARTD_CONF_FILE}" 2>> "${LOG_FILE}" || log "Failed to add DEVICESCAN to smartd.conf" "ERROR"
    uniq_filelines "${SMARTD_CONF_FILE}"
    systemctl enable ${SMARTD_SYSTEMD_SERVICE} 2>> "${LOG_FILE}" || log "Failed to start smartd" "ERROR"

    if [ "${CONFIGURE_NODE_EXPORTER_PYTHON_EXTENSIONS}" = true ] && [ "${IS_VIRTUAL}" != true ]; then
        log "Setting up python smartmontools / nvme tooling for prometheus"
        if [ "${FLAVOR}" = "rhel" ]; then
            # As of 2025-09-23, there is no python3-prometheus_client package so we have to bootstrap in from python on RHEL10
            if [ "${RELEASE}" -eq 10 ]; then
                dnf install -y python3-pip 2>> "${LOG_FILE}" || log "Failed to install python3 and pip3" "ERROR"
                python3 -m pip install --root-user-action ignore --upgrade pip setuptools wheel 2>> "${LOG_FILE}" || log "Failed to upgrade pip3" "ERROR"
                python3 -m pip install --root-user-action ignore prometheus_client 2>> "${LOG_FILE}" || log "Failed to add prometheus_client lib" "ERROR"
            else
                dnf install -y python3-prometheus_client 2>> "${LOG_FILE}" || log "Failed to add prometheus_client lib" "ERROR"
            fi
        elif [ "${FLAVOR}" = "debian" ]; then
            # Debian does not come with ensurepip but has prometheus-client library
            apt install -y python3-prometheus-client 2>> "${LOG_FILE}" || log "Failed to install python3 and pip3" "ERROR"
        fi
        log "Setting up python smart script for prometheus"

        # smartmon.py + PR270 from https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/pull/270
        cat << 'EOF' > /usr/local/bin/smartmon.py
#!/usr/bin/env python3

"""
Formatted with Black:
$ black -l 100 nvme_metrics.py
"""

import argparse
import collections
import csv
import re
import shlex
import subprocess
import sys
from prometheus_client import CollectorRegistry, Gauge, generate_latest

device_info_re = re.compile(r"^(?P<k>[^:]+?)(?:(?:\sis|):)\s*(?P<v>.*)$")
COMPAT_DISK_LABELS = False

ata_error_count_re = re.compile(r"^Error (\d+) \[\d+\] occurred", re.MULTILINE)

self_test_re = re.compile(r"^SMART.*(PASSED|OK)$", re.MULTILINE)

device_info_map = {
    "Vendor": "vendor",
    "Product": "product",
    "Revision": "revision",
    "Logical Unit id": "lun_id",
    "Model Family": "model_family",
    "Device Model": "device_model",
    "Serial Number": "serial_number",
    "Serial number": "serial_number",
    "Firmware Version": "firmware_version",
}

smart_attributes_whitelist = (
    "airflow_temperature_cel",
    "command_timeout",
    "current_pending_sector",
    "end_to_end_error",
    "erase_fail_count_total",
    "g_sense_error_rate",
    "hardware_ecc_recovered",
    "host_reads_mib",
    "host_reads_32mib",
    "host_writes_mib",
    "host_writes_32mib",
    "load_cycle_count",
    "lifetime_writes_gib",
    "media_wearout_indicator",
    "percent_lifetime_remain",
    "wear_leveling_count",
    "nand_writes_1gib",
    "offline_uncorrectable",
    "percent_lifetime_remain",
    "power_cycle_count",
    "power_on_hours",
    "program_fail_count",
    "raw_read_error_rate",
    "reallocated_event_count",
    "reallocated_sector_ct",
    "reported_uncorrect",
    "sata_downshift_count",
    "seek_error_rate",
    "spin_retry_count",
    "spin_up_time",
    "start_stop_count",
    "temperature_case",
    "temperature_celsius",
    "temperature_internal",
    "total_bad_block",
    "total_lbas_read",
    "total_lbas_written",
    "total_writes_gib",
    "total_reads_gib",
    "udma_crc_error_count",
    "unsafe_shutdown_count",
    "unexpect_power_loss_ct",
    "workld_host_reads_perc",
    "workld_media_wear_indic",
    "workload_minutes",
)

registry = CollectorRegistry()
namespace = "smartmon"

metrics = {
    "smartctl_version": Gauge(
        "smartctl_version",
        "SMART metric smartctl_version",
        ["version"],
        namespace=namespace,
        registry=registry,
    ),
    "smartctl_run": Gauge(
        "smartctl_run",
        "SMART metric smartctl_run",
        ["device", "disk"],
        namespace=namespace,
        registry=registry,
    ),
    "device_active": Gauge(
        "device_active",
        "SMART metric device_active",
        ["device", "disk"],
        namespace=namespace,
        registry=registry,
    ),
    "device_info": Gauge(
        "device_info",
        "SMART metric device_info",
        [
            "device",
            "disk",
            "vendor",
            "product",
            "revision",
            "lun_id",
            "model_family",
            "device_model",
            "serial_number",
            "firmware_version",
        ],
        namespace=namespace,
        registry=registry,
    ),
    "device_smart_available": Gauge(
        "device_smart_available",
        "SMART metric device_smart_available",
        ["device", "disk"],
        namespace=namespace,
        registry=registry,
    ),
    "device_smart_enabled": Gauge(
        "device_smart_enabled",
        "SMART metric device_smart_enabled",
        ["device", "disk"],
        namespace=namespace,
        registry=registry,
    ),
    "device_smart_healthy": Gauge(
        "device_smart_healthy",
        "SMART metric device_smart_healthy",
        ["device", "disk"],
        namespace=namespace,
        registry=registry,
    ),
    # SMART attributes - ATA disks only
    "attr_value": Gauge(
        "attr_value",
        "SMART metric attr_value",
        ["device", "disk", "name"],
        namespace=namespace,
        registry=registry,
    ),
    "attr_worst": Gauge(
        "attr_worst",
        "SMART metric attr_worst",
        ["device", "disk", "name"],
        namespace=namespace,
        registry=registry,
    ),
    "attr_threshold": Gauge(
        "attr_threshold",
        "SMART metric attr_threshold",
        ["device", "disk", "name"],
        namespace=namespace,
        registry=registry,
    ),
    "attr_raw_value": Gauge(
        "attr_raw_value",
        "SMART metric attr_raw_value",
        ["device", "disk", "name"],
        namespace=namespace,
        registry=registry,
    ),
    "device_errors": Gauge(
        "device_errors",
        "SMART metric device_errors",
        ["device", "disk"],
        namespace=namespace,
        registry=registry,
    ),
}

SmartAttribute = collections.namedtuple(
    "SmartAttribute",
    [
        "id",
        "name",
        "flag",
        "value",
        "worst",
        "threshold",
        "type",
        "updated",
        "when_failed",
        "raw_value",
    ],
)


class Device(collections.namedtuple("DeviceBase", "path opts")):
    """Representation of a device as found by smartctl --scan output."""

    @property
    def type(self):
        return self.opts.type

    @property
    def base_labels(self):
        if COMPAT_DISK_LABELS:
            return {"disk": self.path, "device": self.type.partition("+")[2] or "0"}
        return {"device": self.path, "disk": self.type.partition("+")[2] or "0"}

    def smartctl_select(self):
        return ["--device", self.type, self.path]


def smart_ctl(*args, check=True):
    """Wrapper around invoking the smartctl binary.

    Returns:
        (str) Data piped to stdout by the smartctl subprocess.
    """
    return subprocess.run(["smartctl", *args], stdout=subprocess.PIPE, check=check).stdout.decode(
        "utf-8"
    )


def smart_ctl_version():
    return smart_ctl("-V").split("\n")[0].split()[1]


def find_devices(by_id):
    """Find SMART devices.

    Yields:
        (Device) Single device found by smartctl.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--device", dest="type")

    args = ["--scan-open"]
    if by_id:
        args.extend(["-d", "by-id"])
    devices = smart_ctl(*args)

    for device in devices.split("\n"):
        device = device.strip()
        if not device:
            continue

        tokens = shlex.split(device, comments=True)
        if not tokens:
            continue

        yield Device(tokens[0], parser.parse_args(tokens[1:]))


def device_is_active(device):
    """Returns whenever the given device is currently active or not.

    Args:
        device: (Device) Device in question.

    Returns:
        (bool) True if the device is active and False otherwise.
    """
    try:
        smart_ctl("--nocheck", "standby", *device.smartctl_select())
    except subprocess.CalledProcessError:
        return False

    return True


def device_info(device):
    """Query device for basic model information.

    Args:
        device: (Device) Device in question.

    Returns:
        (generator): Generator yielding:

            key (str): Key describing the value.
            value (str): Actual value.
    """
    info_lines = smart_ctl("--info", *device.smartctl_select()).strip().split("\n")[3:]

    matches = (device_info_re.match(line) for line in info_lines)
    return (m.groups() for m in matches if m is not None)


def device_smart_capabilities(device):
    """Returns SMART capabilities of the given device.

    Args:
        device: (Device) Device in question.

    Returns:
        (tuple): tuple containing:

            (bool): True whenever SMART is available, False otherwise.
            (bool): True whenever SMART is enabled, False otherwise.
    """
    groups = device_info(device)

    state = {g[1].split(" ", 1)[0] for g in groups if g[0] == "SMART support"}

    smart_available = "Available" in state
    smart_enabled = "Enabled" in state

    return smart_available, smart_enabled


def collect_device_info(device):
    """Collect basic device information.

    Args:
        device: (Device) Device in question.
    """
    values = dict(device_info(device))
    metrics["device_info"].labels(
        device.base_labels["device"],
        device.base_labels["disk"],
        values.get("Vendor", ""),
        values.get("Product", ""),
        values.get("Revision", ""),
        values.get("Logical Unit id", ""),
        values.get("Model Family", ""),
        values.get("Device Model", ""),
        values.get("Serial Number", ""),
        values.get("Firmware Version", ""),
    ).set(1)


def collect_device_health_self_assessment(device):
    """Collect metric about the device health self assessment.

    Args:
        device: (Device) Device in question.
    """
    out = smart_ctl("--health", *device.smartctl_select(), check=False)

    self_assessment_passed = bool(self_test_re.search(out))
    metrics["device_smart_healthy"].labels(
        device.base_labels["device"], device.base_labels["disk"]
    ).set(self_assessment_passed)


def collect_ata_metrics(device):
    # Fetch SMART attributes for the given device.
    attributes = smart_ctl("--attributes", *device.smartctl_select())

    # replace multiple occurrences of whitespace with a single whitespace
    # so that the CSV Parser recognizes individual columns properly.
    attributes = re.sub(r"[\t\x20]+", " ", attributes)

    # Turn smartctl output into a list of lines and skip to the table of
    # SMART attributes.
    attribute_lines = attributes.strip().split("\n")[7:]

    # Some attributes have multiple IDs but have the same name.  Don't
    # yield attributes that already have been reported before.
    seen = set()

    reader = csv.DictReader(
        (line.strip() for line in attribute_lines),
        fieldnames=SmartAttribute._fields[:-1],
        restkey=SmartAttribute._fields[-1],
        delimiter=" ",
    )
    for entry in reader:
        # We're only interested in the SMART attributes that are
        # whitelisted here.
        entry["name"] = entry["name"].lower()
        if entry["name"] not in smart_attributes_whitelist:
            continue

        # Ensure that only the numeric parts are fetched from the raw_value.
        # Attributes such as 194 Temperature_Celsius reported by my SSD
        # are in the format of "36 (Min/Max 24/40)" which can't be expressed
        # properly as a prometheus metric.
        m = re.match(r"^(\d+)", " ".join(entry["raw_value"]))
        if not m:
            continue
        entry["raw_value"] = m.group(1)

        # Some device models report "---" in the threshold value where most
        # devices would report "000". We do the substitution here because
        # downstream code expects values to be convertible to integer.
        if entry["threshold"] == "---":
            entry["threshold"] = "0"

        if entry["name"] in smart_attributes_whitelist and entry["name"] not in seen:
            for col in "value", "worst", "threshold", "raw_value":
                metrics["attr_" + col].labels(
                    device.base_labels["device"],
                    device.base_labels["disk"],
                    entry["name"],
                ).set(entry[col])

            seen.add(entry["name"])


def collect_ata_error_count(device):
    """Inspect the device error log and report the amount of entries.

    Args:
        device: (Device) Device in question.
    """
    error_log = smart_ctl("-l", "xerror,1", *device.smartctl_select(), check=False)

    m = ata_error_count_re.search(error_log)

    error_count = m.group(1) if m is not None else 0
    metrics["device_errors"].labels(device.base_labels["device"], device.base_labels["disk"]).set(
        error_count
    )


def collect_disks_smart_metrics(wakeup_disks, by_id):
    for device in find_devices(by_id):
        is_active = device_is_active(device)
        metrics["device_active"].labels(
            device.base_labels["device"],
            device.base_labels["disk"],
        ).set(is_active)

        # Skip further metrics collection to prevent the disk from spinning up.
        if not is_active and not wakeup_disks:
            continue

        collect_device_info(device)

        smart_available, smart_enabled = device_smart_capabilities(device)

        metrics["device_smart_available"].labels(
            device.base_labels["device"], device.base_labels["disk"]
        ).set(smart_available)

        metrics["device_smart_enabled"].labels(
            device.base_labels["device"], device.base_labels["disk"]
        ).set(smart_enabled)

        # Skip further metrics collection here if SMART is disabled on the device. Further smartctl
        # invocations would fail anyway.
        if not smart_available:
            continue

        collect_device_health_self_assessment(device)

        if device.type.startswith("sat"):
            collect_ata_metrics(device)
            collect_ata_error_count(device)


def main():
    global COMPAT_DISK_LABELS

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--wakeup-disks",
        dest="wakeup_disks",
        action="store_true",
        help="Wake up disks to collect live stats",
    )
    parser.add_argument(
        "--by-id",
        dest="by_id",
        action="store_true",
        help="Use /dev/disk/by-id/X instead of /dev/sdX to index devices",
    )
    parser.add_argument(
        "--compat-disk-labels",
        dest="compat_disk_labels",
        action="store_true",
        help="Invert disk and device labels to be retrocompatible with shell implementation",
    )
    args = parser.parse_args(sys.argv[1:])

    COMPAT_DISK_LABELS = args.compat_disk_labels

    metrics["smartctl_version"].labels(smart_ctl_version()).set(1)

    collect_disks_smart_metrics(args.wakeup_disks, args.by_id)
    print(generate_latest(registry).decode(), end="")


if __name__ == "__main__":
    main()
EOF

        # https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/pull/256
        # Added PR #256
        cat << 'EOF' > /usr/local/bin/nvme_metrics.py
#!/usr/bin/env python3

"""
NVMe device metrics textfile collector.
Requires nvme-cli package.

Formatted with Black:
$ black -l 100 nvme_metrics.py
"""

import json
import os
import re
import sys
import subprocess

# Disable automatic addition of _created series. Must be set before importing prometheus_client.
os.environ["PROMETHEUS_DISABLE_CREATED_SERIES"] = "true"

from prometheus_client import CollectorRegistry, Counter, Gauge, Info, generate_latest  # noqa: E402

registry = CollectorRegistry()
namespace = "nvme"

metrics = {
    # fmt: off
    "avail_spare": Gauge(
        "available_spare_ratio",
        "Device available spare ratio",
        ["device"], namespace=namespace, registry=registry,
    ),
    "controller_busy_time": Counter(
        "controller_busy_time_seconds",
        "Device controller busy time in seconds",
        ["device"], namespace=namespace, registry=registry,
    ),
    "critical_warning": Gauge(
        "critical_warning",
        "Device critical warning bitmap field",
        ["device"], namespace=namespace, registry=registry,
    ),
    "data_units_read": Counter(
        "data_units_read_total",
        "Number of 512-byte data units read by host, reported in thousands",
        ["device"], namespace=namespace, registry=registry,
    ),
    "data_units_written": Counter(
        "data_units_written_total",
        "Number of 512-byte data units written by host, reported in thousands",
        ["device"], namespace=namespace, registry=registry,
    ),
    "device_info": Info(
        "device",
        "Device information",
        ["device", "model", "firmware", "serial"], namespace=namespace, registry=registry,
    ),
    "host_read_commands": Counter(
        "host_read_commands_total",
        "Device read commands from host",
        ["device"], namespace=namespace, registry=registry,
    ),
    "host_write_commands": Counter(
        "host_write_commands_total",
        "Device write commands from host (generally in 512b blocks)",
        ["device"], namespace=namespace, registry=registry,
    ),
    "media_errors": Counter(
        "media_errors_total",
        "Device media errors total",
        ["device"], namespace=namespace, registry=registry,
    ),
    "num_err_log_entries": Counter(
        "num_err_log_entries_total",
        "Device error log entry count",
        ["device"], namespace=namespace, registry=registry,
    ),
    # FIXME: The "nvmecli" metric ought to be an Info type, not a Gauge. However, making this change
    # will result in the metric having a "_info" suffix automatically appended, which is arguably
    # a breaking change.
    "nvmecli": Gauge(
        "nvmecli",
        "nvme-cli tool information",
        ["version"], namespace=namespace, registry=registry,
    ),
    "percent_used": Gauge(
        "percentage_used_ratio",
        "Device percentage used ratio",
        ["device"], namespace=namespace, registry=registry,
    ),
    "physical_size": Gauge(
        "physical_size_bytes",
        "Device size in bytes",
        ["device"], namespace=namespace, registry=registry,
    ),
    "power_cycles": Counter(
        "power_cycles_total",
        "Device number of power cycles",
        ["device"], namespace=namespace, registry=registry,
    ),
    "power_on_hours": Counter(
        "power_on_hours_total",
        "Device power-on hours",
        ["device"], namespace=namespace, registry=registry,
    ),
    "sector_size": Gauge(
        "sector_size_bytes",
        "Device sector size in bytes",
        ["device"], namespace=namespace, registry=registry,
    ),
    "spare_thresh": Gauge(
        "available_spare_threshold_ratio",
        "Device available spare threshold ratio",
        ["device"], namespace=namespace, registry=registry,
    ),
    "temperature": Gauge(
        "temperature_celsius",
        "Device temperature in degrees Celsius",
        ["device"], namespace=namespace, registry=registry,
    ),
    "unsafe_shutdowns": Counter(
        "unsafe_shutdowns_total",
        "Device number of unsafe shutdowns",
        ["device"], namespace=namespace, registry=registry,
    ),
    "used_bytes": Gauge(
        "used_bytes",
        "Device used size in bytes",
        ["device"], namespace=namespace, registry=registry,
    ),
    "physical_media_units_read": Gauge(
        "physical_media_units_read",
        "Physical media units read in bytes",
        ["device"], namespace=namespace, registry=registry,
    ),
    "physical_media_units_written": Gauge(
        "physical_media_units_written",
        "Physical media units written in bytes",
        ["device"], namespace=namespace, registry=registry,
    ),
    # fmt: on
}


def nvme_has_verbose():
    """
    Old nvme-cli versions like 2.3 on Debian 12 don't have --verbose for smart-log command
    We need to check if --verbose is supported. This command will report usage to stderr
    Consider we have a recent version if something goes wrong
    """
    try:
        result = subprocess.run(["nvme", "smart-log", "--help"], check=False, capture_output=True)
        if "--verbose" not in str(result.stderr):
            return False
        return True
    except subprocess.CalledProcessError:
        return True


def exec_nvme(*args):
    """
    Execute nvme CLI tool with specified arguments and return captured stdout result. Set LC_ALL=C
    in child process environment so that the nvme tool does not perform any locale-specific number
    or date formatting, etc.
    """
    cmd = ["nvme", *args]
    return subprocess.check_output(cmd, stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"))


def exec_nvme_json(*args, has_verbose=False, allow_errors=False):
    """
    Execute nvme CLI tool with specified arguments and return parsed JSON output.
    """
    # Note: nvme-cli v2.11 effectively introduced a breaking change by forcing JSON output to always
    # be verbose. Older versions of nvme-cli optionally produced verbose output if the --verbose
    # flag was specified. In order to avoid having to handle two different JSON schemas, always
    # add the --verbose flag.
    # Note2: nvme-cli 2.3 that ships with Debian 12 has
    # no verbose parameter for smart-log command only

    try:
        if has_verbose:
            output = exec_nvme(*args, "--output-format", "json", "--verbose")
        else:
            output = exec_nvme(*args, "--output-format", "json")
        if isinstance(output, bytes):
            output = output.decode("utf-8")
        output = re.sub(r"\\n\S+", "", output)
    except subprocess.CalledProcessError as exc:
        try:
            output = json.loads(exc.output)
            if "Failed to scan topology" in output["error"]:
                return {"Devices": []}
        except json.JSONDecodeError:
            if not allow_errors:
                raise ValueError("Cannot parse nvme binary output")
            else:
                return {}
    return json.loads(output)


def main():
    match = re.match(r"^nvme version (\S+)", exec_nvme("version").decode())
    if match:
        cli_version = match.group(1)
    else:
        cli_version = "unknown"
    metrics["nvmecli"].labels(cli_version).set(1)

    has_verbose = nvme_has_verbose()
    device_list = exec_nvme_json("list", has_verbose=has_verbose)

    for device in device_list["Devices"]:
        for subsys in device["Subsystems"]:
            for ctrl in subsys["Controllers"]:
                for ns in ctrl["Namespaces"]:
                    device_name = ns["NameSpace"]

                    # FIXME: This metric ought to be refactored into a "controller_info" metric,
                    # since it contains information that is not unique to the namespace. However,
                    # previous versions of this collector erroneously referred to namespaces, e.g.
                    # "nvme0n1", as devices, so preserve the former behaviour for now.
                    metrics["device_info"].labels(
                        device_name,
                        ctrl["ModelNumber"],
                        ctrl["Firmware"],
                        ctrl["SerialNumber"].strip(),
                    )

                    metrics["sector_size"].labels(device_name).set(ns["SectorSize"])
                    metrics["physical_size"].labels(device_name).set(ns["PhysicalSize"])
                    metrics["used_bytes"].labels(device_name).set(ns["UsedBytes"])

                    # FIXME: The smart-log should only need to be fetched once per controller, not
                    # per namespace. However, in order to preserve legacy metric labels, fetch it
                    # per namespace anyway. Most consumer grade SSDs will only have one namespace.
                    smart_log = exec_nvme_json(
                        "smart-log", os.path.join("/dev", device_name), has_verbose=has_verbose
                    )
                    ocp_log = exec_nvme_json(
                        "ocp",
                        "smart-add-log",
                        os.path.join("/dev", device_name),
                        has_verbose=False,
                        allow_errors=True,
                    )

                    # Various counters in the NVMe specification are 128-bit, which would have to
                    # discard resolution if converted to a JSON number (i.e., float64_t). Instead,
                    # nvme-cli marshals them as strings. As such, they need to be explicitly cast
                    # to int or float when using them in Counter metrics.
                    metrics["data_units_read"].labels(device_name).inc(
                        int(smart_log["data_units_read"])
                    )
                    metrics["data_units_written"].labels(device_name).inc(
                        int(smart_log["data_units_written"])
                    )
                    metrics["host_read_commands"].labels(device_name).inc(
                        int(smart_log["host_read_commands"])
                    )
                    metrics["host_write_commands"].labels(device_name).inc(
                        int(smart_log["host_write_commands"])
                    )
                    metrics["avail_spare"].labels(device_name).set(smart_log["avail_spare"] / 100)
                    metrics["spare_thresh"].labels(device_name).set(smart_log["spare_thresh"] / 100)
                    metrics["percent_used"].labels(device_name).set(smart_log["percent_used"] / 100)
                    if has_verbose:
                        metrics["critical_warning"].labels(device_name).set(
                            smart_log["critical_warning"]["value"]
                        )
                    else:
                        metrics["critical_warning"].labels(device_name).set(
                            smart_log["critical_warning"]
                        )
                    metrics["media_errors"].labels(device_name).inc(int(smart_log["media_errors"]))
                    metrics["num_err_log_entries"].labels(device_name).inc(
                        int(smart_log["num_err_log_entries"])
                    )
                    metrics["power_cycles"].labels(device_name).inc(int(smart_log["power_cycles"]))
                    metrics["power_on_hours"].labels(device_name).inc(
                        int(smart_log["power_on_hours"])
                    )
                    metrics["controller_busy_time"].labels(device_name).inc(
                        int(smart_log["controller_busy_time"])
                    )
                    metrics["unsafe_shutdowns"].labels(device_name).inc(
                        int(smart_log["unsafe_shutdowns"])
                    )

                    # NVMe reports temperature in kelvins; convert it to degrees Celsius.
                    metrics["temperature"].labels(device_name).set(smart_log["temperature"] - 273)

                    # Optional OCP data
                    try:
                        metrics["physical_media_units_read"].labels(device_name).set(
                            ocp_log["Physical media units read"]["lo"]
                        )
                    except (AttributeError, IndexError, TypeError, KeyError):
                        metrics["physical_media_units_read"].labels(device_name).set(-1)
                    try:
                        metrics["physical_media_units_written"].labels(device_name).set(
                            ocp_log["Physical media units written"]["lo"]
                        )
                    except (AttributeError, IndexError, TypeError, KeyError):
                        metrics["physical_media_units_written"].labels(device_name).set(-1)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: script requires root privileges", file=sys.stderr)
        sys.exit(1)

    # Check if nvme-cli is installed
    try:
        exec_nvme()
    except FileNotFoundError:
        print("ERROR: nvme-cli is not installed. Aborting.", file=sys.stderr)
        sys.exit(1)

    try:
        main()
    except Exception as e:
        print("ERROR: {}".format(e), file=sys.stderr)
        raise
        sys.exit(1)

    print(generate_latest(registry).decode(), end="")
EOF
[ $? -ne 0 ] && log "Failed to create /usr/local/bin/nvme_metrics.py" "ERROR"
        log "Setting up smart & nvme for prometheus task"
        if [ ! -d /var/lib/node_exporter/textfile_collector ]; then
            mkdir -p /var/lib/node_exporter/textfile_collector 2>> "${LOG_FILE}" || log "Failed to create /var/lib/node_exporter/textfile_collector directory" "ERROR"
        fi
        echo -e "MAILTO=\"\"\nPATH=\"/usr/sbin:/usr/bin\"\n*/5 * * * * root python3 /usr/local/bin/smartmon.py > /var/lib/node_exporter/textfile_collector/smart_metrics.prom" > /etc/cron.d/smartmon_metrics 2>> "${LOG_FILE}" || log "Failed to add smartmon cron job" "ERROR"
        echo -e "MAILTO=\"\"\nPATH=\"/usr/sbin:/usr/bin\"\n*/5 * * * * root python3 /usr/local/bin/nvme_metrics.py > /var/lib/node_exporter/textfile_collector/nvme_metrics.prom" > /etc/cron.d/nvme_metrics 2>> "${LOG_FILE}" || log "Failed to add nvme metrics cron job" "ERROR"

    else
        log "Setting up bash smart script for prometheus"

        # https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/commit/6e26d97df7ee48880255dc3ec91e34128bfd2fb1
        # 2024-10-23
        cat << 'EOF' > /usr/local/bin/smartmon.sh
#!/usr/bin/env bash
#
# Script informed by the collectd monitoring script for smartmontools (using smartctl)
# by Samuel B. <samuel_._behan_(at)_dob_._sk> (c) 2012
# source at: http://devel.dob.sk/collectd-scripts/

# TODO: This probably needs to be a little more complex.  The raw numbers can have more
#       data in them than you'd think.
#       http://arstechnica.com/civis/viewtopic.php?p=22062211

# Formatting done via shfmt -i 2
# https://github.com/mvdan/sh

# Ensure predictable numeric / date formats, etc.
export LC_ALL=C

parse_smartctl_attributes_awk="$(
  cat <<'SMARTCTLAWK'
$1 ~ /^ *[0-9]+$/ && $2 ~ /^[a-zA-Z0-9_-]+$/ {
  gsub(/-/, "_");
  printf "%s_value{%s,smart_id=\"%s\"} %d\n", $2, labels, $1, $4
  printf "%s_worst{%s,smart_id=\"%s\"} %d\n", $2, labels, $1, $5
  printf "%s_threshold{%s,smart_id=\"%s\"} %d\n", $2, labels, $1, $6
  printf "%s_raw_value{%s,smart_id=\"%s\"} %e\n", $2, labels, $1, $10
}
SMARTCTLAWK
)"

smartmon_attrs="$(
  cat <<'SMARTMONATTRS'
airflow_temperature_cel
command_timeout
current_pending_sector
end_to_end_error
erase_fail_count
g_sense_error_rate
hardware_ecc_recovered
host_reads_32mib
host_reads_mib
host_writes_32mib
host_writes_mib
load_cycle_count
media_wearout_indicator
nand_writes_1gib
offline_uncorrectable
percent_lifetime_remain
power_cycle_count
power_on_hours
program_fail_cnt_total
program_fail_count
raw_read_error_rate
reallocated_event_count
reallocated_sector_ct
reported_uncorrect
runtime_bad_block
sata_downshift_count
seek_error_rate
spin_retry_count
spin_up_time
start_stop_count
temperature_case
temperature_celsius
temperature_internal
total_lbas_read
total_lbas_written
udma_crc_error_count
unsafe_shutdown_count
unused_rsvd_blk_cnt_tot
wear_leveling_count
workld_host_reads_perc
workld_media_wear_indic
workload_minutes
SMARTMONATTRS
)"
smartmon_attrs="$(echo "${smartmon_attrs}" | xargs | tr ' ' '|')"

parse_smartctl_attributes() {
  local disk="$1"
  local disk_type="$2"
  local labels="disk=\"${disk}\",type=\"${disk_type}\""
  sed 's/^ \+//g' |
    awk -v labels="${labels}" "${parse_smartctl_attributes_awk}" 2>/dev/null |
    tr '[:upper:]' '[:lower:]' |
    grep -E "(${smartmon_attrs})"
}

parse_smartctl_scsi_attributes() {
  local disk="$1"
  local disk_type="$2"
  local labels="disk=\"${disk}\",type=\"${disk_type}\""
  while read -r line; do
    attr_type="$(echo "${line}" | tr '=' ':' | cut -f1 -d: | sed 's/^ \+//g' | tr ' ' '_')"
    attr_value="$(echo "${line}" | tr '=' ':' | cut -f2 -d: | sed 's/^ \+//g')"
    case "${attr_type}" in
    number_of_hours_powered_up_) power_on="$(echo "${attr_value}" | awk '{ printf "%e\n", $1 }')" ;;
    Current_Drive_Temperature) temp_cel="$(echo "${attr_value}" | cut -f1 -d' ' | awk '{ printf "%e\n", $1 }')" ;;
    Blocks_sent_to_initiator_) lbas_read="$(echo "${attr_value}" | awk '{ printf "%e\n", $1 }')" ;;
    Blocks_received_from_initiator_) lbas_written="$(echo "${attr_value}" | awk '{ printf "%e\n", $1 }')" ;;
    Accumulated_start-stop_cycles) power_cycle="$(echo "${attr_value}" | awk '{ printf "%e\n", $1 }')" ;;
    Elements_in_grown_defect_list) grown_defects="$(echo "${attr_value}" | awk '{ printf "%e\n", $1 }')" ;;
    esac
  done
  [ -n "$power_on" ] && echo "power_on_hours_raw_value{${labels},smart_id=\"9\"} ${power_on}"
  [ -n "$temp_cel" ] && echo "temperature_celsius_raw_value{${labels},smart_id=\"194\"} ${temp_cel}"
  [ -n "$lbas_read" ] && echo "total_lbas_read_raw_value{${labels},smart_id=\"242\"} ${lbas_read}"
  [ -n "$lbas_written" ] && echo "total_lbas_written_raw_value{${labels},smart_id=\"241\"} ${lbas_written}"
  [ -n "$power_cycle" ] && echo "power_cycle_count_raw_value{${labels},smart_id=\"12\"} ${power_cycle}"
  [ -n "$grown_defects" ] && echo "grown_defects_count_raw_value{${labels},smart_id=\"-1\"} ${grown_defects}"
}

parse_smartctl_info() {
  local -i smart_available=0 smart_enabled=0 smart_healthy=
  local disk="$1" disk_type="$2"
  local model_family='' device_model='' serial_number='' fw_version='' vendor='' product='' revision='' lun_id=''
  while read -r line; do
    info_type="$(echo "${line}" | cut -f1 -d: | tr ' ' '_')"
    info_value="$(echo "${line}" | cut -f2- -d: | sed 's/^ \+//g' | sed 's/"/\\"/')"
    case "${info_type}" in
    Model_Family) model_family="${info_value}" ;;
    Device_Model) device_model="${info_value}" ;;
    Serial_Number|Serial_number) serial_number="${info_value}" ;;
    Firmware_Version) fw_version="${info_value}" ;;
    Vendor) vendor="${info_value}" ;;
    Product) product="${info_value}" ;;
    Revision) revision="${info_value}" ;;
    Logical_Unit_id) lun_id="${info_value}" ;;
    esac
    if [[ "${info_type}" == 'SMART_support_is' ]]; then
      case "${info_value:0:7}" in
      Enabled) smart_available=1; smart_enabled=1 ;;
      Availab) smart_available=1; smart_enabled=0 ;;
      Unavail) smart_available=0; smart_enabled=0 ;;
      esac
    fi
    if [[ "${info_type}" == 'SMART_overall-health_self-assessment_test_result' ]]; then
      case "${info_value:0:6}" in
      PASSED) smart_healthy=1 ;;
      *) smart_healthy=0 ;;
      esac
    elif [[ "${info_type}" == 'SMART_Health_Status' ]]; then
      case "${info_value:0:2}" in
      OK) smart_healthy=1 ;;
      *) smart_healthy=0 ;;
      esac
    fi
  done
  echo "device_info{disk=\"${disk}\",type=\"${disk_type}\",vendor=\"${vendor}\",product=\"${product}\",revision=\"${revision}\",lun_id=\"${lun_id}\",model_family=\"${model_family}\",device_model=\"${device_model}\",serial_number=\"${serial_number}\",firmware_version=\"${fw_version}\"} 1"
  echo "device_smart_available{disk=\"${disk}\",type=\"${disk_type}\"} ${smart_available}"
  echo "device_smart_enabled{disk=\"${disk}\",type=\"${disk_type}\"} ${smart_enabled}"
  [[ "${smart_healthy}" != "" ]] && echo "device_smart_healthy{disk=\"${disk}\",type=\"${disk_type}\"} ${smart_healthy}"
}

output_format_awk="$(
  cat <<'OUTPUTAWK'
BEGIN { v = "" }
v != $1 {
  print "# HELP smartmon_" $1 " SMART metric " $1;
  print "# TYPE smartmon_" $1 " gauge";
  v = $1
}
{print "smartmon_" $0}
OUTPUTAWK
)"

format_output() {
  sort |
    awk -F'{' "${output_format_awk}"
}

smartctl_version="$(/usr/sbin/smartctl -V | awk 'NR==1 && $1 == "smartctl" {print $2}')"

echo "smartctl_version{version=\"${smartctl_version}\"} 1" | format_output

# Exit if "smartctl" version is lower 6
if [[ ${smartctl_version%.*} -lt 6 ]]; then
  exit 0
fi

device_list="$(/usr/sbin/smartctl --scan-open | awk '/^\/dev/{print $1 "|" $3}')"

for device in ${device_list}; do
  disk="$(echo "${device}" | cut -f1 -d'|')"
  type="$(echo "${device}" | cut -f2 -d'|')"
  active=1
  echo "smartctl_run{disk=\"${disk}\",type=\"${type}\"}" "$(TZ=UTC date '+%s')"
  # Check if the device is in a low-power mode
  /usr/sbin/smartctl -n standby -d "${type}" "${disk}" > /dev/null || active=0
  echo "device_active{disk=\"${disk}\",type=\"${type}\"}" "${active}"
  # Skip further metrics to prevent the disk from spinning up
  test ${active} -eq 0 && continue
  # Get the SMART information and health
  /usr/sbin/smartctl -i -H -d "${type}" "${disk}" | parse_smartctl_info "${disk}" "${type}"
  # Get the SMART attributes
  case ${type} in
  sat) /usr/sbin/smartctl -A -d "${type}" "${disk}" | parse_smartctl_attributes "${disk}" "${type}" ;;
  sat+megaraid*) /usr/sbin/smartctl -A -d "${type}" "${disk}" | parse_smartctl_attributes "${disk}" "${type}" ;;
  scsi) /usr/sbin/smartctl -A -d "${type}" "${disk}" | parse_smartctl_scsi_attributes "${disk}" "${type}" ;;
  megaraid*) /usr/sbin/smartctl -A -d "${type}" "${disk}" | parse_smartctl_scsi_attributes "${disk}" "${type}" ;;
  nvme*) /usr/sbin/smartctl -A -d "${type}" "${disk}" | parse_smartctl_scsi_attributes "${disk}" "${type}" ;;
  usbprolific) /usr/sbin/smartctl -A -d "${type}" "${disk}" | parse_smartctl_attributes "${disk}" "${type}" ;;
  *)
      (>&2 echo "disk type is not sat, scsi, nvme or megaraid but ${type}")
    exit
    ;;
  esac
done | format_output
EOF
        [ $? -ne 0 ] && log "Failed to create /usr/local/bin/smartmon.sh" "ERROR"

        chmod +x /usr/local/bin/smartmon.sh 2>> "${LOG_FILE}" || log "Failed to chmod /usr/local/bin/smartmon.sh" "ERROR"
        log "Setting up smart script for prometheus task"
        if [ ! -d /var/lib/node_exporter/textfile_collector ]; then
            mkdir -p /var/lib/node_exporter/textfile_collector 2>> "${LOG_FILE}" || log "Failed to create /var/lib/node_exporter/textfile_collector directory" "ERROR"
        fi
        echo -e "MAILTO=""\n*/5 * * * * root /bin/bash /usr/local/bin/smartmon.sh > /var/lib/node_exporter/textfile_collector/smart_metrics.prom" > /etc/cron.d/smartmon_metrics 2>> "${LOG_FILE}" || log "Failed to add smartmon cron job" "ERROR"
    fi

    # TODO Test this for Debian
    if [ "${CONFIGURE_WATCHDOG}" != false ]; then
        log "Setting up iTCO_wdt watchdog"
        echo "iTCO_wdt" > /etc/modules-load.d/10-watchdog.conf
    fi

    log "Setting up lm_sensors"
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y lm_sensors || log "Failed to install lm_sensors" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y lm-sensors || log "Failed to install lm_sensors" "ERROR"
    fi

    sensors-detect --auto | grep "no driver for ITE IT8613E" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log "Setting up partial ITE 8613E support for NP0F6V2 hardware"
        echo "it87" > /etc/modules-load.d/20-it87.conf
        echo "options it87 force_id=0x8620" > /etc/modprobe.d/it87.conf
    fi

    if [ "${CONFIGURE_TUNED}" != false ]; then
        log "Setting up tuned profiles"

        # RHEL 10 as well as Debian 13 use /etc/tuned/profiles whareas RHEL 8 and 9 use /etc/tuned as profile directory
        if [ "${FLAVOR}" = "rhel" ] && [ "${RELEASE}" -ge 10 ]; then
            TUNED_DIR=/etc/tuned/profiles
        elif [ "${FLAVOR}" = "debian" ] && [ "${RELEASE}" -ge 13 ]; then
            TUNED_DIR=/etc/tuned/profiles
        else
            TUNED_DIR=/etc/tuned
        fi
        if [ ! -d "${TUNED_DIR}/el-eco" ]; then
            mkdir -p "${TUNED_DIR}/el-eco" 2>> "${LOG_FILE}" || log "Failed to create ${TUNED_DIR}/el-eco directory" "ERROR"
        fi
        if [ ! -d "${TUNED_DIR}/el-balanced" ]; then
            mkdir -p "${TUNED_DIR}/el-balanced" 2>> "${LOG_FILE}" || log "Failed to create ${TUNED_DIR}/el-balanced directory" "ERROR"
        fi
        if [ ! -d "${TUNED_DIR}/el-perf" ]; then
            mkdir -p "${TUNED_DIR}/el-perf" 2>> "${LOG_FILE}" || log "Failed to create ${TUNED_DIR}/el-perf directory" "ERROR"
        fi

        cat << 'EOF' > "${TUNED_DIR}/el-eco/tuned.conf"
[main]
summary=EL NetPerfect Powersaver
include=powersave

# SETTINGS_VER 2023110301

[cpu]
# Use governor conservative whenever we can, if not, use powersave
governor=conserative
# The way we scale (set via cpupower set --perf-bias 0-15, 15 being most power efficient)
energy_perf_bias=15
# This will set the minimal frequency available (used with intel_pstate, which replaces cpufreq values
min_perf_pct=1
max_perf_pct=75

[sysctl]
# Never put 0, because of potential OOMs
vm.swappiness=1
# Keep watchguard active so our machine does not lay there for months without operating
# nmi_watchdog is enabled while we do not operate the tunnel so the machine does not stay dead
kernel.nmi_watchdog = 1

##### Prevent blocking system on high IO

#Percentage of system memory which when dirty then system can start writing data to the disks.
vm.dirty_background_ratio = 1

#Percentage of system memory which when dirty, the process doing writes would block and write out dirty pages to the disks.
vm.dirty_ratio = 2

# delay for disk commit
vm.dirty_writeback_centisecs = 100

[script]
# ON RHEL8, we need to keep profile dir
# ON RHEL9, relative path is enough
#script=\${i:PROFILE_DIR}/script.sh
script=script.sh
EOF
        [ $? -ne 0 ] && log "Failed to create ${TUNED_DIR}/el-eco/tuned.conf" "ERROR"

 cat << 'EOF' > "${TUNED_DIR}/el-balanced/tuned.conf"
[main]
summary=EL NetPerfect Balanced
include=powersave

# SETTINGS_VER 2026052101

[cpu]
# Use governor conservative whenever we can, if not, use powersave
governor=schedutil
# The way we scale (set via cpupower set --perf-bias 0-15, 15 being most power efficient)
energy_perf_bias=0
# This will set the minimal frequency available (used with intel_pstate, which replaces cpufreq values
min_perf_pct=40
max_perf_pct=90

[sysctl]
# Never put 0, because of potential OOMs
vm.swappiness=1
# Keep watchguard active so our machine does not lay there for months without operating
# nmi_watchdog is enabled while we do not operate the tunnel so the machine does not stay dead
kernel.nmi_watchdog = 0

##### Prevent blocking system on high IO

#Percentage of system memory which when dirty then system can start writing data to the disks.
vm.dirty_background_ratio = 1

#Percentage of system memory which when dirty, the process doing writes would block and write out dirty pages to the disks.
vm.dirty_ratio = 2

# delay for disk commit
vm.dirty_writeback_centisecs = 100

[script]
# ON RHEL8, we need to keep profile dir
# ON RHEL9, relative path is enough
#script=\${i:PROFILE_DIR}/script.sh
script=script.sh
EOF
        [ $? -ne 0 ] && log "Failed to create ${TUNED_DIR}/el-balanced/tuned.conf" "ERROR"

        cat << 'EOF' > "${TUNED_DIR}/el-perf/tuned.conf"
[main]
summary=EL NetPerfect Performance
include=network-latency

# SETTINGS_VER 2023110301

[cpu]
# Use governor ondemand whenever we can, if not, use performance which will disable all frequency changes
governor=ondemand
# The way we scale (set via cpupower set --perf-bias 0-15, 15 being most powersave)
energy_perf_bias=performance
# This will set the minimal frequency available (used with intel_pstate, which replaces cpufreq values
min_perf_pct=40
max_perf_pct=100

[sysctl]
# Never put 0, because of potential OOMs
vm.swappiness=1
# Keep watchguard active so our machine does not lay there for months without operating
# let's keep the nmi_watchdog disabled while we operate the tunnel so we get no interruptions
kernel.nmi_watchdog = 0

##### Prevent blocking system on high IO

#Percentage of system memory which when dirty then system can start writing data to the disks.
vm.dirty_background_ratio = 1

#Percentage of system memory which when dirty, the process doing writes would block and write out dirty pages to the disks.
vm.dirty_ratio = 2

# delay for disk commit
vm.dirty_writeback_centisecs = 100

[script]
# ON RHEL8, we need to keep profile dir
# ON RHEL9, relative path is enough
#script=\${i:PROFILE_DIR}/script.sh
script=script.sh
EOF
        [ $? -ne 0 ] && log "Failed to create ${TUNED_DIR}/el-perf/tuned.conf" "ERROR"

        cat << 'EOF' > "${TUNED_DIR}/el-eco/script.sh"
#!/usr/bin/env bash

# el-eco tuned script
SCRIPT_VER=2024040701

# Make sure cpupower output is language consistent
export LANG=C

# Powersave will keep low frequency no matter what. If available, use conservative. If not use powersave
if cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors | grep conservative > /dev/null; then
	governor=conservative
else
	governor=powersave
fi

min_freq=$(cpupower frequency-info | grep limits | awk '{print $3}')
min_freq_unit=$(cpupower frequency-info | grep limits | awk '{print $4}')
max_freq=$(cpupower frequency-info | grep limits | awk '{print $6}')
max_freq_unit=$(cpupower frequency-info | grep limits | awk '{print $7}')

# Calc max freq in eco mode, don't use bc anymore since it's probably not installed
#max_freq_eco=$(bc <<< "scale=2; $max_freq/1.5")
max_freq_eco=$(echo "print(round(${max_freq}/1.8, 2))" | python3)

# Set governor, min and max freq
cpupower frequency-set -g $governor -d ${min_freq}${min_freq_unit} -u ${max_freq_eco}${max_freq_unit}

# Set perf bias to max eco
cpupower set --perf-bias 15

# Using idle states with a lacency > 10 will greatly affect bandwidth on KVM virtual machines
# Enable all idle states
cpupower idle-set -E
# Disable any higher than 50ns latency idle states
cpupower idle-set -D 50
EOF
        [ $? -ne 0 ] && log "Failed to create ${TUNED_DIR}/el-eco/script.sh" "ERROR"

cat << 'EOF' > "${TUNED_DIR}/el-balanced/script.sh"
#!/usr/bin/env bash

# el-balanced tuned script
SCRIPT_VER=2026052101

# Make sure cpupower output is language consistent
export LANG=C

# schedutil is a good alternative to conservative/powersave/ondemand if exists
if cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors | grep schedutil > /dev/null; then
	governor=schedutil
if cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors | grep ondemand > /dev/null; then
    governor=ondemand
else
	governor=conservative
fi

min_freq=$(cpupower frequency-info | grep limits | awk '{print $3}')
min_freq_unit=$(cpupower frequency-info | grep limits | awk '{print $4}')
max_freq=$(cpupower frequency-info | grep limits | awk '{print $6}')
max_freq_unit=$(cpupower frequency-info | grep limits | awk '{print $7}')

# Calc max freq in eco mode, don't use bc anymore since it's probably not installed
#max_freq_eco=$(bc <<< "scale=2; $max_freq/1.5")
max_freq_eco=$(echo "print(round(${max_freq}/1.2, 2))" | python3)

# Set governor, min and max freq
cpupower frequency-set -g $governor -d ${min_freq}${min_freq_unit} -u ${max_freq_eco}${max_freq_unit}

# Set perf bias to max eco
cpupower set --perf-bias 5

# Using idle states with a lacency > 10 will greatly affect bandwidth on KVM virtual machines
# Enable all idle states
cpupower idle-set -E
# Disable any higher than 50ns latency idle states
cpupower idle-set -D 50
EOF
        [ $? -ne 0 ] && log "Failed to create ${TUNED_DIR}/el-balanced/script.sh" "ERROR"

        cat << 'EOF' > "${TUNED_DIR}/el-perf/script.sh"
#!/usr/bin/env bash

# el-perf tuned script
SCRIPT_VER=2024040701

# Make sure cpupower output is language consistent
export LANG=C

# Performance will keep CPU freq at max all the time. Prefer ondemand if available
if cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors | grep ondemand > /dev/null; then
	governor=ondemand
else
	governor=performance
fi

min_freq=$(cpupower frequency-info | grep limits | awk '{print $3}')
min_freq_unit=$(cpupower frequency-info | grep limits | awk '{print $4}')
max_freq=$(cpupower frequency-info | grep limits | awk '{print $6}')
max_freq_unit=$(cpupower frequency-info | grep limits | awk '{print $7}')

# Set governor, min and max freq
cpupower frequency-set -g $governor -d ${min_freq}${min_freq_unit} -u ${max_freq}${max_freq_unit}

# Set perf bias to max perf
cpupower set --perf-bias 0

# Using idle states with a lacency > 10 will greatly affect bandwidth on KVM virtual machines
# Enable all idle states
cpupower idle-set -E
# Disable any higher than 50ns latency idle states
cpupower idle-set -D 50
EOF
        [ $? -ne 0 ] && log "Failed to create ${TUNED_DIR}/el-perf/script.sh" "ERROR"

        chmod +x "${TUNED_DIR}/el-eco/script.sh" 2>> "${LOG_FILE}" || log "Failed to chmod +x el-eco tuned script" "ERROR"
        chmod +x "${TUNED_DIR}/el-balanced/script.sh" 2>> "${LOG_FILE}" || log "Failed to chmod +x el-balanced tuned script" "ERROR"
        chmod +x "${TUNED_DIR}/el-perf/script.sh" 2>> "${LOG_FILE}" || log "Failed to chmod +x el-perf tuned script" "ERROR"
    fi
else
    log "This is a virtual machine. We will not setup hardware tooling"
fi

if [ "${CONFIGURE_SERIAL_TERMINAL}" != false ]; then
    # Configure serial console
    log "Setting up serial console"
    systemctl enable serial-getty@ttyS0.service 2>> "${LOG_FILE}" || log "Enabling serial getty failed" "ERROR"
    systemctl start serial-getty@ttyS0.service 2>> "${LOG_FILE}" || log "Starting serial getty failed" "ERROR"
    sed -i 's/^GRUB_TERMINAL="console"/GRUB_TERMINAL="serial console"/g' /etc/default/grub 2>> "${LOG_FILE}" || log "sed failed on /etc/default/grub" "ERROR"
    sed -i 's/^GRUB_SERIAL_COMMAND=.*/GRUB_SERIAL_COMMAND="serial --unit=0 --word=8 --parity=no --speed 115200 --stop=1"/g' /etc/default/grub 2>> "${LOG_FILE}" || log "sed failed on /etc/default/grub" "ERROR"
    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=\(.*\)quiet\(.*\)/GRUB_CMDLINE_LINUX_DEFAULT=\1\2/g' /etc/default/grub 2>> "${LOG_FILE}" || log "sed failed on /etc/default/grub for removing quiet" "ERROR"
    # Update grub to add console
    if [ "${FLAVOR}" = "rhel" ]; then
        grubby --update-kernel=ALL --args="console=tty0 console=ttyS0,115200,n8" || log "Enabling serial getty failed" "ERROR"
        grub2-mkconfig --update-bls-cmdline -o /boot/grub2/grub.cfg 2>> "${LOG_FILE}" || log "grub2-mkconfig failed" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        set_grub_console_args /etc/default/grub "GRUB_CMDLINE_LINUX" "console=tty0 console=ttyS0,115200,n8" \
            || log "Failed to set console arguments in /etc/default/grub" "ERROR"
        /sbin/grub-mkconfig -o /boot/grub/grub.cfg 2>> "${LOG_FILE}" || log "grub-mkconfig failed" "ERROR"
    else
        log_quit "Cannot setup serial console on this system"
    fi

    log "Optimizing for serial console speed"
    set_conf_value /etc/sysctl.d/99-kernel_printk.conf "kernel.printk" "4 4 1 7"
fi

if [ "${CONFIGURE_TERMINAL_RESIZER}" != false ]; then
    # Setup automagic terminal resize
    # singequotes on EOF prevents variable expansion
    # Tested on EL7, EL8, EL9, Debian 12 and Debian 13
    cat << 'EOF' > /etc/profile.d/term_resize.sh
# Based on solution https://unix.stackexchange.com/a/283206/135459 that replaces xterm-resize package


resize_term() {
    old=$(stty -g)
    stty raw -echo min 0 time 5

    printf '\0337\033[r\033[999;999H\033[6n\0338' > /dev/tty
    IFS='[;R' read -t 1 -r _ rows cols _ < /dev/tty

    stty "$old"

    [ -z "$cols" ] || [ -z "$rows" ] && echo "could not determine tty size: cols: $cols, rows: $rows" || stty cols "$cols" rows "$rows"
}

resize_term2() {
    oldrows=$(tput lines)
    oldcols=$(tput cols)
    old=$(stty -g)
    stty raw -echo min 0 time 5

    printf '\033[18t' > /dev/tty
    IFS=';t' read -t 1 -r _ rows cols _ < /dev/tty

    stty "$old"

    if [ -z "$cols" ] || [ -z "$rows" ]; then
        echo "could not determine tty size: cols: $cols, rows: $rows"
    else
        if [ "$cols" -eq "$oldcols" ] && [ "$rows" -eq "$oldrows" ]; then
            return
        fi
        stty cols "$cols" rows "$rows"
        if [ $? -eq 0 ]; then
            echo "Resized terminal from ${oldcols}x${oldrows} to ${cols}x${rows}"
        else
            echo "Failed to resize terminal from ${oldcols}x${oldrows} to ${cols}x${rows}"
        fi
    fi
}

# Run only if we're in a serial terminal
[ "$(tty)" = /dev/ttyS0 ] && resize_term2
EOF
    [ $? -ne 0 ] && log "Failed to create /etc/profile.d/term_resize.sh" "ERROR"
fi

# Configure persistent journal
log "Setting up persistent boot journal"
if [ ! -d /var/log/journal ]; then
    mkdir -p /var/log/journal 2>> "${LOG_FILE}" || log "Failed to create /var/log/journal directory" "ERROR"
fi
systemd-tmpfiles --create --prefix /var/log/journal 2>> "${LOG_FILE}" || log "Failed to create systemd-tmpfiles" "ERROR"
sed -i 's/.*Storage=.*/Storage=persistent/g' "${SYSTEMD_PREFIX}/journald.conf" 2>> "${LOG_FILE}" || log "Failed to sed ${SYSTEMD_PREFIX}/journald.conf" "ERROR"

# Since kilall is not present on debian, we'll use plain old kill
# killall -USR1 systemd-journald
# We don't use pgrep since it's not installed everywhere
# shellcheck disable=SC2009
kill -USR1 "$(ps aux | grep '[s]ystemd-journald' | awk '{print $2}')"

# Configure max journal size
journalctl --vacuum-size=2G 2>> "${LOG_FILE}" || log "Failed to set journald vaccumsize" "ERROR"

if [ "${CONFIGURE_AUTOMATIC_UPDATES}" != false ]; then
    log "Setting up automatic updates"
    if [ "${FLAVOR}" = "rhel" ]; then
        log "Setup DNF automatic except for updates that require reboot"
        auto_upgrades_file="/etc/dnf/automatic.conf"
        set_conf_value "${auto_upgrades_file}" "upgrade_type" "security" "="
        set_conf_value "${auto_upgrades_file}" "download_updates" "yes" "="
        set_conf_value "${auto_upgrades_file}" "apply_updates" "yes" "="
        set_conf_value "${auto_upgrades_file}" "emit_via" "stdio" "="
        systemctl enable dnf-automatic.timer 2>> "${LOG_FILE}" || log "Failed to start dnf-automatic timer" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        log "Setup unattended automatic upgrades"
        # Base file can be found in /usr/share/unattended-upgrades/20auto-upgrades
        auto_upgrades_file="/etc/apt/apt.conf.d/20auto-upgrades"
        : > "${auto_upgrades_file}"
        set_conf_value "${auto_upgrades_file}" "APT::Periodic::Update-Package-Lists" "\"1\";" " "
        set_conf_value "${auto_upgrades_file}" "APT::Periodic::Unattended-Upgrade" "\"1\";" " "
        set_conf_value "${auto_upgrades_file}" "APT::Periodic::Download-Upgradeable-Packages" "\"1\";" " "
        set_conf_value "${auto_upgrades_file}" "APT::Periodic::AutocleanInterval" "\"30\";" " "
        systemctl enable unattended-upgrades 2>> "${LOG_FILE}" || log "Failed to enable unattended-upgrades" "ERROR"
        systemctl enable apt-daily-upgrade.timer 2>> "${LOG_FILE}" || log "Failed to enable apt-daily-upgrade.timer" "ERROR"
    else
        log_quit "Cannot setup automatic updates on this system. Looks unsupported"
    fi
fi

if [ "${CONFIGURE_TUNED}" != false ]; then
    log "Setting up tuned"
    systemctl enable tuned 2>> "${LOG_FILE}" || log "Failed to start tuned" "ERROR"
    # tuned-adm will complain that tuned is not running, but we cannot start tuned in install environment
    # Hence, we will not log these errors. On reboot, the "good" profile will be selected anyway
    if [ ${IS_VIRTUAL} != true ]; then
        log "Setting up hardware tuned profile"
        tuned-adm profile el-eco
    else
        log "Setting up virtual tuned profile"
        tuned-adm profile virtual-guest
    fi
fi

if [ "${CONFIGURE_FIREWALL}" != false ]; then
    log "Setting up firewall"
    # Enable firewall (firewalld is enabled by default on EL)
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y firewalld 2>> "${LOG_FILE}" || log "Failed to install firewalld" "ERROR"
        # By default, firewalld has ssh and cockpit allowed for public zone
        # kickstart enables firewalld with "firewall --enabled --service ssh", and starting it
        # will not work in the postinstall environment, so the config is written offline here
        configure_firewalld
        systemctl enable firewalld 2>> "${LOG_FILE}" || log "Failed to enable firewalld" "ERROR"
        systemctl start firewalld || log "Cannot start firewalld. This happens in kickstart environment, but not in production"
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y ufw 2>> "${LOG_FILE}" || log "Failed to install ufw" "ERROR"
        configure_ufw
    fi
fi

if [ "${CONFIGURE_FAIL2BAN}" != false ]; then
    log "Setting up fail2ban"
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y fail2ban 2>> "${LOG_FILE}"
        if [ $? -ne 0 ]; then
    	    log "Failed to install fail2ban" "ERROR"
    	    __FAIL2BAN_INSTALLED=false
     	else
      		__FAIL2BAN_INSTALLED=true
        fi
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y fail2ban 2>> "${LOG_FILE}"
        if [ $? -ne 0 ]; then
            log "Failed to install fail2ban" "ERROR"
            __FAIL2BAN_INSTALLED=false
        else
            __FAIL2BAN_INSTALLED=true
            # On Debian 12+, fail2ban backend needs to be set to systemd since /var/log/auth.log does not exist anymore
            if [ "${RELEASE}" -ge 12 ]; then
                sed -i 's#^backend = %(sshd_backend)s#backend = systemd#g' /etc/fail2ban/jail.conf 2>> "${LOG_FILE}" || log "Failed to set fail2ban backend to systemd" "ERROR"
            fi
        fi
    fi
fi

if [ "${__FAIL2BAN_INSTALLED}" = true ]; then
    log "Setting up fail2ban configuration"
    # Enable SSHD jail by adding a local jail conf file
    ssh_jailfile="/etc/fail2ban/jail.d/99-sshd-el.conf"
    if [ ! -f "${ssh_jailfile}" ]; then
        echo "[sshd]" > "${ssh_jailfile}" 2>> "${LOG_FILE}" || log "Failed to create ${ssh_jailfile}" "ERROR"
    fi
    set_conf_value "${ssh_jailfile}" "enabled" "true" " = "

    default_jailfile="/etc/fail2ban/jail.d/99-default-el.conf"
    if [ ! -f "${default_jailfile}" ]; then
        echo "[DEFAULT]" > "${default_jailfile}" 2>> "${LOG_FILE}" || log "Failed to create ${default_jailfile}" "ERROR"
    fi

    set_conf_value "${default_jailfile}" "bantime" "30m" " = "
    set_conf_value "${default_jailfile}" "bantime.increment" "true" " = "
    set_conf_value "${default_jailfile}" "bantime.rndtime" "300" " = "
    if [ "${FAIL2BAN_IGNORE_IP_LIST}" != "" ]; then
        log "Adding ignore IPs to fail2ban: ${FAIL2BAN_IGNORE_IP_LIST//:/ }"
        # We replace the semicolons with spaces since fail2ban needs a space separated CIDR list
        set_conf_value "${default_jailfile}" "ignoreip" "${FAIL2BAN_IGNORE_IP_LIST//:/ }" " = "
    fi

    set_conf_value "${default_jailfile}" "findtime" "2h" " = "
    set_conf_value "${default_jailfile}" "maxretry" "3" " = "

    systemctl enable fail2ban 2>> "${LOG_FILE}" || log "Failed to enable fail2ban" "ERROR"
    # Starting fail2ban may need a reboot to work, so let's not log start failures here
    systemctl start fail2ban 2>> "${LOG_FILE}" || log "Failed to start fail2ban. It may need a reboot to work" "ERROR"
fi

# Configure NTP if given
if [ "${NTP_SERVERS}" != "" ]; then
    log "Setting up NTP servers: ${NTP_SERVERS//:/ }"
    ntp_conf_file=""
    chrony_main_conf=""
    ntp_sources_dir=""
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y chrony 2>> "${LOG_FILE}" || log "Failed to install chrony" "ERROR"
        chrony_svc=chronyd
        # EL8, EL9 and EL10 all read /etc/chrony.conf, and the package owns no sources directory
        ntp_conf_file=/etc/chrony.conf
        chrony_main_conf=/etc/chrony.conf
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y chrony 2>> "${LOG_FILE}" || log "Failed to install chrony" "ERROR"
        chrony_svc=chrony
        # Debian ships /etc/chrony/sources.d together with the sourcedir directive that reads it
        ntp_conf_file=/etc/chrony/sources.d/local-ntp-server.sources
        chrony_main_conf=/etc/chrony/chrony.conf
        ntp_sources_dir=/etc/chrony/sources.d
        if [ ! -d /etc/chrony/sources.d ]; then
            mkdir -p /etc/chrony/sources.d 2>> "${LOG_FILE}" || log "Failed to create /etc/chrony/sources.d directory" "ERROR"
        fi
    else
        log "Cannot setup NTP on this system. Looks unsupported" "ERROR"
    fi
    if [ -n "${ntp_conf_file}" ]; then
        # Disabling comes first, so that the servers added below are never commented out themselves
        if [ "${REPLACE_EXISTING_NTP}" != false ]; then
            log "Replacing the distribution time sources with ${NTP_SERVERS//:/ }"
            disable_existing_ntp_sources "${chrony_main_conf}" "${ntp_sources_dir}" || log "Failed to disable the existing NTP sources in ${chrony_main_conf}" "ERROR"
        fi
        configure_ntp_servers "${ntp_conf_file}" || log "Some NTP servers could not be configured, time synchronisation may be incomplete" "ERROR"
        systemctl enable "${chrony_svc}" 2>> "${LOG_FILE}" || log "Failed to enable ${chrony_svc}" "ERROR"
        systemctl start "${chrony_svc}" 2>> "${LOG_FILE}" || log "Failed to start ${chrony_svc}" "ERROR"
    fi
fi


# Enable guest agent on KVM
if [ ${IS_VIRTUAL} = true ]; then
    log "Setting up Qemu guest agent"
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y qemu-guest-agent 2>> "${LOG_FILE}" || log "Failed to install qemu-guest-agent" "ERROR"
        setsebool -P virt_qemu_ga_read_nonsecurity_files 1 2>> "${LOG_FILE}" || log "Failed to SELinux for qemu virtual machine" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y qemu-guest-agent 2>> "${LOG_FILE}" || log "Failed to install qemu-guest-agent" "ERROR"
    else
        log_quit "Cannot setup qemu-guest-agent on this system"
    fi
	systemctl enable qemu-guest-agent 2>> "${LOG_FILE}" || log "Failed to start qumu-guest-agent" "ERROR"
fi

# Prometheus support
if [ "${CONFIGURE_NODE_EXPORTER}" != false ]; then
    check_internet
    if [ $? -eq 0 ]; then
        log "Installing Node exporter"
        cd /opt || log "No /opt directory found"
        if [ ! -d /var/lib/node_exporter/textfile_collector ]; then
            mkdir -p /var/lib/node_exporter/textfile_collector 2>> "${LOG_FILE}" || log "Failed to create /var/lib/node_exporter/textfile_collector directory" "ERROR"
        fi
        # Node exporter installer, vendored so that provisioning never pipes remote code into a shell.
        # Upstream: https://github.com/carlocorradini/node_exporter_installer (MIT, see LICENSES/)
        #   file    install.sh
        #   commit  08f4b4d08fd3c5a462aaa23599a82f154c763376 (2023-12-18, latest as of 2026-08-22)
        #   sha256  920a32161e15b1d8bc90d1d5f90a1399e5378b4cbe3471536712757af4ae9ac7
        # Embedded verbatim. To refresh it, diff against upstream and update the three lines above.
        # It still reaches the network for the node_exporter release itself, but verifies the archive
        # against the sha256sums.txt published with that same release before installing it.
        node_exporter_installer=$(mktemp) || log "Cannot create temporary file for node_exporter installer" "ERROR"
        cat << 'NODE_EXPORTER_INSTALLER_EOF' > "${node_exporter_installer}"
#!/usr/bin/env sh

# Usage:
#   curl ... | ENV_VAR=... sh -
#       or
#   ENV_VAR=... ./install.sh
#
# Example:
#   Installing Node exporter enabling only os collector:
#     curl ... | INSTALL_NODE_EXPORTER="--collector.disable-defaults --collector.os" sh -
#   Installing Node exporter enabling only os collector:
#     curl ... | sh -s - --collector.disable-defaults --collector.os
#
# Environment variables:
#   - INSTALL_NODE_EXPORTER_SKIP_DOWNLOAD
#     If set to true will not download Node exporter hash or binary
#
#   - INSTALL_NODE_EXPORTER_FORCE_RESTART
#     If set to true will always restart the Node exporter service
#
#   - INSTALL_NODE_EXPORTER_SKIP_ENABLE
#     If set to true will not enable or start Node exporter service
#
#   - INSTALL_NODE_EXPORTER_SKIP_START
#     If set to true will not start Node exporter service
#
#   - INSTALL_NODE_EXPORTER_SKIP_FIREWALL
#     If set to true will not add firewall rules
#
#   - INSTALL_NODE_EXPORTER_SKIP_SELINUX
#     If set to true will not change SELinux context for binary
#
#   - INSTALL_NODE_EXPORTER_VERSION
#     Version of Node exporter to download from GitHub
#
#   - INSTALL_NODE_EXPORTER_BIN_DIR
#     Directory to install Node exporter binary, and uninstall script to, or use
#     /usr/local/bin as the default
#
#   - INSTALL_NODE_EXPORTER_SYSTEMD_DIR
#     Directory to install systemd service files, or use
#     /etc/systemd/system as the default
#
#   - INSTALL_NODE_EXPORTER_EXEC or script arguments
#     Command with flags to use for launching Node exporter service
#
#     The following commands result in the same behavior:
#       curl ... | INSTALL_NODE_EXPORTER_EXEC="--collector.disable-defaults --collector.os" sh -s -
#       curl ... | INSTALL_NODE_EXPORTER_EXEC="--collector.disable-defaults" sh -s - --collector.os
#       curl ... | sh -s - --collector.disable-defaults --collector.os
#

# Fail on error
set -o errexit
# Disable wildcard character expansion
set -o noglob

# ================
# CONFIGURATION
# ================
# GitHub release URL
GITHUB_URL=https://github.com/prometheus/node_exporter/releases
# GitHub API URL
GITHUB_API_URL=https://api.github.com/repos/prometheus/node_exporter/releases/latest

# ================
# LOGGER
# ================
# Fatal log message
fatal() {
  printf '[FATAL] %s\n' "$@" >&2
  exit 1
}

# Error log message
error() {
  printf '[ERROR] %s\n' "$@" >&2
}

# Info log message
info() {
  printf '[INFO ] %s\n' "$@"
}

# ================
# FUNCTIONS
# ================
# Add quotes to command arguments
quote() {
  for arg in "$@"; do
    printf '%s\n' "$arg" | sed "s/'/'\\\\''/g;1s/^/'/;\$s/\$/'/"
  done
}

# Add indentation and trailing slash to quoted args except last one
# Also don't add trailing slash to command if no args are given
quote_indent() {
  _arg_count=1

  if [ $# -ge 1 ]; then
    printf ' \\\n'
  fi

  for _arg in "$@"; do
    if [ $_arg_count -eq $# ]; then
      printf '\t%s' "$(quote "$_arg")"
    else
      printf '\t%s \\\n' "$(quote "$_arg")"
    fi
    _arg_count=$((_arg_count + 1))
  done
}

# Escape most punctuation characters, except quotes, forward slash, and space
escape() {
  printf '%s' "$@" | sed -e 's/\([][!#$%&()*;<=>?\_`{|}]\)/\\\1/g;'
}

# Escape double quotes
escape_dq() {
  printf '%s' "$@" | sed -e 's/"/\\"/g'
}

# Define needed environment variables
setup_env() {
  # Command args
  case "$1" in
    -* | "")
      _cmd_node_exporter=
      ;;
      # Command provided
    *)
      _cmd_node_exporter=$1
      shift
      ;;
  esac

  CMD_NODE_EXPORTER_EXEC="$_cmd_node_exporter$(quote_indent "$@")"

  # use sudo if not already root
  SUDO=sudo
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=
  fi

  # Use binary install directory if defined or create default
  if [ -n "$INSTALL_NODE_EXPORTER_BIN_DIR" ]; then
    BIN_DIR="$INSTALL_NODE_EXPORTER_BIN_DIR"
  else
    # Use /usr/local/bin if root can write to it, otherwise use /opt/bin if it exists
    BIN_DIR=/usr/local/bin
    if ! $SUDO sh -c "touch $BIN_DIR/node_exporter-ro-test && rm -rf $BIN_DIR/node_exporter-ro-test"; then
      if [ -d /opt/bin ]; then
        BIN_DIR=/opt/bin
      fi
    fi
  fi

  # Set related files from system name
  SERVICE_NODE_EXPORTER=node_exporter.service
  UNINSTALL_NODE_EXPORTER_SH="$BIN_DIR/node_exporter.uninstall.sh"
  KILLALL_NODE_EXPORTER_SH="$BIN_DIR/node_exporter.killall.sh"

  # Extract port when address is specified or use default
  if test "${CMD_NODE_EXPORTER_EXEC#*"--web.listen-address="}" != "$CMD_NODE_EXPORTER_EXEC"; then
    NODE_EXPORTER_PORT=$(echo "$CMD_NODE_EXPORTER_EXEC" \
      | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/ /g' \
      | sed -e 's/.*--web.listen-address=\(.*\)[[:space:]].*/\1/' \
      | sed 's/[^0-9]*//g')
    info "Listening port '$NODE_EXPORTER_PORT'"
  else
    NODE_EXPORTER_PORT=9100
  fi

  # Use systemd directory if defined or create default
  if [ -n "$INSTALL_NODE_EXPORTER_SYSTEMD_DIR" ]; then
    SYSTEMD_DIR="$INSTALL_NODE_EXPORTER_SYSTEMD_DIR"
  else
    SYSTEMD_DIR=/etc/systemd/system
  fi

  # Use service or environment location depending on systemd/openrc
  case $INIT_SYSTEM in
    openrc)
      $SUDO mkdir -p /etc/node_exporter
      FILE_NODE_EXPORTER_SERVICE=/etc/init.d/node_exporter
      ;;
    systemd)
      FILE_NODE_EXPORTER_SERVICE=$SYSTEMD_DIR/$SERVICE_NODE_EXPORTER
      ;;
    upstart)
      $SUDO mkdir -p /etc/node_exporter
      FILE_NODE_EXPORTER_SERVICE=/etc/init/node_exporter.conf
      ;;
    *)
      fatal "Unknown init system '$INIT_SYSTEM'"
      ;;
  esac

  # Get hash of config & exec for currently installed Node exporter
  PRE_INSTALL_HASHES=$(get_installed_hashes)
}

# Verify architecture
verify_arch() {
  ARCH=$(uname -m)
  case $ARCH in
    amd64 | x86_64) ARCH=amd64 ;;
    arm64 | aarch64) ARCH=arm64 ;;
    armv5*) ARCH=armv5 ;;
    armv6*) ARCH=armv6 ;;
    armv7*) ARCH=armv7 ;;
    mips) ARCH=mips ;;
    mipsle) ARCH=mipsle ;;
    mips64) ARCH=mips64 ;;
    mips64le) ARCH=mips64le ;;
    ppc64) ARCH=ppc64 ;;
    ppc64le) ARCH=ppc64le ;;
    s390x) ARCH=s390x ;;
    i386) ARCH=386 ;;
    # Not supported
    *) fatal "Architecture '$ARCH' not supported" ;;
  esac
}

# Verify Operating System
verify_os() {
  OS=$(uname -s)
  case $OS in
    Linux) OS=linux ;;
    Darwin) OS=darwin ;;
    NetBSD) OS=netbsd ;;
    OpenBSD) OS=openbsd ;;
    # Not supported
    *) fatal "OS '$OS' not supported" ;;
  esac
}

# Verify architecture and os are supported
verify_arch_os() {
  case $OS in
    linux)
      case $ARCH in
        amd64 | arm64 | armv5 | armv6 | armv7 | mips | mipsle | mips64 | mips64le | ppc64 | ppc64le | s390x | 386) return ;;
      esac
      ;;
    darwin)
      case $ARCH in
        amd64 | arm64) return ;;
      esac
      ;;
    netbsd)
      case $ARCH in
        386 | amd64) return ;;
      esac
      ;;
    openbsd)
      case $ARCH in
        amd64) return ;;
      esac
      ;;
    # Not supported
    *) fatal "OS '$OS' not supported" ;;
  esac

  # Not supported
  fatal "Architecture '$ARCH' on OS '$OS' not supported"
}

# Verify init system
verify_init_system() {
  # OpenRC
  if [ -x /sbin/openrc-run ]; then
    INIT_SYSTEM=openrc
    return
  fi
  # systemd
  if [ -x /bin/systemctl ] || type systemctl > /dev/null 2>&1; then
    INIT_SYSTEM=systemd
    return
  fi
  # Upstart
  case $(/sbin/init --version) in
    *upstart*)
      INIT_SYSTEM=upstart
      return
      ;;
  esac

  # Not supported
  fatal 'No supported init system found (OpenRC, systemd, or Upstart)'
}

# Check command is installed
# @param $1 Command name
check_cmd() {
  command -v "$1" > /dev/null 2>&1
}

# Assert command is installed
# @param $1 Command name
assert_cmd() {
  check_cmd "$1" || fatal "Command '$1' not found"
}

# Verify firewall
verify_firewall_cmd() {
  # Cycle firewall commands
  for _cmd in "$@"; do
    # Check if exists
    if command -v "$_cmd" > /dev/null 2>&1; then
      # Found
      FIREWALL=$_cmd
      return
    fi
  done

  # Not found
  fatal "Unable to find any firewall command in list '$*'"
}

# Verify downloader command is installed
verify_downloader_cmd() {
  # Cycle downloader commands
  for _cmd in "$@"; do
    # Check if exists
    if command -v "$_cmd" > /dev/null 2>&1; then
      # Found
      DOWNLOADER=$_cmd
      return
    fi
  done

  # Not found
  fatal "Unable to find any downloader command in list '$*'"
}

# Check if skip firewall environment variable set
can_skip_firewall() {
  if [ "$INSTALL_NODE_EXPORTER_SKIP_FIREWALL" != true ]; then
    return 1
  fi
}

# Check if skip selinux environment variable set
can_skip_selinux() {
  if [ "$INSTALL_NODE_EXPORTER_SKIP_SELINUX" != true ]; then
    return 1
  fi
}

# Check if skip download environment variable set
can_skip_download() {
  if [ "$INSTALL_NODE_EXPORTER_SKIP_DOWNLOAD" != true ]; then
    return 1
  fi
}

# Verify system
verify_system() {
  # Arch and OS
  verify_arch
  verify_os
  verify_arch_os
  # Commands
  assert_cmd chmod
  assert_cmd chown
  assert_cmd grep
  assert_cmd mktemp
  assert_cmd rm
  assert_cmd sed
  assert_cmd sha256sum
  assert_cmd tar
  assert_cmd tee
  # Init system
  verify_init_system
  # Firewall
  can_skip_firewall || verify_firewall_cmd firewall-cmd ufw iptables
  # Downloader
  can_skip_download || verify_downloader_cmd curl wget
}

# Verify an executable Node exporter binary is installed
verify_node_exporter_is_executable() {
  if [ ! -x "$BIN_DIR/node_exporter" ]; then
    fatal "Executable Node exporter binary not found at '$BIN_DIR/node_exporter'"
  fi
}

# Create temporary directory and cleanup
setup_tmp() {
  TMP_DIR=$(mktemp -d -t node_exporter.XXXXXXXX)
  TMP_HASH="$TMP_DIR/node_exporter.hash"
  TMP_ARCHIVE="$TMP_DIR/node_exporter.archive"
  TMP_BIN="$TMP_DIR/node_exporter.bin"

  cleanup() {
    _exit_code=$?
    [ "$_exit_code" -eq 0 ] || error "Install script exited with code $_exit_code"
    set +o errexit
    trap - EXIT
    rm -rf "$TMP_DIR"
    exit $_exit_code
  }
  trap cleanup INT EXIT
}

# Use provided version or obtain from latest release
get_release_version() {
  if [ -n "$INSTALL_NODE_EXPORTER_VERSION" ]; then
    VERSION_NODE_EXPORTER=$INSTALL_NODE_EXPORTER_VERSION
  else
    info "Finding latest release"
    case $DOWNLOADER in
      curl) VERSION_NODE_EXPORTER=$(curl -L -f -s -S $GITHUB_API_URL) || fatal "Download '$GITHUB_API_URL' failed" ;;
      wget) VERSION_NODE_EXPORTER=$(wget -q -O - $GITHUB_API_URL 2>&1) || fatal "Download '$GITHUB_API_URL' failed" ;;
      *) fatal "Invalid downloader '$DOWNLOADER'" ;;
    esac
    VERSION_NODE_EXPORTER=$(echo "$VERSION_NODE_EXPORTER" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  fi

  info "Using $VERSION_NODE_EXPORTER as release"
}

# Download a file
download() {
  [ $# -eq 2 ] || fatal "Download requires exactly 2 arguments but '$#' found"

  # Download
  case $DOWNLOADER in
    curl)
      curl --fail --silent --location --output "$1" "$2" || fatal "Download '$2' failed"
      ;;
    wget)
      wget --quiet --output-document="$1" "$2" || fatal "Download '$2' failed"
      ;;
    *)
      fatal "Unknown downloader '$DOWNLOADER'"
      ;;
  esac
}

# Download hash
download_hash() {
  _hash_url=$GITHUB_URL/download/$VERSION_NODE_EXPORTER/sha256sums.txt

  info "Downloading hash '$_hash_url'"
  download "$TMP_HASH" "$_hash_url"
  HASH_ARCHIVE_EXPECTED=$(grep " $RELEASE_ARCHIVE" "$TMP_HASH")
  HASH_ARCHIVE_EXPECTED=${HASH_ARCHIVE_EXPECTED%%[[:blank:]]*}
}

# Download archive
download_archive() {
  _archive_url=$GITHUB_URL/download/$VERSION_NODE_EXPORTER/$RELEASE_ARCHIVE

  info "Downloading archive '$_archive_url'"
  download "$TMP_ARCHIVE" "$_archive_url"
  HASH_ARCHIVE=$(sha256sum "$TMP_ARCHIVE")
  HASH_ARCHIVE=${HASH_ARCHIVE%%[[:blank:]]*}
}

# Verify downloaded archive hash
verify_archive() {
  info "Verifying archive download '$TMP_ARCHIVE'"
  if [ "$HASH_ARCHIVE_EXPECTED" != "$HASH_ARCHIVE" ]; then
    fatal "Download sha256 does not match '$HASH_ARCHIVE_EXPECTED', got '$HASH_ARCHIVE'"
  fi
}

# Extract archive
extract_archive() {
  info "Extracting archive '$TMP_ARCHIVE'"
  tar xzf "$TMP_ARCHIVE" -C "$TMP_DIR" --strip-components 1 "$RELEASE_NAME/node_exporter" || fatal "Error extracting archive '$TMP_ARCHIVE'"
  mv "$TMP_DIR/node_exporter" "$TMP_BIN"

  info "Extracted binary '$TMP_BIN'"
  HASH_BIN_EXPECTED=$(sha256sum "$TMP_BIN")
  HASH_BIN_EXPECTED=${HASH_BIN_EXPECTED%%[[:blank:]]*}
}

# Check hash against installed version
installed_hash_matches() {
  if [ -x "$BIN_DIR/node_exporter" ]; then
    _hash_bin_installed=$(sha256sum "$BIN_DIR/node_exporter")
    _hash_bin_installed=${_hash_bin_installed%%[[:blank:]]*}
    if [ "$HASH_BIN_EXPECTED" = "$_hash_bin_installed" ]; then
      return 0
    fi
  fi
  return 1
}

# Setup permissions and move binary to system directory
setup_binary() {
  chmod 755 "$TMP_BIN"
  info "Installing Node exporter to '$BIN_DIR/node_exporter'"
  $SUDO chown root:root "$TMP_BIN"
  $SUDO mv -f "$TMP_BIN" "$BIN_DIR/node_exporter"
}

# Download and verify
download_and_verify() {
  if can_skip_download; then
    info 'Skipping Node exporter download and verify'
    verify_node_exporter_is_executable
    return
  fi

  setup_tmp
  get_release_version

  RELEASE_NAME=node_exporter-$(echo "$VERSION_NODE_EXPORTER" | sed 's/^v//').$OS-$ARCH
  RELEASE_ARCHIVE="$RELEASE_NAME.tar.gz"

  download_hash
  download_archive
  verify_archive
  extract_archive

  if installed_hash_matches; then
    info 'Skipping binary setup, installed Node exporter matches hash'
    return
  fi

  setup_binary
}

# Create killall script
create_killall() {
  info "Creating killall script '$KILLALL_NODE_EXPORTER_SH'"
  $SUDO tee "$KILLALL_NODE_EXPORTER_SH" > /dev/null << \EOF
#!/usr/bin/env sh
[ $(id -u) -eq 0 ] || exec sudo $0 $@

set -x

[ -s '/etc/systemd/system/node_exporter.service' ] && systemctl stop node_exporter.service

[ -x '/etc/init.d/node_exporter' ] && /etc/init.d/node_exporter stop

do_unmount_and_remove() {
  set +x
  while read -r _ path _; do
    case "$path" in $1*) echo "$path" ;; esac
  done < /proc/self/mounts | sort -r | xargs -r -t -n 1 sh -c 'umount "$0" && rm -rf "$0"'
  set -x
}
do_unmount_and_remove '/run/node_exporter'
EOF
  $SUDO chmod 755 "$KILLALL_NODE_EXPORTER_SH"
  $SUDO chown root:root "$KILLALL_NODE_EXPORTER_SH"
}

# Create uninstall script
create_uninstall() {
  info "Creating uninstall script '$UNINSTALL_NODE_EXPORTER_SH'"
  $SUDO tee "$UNINSTALL_NODE_EXPORTER_SH" > /dev/null << EOF
#!/usr/bin/env sh
set -x
[ \$(id -u) -eq 0 ] || exec sudo \$0 \$@

$KILLALL_NODE_EXPORTER_SH

if command -v systemctl; then
  systemctl disable node_exporter
  systemctl reset-failed node_exporter
  systemctl daemon-reload
fi
if command -v rc-update; then
  rc-update delete node_exporter default
fi

rm -f "$FILE_NODE_EXPORTER_SERVICE"

remove_uninstall() {
  rm -f "$UNINSTALL_NODE_EXPORTER_SH"
}
trap remove_uninstall EXIT

rm -rf /etc/node_exporter
rm -rf /run/node_exporter
rm -f "$BIN_DIR/node_exporter"
rm -f "$KILLALL_NODE_EXPORTER_SH"
EOF
  $SUDO chmod 755 "$UNINSTALL_NODE_EXPORTER_SH"
  $SUDO chown root:root "$UNINSTALL_NODE_EXPORTER_SH"
}

# Disable current service if loaded
systemd_disable() {
  $SUDO systemctl disable node_exporter > /dev/null 2>&1 || true
  $SUDO rm -f "/etc/systemd/system/$SERVICE_NODE_EXPORTER" || true
}

# Compose firewall rule
firewall_rule() {
  _firewall_path=$(command -v "$FIREWALL" 2>&1 || :)

  case $FIREWALL in
    firewall-cmd)
      printf "%s\n%s\n" \
        "$_firewall_path --add-port=$NODE_EXPORTER_PORT/tcp --permanent" \
        "$_firewall_path --reload"
      ;;
    ufw)
      printf "%s\n" \
        "$_firewall_path allow $NODE_EXPORTER_PORT/tcp"
      ;;
    iptables)
      printf "%s\n" \
        "$_firewall_path -A INPUT -p tcp --dport $NODE_EXPORTER_PORT -m state --state NEW -j ACCEPT"
      ;;
    *) fatal "Unknown firewall '$FIREWALL'" ;;
  esac
}

# Write openrc service file
create_openrc_service_file() {
  LOG_FILE=/var/log/node_exporter.log

  info "openrc: Creating service file '$FILE_NODE_EXPORTER_SERVICE'"
  $SUDO tee "$FILE_NODE_EXPORTER_SERVICE" > /dev/null << EOF
#!/sbin/openrc-run

description="Node exporter"

depend() {
  need net
  need localmount
  use dns
  after firewall
}
EOF

  if ! can_skip_firewall; then
    _firewall=$(firewall_rule)
    $SUDO tee -a "$FILE_NODE_EXPORTER_SERVICE" > /dev/null << EOF
start_pre() {
  $_firewall
}
EOF
  fi

  $SUDO tee -a "$FILE_NODE_EXPORTER_SERVICE" > /dev/null << EOF
supervisor=supervise-daemon
name=node_exporter
command="$BIN_DIR/node_exporter"
command_args="$(escape_dq "$CMD_NODE_EXPORTER_EXEC") >> $LOG_FILE 2>&1"

output_log=$LOG_FILE
error_log=$LOG_FILE

pidfile="/var/run/node_exporter.pid"
respawn_delay=5
respawn_max=0

set -o allexport
if [ -f /etc/environment ]; then source /etc/environment; fi
set +o allexport
EOF
  $SUDO chmod 0755 "$FILE_NODE_EXPORTER_SERVICE"

  $SUDO tee /etc/logrotate.d/node_exporter > /dev/null << EOF
$LOG_FILE {
	missingok
	notifempty
	copytruncate
}
EOF
}

# Write systemd service file
create_systemd_service_file() {
  info "systemd: Creating service file '$FILE_NODE_EXPORTER_SERVICE'"
  $SUDO tee "$FILE_NODE_EXPORTER_SERVICE" > /dev/null << EOF
[Unit]
Description=Node exporter
Documentation=https://github.com/prometheus/node_exporter
After=local-fs.target network-online.target network.target
Wants=local-fs.target network-online.target network.target

[Install]
WantedBy=multi-user.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/%N
EnvironmentFile=-/etc/sysconfig/%N
KillMode=process
Delegate=yes
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStart=$BIN_DIR/node_exporter $CMD_NODE_EXPORTER_EXEC
EOF

  if ! can_skip_firewall; then
    _firewall=""

    # Prepend 'ExecStartPre=-' to each rule
    while read -r _rule; do
      _firewall="$_firewall
ExecStartPre=-$_rule"
    done << EOF
$(firewall_rule)
EOF

    $SUDO tee -a "$FILE_NODE_EXPORTER_SERVICE" > /dev/null << EOF
$_firewall
EOF
  fi
}

# Write upstart service file
create_upstart_service_file() {
  info "upstart: Creating service file '$FILE_NODE_EXPORTER_SERVICE'"
  $SUDO tee "$FILE_NODE_EXPORTER_SERVICE" > /dev/null << EOF
description "Node exporter"
start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit unlimited

exec $BIN_DIR/node_exporter $CMD_NODE_EXPORTER_EXEC
EOF
}

# Write service file
create_service_file() {
  case $INIT_SYSTEM in
    openrc) create_openrc_service_file ;;
    systemd) create_systemd_service_file ;;
    upstart) create_upstart_service_file ;;
    *) fatal "Unknown init system '$INIT_SYSTEM'" ;;
  esac
}

# Get hashes of the current Node exporter bin and service files
get_installed_hashes() {
  $SUDO sha256sum "$BIN_DIR/node_exporter" "$FILE_NODE_EXPORTER_SERVICE" 2>&1 || true
}

# Enable openrc service
openrc_enable() {
  info "openrc: Enabling node_exporter service"
  $SUDO rc-update add node_exporter default > /dev/null
}
# Start openrc service
openrc_start() {
  info "openrc: Starting node_exporter"
  $SUDO "$FILE_NODE_EXPORTER_SERVICE" restart
  # Wait an arbitrary amount of time for service to load
  sleep 1
  rc-service --quiet node_exporter status || fatal "openrc: Error starting node_exporter"
}

# Enable systemd service
systemd_enable() {
  info "systemd: Enabling node_exporter service"
  $SUDO systemctl enable "$FILE_NODE_EXPORTER_SERVICE" > /dev/null
  $SUDO systemctl daemon-reload > /dev/null
}
# Start systemd service
systemd_start() {
  info "systemd: Starting node_exporter"
  $SUDO systemctl restart node_exporter
  # Wait an arbitrary amount of time for service to load
  sleep 1
  systemctl is-active --quiet node_exporter || fatal "systemd: Error starting node_exporter"

}

# Enable upstart service
upstart_enable() {
  info "upstart: Enabling node_exporter service"
  # Already defined in /etc/init/node_exporter.conf
}
# Start upstart service
upstart_start() {
  info "upstart: Starting node_exporter"
  $SUDO initctl start node_exporter
  # Wait an arbitrary amount of time for service to load
  sleep 1
  initctl status node_exporter || fatal "upstart: Error starting node_exporter"
}

# relabel to executable if SElinux is installed
setup_selinux() {
  if can_skip_selinux; then
    info 'Skipping SELinux setup'
    return
  fi

  if check_cmd getenforce; then
    if check_cmd semanage; then
      semanage fcontext -D "$BIN_DIR/node_exporter"
      semanage fcontext -a -t bin_t "$BIN_DIR/node_exporter"
      restorecon -v "$BIN_DIR/node_exporter"
    else
      error "Cannot setup SELinux context for binary '$BIN_DIR/node_exporter'. Please install 'policycoreutils-python-utils' package then re-run this script"
      if check_cmd chcon; then
        info "Trying non permanent SELinux labeling. This won't survive a FS relabeling"
        if ! chcon -t bin_t "$BIN_DIR/node_exporter"; then
          error "Cannot set context of binary '$BIN_DIR/node_exporter'"
        else
          info "Temporary SELinux context set for '$BIN_DIR/node_exporter'"
        fi
      fi
    fi
  fi

}

# Startup service
service_enable_and_start() {
  [ "$INSTALL_NODE_EXPORTER_SKIP_ENABLE" = true ] && return
  case $INIT_SYSTEM in
    openrc) openrc_enable ;;
    systemd) systemd_enable ;;
    upstart) upstart_enable ;;
    *) fatal "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  [ "$INSTALL_NODE_EXPORTER_SKIP_START" = true ] && return
  POST_INSTALL_HASHES=$(get_installed_hashes)
  if [ "$PRE_INSTALL_HASHES" = "$POST_INSTALL_HASHES" ] && [ "$INSTALL_NODE_EXPORTER_FORCE_RESTART" != true ]; then
    info 'No change detected so skipping service start'
    return
  fi
  case $INIT_SYSTEM in
    openrc) openrc_start ;;
    systemd) systemd_start ;;
    upstart) upstart_start ;;
    *) fatal "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  return 0
}

# ================
# MAIN
# ================
# Re-evaluate args to include env command
eval set -- "$(escape "$INSTALL_NODE_EXPORTER_EXEC") $(quote "$@")"
# Run
{
  verify_system
  setup_env "$@"
  download_and_verify
  setup_selinux
  create_killall
  create_uninstall
  systemd_disable
  create_service_file
  service_enable_and_start
}
NODE_EXPORTER_INSTALLER_EOF
        if [ ! -s "${node_exporter_installer}" ]; then
            log "Failed to write node_exporter installer" "ERROR"
        else
            # Pin a release with NODE_EXPORTER_VERSION to make installs reproducible.
            # Left empty, the installer resolves the latest release from the GitHub API.
            INSTALL_NODE_EXPORTER_VERSION="${NODE_EXPORTER_VERSION}" \
            INSTALL_NODE_EXPORTER_SKIP_FIREWALL="${NODE_EXPORTER_SKIP_FIREWALL}" \
            INSTALL_NODE_EXPORTER_EXEC="--collector.logind --collector.interrupts --collector.systemd --collector.processes --collector.textfile.directory=/var/lib/node_exporter/textfile_collector" \
            sh "${node_exporter_installer}" 2>> "${LOG_FILE}" || log "Failed to setup node_exporter" "ERROR"
        fi
        rm -f "${node_exporter_installer}" > /dev/null 2>&1
        harden_node_exporter_service
    else
        log "No node_exporter installed" "ERROR"
    fi

    # Prometheus el_configurator version support
    cat << 'EOF' > /etc/cron.d/el_configurator
# Run el_configurator prometheus metrics every hour only
MAILTO=""
45 * * * * root /bin/bash /usr/local/bin/el_configurator_metrics.sh > /dev/null 2>&1
EOF
    [ $? -ne 0 ] && log "Failed to create /etc/cron.d/el_configurator" "ERROR"

    # EL configurator metrics
    cat << 'EOF' > /usr/local/bin/el_configurator_metrics.sh
#!/usr/bin/env bash

el_configurator_date=0
el_configurator_date=$(date -r /root/.el-configurator.log +%s 2>/dev/null)
echo -e "# HELP el_configurator_setup_date timestamp when last EL configurator was run\n# TYPE el_configurator_setup_date gauge\nel_configurator_setup_date ${el_configurator_date}" > /var/lib/node_exporter/textfile_collector/el_configurator.prom

if grep "EL POST SCRIPT: SUCCESS" /etc/motd >/dev/null 2>&1; then
    el_configurator_state=0
else
    el_configurator_state=1
fi
echo -e "# HELP el_configurator_state current state of el_configurator run (0=OK)\n# TYPE el_configurator_state gauge\nel_configurator_state ${el_configurator_state}" >> /var/lib/node_exporter/textfile_collector/el_configurator.prom

needs_rebooting() {
    if type dnf > /dev/null 2>&1; then
        dnf needs-restarting -r >/dev/null 2>&1
        needs_reboot=$?
    elif type apt > /dev/null 2>&1; then
        if [ -f /var/run/reboot-required ]; then
                needs_reboot=1
        fi
    elif type zypper > /dev/null 2>&1; then
        zypper needs-rebooting -r >/dev/null 2>&1
        needs_reboot=$?
    else
        needs_reboot=2
    fi
}
needs_reboot=0
needs_rebooting
echo -e "# HELP node_needs_reboot if node needs a restart (1=yes, 0=no)\n# TYPE node_needs_reboot gauge\nnode_needs_reboot $needs_reboot" >> /var/lib/node_exporter/textfile_collector/el_configurator.prom
EOF
    [ $? -ne 0 ] && log "Failed to create /usr/local/bin/el_configurator_metrics.sh" "ERROR"
    chmod +x /usr/local/bin/el_configurator_metrics.sh  || log "Failed to chmod /usr/local/bin/el_configurator_metrics.sh" "ERROR"
fi

if [ "${KEEP_IPV4_FORWARDING}" != false ]; then
    log "Keeping IPv4 forwarding enabled"
    sysctl -w net.ipv4.ip_forward=1 2>> "${LOG_FILE}" || log "Failed to set net.ipv4.ip_forward at runtime" "ERROR"
    # This file is created by OpenSCAP profiles on EL systems
    # Note that /etc/sysctl.d/99-sysctl.conf is a symlink to /etc/sysctl.conf if OpenSCAP was used
    if [ -f /etc/sysctl.d/99-sysctl.conf ]; then
        set_conf_value /etc/sysctl.d/99-sysctl.conf "net.ipv4.ip_forward" "1" || log "Failed to set net.ipv4.ip_forward in /etc/sysctl.d/99-sysctl.conf" "ERROR"
    else
        # Create our own file to enforce the setting
        set_conf_value /etc/sysctl.d/99-ipv4-forward.conf "net.ipv4.ip_forward" "1" || log "Failed to set net.ipv4.ip_forward in /etc/sysctl.d/99-ipv4-forward.conf" "ERROR"
    fi
    # We also need to patch /etc/sysctl.conf since OpenScap and others may disable the setting there too
    set_conf_value /etc/sysctl.conf "net.ipv4.ip_forward" "1" || log "Failed to set net.ipv4.ip_forward in /etc/sysctl.conf" "ERROR"
fi

if [ "${KEEP_ARP_FILTER_DISABLED}" != false ]; then
    log "Disabling ARP filtering which may cause network issues with some cloud provider VMs"
    sysctl -w net.ipv4.conf.all.arp_filter=0 2>> "${LOG_FILE}" || log "Failed to set net.ipv4.conf.all.arp_filter at runtime" "ERROR"
    # This file is created by OpenSCAP profiles on EL systems
    # Note that /etc/sysctl.d/99-sysctl.conf is a symlink to /etc/sysctl.conf if OpenSCAP was used
    if [ -f /etc/sysctl.d/99-sysctl.conf ]; then
        set_conf_value /etc/sysctl.d/99-sysctl.conf "net.ipv4.conf.all.arp_filter" "0" || log "Failed to set net.ipv4.conf.all.arp_filter in /etc/sysctl.d/99-sysctl.conf" "ERROR"
    else
        # Create our own file to enforce the setting
        set_conf_value /etc/sysctl.d/99-arp-filter.conf "net.ipv4.conf.all.arp_filter" "0" || log "Failed to set net.ipv4.conf.all.arp_filter in /etc/sysctl.d/99-arp-filter.conf" "ERROR"
    fi
    # We also need to patch /etc/sysctl.conf since OpenScap and others may disable the setting there too
    set_conf_value /etc/sysctl.conf "net.ipv4.conf.all.arp_filter" "0" || log "Failed to set net.ipv4.conf.all.arp_filter in /etc/sysctl.conf" "ERROR"
fi

if [ "${ALLOW_UNPROTECTED_FS_SYMLINKS}" != false ]; then
    log "Allowing unprotected symlinks in filesystems"
    sysctl -w fs.protected_symlinks=0 2>> "${LOG_FILE}" || log "Failed to set fs.protected_symlinks at runtime" "ERROR"
    set_conf_value /etc/sysctl.d/99-fs-symlinks.conf "fs.protected_symlinks" "0" || log "Failed to set fs.protected_symlinks in /etc/sysctl.d/99-fs-symlinks.conf" "ERROR"
fi

if [ "${DISABLE_APPARMOR_RUNC_PROFILE}" == true ]; then
    if [ -f /etc/apparmor.d/runc ]; then
        log "Disabling AppArmor runc profile which may cause issues with containers"
        ln -s /etc/apparmor.d/runc /etc/apparmor.d/disable/ 2>> "${LOG_FILE}" || log "Failed to disable AppArmor runc profile" "ERROR"
        systemctl restart apparmor 2>> "${LOG_FILE}" || log "Failed to restart AppArmor after disabling runc profile" "ERROR"
    fi
fi

# Setting up watchdog in systemd
if [ "${CONFIGURE_WATCHDOG}" != false ]; then
    log "Setting up systemd watchdog"
    sed -i -e 's,^#RuntimeWatchdogSec=.*,RuntimeWatchdogSec=60s,' "${SYSTEMD_PREFIX}/system.conf" 2>> "${LOG_FILE}" || log "Failed to sed ${SYSTEMD_PREFIX}/system.conf" "ERROR"
fi

if [ "${CONFIGURE_NETWORK_SCHEDULING}" != false ]; then
    log "Setup cake qdisc algorithm and bbr congestion control"
    set_conf_value /etc/sysctl.d/99-sched.conf "net.core.default_qdisc" "cake"
    set_conf_value /etc/sysctl.d/99-sched.conf "net.ipv4.tcp_congestion_control" "bbr"
fi

if [ -n "${VM_SWAPPINESS_VALUE}" ]; then
    log "Setting vm.swappiness to ${VM_SWAPPINESS_VALUE}"
    sysctl -w vm.swappiness="${VM_SWAPPINESS_VALUE}" 2>> "${LOG_FILE}" || log "Failed to set vm.swappiness at runtime" "ERROR"
    set_conf_value /etc/sysctl.d/99-vm-swappiness.conf "vm.swappiness" "${VM_SWAPPINESS_VALUE}" || log "Failed to set vm.swappiness in /etc/sysctl.d/99-vm-swappiness.conf" "ERROR"
fi

if [ "${KERNELS_TO_KEEP}" -ne 0 ]; then
    log "Setting number of kernels to keep to ${KERNELS_TO_KEEP}"
    if [ "${FLAVOR}" = "rhel" ]; then
        set_conf_value /etc/dnf/dnf.conf "installonly_limit" "${KERNELS_TO_KEEP}" "=" || log "Failed to set installonly_limit in /etc/dnf/dnf.conf" "ERROR"
        dnf_remove_old_kernels
    elif [ "${FLAVOR}" = "debian" ]; then
        cat << EOF > /etc/apt/apt.conf.d/01autoremove-kernels
APT::NeverAutoRemove::KernelCount "${KERNELS_TO_KEEP}";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
        if [ $? -ne 0 ]; then
            log "Failed to create /etc/apt/apt.conf.d/01autoremove-kernels" "ERROR"
        fi
        apt autoremove --purge -y 2>> "${LOG_FILE}" || log "Failed to autoremove old kernels" "ERROR"
    fi
fi


# All sshd directives go into one drop-in, written and checked as a single change, so that a bad
# value is caught by sshd -t here instead of stopping sshd from starting at the next reboot
if [ "${CONFIGURE_SSHD_CLIENT_ALIVE}" != false ] || [ "${CONFIGURE_CIS_SSHD_SETTINGS}" != false ]; then
    if sshd_begin_edit; then
        if [ "${CONFIGURE_SSHD_CLIENT_ALIVE}" != false ]; then
            log "Adding ClientAlive settings to sshd"
            set_conf_value "${SSHD_EDIT_FILE}" "TCPKeepAlive" "no" " "
        fi
        if [ "${CONFIGURE_CIS_SSHD_SETTINGS}" != false ]; then
            # The following CIS parameters aren't applied automagically by scap profiles
            # CIS 5.2.12
            log "Applying CIS 5.2.12"
            set_conf_value "${SSHD_EDIT_FILE}" "X11Forwarding" "no" " "
            # CIS 5.2.13
            log "Applying CIS 5.2.13"
            set_conf_value "${SSHD_EDIT_FILE}" "AllowTcpForwarding" "no" " "
            # CIS 5.2.15
            log "Applying CIS 5.2.15"
            set_conf_value "${SSHD_EDIT_FILE}" "Banner" "/etc/issue.net" " "
            # CIS 5.2.16
            log "Applying CIS 5.2.16"
            set_conf_value "${SSHD_EDIT_FILE}" "MaxAuthTries" "3" " "
            # CIS 5.2.17
            log "Applying CIS 5.2.17"
            set_conf_value "${SSHD_EDIT_FILE}" "MaxStartups" "10:30:60" " "
            # CIS 5.2.19
            log "Applying CIS 5.2.19"
            set_conf_value "${SSHD_EDIT_FILE}" "LoginGraceTime" "60" " "
            # CIS 5.2.20
            log "Applying CIS 5.2.20"
            set_conf_value "${SSHD_EDIT_FILE}" "ClientAliveInterval" "120" " "
            set_conf_value "${SSHD_EDIT_FILE}" "ClientAliveCountMax" "3" " "
        fi
        sshd_commit_edit
    fi
fi

# sshd uses the first value it obtains for a keyword, and the distribution drop-in sorts before
# ours, so X11Forwarding has to be turned off there too rather than only in our own file
if [ "${CONFIGURE_CIS_SSHD_SETTINGS}" != false ] && [ -f /etc/ssh/sshd_config.d/50-redhat.conf ]; then
    log "Patching /etc/ssh/sshd_config.d/50-redhat.conf for CIS 5.2.12"
    if sshd_begin_edit /etc/ssh/sshd_config.d/50-redhat.conf; then
        set_conf_value "${SSHD_EDIT_FILE}" "X11Forwarding" "no" " "
        sshd_commit_edit
    fi
fi

# CIS 5.6.12
log "Applying CIS 5.6.12 with deviation to allow multiple password changes"
set_conf_value /etc/login.defs "PASS_MIN_DAYS" "0" " "

if [ "${ALLOW_SUDO}" = true ] && [ "${SCAP_PROFILE}" != false ]; then
    log "Allowing sudo command regardless of scap profile ${SCAP_PROFILE}"
    # Patch sudoers file since noexec is set by default, which prevents sudo
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y sudo 2>> "${LOG_FILE}" || log "Failed to install sudo" "ERROR"
        # chmod 4111 /usr/bin/sudo is not needed on RHEL normally
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y sudo 2>> "${LOG_FILE}" || log "Failed to install sudo" "ERROR"
    fi
    log "chmod /usr/bin/sudo to setuid root and disabling noexec in sudoers"
    chmod 4755 /usr/bin/sudo 2>> "${LOG_FILE}" || log "Failed to chmod /usr/bin/sudo" "ERROR"
    if sudoers_begin_edit; then
        sed -i 's/^Defaults noexec/#Defaults noexec/g' "${SUDOERS_EDIT_FILE}" 2>> "${LOG_FILE}" || log "Failed to sed the sudoers copy" "ERROR"
        sudoers_commit_edit
    fi
else
    log "Not altering sudo behavior"
fi

# Apply CIS 5.3.3 and CIS 5.3.6
# Both Defaults go in together, so that visudo validates them as one change
if ! type sudo > /dev/null 2>&1; then
    log "sudo is not installed, skipping CIS 5.3.3 and CIS 5.3.6"
elif sudoers_begin_edit; then
    # Not an ERROR: shipping sudo-rs is a normal state, not a failure of this script
    if sudo -V 2>/dev/null | grep "sudo-rs" > /dev/null 2>&1; then
        log "This system uses sudo-rs, which does not support logging input/output. Not setting a sudo logfile"
    else
        set_conf_value "${SUDOERS_EDIT_FILE}" "Defaults logfile" "/var/log/sudo.log" "="
    fi
    set_conf_value "${SUDOERS_EDIT_FILE}" "Defaults timestamp_timeout" "15" "="
    sudoers_commit_edit
fi

# Apply CIS 1.1.1.1,1.1.1.1,1.1.9,3.1.3
if [ -d /etc/modprobe.d ]; then
    log "Applying CIS 1.1.1.1,1.1.1.2,1.1.9,3.1.3"
    set_conf_value /etc/modprobe.d/CIS_blacklists.conf "blacklist squashfs" "" " "
    set_conf_value /etc/modprobe.d/CIS_blacklists.conf "install squashfs" "/bin/false" " "
    set_conf_value /etc/modprobe.d/CIS_blacklists.conf "blacklist udf" "" " "
    set_conf_value /etc/modprobe.d/CIS_blacklists.conf "install udf" "/bin/false" " "
    set_conf_value /etc/modprobe.d/CIS_blacklists.conf "blacklist usb-storage" "" " "
    set_conf_value /etc/modprobe.d/CIS_blacklists.conf "install usb-storage" "/bin/false" " "
    set_conf_value /etc/modprobe.d/CIS_blacklists.conf "blacklist tipc" "" " "
    set_conf_value /etc/modprobe.d/CIS_blacklists.conf "install tipc" "/bin/false" " "
fi

# Apply CIS 1.5.1,1.5.2
if [ -f /etc/systemd/coredump.conf ]; then
    log "Applying CIS 1.5.1-,1.5.2"
    set_conf_value /etc/systemd/coredump.conf "Storage" "none" "="
    set_conf_value /etc/systemd/coredump.conf "ProcessSizeMax" "0" "="
fi


# Apply CIS 5.1.2-5.1.5
for file in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
    if [ ! -e "${file}" ]; then
        log "File ${file} does not exist, skipping CIS 5.1.2-5.1.5"
        continue
    fi
    log "Applying CIS 5.1.2-5.1.5 on ${file}"
    chown root:root "${file}" 2>> "${LOG_FILE}" || log "Failed to chown root:root ${file}" "ERROR"
    chmod og-rwx "${file}" 2>> "${LOG_FILE}" || log "Failed to chmod og-rwx ${file}" "ERROR"
done

log "Configuring /etc/profile.d/tmout.sh since some shells dont like typeset"
cat << 'EOF' > /etc/profile.d/tmout.sh
# Set TMOUT to 600 seconds (10 minutes) of inactivity for interactive shells

if [ "$0" = "tcsh" ]; then
    set autologout=10
elif [ "$0" = "bash" ]; then
    typeset -xr TMOUT=600
else
    export TMOUT=600
    readonly TMOUT
    export TMOUT
fi
EOF
[ $? -ne 0 ] && log "Failed to create /etc/profile.d/tmout.sh" "ERROR"

# Setting up banner
if [ "${POST_INSTALL_SCRIPT_GOOD}" != true ]; then
    MOTD_STATUS="___EL POST SCRIPT: FAILURE___"
else
    MOTD_STATUS="___EL POST SCRIPT: SUCCESS___"
fi
echo "${REMOTE_LOGIN_BANNER}" > /etc/motd 2>> "${LOG_FILE}" || log "Failed to create /etc/motd" "ERROR"
echo "${MOTD_MSG}" >> /etc/motd 2>> "${LOG_FILE}" || log "Failed to add cow to /etc/motd" "ERROR"
sed -i "s/___MOTD_STATUS_DO_NOT_DELETE___/${MOTD_STATUS}/g" /etc/motd 2>> "${LOG_FILE}" || log "Failed to set status in /etc/motd" "ERROR"


# Cleanup kickstart file replaced with inst.nosave=all_ks
[ -f /root/anaconda-ks.cfg ] && /bin/shred -uz /root/anaconda-ks.cfg
[ -f /root/original-ks.cfg ] && /bin/shred -uz /root/original-ks.cfg

# Clean up log files, caches and temp
# Clear caches, files, and logs
/bin/rm -rf /tmp/* /tmp/.[a-zA-Z]* /var/tmp/*
/bin/rm -rf /etc/*- /etc/*.bak /etc/*~ /etc/sysconfig/*~
/bin/rm -rf /var/log/*debug /var/log/dmesg*
/bin/rm -rf /var/lib/cloud/a* /var/log/cloud-init*.log
/bin/rm -rf /var/lib/authselect/backups/*
if [ "${FLAVOR}" = "rhel" ]; then
    /bin/rm -rf /var/cache/dnf/* /var/cache/yum/* /var/log/rhsm/*
    /bin/rm -rf /var/lib/dnf/* /var/lib/yum/repos/* /var/lib/yum/yumdb/*
    /bin/rm -rf /var/lib/NetworkManager/* /var/lib/unbound/*.key
fi
#/bin/rm -rf /var/log/anaconda

# Make sure we write everything to disk
sync; echo 3 > /proc/sys/vm/drop_caches

log "Finished at $(date) with state ${POST_INSTALL_SCRIPT_GOOD}"
