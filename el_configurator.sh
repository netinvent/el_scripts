#!/usr/bin/env bash

# Security & basic setup configuration script from NetPerfect
# Works with RHEL / AlmaLinux / RockyLinux / CentOS EL8, EL9 and EL10
# Works with Debian 12

SCRIPT_BUILD="2025080401"

# Note that all variables can be overridden by kernel arguments
# Example: Override BRAND_NAME with kernel argument: NPF_BRAND_NAME=MyBrand

BRAND_NAME=NetPerfect # Name which will be displayed in /etc/issue
VIRT_BRAND_NAME=NetPerfect # Brand which will be used to detect virtual machines
BRAND_VER=4.9

MOTD_MSG=$(cat << 'EOF'
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
         \   ^__^
          \  (oo)\_______
             (__)\       )\/\
                 ||----w |
                 ||     ||
___MOTD_STATUS_DO_NOT_DELETE___
 
EOF
)


# Select SCAP PROFILE, choosing "" disables scap profile
# Get profile list with oscap info "/usr/share/xml/scap/ssg/content/ssg-${DIST}${RELEASE}-ds.xml"
# where flavor in rhel,debian and release = major os version
SCAP_PROFILE=anssi_bp28_high
#SCAP_PROFILE=anssi_bp28_intermediary
#SCAP_PROFILE=false

# By default, ANSSI profiles disable sudo (which is a good thing, but el10 also disables root account by default, so we need at least a root account or sudo working)
ALLOW_SUDO=false

# Setup SELinux on Debian
SETUP_SELINUX_DEBIAN=false

# Configure serial terminal
CONFIGURE_SERIAL_TERMINAL=true

# Add resize_term and resize_term2 scripts to /etc/profile.d
CONFIGURE_TERMINAL_RESIZER=true

# Installa and configure node_exporter
CONFIGURE_NODE_EXPORTER=true
NODE_EXPORTER_SKIP_FIREWALL=false # Do not open node_exporter port in firewall
# Setup python smartmontools / nvme tooling for prometheus
CONFIGURE_NODE_EXPORTER_PYTHON_EXTENSIONS=true

# Make sure system automatically installs security updates
CONFIGURE_AUTOMATIC_UPDATES=true

# Enable system watchdog
CONFIGURE_WATCHDOG=true

# Use specific network schedulers (bbr + cake)
CONFIGURE_NETWORK_SCHEDULING=true

# Add client keep alives to sshd
CONFIGURE_SSHD_CLIENT_ALIVE=true

# Implement tuned profiles
CONFIGURE_TUNED=true

# Install and configure firewall
CONFIGURE_FIREWALL=true

# Optional whihtelist IPs / CIDR for firewall
#FIREWALL_WHITELIST_IP_LIST="192.168.200.0/24 10.0.0.1"
FIREWALL_WHITELIST_IP_LIST=""

# Install and configure fail2ban
CONFIGURE_FAIL2BAN=true

# Optional whitelist IPs / CIDR for Fail2ban
FAIL2BAN_IGNORE_IP_LIST="${FIREWALL_WHITELIST_IP_LIST}"

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

    kernel_arg_prefix="NPF_"

    if [ -f /proc/cmdline ]; then
        KERNEL_ARGS=$(cat /proc/cmdline)
        log "Current kernel arguments: ${KERNEL_ARGS}"
        # Split kernel arguments. We want word splitting here, so no to shellcheck SC2206
        # shellcheck disable=SC2206
        KERNEL_ARGS_SPLIT=(${KERNEL_ARGS// / })
        for argument in "${KERNEL_ARGS_SPLIT[@]}"; do
            if [ "${argument:0:${#kernel_arg_prefix}}" = "${kernel_arg_prefix}" ]; then
                argument="${argument:${#kernel_arg_prefix}}"
                # No need to check SC2206 here neither
                # shellcheck disable=SC2206
                argument_split=(${argument//=/ })
                log "Retrieved variable from kernel arguments: ${argument_split[0]}=${argument_split[1]}"
                eval "${argument_split[0]}=${argument_split[1]}"
            fi
        done
    else
        log "Cannot find kernel arguments from /proc/cmdline" "ERROR"
    fi
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
        # DIST must contain "rhel", "almalinux", "debian" or alike
	# The following awk line has been tested on almalinux 8, rhel 10 and debian 12
        DIST=$(awk '{ if ($1~/^ID=/) { sub("ID=","", $0); gsub("\"","", $0); print tolower($0) }}' /etc/os-release)
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
            fi
            if [ "${RELEASE}" -eq 11 ] || [ "${RELEASE}" -eq 12 ]; then
                log "Found Linux ${DIST} release ${RELEASE}"
            else
                log_quit "Not compatible with ${DIST} release ${RELEASE} "
            fi

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
            log "IP check to ${host} works."
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

set_conf_value() {
    # Updates a line in a configuration file
    # name=value or name    =   value (gets rewritten to name=value) if separator = '='
    # name value if separator = ' '
    # name = value if separator = ' = '
	file="${1}"
	name="${2}"
	value="${3}"
	separator="${4:-=}"
    # sed separator $'\001' is chosen since it's unlikely to be used in a configuration file
    # sed separator can be changede to any other character as long as it's not used
    sed_separator="${5:-$'\001'}"

	if [ -f "$file" ]; then
		if grep -e "^${name}.*${separator}" "${file}" > /dev/null 2>&1; then
			# Using -i.tmp for BSD compat
			sed -i.eltmp "s${sed_separator}^${name}\s*${separator}\s*.*${sed_separator}${name}${separator}${value}${sed_separator}g" "${file}"
			if [ $? -ne 0 ]; then
				log "Cannot update value [${name}] to [${value}] in file [${file}]." "ERROR"
			fi
            # Remove temp file if exists
			rm -f "$file.eltmp" > /dev/null 2>&1
			log "Updating conf [${name}] to [${value}] in file [${file}]." "INFO"
		else
            log "Creating conf [${name}] set to [${value}] in file [${file}]." "INFO"
			echo "${name}${separator}${value}" >> "${file}" || log "Cannot create value [${name}] to [${value}] in file [${file}]." "ERROR"
		fi
	else
        log "Creating file [${file}] with conf [${name}] set to [${value}]." "INFO"
		echo "${name}${separator}${value}" > "${file}" || log "File [${file}] does not exist. Failed to create it with value for [${name}]" "ERROR"
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

check_internet
if [ $? -eq 0 ]; then
    log "Updating system"
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf update -y 2>> "${LOG_FILE}" || log "Failed to update system" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        apt update -y 2>> "${LOG_FILE}" || log "Failed to update system" "ERROR"
        apt dist-upgrade -y 2>> "${LOG_FILE}" || log "Failed to update system" "ERROR"
    fi
fi

if [ "${SCAP_PROFILE}" != false ]; then  
    # Disable --fetch-remote-resources on machines without internet
    [ ! -d /root/openscap_report ] && mkdir /root/openscap_report

    check_internet
    if [ $? -eq 0 ]; then
        # Let's reinstall openscap in case we're running this script on a non prepared machine
        if [ "${FLAVOR}" = "rhel" ]; then
            dnf install -y openscap scap-security-guide 2> "${LOG_FILE}" || log "OpenSCAP is missing and cannot be installed" "ERROR"
        elif [ "${FLAVOR}" = "debian" ]; then
            # Download debian 12 anssi profiles which need ssg-debian 0.17.4 at least
            # which are not available in stable as of 2025/02/14
            # As of 2025/04/24, ssg-debian 0.1.76-1 is the most recent release one can get
            if [ "${RELEASE}" -eq 12 ]; then
                log "Downloading up ssg openscap data for debian 12"
                if type curl > /dev/null 2>&1; then
                    curl -OL http://ftp.debian.org/debian/pool/main/s/scap-security-guide/ssg-base_0.1.76-1_all.deb 2> "${LOG_FILE}" || log "OpenSCAP new deb 12 profiles ssg-base cannot be downloaded with curl" "ERROR"
                    curl -OL http://ftp.debian.org/debian/pool/main/s/scap-security-guide/ssg-debian_0.1.76-1_all.deb 2> "${LOG_FILE}" || log "OpenSCAP new deb 12 profiles ssg-debian cannot be downloaded with curl" "ERROR"
                else
                    wget http://ftp.debian.org/debian/pool/main/s/scap-security-guide/ssg-base_0.1.76-1_all.deb 2> "${LOG_FILE}" || log "OpenSCAP new deb 12 profiles ssg-base cannot be downloaded with wget" "ERROR"
                    wget http://ftp.debian.org/debian/pool/main/s/scap-security-guide/ssg-debian_0.1.76-1_all.deb 2> "${LOG_FILE}" || log "OpenSCAP new deb 12 profiles ssg-debian cannot be downloaded with wget" "ERROR"
                fi
                dpkg -i ssg-base_0.1.76-1_all.deb 2> "${LOG_FILE}" || log "OpenSCAP new deb 12 profiles ssg-base cannot be installed" "ERROR"
                dpkg -i ssg-debian_0.1.76-1_all.deb 2> "${LOG_FILE}" || log "OpenSCAP new deb 12 profiles ssg-debian cannot be installed" "ERROR"
            fi
            apt install -y openscap-utils  2> "${LOG_FILE}" || log "OpenSCAP is missing and cannot be installed" "ERROR"
        else
            log_quit "Cannot setup OpenSCAP on this system"
        fi
        log "Setting up scap profile with remote resources"
        oscap xccdf eval --profile ${SCAP_PROFILE} --fetch-remote-resources --remediate "/usr/share/xml/scap/ssg/content/ssg-${DIST}${RELEASE}-ds.xml" > /root/openscap_report/actions.log 2>&1
        # result 2 is partially applied, which can be normal
        if [ $? -eq 1 ]; then
            log "OpenSCAP failed. See /root/openscap_report/actions.log" "ERROR"
        else
            log "Generating scap results with remote resources"
            oscap xccdf generate guide --fetch-remote-resources --profile ${SCAP_PROFILE} "/usr/share/xml/scap/ssg/content/ssg-${DIST}${RELEASE}-ds.xml" > "/root/openscap_report/${SCAP_PROFILE}_$(date '+%Y-%m-%d').html" 2>> "${LOG_FILE}"
            [ $? -ne 0 ] && log "OpenSCAP results failed. See log file" "ERROR"
        fi
    else
        log "Setting up scap profile without internet"
        oscap xccdf eval --profile ${SCAP_PROFILE} --remediate "/usr/share/xml/scap/ssg/content/ssg-${DIST}${RELEASE}-ds.xml" > /root/openscap_report/actions.log 2>&1
        if [ $? -eq 1 ]; then
            log "OpenSCAP failed. See /root/openscap_report/actions.log" "ERROR"
        else
            log "Generating scap results without internet"
            oscap xccdf generate guide --profile ${SCAP_PROFILE} "/usr/share/xml/scap/ssg/content/ssg-${DIST}${RELEASE}-ds.xml" > "/root/openscap_report/${SCAP_PROFILE}_$(date '+%Y-%m-%d').html" 2>> "${LOG_FILE}"
            [ $? -ne 0 ] && log "OpenSCAP results failed. See log file" "ERROR"
        fi
    fi


    # Fix firewall cannot load after anssi_bp28_high
    if [ "${SCAP_PROFILE}" = "anssi_bp28_high" ] && [ "${FLAVOR}" = "rhel" ]; then
        log "Fixing firewalld cannot load after anssi_bp28_high profile on ${FLAVOR}"
        setsebool -P secure_mode_insmod=off || log "Cannot set secure_mode_insmod to off" "ERROR"
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
    dnf install -4 -y tar >> "${LOG_FILE}" || log "Cannot install tar" "ERROR"
    if  [ "${FLAVOR}" = "rhel" ]; then
        dnf install -4 -y epel-release 2>> "${LOG_FILE}" || log "Failed to install epel-release, some tools like fail2ban will not be installed" "ERROR"
        # The following packages are epel dependent
        # WIP: RHEL 10 ha no atop nor nmon for the moment
        if [ "${RELEASE}" -eq 10 ]; then
            available_packages="htop iftop iptraf"
        else
            available_packages="htop atop nmon iftop iptraf"
        fi
        # We actually want word splitting here
        # shellcheck disable=SC2086
        dnf install -4 -y ${available_packages} 2>> "${LOG_FILE}" || log "Failed to install additional tools ${available_packages}" "ERROR"
        dnf config-manager --set-enabled crb 2>> "${LOG_FILE}" || log "Failed to enable crb" "ERROR"
        if [ "${CONFIGURE_AUTOMATIC_UPDATES}" != false ]; then
            dnf install -4 -y dnf-automatic 2>> "${LOG_FILE}" || log "Failed to install dnf-automatic" "ERROR"
        fi
        if [ "${CONFIGURE_TUNED}" != false ]; then
            dnf install -4 -y tuned 2>> "${LOG_FILE}" || log "Failed to install tuned" "ERROR"
        fi
    elif [ "${FLAVOR}" = "debian" ]; then
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
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y smartmontools nvme-cli 2>> "${LOG_FILE}" || log "Failed to install smartmontools" "ERROR"
        SMARTD_CONF_FILE=/etc/smartmontools/smartd.conf
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y smartmontools nvme-cli 2>> "${LOG_FILE}" || log "Failed to install smartmontools" "ERROR"
        SMARTD_CONF_FILE=/etc/smartd.conf
    fi
    echo "DEVICESCAN -H -l error -f -C 197+ -U 198+ -t -l selftest -I 194 -n sleep,7,q -s (S/../.././10|L/../../[5]/13)" >> "${SMARTD_CONF_FILE}" 2>> "${LOG_FILE}" || log "Failed to add DEVICESCAN to smartd.conf" "ERROR"
    systemctl enable smartd 2>> "${LOG_FILE}" || log "Failed to start smartd" "ERROR"

    if [ "${CONFIGURE_NODE_EXPORTER_PYTHON_EXTENSIONS}" == true ]; then
        log "Setting up python smartmontools / nvme tooling for prometheus"
        if [ "${FLAVOR}" = "rhel" ]; then
            dnf install -y python3-prometheus_client 2>> "${LOG_FILE}" || log "Failed to add prometheus_client lib" "ERROR"
        elif [ "${FLAVOR}" = "debian" ]; then
            # Debian does not come with ensurepip but has prometheus-client library
            apt install -y python3-prometheus-client 2>> "${LOG_FILE}" || log "Failed to install python3 and pip3" "ERROR"
        fi
        log "Setting up python smart script for prometheus"

        # github https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/commit/6b36c812b59f42ee5d9e609fcaf17a61692e08d5
        # 2024-10-21
        cat << 'EOF' > /usr/local/bin/smartmon.py
#!/usr/bin/env python3

import argparse
import collections
import csv
import re
import shlex
import subprocess
import sys
from prometheus_client import CollectorRegistry, Gauge, generate_latest

device_info_re = re.compile(r'^(?P<k>[^:]+?)(?:(?:\sis|):)\s*(?P<v>.*)$')

ata_error_count_re = re.compile(
    r'^Error (\d+) \[\d+\] occurred', re.MULTILINE)

self_test_re = re.compile(r'^SMART.*(PASSED|OK)$', re.MULTILINE)

device_info_map = {
    'Vendor': 'vendor',
    'Product': 'product',
    'Revision': 'revision',
    'Logical Unit id': 'lun_id',
    'Model Family': 'model_family',
    'Device Model': 'device_model',
    'Serial Number': 'serial_number',
    'Serial number': 'serial_number',
    'Firmware Version': 'firmware_version',
}

smart_attributes_whitelist = (
    'airflow_temperature_cel',
    'command_timeout',
    'current_pending_sector',
    'end_to_end_error',
    'erase_fail_count_total',
    'g_sense_error_rate',
    'hardware_ecc_recovered',
    'host_reads_mib',
    'host_reads_32mib',
    'host_writes_mib',
    'host_writes_32mib',
    'load_cycle_count',
    'lifetime_writes_gib',
    'media_wearout_indicator',
    'percent_lifetime_remain',
    'wear_leveling_count',
    'nand_writes_1gib',
    'offline_uncorrectable',
    'percent_lifetime_remain',
    'power_cycle_count',
    'power_on_hours',
    'program_fail_count',
    'raw_read_error_rate',
    'reallocated_event_count',
    'reallocated_sector_ct',
    'reported_uncorrect',
    'sata_downshift_count',
    'seek_error_rate',
    'spin_retry_count',
    'spin_up_time',
    'start_stop_count',
    'temperature_case',
    'temperature_celsius',
    'temperature_internal',
    'total_bad_block',
    'total_lbas_read',
    'total_lbas_written',
    'total_writes_gib',
    'total_reads_gib',
    'udma_crc_error_count',
    'unsafe_shutdown_count',
    'unexpect_power_loss_ct',
    'workld_host_reads_perc',
    'workld_media_wear_indic',
    'workload_minutes',
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

SmartAttribute = collections.namedtuple('SmartAttribute', [
    'id', 'name', 'flag', 'value', 'worst', 'threshold', 'type', 'updated',
    'when_failed', 'raw_value',
])


class Device(collections.namedtuple('DeviceBase', 'path opts')):
    """Representation of a device as found by smartctl --scan output."""

    @property
    def type(self):
        return self.opts.type

    @property
    def base_labels(self):
        return {'device': self.path, 'disk': self.type.partition('+')[2] or '0'}

    def smartctl_select(self):
        return ['--device', self.type, self.path]


def smart_ctl(*args, check=True):
    """Wrapper around invoking the smartctl binary.

    Returns:
        (str) Data piped to stdout by the smartctl subprocess.
    """
    return subprocess.run(
        ['smartctl', *args], stdout=subprocess.PIPE, check=check
    ).stdout.decode('utf-8')


def smart_ctl_version():
    return smart_ctl('-V').split('\n')[0].split()[1]


def find_devices(by_id):
    """Find SMART devices.

    Yields:
        (Device) Single device found by smartctl.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--device', dest='type')

    args = ['--scan-open']
    if by_id:
        args.extend(['-d', 'by-id'])
    devices = smart_ctl(*args)

    for device in devices.split('\n'):
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
        smart_ctl('--nocheck', 'standby', *device.smartctl_select())
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
    info_lines = smart_ctl(
        '--info', *device.smartctl_select()
    ).strip().split('\n')[3:]

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

    state = {
        g[1].split(' ', 1)[0]
        for g in groups if g[0] == 'SMART support'}

    smart_available = 'Available' in state
    smart_enabled = 'Enabled' in state

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
    out = smart_ctl('--health', *device.smartctl_select(), check=False)

    self_assessment_passed = bool(self_test_re.search(out))
    metrics["device_smart_healthy"].labels(
        device.base_labels["device"], device.base_labels["disk"]
    ).set(self_assessment_passed)


def collect_ata_metrics(device):
    # Fetch SMART attributes for the given device.
    attributes = smart_ctl(
        '--attributes', *device.smartctl_select()
    )

    # replace multiple occurrences of whitespace with a single whitespace
    # so that the CSV Parser recognizes individual columns properly.
    attributes = re.sub(r'[\t\x20]+', ' ', attributes)

    # Turn smartctl output into a list of lines and skip to the table of
    # SMART attributes.
    attribute_lines = attributes.strip().split('\n')[7:]

    # Some attributes have multiple IDs but have the same name.  Don't
    # yield attributes that already have been reported before.
    seen = set()

    reader = csv.DictReader(
        (line.strip() for line in attribute_lines),
        fieldnames=SmartAttribute._fields[:-1],
        restkey=SmartAttribute._fields[-1], delimiter=' ')
    for entry in reader:
        # We're only interested in the SMART attributes that are
        # whitelisted here.
        entry['name'] = entry['name'].lower()
        if entry['name'] not in smart_attributes_whitelist:
            continue

        # Ensure that only the numeric parts are fetched from the raw_value.
        # Attributes such as 194 Temperature_Celsius reported by my SSD
        # are in the format of "36 (Min/Max 24/40)" which can't be expressed
        # properly as a prometheus metric.
        m = re.match(r'^(\d+)', ' '.join(entry['raw_value']))
        if not m:
            continue
        entry['raw_value'] = m.group(1)

        # Some device models report "---" in the threshold value where most
        # devices would report "000". We do the substitution here because
        # downstream code expects values to be convertible to integer.
        if entry['threshold'] == '---':
            entry['threshold'] = '0'

        if entry['name'] in smart_attributes_whitelist and entry['name'] not in seen:
            for col in 'value', 'worst', 'threshold', 'raw_value':
                metrics["attr_" + col].labels(
                    device.base_labels["device"],
                    device.base_labels["disk"],
                    entry["name"],
                ).set(entry[col])

            seen.add(entry['name'])


def collect_ata_error_count(device):
    """Inspect the device error log and report the amount of entries.

    Args:
        device: (Device) Device in question.
    """
    error_log = smart_ctl(
        '-l', 'xerror,1', *device.smartctl_select(), check=False)

    m = ata_error_count_re.search(error_log)

    error_count = m.group(1) if m is not None else 0
    metrics["device_errors"].labels(
        device.base_labels["device"], device.base_labels["disk"]
    ).set(error_count)


def collect_disks_smart_metrics(wakeup_disks, by_id):
    for device in find_devices(by_id):
        is_active = device_is_active(device)
        metrics["device_active"].labels(
            device.base_labels["device"], device.base_labels["disk"],
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

        if device.type.startswith('sat'):
            collect_ata_metrics(device)
            collect_ata_error_count(device)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--wakeup-disks', dest='wakeup_disks', action='store_true',
                        help="Wake up disks to collect live stats")
    parser.add_argument('--by-id', dest='by_id', action='store_true',
                        help="Use /dev/disk/by-id/X instead of /dev/sdX to index devices")
    args = parser.parse_args(sys.argv[1:])

    metrics["smartctl_version"].labels(smart_ctl_version()).set(1)

    collect_disks_smart_metrics(args.wakeup_disks, args.by_id)
    print(generate_latest(registry).decode(), end="")


if __name__ == '__main__':
    main()
EOF
        [ $? -ne 0 ] && log "Failed to create /usr/local/bin/smartmon.py" "ERROR"

        # github https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/commit/a2b43e19be1e64c31b626ca827506977cac93488
        # Added PR #246
        cat << 'EOF' >> /usr/local/bin/nvme_metrics.py
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
        "Device write commands from host",
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


def exec_nvme_json(*args, has_verbose):
    """
    Execute nvme CLI tool with specified arguments and return parsed JSON output.
    """
    # Note: nvme-cli v2.11 effectively introduced a breaking change by forcing JSON output to always
    # be verbose. Older versions of nvme-cli optionally produced verbose output if the --verbose
    # flag was specified. In order to avoid having to handle two different JSON schemas, always
    # add the --verbose flag.
    # Note2: nvme-cli 2.3 that ships with Debian 12 has no verbose parameter for smart-log command only

    if "smart-log" in args and not has_verbose:
        output = exec_nvme(*args, "--output-format", "json")
    else:
        output = exec_nvme(*args, "--output-format", "json", "--verbose")
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
        [ ! -d /var/lib/node_exporter/textfile_collector ] && mkdir -p /var/lib/node_exporter/textfile_collector
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
        [ ! -d /var/lib/node_exporter/textfile_collector ] && mkdir -p /var/lib/node_exporter/textfile_collector
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

        if [ "${RELEASE}" -eq 10 ]; then
            TUNED_DIR=/etc/tuned/profiles
        else
            TUNED_DIR=/etc/tuned
        fi
        [ ! -d "${TUNED_DIR}/el-eco" ] && mkdir -p "${TUNED_DIR}/el-eco"
        [ ! -d "${TUNED_DIR}/el-eco" ]&& mkdir -p "${TUNED_DIR}/el-perf"

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

        cat << 'EOF' > "${TUNED_DIR}/el-perf/script.sh"
#!/usr/bin/env bash

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

        chmod +x /etc/tuned/{el-eco,el-perf}/script.sh 2>> "${LOG_FILE}" || log "Failed to chmod on tuned scripts" "ERROR"
    fi
else
    log "This is a virtual machine. We will not setup hardware tooling"
fi

if [ "${CONFIGURE_SERIAL_TERMINAL}" != false ]; then
    # Configure serial console
    log "Setting up serial console"
    systemctl enable --now serial-getty@ttyS0.service 2>> "${LOG_FILE}" || log "Enabling serial getty failed" "ERROR"
    sed -i 's/^GRUB_TERMINAL="console"/GRUB_TERMINAL="serial console"/g' /etc/default/grub 2>> "${LOG_FILE}" || log "sed failed on /etc/default/grub" "ERROR"
    sed -i 's/^GRUB_SERIAL_COMMAND=.*/GRUB_SERIAL_COMMAND="serial --unit=0 --word=8 --parity=no --speed 115200 --stop=1"/g' /etc/default/grub 2>> "${LOG_FILE}" || log "sed failed on /etc/default/grub" "ERROR"
    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=\(.*\)quiet\(.*\)/GRUB_CMDLINE_LINUX_DEFAULT=\1\2/g' /etc/default/grub 2>> "${LOG_FILE}" || log "sed failed on /etc/default/grub for removing quiet" "ERROR"
    # Update grub to add console
    if [ "${FLAVOR}" = "rhel" ]; then
        grubby --update-kernel=ALL --args="console=tty0 console=ttyS0,115200,n8" || log "Enabling serial getty failed" "ERROR"
        grub2-mkconfig --update-bls-cmdline -o /boot/grub2/grub.cfg 2>> "${LOG_FILE}" || log "grub2-mkconfig failed" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        # Replace existing console arguments
        if grep "GRUB_CMDLINE_LINUX=.*console.*" /etc/default/grub > /dev/null 2>&1; then
            sed -Ei 's#GRUB_CMDLINE_LINUX=(.*)(console=.*)(.*)"#GRUB_CMDLINE_LINUX=\1 console=tty0 console=ttyS0,115200,n8 \3"#g' /etc/default/grub
        # Add non existing console arguments
        else
            sed -Ei 's#GRUB_CMDLINE_LINUX=(.*)"#GRUB_CMDLINE_LINUX=\1  console=tty0 console=ttyS0,115200,n8"#g' /etc/default/grub
        fi
        /sbin/grub-mkconfig -o /boot/grub/grub.cfg 2>> "${LOG_FILE}" || log "grub-mkconfig failed" "ERROR"
    else
        log_quit "Cannot setup serial console on this system"
    fi
fi

if [ "${CONFIGURE_TERMINAL_RESIZER}" != false ]; then
    # Setup automagic terminal resize
    # singequotes on EOF prevents variable expansion
    # Tested on EL8, EL9 and Debian 12
    cat << 'EOF' > /etc/profile.d/term_resize.sh
# Based on solution https://unix.stackexchange.com/a/283206/135459 that replaces xterm-resize package


resize_term() {

    old=$(stty -g)
    stty raw -echo min 0 time 5

    printf '\0337\033[r\033[999;999H\033[6n\0338' > /dev/tty
    IFS='[;R' read -r _ rows cols _ < /dev/tty

    stty "$old"

    # echo "cols:$cols"
    # echo "rows:$rows"
    stty cols "$cols" rows "$rows"
}

resize_term2() {

    old=$(stty -g)
    stty raw -echo min 0 time 5

    printf '\033[18t' > /dev/tty
    IFS=';t' read -r _ rows cols _ < /dev/tty

    stty "$old"

    # echo "cols:$cols"
    # echo "rows:$rows"
    stty cols "$cols" rows "$rows"
}

# Run only if we're in a serial terminal
[ "$(tty)" = /dev/ttyS0 ] && resize_term2
EOF
    [ $? -ne 0 ] && log "Failed to create /etc/profile.d/term_resize.sh" "ERROR"
fi

# Configure persistent journal
log "Setting up persistent boot journal"
[ ! -d /var/log/journal ] && mkdir /var/log/journal
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
        set_conf_value "${auto_updates}" "upgrade_type" "security" " "
        set_conf_value "${auto_updates}" "download_updates" "yes" " "
        set_conf_value "${auto_updates}" "apply_updates" "yes" " "
        set_conf_value "${auto_updates}" "emit_via" "stdio" " "
        set_conf_value "${auto_updates}" "apply_updates" "yes" " "
        #sed -i 's/^upgrade_type[[:space:]]*=[[:space:]].*/upgrade_type = security/g' /etc/dnf/automatic.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/dnf/automatic.conf" "ERROR"
        #sed -i 's/^download_updates[[:space:]]*=[[:space:]].*/download_updates = yes/g' /etc/dnf/automatic.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/dnf/automatic.conf" "ERROR"
        #sed -i 's/^apply_updates[[:space:]]*=[[:space:]].*/apply_updates = yes/g' /etc/dnf/automatic.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/dnf/automatic.conf" "ERROR"
        #sed -i 's/^emit_via[[:space:]]*=[[:space:]].*/emit_via = stdio/g' /etc/dnf/automatic.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/dnf/automatic.conf" "ERROR"
        systemctl enable dnf-automatic.timer 2>> "${LOG_FILE}" || log "Failed to start dnf-automatic timer" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        log "Setup unattended automatic upgrades"
        # Base file can be found in /usr/share/unattended-upgrades/20auto-upgrades
        auto_upgrades="/etc/apt/apt.conf.d/20auto-upgrades"
        : > "${auto_upgrades}"
        set_conf_value "${auto_upgrades}" "APT::Periodic::Update-Package-Lists" "\"1\";" " "
        set_conf_value "${auto_upgrades}" "APT::Periodic::Unattended-Upgrade" "\"1\";" " "
        set_conf_value "${auto_upgrades}" "APT::Periodic::Download-Upgradeable-Packages" "\"1\";" " "
        set_conf_value "${auto_upgrades}" "APT::Periodic::AutocleanInterval" "\"30\";" " "
        systemctl enable unattended-upgrades 2>> "${LOG_FILE}" || log "Failed to enable unattended-upgrades" "ERROR"
        systemctl enable apt-daily-upgrade.timer 2>> "${LOG_FILE}" || log "Failed to enable apt-daily-upgrade.timer" "ERROR"
    else
        log_quit "Cannot setup automatic updates on this system. Looks unsupporte"
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
        systemctl enable firewalld 2>> "${LOG_FILE}" || log "Failed to start firewalld" "ERROR"
        # Starting firewalld may need a reboot to work, so let's not log start failures here
        if [ "${FIREWALL_WHITELIST_IP_LIST}" != "" ]; then
            log "Adding whitelisted IPs to firewalld in trusted zone"
            # shellcheck disable=SC2086
            for whitelist_ip in ${FIREWALL_WHITELIST_IP_LIST[@]}; do
                firewall-cmd --permanent --zone=trusted ---add-source=${whitelist_ip} 2>> "${LOG_FILE}" || log "Failed to add ${whitelist_ip} to firewalld whitelist" "ERROR"
            done
        fi
        systemctl start firewalld
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y ufw 2>> "${LOG_FILE}" || log "Failed to install ufw" "ERROR"
        systemctl enable --now ufw 2>> "${LOG_FILE}" || log "Failed to start ufw service" "ERROR"
        echo y | /sbin/ufw enable 2>> "${LOG_FILE}" || log "Failed to enable ufw" "ERROR"
        if [ "${FIREWALL_WHITELIST_IP_LIST}" != "" ]; then
            log "Adding whitelisted IPs to ufw"
            for whitelist_ip in ${FIREWALL_WHITELIST_IP_LIST[@]}; do
                /sbin/ufw allow from "${whitelist_ip}" 2>> "${LOG_FILE}" || log "Failed to add ${whitelist_ip} to ufw whitelist" "ERROR"
            done
        else
            Log "Adding generic SSH port permission to ufw so we can work"
                /sbin/ufw allow ssh 2>> "${LOG_FILE}" || log "Failed to allow ssh in ufw" "ERROR"*
        fi
    fi
fi

if [ "${CONFIGURE_FAIL2BAN}" != false ]; then
    log "Setting up fail2ban"
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y fail2ban 2>> "${LOG_FILE}"
	if [ $? != 0 ]; then
 		log "Failed to install fail2ban" "ERROR"
   		FAIL2BAN_INSTALLED=false
     	else
      		FAIL2BAN_INSTALLED=true
	fi
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y fail2ban 2>> "${LOG_FILE}"
	if [ $? != 0 ]; then
 		log "Failed to install fail2ban" "ERROR"
   		FAIL2BAN_INSTALLED=false
	else
 		FAIL2BAN_INSTALLED=true
        	# On Debian 12, fail2ban backend needs to be set to systemd since /var/log/auth.log does not exist anymore
        	if [ "${RELEASE}" = 12 ]; then
            	sed -i 's#^backend = %(sshd_backend)s#backend = systemd#g' /etc/fail2ban/jail.conf*
        	fi
	 fi
    fi

    if [ "${FAIL2BAN_INSTALLED}" == true ]; then
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

        set_conf_value "${default_jailfile}" "bantime.increment" "true" " = "
        set_conf_value "${default_jailfile}" "bantime.rndtime" "300" " = "
        if [ "${FAIL2BAN_IGNORE_IP_LIST}" != "" ]; then
            set_conf_value "${default_jailfile}" "ignoreip" "${FAIL2BAN_IGNORE_IP_LIST}" " = "
        fi
        set_conf_value "${default_jailfile}" "bantime" "30m" " = "
        set_conf_value "${default_jailfile}" "findtime" "2h" " = "
        set_conf_value "${default_jailfile}" "maxretry" "3" " = "

	    systemctl enable fail2ban 2>> "${LOG_FILE}" || log "Failed to enable fail2ban" "ERROR"
	    # Starting fail2ban may need a reboot to work, so let's not log start failures here
	    systemctl start fail2ban
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
        [ ! -d /var/lib/node_exporter/textfile_collector ] && mkdir -p /var/lib/node_exporter/textfile_collector
        if type curl > /dev/null 2>&1; then
            curl -sSfL https://raw.githubusercontent.com/carlocorradini/node_exporter_installer/main/install.sh | INSTALL_NODE_EXPORTER_SKIP_FIREWALL=${NODE_EXPORTER_SKIP_FIREWALL} INSTALL_NODE_EXPORTER_EXEC="--collector.logind --collector.interrupts --collector.systemd --collector.processes --collector.textfile.directory=/var/lib/node_exporter/textfile_collector" sh -s - 2>> "${LOG_FILE}" || log "Failed to setup node_exporter" "ERROR"
        else
            wget -qO- https://raw.githubusercontent.com/carlocorradini/node_exporter_installer/main/install.sh | INSTALL_NODE_EXPORTER_SKIP_FIREWALL=${NODE_EXPORTER_SKIP_FIREWALL} INSTALL_NODE_EXPORTER_EXEC="--collector.logind --collector.interrupts --collector.systemd --collector.processes --collector.textfile.directory=/var/lib/node_exporter/textfile_collector" sh -s - 2>> "${LOG_FILE}" || log "Failed to setup node_exporter" "ERROR"
        fi
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
EOF
    [ $? -ne 0 ] && log "Failed to create /usr/local/bin/el_configurator_metrics.sh" "ERROR"
    chmod +x /usr/local/bin/el_configurator_metrics.sh  || log "Failed to chmod /usr/local/bin/el_configurator_metrics.sh" "ERROR"
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

if [ "${CONFIGURE_SSHD_CLIENT_ALIVE}" != false ]; then
    log "Adding ClientAlive settings to sshd"
    set_conf_value /etc/ssh/sshd_config "TCPKeepAlive" "no" " "
    set_conf_value /etc/ssh/sshd_config "ClientAliveInterval" "120" " "
    set_conf_value /etc/ssh/sshd_config "ClientAliveCountMax" "3" " "
fi

if [ "${ALLOW_SUDO}" = true ] && [ "${SCAP_PROFILE}" != false ]; then
    log "Allowing sudo command regardless of scap profile ${SCAP_PROFILE}"
    # Patch sudoers file since noexec is set by default, which prevents sudo
    sed -i 's/^Defaults noexec/#Defaults noexec/g' /etc/sudoers 2>> "${LOG_FILE}" || log "Failed to sed /etc/sudoers" "ERROR"
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y sudo 2>> "${LOG_FILE}" || log "Failed to install sudo" "ERROR"
        # chmod 4111 /usr/bin/sudo is not needed on RHEL normally
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y sudo 2>> "${LOG_FILE}" || log "Failed to install sudo" "ERROR"
        chmod 4755 /usr/bin/sudo 2>> "${LOG_FILE}" || log "Failed to chmod /usr/bin/sudo" "ERROR"
    fi
else
    log "Not altering sudo behavior"
fi

# Setting up banner
if [ "${POST_INSTALL_SCRIPT_GOOD}" != true ]; then
    MOTD_STATUS="___EL POST SCRIPT: FAILURE___"
else
    MOTD_STATUS="___EL POST SCRIPT: SUCCESS___"
fi
echo "${MOTD_MSG}" > /etc/motd 2>> "${LOG_FILE}" || log "Failed to create /etc/motd" "ERROR"
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
