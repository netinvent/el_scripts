#!/usr/bin/env bash

# Security & basic setup configuration script from NetPerfect
# Works with RHEL / AlmaLinux / RockyLinux / CentOS EL8 and EL9
# Works with Debian 12

SCRIPT_BUILD="2025032101"

# Note that all variables can be overridden by kernel arguments
# Example: Override BRAND_NAME with kernel argument: NPF_BRAND_NAME=MyBrand

BRAND_NAME=NetPerfect # Name which will be displayed in /etc/issue
VIRT_BRAND_NAME=NetPerfect # Brand which will be used to detect virtual machines
BRAND_VER=4.6

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

NODE_EXPORTER_SKIP_FIREWALL=false # Do not open node_exporter port in firewall

# Select SCAP PROFILE, choosing "" disables scap profile
# Get profile list with oscap info "/usr/share/xml/scap/ssg/content/ssg-${FLAVOR}${RELEASE}-ds.xml"
# where flavor in rhel,debian and release = major os version
SCAP_PROFILE=anssi_bp28_high
#SCAP_PROFILE=anssi_bp28_intermediary
#SCAP_PROFILE=false

# By default, ANSSI profiles disable sudo (which is a good thing)
ALLOW_SUDO=false

# Setup SELinux on Debian
SETUP_SELINUX_DEBIAN=false

# Configure serial terminal
CONFIGURE_SERIAL_TERMINAL=true

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
        DIST=$(awk '{ if ($1~/^NAME=/) { sub("NAME=","", $1); gsub("\"", "", $1); print tolower($1) }}' /etc/os-release)
        if grep 'ID_LIKE="*rhel*' /etc/os-release > /dev/null; then
            FLAVOR=rhel
            if grep -e 'PLATFORM_ID=".*el9' /etc/os-release > /dev/null; then
                RELEASE=9
            elif grep -e 'PLATFORM_ID=".*el8' /etc/os-release > /dev/null; then
                RELEASE=8
            else
                log_quit "RHEL Like release not compatible"
            fi
            if [ "${RELEASE}" -eq 8 ] || [ "${RELEASE}" -eq 9 ]; then
                log "Found Linux ${DIST} release ${RELEASE}"
            else
                log_quit "Not compatible with ${DIST} release ${RELEASE}"
            fi
        elif grep 'ID=*debian*' /etc/os-release > /dev/null; then
            FLAVOR=debian
            if grep -e 'VERSION_ID="11' /etc/os-release > /dev/null; then
                RELEASE=11
            elif grep -e 'VERSION_ID="12' /etc/os-release > /dev/null; then
                RELEASE=12
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
    # sed separator needs to be updated if '#' is used in name, separator or value
    sed_separator="${5:-#}"

	if [ -f "$file" ]; then
		if grep "^${name}=" "${file}" > /dev/null 2>&1; then
			# Using -i.tmp for BSD compat
			sed -i.eltmp "s${separator}^${name}(\s*)${sed_separator}(\s*).*${separator}${name}${sed_separator}${value}${separator}" "${file}"
			if [ $? -ne 0 ]; then
				log "Cannot update value [${name}] to [${value}] in file [${file}]." "ERROR"
			fi
            # Remove temp file if exists
			rm -f "$file.eltmp" > /dev/null 2>&1
			log "Set [${name}] to [${value}] in file [${file}]." "INFO"
		else
			echo "${name}${separator}${value}" >> "${file}" || log "Cannot create value [${name}] to [${value}] in file [${file}]." "ERROR"
		fi
	else
		echo "${name}${separator}${value}" > "${file}" || log "File [${file}] does not exist. Failed to create it with value for [${name}]" "ERROR"
	fi
}

## Script entry point
POST_INSTALL_SCRIPT_GOOD=true

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
            if [ "${RELEASE}" = 12 ]; then
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
            loq_quit "Cannot setup OpenSCAP on this system"
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
    if  [ "${FLAVOR}" = "rhel" ]; then
        dnf install -4 -y epel-release 2>> "${LOG_FILE}" || log "Failed to install epel-release" "ERROR"
        dnf install -4 -y htop atop nmon iftop iptraf tuned tar dnf-automatic 2>> "${LOG_FILE}" || log "Failed to install additional tools" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y htop atop nmon iftop iptraf-ng tuned tar 2>> "${LOG_FILE}" || log "Failed to install additional tools" "ERROR"
    fi
else
    log "No epel available without internet. Didn't install additional packages."
fi

if [ ${IS_VIRTUAL} != true ]; then
    log "Setting up disk SMART tooling"
    # Make sure we install smartmontools even if already present
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y smartmontools || log "Failed to install smartmontools" "ERROR"
        SMARTD_CONF_FILE=/etc/smartmontools/smartd.conf
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y smartmontools || log "Failed to install smartmontools" "ERROR"
        SMARTD_CONF_FILE=/etc/smartd.conf
    fi
    echo "DEVICESCAN -H -l error -f -C 197+ -U 198+ -t -l selftest -I 194 -n sleep,7,q -s (S/../.././10|L/../../[5]/13)" >> "${SMARTD_CONF_FILE}" 2>> "${LOG_FILE}" || log "Failed to add DEVICESCAN to smartd.conf" "ERROR"
    systemctl enable smartd 2>> "${LOG_FILE}" || log "Failed to start smartd" "ERROR"

    log "Setting up smart script for prometheus"
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

smartctl_version="$(/usr/sbin/smartctl -V | head -n1 | awk '$1 == "smartctl" {print $2}')"

echo "smartctl_version{version=\"${smartctl_version}\"} 1" | format_output

if [[ "$(expr "${smartctl_version}" : '\([0-9]*\)\..*')" -lt 6 ]]; then
    exit
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
    echo "*/5 * * * * root /bin/bash /usr/local/bin/smartmon.sh > /var/lib/node_exporter/textfile_collector/smart_metrics.prom" > /etc/cron.d/smartmon_metrics 2>> "${LOG_FILE}" || log "Failed to add smartmon cron job" "ERROR"

    # TODO Test this for Debian
    log "Setting up iTCO_wdt watchdog"
    echo "iTCO_wdt" > /etc/modules-load.d/10-watchdog.conf

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

    log "Setting up tuned profiles"

    [ ! -d /etc/tuned/el-eco ] && mkdir /etc/tuned/el-eco
    [ ! -d /etc/tuned/el-perf ]&& mkdir /etc/tuned/el-perf

    cat << 'EOF' > /etc/tuned/el-eco/tuned.conf
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
    [ $? -ne 0 ] && log "Failed to create /etc/tuned/el-eco/tuned.conf" "ERROR"

    cat << 'EOF' > /etc/tuned/el-perf/tuned.conf
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
    [ $? -ne 0 ] && log "Failed to create /etc/tuned/el-perf/tuned.conf" "ERROR"

    cat << 'EOF' > /etc/tuned/el-eco/script.sh
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
    [ $? -ne 0 ] && log "Failed to create /etc/tuned/el-eco/script.sh" "ERROR"

    cat << 'EOF' > /etc/tuned/el-perf/script.sh
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
    [ $? -ne 0 ] && log "Failed to create /etc/tuned/el-perf/script.sh" "ERROR"

    chmod +x /etc/tuned/{el-eco,el-perf}/script.sh 2>> "${LOG_FILE}" || log "Failed to chmod on tuned scripts" "ERROR"
else
    log "This is a virtual machine. We will not setup hardware tooling"
fi

if [ "${CONFIGURE_SERIAL_TERMINAL}" = true ]; then
    # Configure serial console
    log "Setting up serial console"
    systemctl enable --now serial-getty@ttyS0.service 2>> "${LOG_FILE}" || log "Enabling serial getty failed" "ERROR"
    sed -i 's/^GRUB_TERMINAL="console"/GRUB_TERMINAL="serial console"/g' /etc/default/grub 2>> "${LOG_FILE}" || log "sed failed on /etc/default/grub" "ERROR"
    sed -i 's/^GRUB_SERIAL_COMMAND=.*/GRUB_SERIAL_COMMAND="serial --unit=0 --word=8 --parity=no --speed 115200 --stop=1"/g' /etc/default/grub 2>> "${LOG_FILE}" || log "sed failed on /etc/default/grub" "ERROR"
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
        grub-mkconfig -o /boot/grub/grub.cfg 2>> "${LOG_FILE}" || log "grub-mkconfig failed" "ERROR"
    else
        log_quit "Cannot setup serial console on this system"
    fi
fi



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

# Configure persistent journal
log "Setting up persistent boot journal"
[ ! -d /var/log/journal ] && mkdir /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>> "${LOG_FILE}" || log "Failed to create systemd-tmpfiles" "ERROR"
sed -i 's/.*Storage=.*/Storage=persistent/g' /etc/systemd/journald.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/systemd/journald.conf" "ERROR"

# Since kilall is not present on debian, we'll use plain old kill
# killall -USR1 systemd-journald
# We don't use pgrep since it's not installed everywhere
# shellcheck disable=SC2009
kill -USR1 "$(ps aux | grep '[s]ystemd-journald' | awk '{print $2}')"

# Configure max journal size
journalctl --vacuum-size=2G 2>> "${LOG_FILE}" || log "Failed to set journald vaccumsize" "ERROR"

if [ "${FLAVOR}" = "rhel" ]; then
    log "Setup DNF automatic except for updates that require reboot"
    sed -i 's/^upgrade_type[[:space:]]*=[[:space:]].*/upgrade_type = security/g' /etc/dnf/automatic.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/dnf/automatic.conf" "ERROR"
    sed -i 's/^download_updates[[:space:]]*=[[:space:]].*/download_updates = yes/g' /etc/dnf/automatic.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/dnf/automatic.conf" "ERROR"
    sed -i 's/^apply_updates[[:space:]]*=[[:space:]].*/apply_updates = yes/g' /etc/dnf/automatic.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/dnf/automatic.conf" "ERROR"
    sed -i 's/^emit_via[[:space:]]*=[[:space:]].*/emit_via = stdio/g' /etc/dnf/automatic.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/dnf/automatic.conf" "ERROR"
    systemctl enable dnf-automatic.timer 2>> "${LOG_FILE}" || log "Failed to start dnf-automatic timer" "ERROR"
elif [ "${FLAVOR}" = "debian" ]; then
    log "Setup unattended automatic upgrades"
    apt install -y unattended-upgrades 2>> "${LOG_FILE}" || log "Failed to install unattended-upgrades" "ERROR"
    systemctl enable unattended-upgrades 2>> "${LOG_FILE}" || log "Failed to start unattended-upgrades" "ERROR"
else
    log_quit "Cannot setup automatic updates on this system"
fi

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

# Enable firewall (firewalld is enabled by default on EL)
if [ "${FLAVOR}" = "rhel" ]; then
    dnf install -y firewalld 2>> "${LOG_FILE}" || log "Failed to install firewalld" "ERROR"
    systemctl enable --now firewalld 2>> "${LOG_FILE}" || log "Failed to start firewalld" "ERROR"
elif [ "${FLAVOR}" = "debian" ]; then
    apt install -y ufw 2>> "${LOG_FILE}" || log "Failed to install ufw" "ERROR"
    systemctl enable --now ufw 2>> "${LOG_FILE}" || log "Failed to start ufw service" "ERROR"
    ufw enable 2>> "${LOG_FILE}" || log "Failed to enable ufw" "ERROR"
    ufw allow ssh 2>> "${LOG_FILE}" || log "Failed to allow ssh in ufw" "ERROR"
fi

# Install fail2ban
if [ "${SETUP_FAIL2BAN}" != false ]; then
    log "Setting up fail2ban"
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y fail2ban 2>> "${LOG_FILE}" || log "Failed to install fail2ban" "ERROR"
    elif [ "${FLAVOR}" = "debian" ]; then
        apt install -y fail2ban 2>> "${LOG_FILE}" || log "Failed to install fail2ban" "ERROR"
        # On Debian 12, fail2ban backend needs to be set to systemd since /var/log/auth.log does not exist anymore
        if [ "${RELEASE}" = 12 ]; then
            sed -i 's#^backend = %(sshd_backend)s#backend = systemd#g' /etc/fail2ban/jail.conf*
        fi
    fi
    # Enable SSHD jail
    sed -i 's#^\[sshd\]#\[sshd\]\nenabled = true#g' /etc/fail2ban/jail.conf
    systemctl enable --now fail2ban 2>> "${LOG_FILE}" || log "Failed to enable fail2ban" "ERROR"
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

# Setting up watchdog in systemd
log "Setting up systemd watchdog"
sed -i -e 's,^#RuntimeWatchdogSec=.*,RuntimeWatchdogSec=60s,' /etc/systemd/system.conf 2>> "${LOG_FILE}" || log "Failed to sed /etc/systemd/system.conf" "ERROR"

log "Setup cake qdisc algorithm and bbr congestion control"
set_conf_value /etc/sysctl.d/99-sched.conf "net.core.default_qdisc" "cake"
set_conf_value /etc/sysctl.d/99-sched.conf "net.ipv4.tcp_congestion_control" "bbr"

# Add ClientAlive to SSHD
set_conf_value /etc/ssh/sshd_config "TCPKeepAlive" "no" " "
set_conf_value /etc/ssh/sshd_config "ClientAliveInterval" "120" " "
set_conf_value /etc/ssh/sshd_config "ClientAliveCountMax" "3" " "

if [ "${ALLOW_SUDO}" = true ] && [ "${SCAP_PROFILE}" != false ]; then
    log "Allowing sudo command regardless of scap profile ${SCAP_PROFILE}"
    # Patch sudoers file since noexec is set by default, which prevents sudo
    sed -i 's/^Defaults noexec/#Defaults noexec/g' /etc/sudoers 2>> "${LOG_FILE}" || log "Failed to sed /etc/sudoers" "ERROR"
    if [ "${FLAVOR}" = "rhel" ]; then
        dnf install -y sudo 2>> "${LOG_FILE}" || log "Failed to install sudo" "ERROR"
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