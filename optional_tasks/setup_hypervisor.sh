#!/usr/bin/env bash

## Hypervisor Installer 2025092301 for RHEL9/10

# Requirements:
# RHEL9 / 10
# System partition 30G for system

# optional, setup_hypervisor.conf file with variable overrides
[ -f ./setup_hypervisor.conf ] && source ./setup_hypervisor.conf

# Setup bridge for first ethernet interface and use it's IP configuration
[ -z "${SETUP_BRIDGE}" ] && SETUP_BRIDGE=true

# COCKPIT ALLOWED USER
[ -z "${ADMIN_USER}" ] && ADMIN_USER=myuser

# Setup SNMP
[ -z "${SETUP_SNMP}" ] && SETUP_SNMP=false

# HARDWARE ID for NetPerfect hardware
# or UNKNOWN for other hardware
[ -z "${HARDWARE_ID}" ] && HARDWARE_ID="UNKNOWN"


# Autosigned certificate information
[ -z "${COMMON_NAME}" ] && COMMON_NAME=hyper.local
[ -z "${EMAIL}" ] && EMAIL=contact@local.tld
[ -z "${CITY}" ] && CITY=DetroitRockCity
[ -z "${STATE}" ] && STATE=Kiss

CERT_DIR=/etc/pki/tls
TARGET_DIR=/etc/ssl/certs
CRT_SUBJECT="/C=FR/O=Oranization/CN=${COMMON_NAME}/OU=RD/L=${CITY}/ST=${STATE}/emailAddress=${EMAIL}"


LOG_FILE=/root/.npf-hypervisor.log
SCRIPT_GOOD=true

function log {
    local log_line="${1}"
    local level="${2}"

    if [ "${level}" != "" ]; then
        log_line="${level}: ${log_line}"
    fi
    echo "${log_line}" >> "${LOG_FILE}"
    echo "${log_line}"

    if [ "${level}" == "ERROR" ]; then
        SCRIPT_GOOD=false
    fi
}

function log_quit {
    log "${1}" "${2}"
    log "Exiting script"
    exit 1
}

get_el_version() {
    if [ -f /etc/os-release ]; then
        # DIST must contain "rhel", "almalinux", "debian" or alike
	# The following awk line has been tested on almalinux 8, rhel 10 and debian 12
        DIST=$(awk '{ if ($1~/^ID=/) { sub("ID=","", $0); gsub("\"","", $0); print tolower($0) }}' /etc/os-release)
        RELEASE=0
        if grep 'ID="rhel"' /etc/os-release > /dev/null || grep 'ID_LIKE="*rhel*' /etc/os-release > /dev/null; then
            FLAVOR=rhel
	    if grep -e 'PLATFORM_ID=".*el10' /etc/os-release > /dev/null; then
                RELEASE=10
		        #SYSTEMD_PREFIX=/usr/lib/systemd
            elif grep -e 'PLATFORM_ID=".*el9' /etc/os-release > /dev/null; then
                RELEASE=9
		        #SYSTEMD_PREFIX=/etc/systemd
            elif grep -e 'PLATFORM_ID=".*el8' /etc/os-release > /dev/null; then
                RELEASE=8
		        #SYSTEMD_PREFIX=/etc/systemd
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
		        #SYSTEMD_PREFIX=/etc/systemd
            elif grep -e 'VERSION_ID="12' /etc/os-release > /dev/null; then
                RELEASE=12
		        #SYSTEMD_PREFIX=/etc/systemd
            elif grep -e 'VERSION_ID="13' /etc/os-release > /dev/null; then
                RELEASE=13
		        #SYSTEMD_PREFIX=/etc/systemd
            fi
            if [ "${RELEASE}" -eq 11 ] || [ "${RELEASE}" -eq 12 ] || [ "${RELEASE}" -eq 13 ]; then
                log "Found Linux ${DIST} release ${RELEASE}"
            else
                log_quit "Not compatible with ${DIST} release ${RELEASE} "
            fi

        fi
    else
        log_quit "No /etc/os-release file found"
    fi
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
    # sed separator $'\001' (SOH) is chosen since it's unlikely to be used in a configuration file
    # sed separator can be changed to any other character as long as it's not used
    # if not used, we'll go for the SOH character
    sed_separator="${5:-false}"
    if [ "${sed_separator}" == false ]; then
        sed_separator=$(echo -en "\001")
    fi

	if [ -f "$file" ]; then
        # If separator is empty, this may fail if multiple entries beginning with name exist in file
		if grep -e "^${name}.*${separator}" "${file}" > /dev/null 2>&1; then
            log "Updating conf [${name}] to [${value}] in file [${file}]." "INFO"
			# Using -i.tmp for BSD compat
			sed -i.eltmp "s${sed_separator}^${name}\s*${separator}\s*.*${sed_separator}${name}${separator}${value}${sed_separator}g" "${file}" >> "${LOG_FILE}" 2>&1
			if [ $? -ne 0 ]; then
				log "Cannot update value [${name}] to [${value}] in file [${file}]." "ERROR"
                log "Current value is $(grep -e "^${name}.*${separator}" "${file}")" "NOTICE"
			fi
            # Remove temp file if exists
			rm -f "$file.eltmp" > /dev/null 2>&1
		else
            log "Creating conf [${name}] set to [${value}] in file [${file}]." "INFO"
			echo "${name}${separator}${value}" >> "${file}" || log "Cannot create value [${name}] to [${value}] in file [${file}]." "ERROR"
		fi
	else
        log "Creating file [${file}] with conf [${name}] set to [${value}]." "INFO"
		echo "${name}${separator}${value}" > "${file}" || log "File [${file}] does not exist. Failed to create it with value for [${name}]" "ERROR"
	fi
}

get_el_version

log "#### Installing prerequisites ####"

dnf install -y epel-release 2>> "${LOG_FILE}" || log "Failed to install epel release" "ERROR"
dnf install -y policycoreutils-python-utils 2>> "${LOG_FILE}" || log "Failed to install selinux tools" "ERROR"
dnf install -y virt-what tar bzip2 2>> "${LOG_FILE}" || log "Failed to install system tools" "ERROR"
dnf install -y qemu-kvm libvirt virt-install bridge-utils libguestfs-tools guestfs-tools cockpit cockpit-machines 2>> "${LOG_FILE}" || log "Failed to install KVM" "ERROR"
dnf install -y cockpit cockpit-machines 2>> "${LOG_FILE}" || log "Failed to install cockpit" "ERROR"
dnf install -y pcp 2>> "${LOG_FILE}" || log "pcp" "ERROR"
# RHEL 10 does not need cockpit-pcp anymore, but python3-pcp
if [ "${RELEASE}" -eq 10 ]; then
    dnf install -y python3-pcp 2>> "${LOG_FILE}" || log "Failed to install python3-pcp" "ERROR"
else
    dnf install -y cockpit-pcp 2>> "${LOG_FILE}" || log "Failed to install cockpit-pcp" "ERROR"
fi
dnf install -y openssl 2>> "${LOG_FILE}" || log "Failed to install openssl" "ERROR"

# Optional virt-manager + X11 support (does not work in readonly mode)
dnf install -y virt-manager xorg-x11-xauth 2>> "${LOG_FILE}" || log "Failed to install virt-manager and X11 auth support" "ERROR"
log "Disabling upower that comes with virt-manager for whatever reason"
systemctl stop upower 2>> "${LOG_FILE}" || log "Failed to stop upower" "ERROR"
systemctl disable upower 2>> "${LOG_FILE}" || log "Failed to disable upower" "ERROR"


log "#### System tuning ####"
# Don't log martian packets, obviously we'll get plenty
# These are RHEL specific with ANSSI BP028 high profile
sysctl -w net.ipv4.conf.all.log_martians=0 2>> "${LOG_FILE}" || log "Cannot set net.ipv4.conf.all.log_martians=0 live" "ERROR"
# /etc/sysctl.d/99-sysctl.conf is is a symlink to /etc/sysctl.conf in EL9
set_conf_value /etc/sysctl.conf "net.ipv4.conf.all.log_martians" "0"

log "#### Setting up system certificate ####"

[ ! -d "${TARGET_DIR}" ] && mkdir "${TARGET_DIR}"

openssl req -nodes -new -x509 -days 7300 -newkey rsa:4096 -keyout "${CERT_DIR}/private/${COMMON_NAME// /_}.key" -subj "${CRT_SUBJECT}" -out "${CERT_DIR}/certs/${COMMON_NAME// /_}.crt"  2>> "${LOG_FILE}" || log "Failed to generate local cert" "ERROR"
cat "${CERT_DIR}/private/${COMMON_NAME// /_}.key" "${CERT_DIR}/certs/${COMMON_NAME// /_}.crt" > "${TARGET_DIR}/${COMMON_NAME// /_}.pem" 2>> "${LOG_FILE}" || log "Failed to concat local cert" "ERROR"

if [ "${SETUP_SNMP}" == true ]; then
    log "#### Setup SNMP ####"
    dnf install -y net-snmp net-snmp-utils 2>> "${LOG_FILE}" || log "Failed to install SNMP" "ERROR"
    cat << 'EOF' > /tmp/snmpd_part.conf
# View all tree in default systemview
view    systemview    included   .1
# System data
view    systemview    included   .1.3.6.1.2.1.1
view    systemview    included   .1.3.6.1.2.1.25.1.1
# Exclude USM and VACM MIBs
view systemview excluded .1.3.6.1.6.3.15
view systemview excluded .1.3.6.1.6.3.16
# Disks
view   systemview    included   .1.3.6.1.4.1.2021.9
# CPU
view    systemview    included   .1.3.6.1.4.1.2021.10
EOF
    [ $? -eq 0 ] 2>> "${LOG_FILE}" || log "Failed to create /tmp/snmpd_part.conf" "ERROR"

    sed -i '/^view    systemview    included   .1.3.6.1.2.1.25.1.1$/ r /tmp/snmpd_part.conf' /etc/snmp/snmpd.conf 2>> "${LOG_FILE}" || log "Configuring SNMP failed" "ERROR"
fi

log "#### Setting up cockpit & performance logging ####"
systemctl enable pmcd 2>> "${LOG_FILE}" || log "Failed to enable pmcd" "ERROR"
systemctl start pmcd 2>> "${LOG_FILE}" || log "Failed to start pmcd" "ERROR"
systemctl enable pmlogger 2>> "${LOG_FILE}" || log "Failed enable pmlogger" "ERROR"
systemctl start pmlogger 2>> "${LOG_FILE}" || log "Failed start pmlogger" "ERROR"
systemctl enable cockpit.socket 2>> "${LOG_FILE}" || log "Failed to enable cockpit" "ERROR"
systemctl start cockpit.socket 2>> "${LOG_FILE}" || log "Failed to start cockpit" "ERROR"


# Actually, we won't allow sudo since ANSSI BP-028 prohibits it (using Defaults noexec in /etc/sudoers)
# Cockpit sudo must work for admin user
#usermod -aG wheel ${ADMIN_USER} || result=1
#echo 'Defaults:'${ADMIN_USER}' !requiretty' >> /etc/sudoers

#Let's allow cockpit user root (which is okay since we have pam faillock set)
sed -i 's/^root/#root/g' /etc/cockpit/disallowed-users 2>> "${LOG_FILE}" || log "Allowing root user for cockpit failed" "ERROR"


if [ "${SETUP_BRIDGE}" != false ]; then
    log "#### Setup first ethernet interface as bridged to new bridge kvmbr0 ####"
    # ip -br l == ip print brief list of network interfaces
    iface=$(ip -br l | awk '$1 !~ "lo|vir|wl" { print $1; exit }')
    if [ -z "${iface}" ]; then
        log_quit "Failed to get first ethernet interface" "ERROR"
    fi

    # Get nmcli connection name for interface
    cnx="$(nmcli -t -f GENERAL.CONNECTION d show "${iface}" | awk -F':' '{print $2}')"
    if [ -z "$cnx" ]; then
        log_quit "Failed to get connection name for interface ${iface}" "ERROR"
    fi

    # Configure a bridge
     # Disable spanning tree so we don't interrupt existing STP infrastructure
    nmcli c add type bridge ifname kvmbr0 con-name kvmbr0 autoconnect yes bridge.stp no 2>> "${LOG_FILE}" || log "Creating bridge failed" "ERROR"
    
    # Get IPv4 and IPv6 settings only from connection and apply them to newly created bridge
    # For whatever reason, there's no config export / import in nmcli
    # --terse allows some parseable output
    # So we need to parse nmcli output lines like ipv4.method:auto to ipv4.method auto so nmcli accepts it's own output !!!
    # like ':' separator could never be used in an IP address !!!
    nmcli_settings=""
    while read -r setting; do
        nmcli_setting_name=$(echo "${setting}" | awk -F'=' '{print $1}')
        nmcli_setting_value=$(echo "${setting}" | awk -F'=' '{print $2}')
        if [ "${nmcli_setting_name}" == "ipv4.routes" ] || [ "${nmcli_setting_name}" == "ipv6.routes" ]; then
            while read -rd, route_setting; do
                nmcli_settings="${nmcli_settings} +${nmcli_setting_name} \"${route_setting}\""
            done <<< "${nmcli_setting_value}"
        else
            nmcli_settings="${nmcli_settings} ${nmcli_setting_name} \"${nmcli_setting_value}\""
        fi
    done < <(nmcli --terse -o --show-secrets c show --active "$cnx" | grep "^ipv4\|^ipv6" | sed 's/:/=/')
    echo "Configuring bridge with settings: ${nmcli_settings}"
    eval "nmcli c modify kvmbr0 ${nmcli_settings}" 2>> "${LOG_FILE}" || log "Failed to modify connection $cnx" "ERROR"


    #nmcli c modify kvmbr0 ipv4.method auto 2>> "${LOG_FILE}" || log "Setting bridge ipv4 DHCP failed" "ERROR"
    nmcli c add type bridge-slave ifname "${iface}" master kvmbr0 autoconnect yes 2>> "${LOG_FILE}" || log "Adding bridge slave failed" "ERROR"
    nmcli c up kvmbr0  2>> "${LOG_FILE}" || log "Enabling bridge failed" "ERROR"
    nmcli c del "${cnx}"  2>> "${LOG_FILE}" || log "Deleting interface ${iface} config failed" "ERROR"
fi

log "#### Setting up virtualization ####"
cat << 'EOF' > /etc/sysconfig/libvirt-guests
ON_BOOT=start
ON_SHUTDOWN=shutdown
PARALLEL_SHUTDOWN=2
SHUTDOWN_TIMEOUT=360
SYNC_TIME=1
EOF
[ $? -eq 0 ] 2>> "${LOG_FILE}" || log "Failed to create /etc/sysconfig/libvirt-guests" "ERROR"

systemctl enable libvirtd 2>> "${LOG_FILE}" || log "Failed to enable libvirtd" "ERROR"
systemctl start libvirtd 2>> "${LOG_FILE}" || log "Failed to enable libvirtd" "ERROR"
systemctl enable libvirt-guests 2>> "${LOG_FILE}" || log "Failed to enable libvirt-guests" "ERROR"
systemctl start libvirt-guests 2>> "${LOG_FILE}" || log "Failed to start libvirt-guests" "ERROR"


log "#### Setup PCI Passthrough ####"
grubby --update-kernel=ALL --args="intel_iommu=on" 2>> "${LOG_FILE}" || log "Failed to add iommu kernel argument" "ERROR"
grub2-mkconfig -o /boot/grub2/grub.cfg 2>> "${LOG_FILE}" || log "Failed to generate grub.cfg" "ERROR"


log "#### Identifying system ####"

host=$(virt-what)

case "$host" in
        *"redhat"*)
        NPFSYSTEM="VMv4r-rhhv"
        ;;
        *"hyperv"*)
        NPFSYSTEM="VMv4r-mshv"
        ;;
        *"vmware"*)
        NPFSYSTEM="VMv4r-vmhv"
        ;;
        *"kvm"*)
        NPFSYSTEM="VMv4r-kvhv"
        ;;
        *)
        echo "Change etc/netperfect-release if we are one an original NetPerfect hardware"
        NPFSYSTEM="${HARDWARE_ID}"
        ;;
esac

echo "NPF-${NPFSYSTEM}" > /etc/netperfect-release 2>> "${LOG_FILE}" || log "Failed to create /etc/netperfect-release" "ERROR"

## Disable sssd
systemctl disable sssd 2>> "${LOG_FILE}" || log "Cannot disable sssd" "ERROR"


log "#### Cleanup system files ####"
## Clean system so readonly will be clean
# Need to be done before installing the appliance so we can keep logs

# Clean up log files, caches and temp
# Clear caches, files, and logs
/bin/rm -rf /root/* /tmp/* /tmp/.[a-zA-Z]* /var/tmp/*
/bin/rm -rf /etc/*- /etc/*.bak /etc/*~ /etc/sysconfig/*~
/bin/rm -rf /var/cache/dnf/* /var/cache/yum/* /var/log/rhsm/*
/bin/rm -rf /var/lib/dnf/* /var/lib/yum/repos/* /var/lib/yum/yumdb/*
/bin/rm -rf /var/lib/NetworkManager/* /var/lib/unbound/*.key
/bin/rm -rf /var/log/*debug /var/log/dmesg*
/bin/rm -rf /var/lib/cloud/* /var/log/cloud-init*.log
/bin/rm -rf /var/lib/authselect/backups/*
#/bin/rm -rf /var/log/anaconda

if [ "${SCRIPT_GOOD}" == false ]; then
    log "#### WARNING Installation FAILED ####"
    exit 1
else
    log "#### Installation done (check logs) ####"
    echo "Don't forget to remove this file if it was on disk"
    echo "Then reboot this machine"
    exit 0
fi