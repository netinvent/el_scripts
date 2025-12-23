#!/usr/bin/env bash

## Readonly setup script 2025122301 for RHEL9/10

# Requirements:
# RHEL9/10 installed

LOG_FILE=/root/.npf-readonly.log
SCRIPT_GOOD=true

target="${1:-false}"

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

if [ "${target}" != "ztl" ] && [ "${target}" != "hv" ]; then
    log_quit "Target needs to be ztl or hv"
 fi

dnf install -y readonly-root 2>> "${LOG_FILE}" || log_quit "Cannot install readonly_root"

echo "#### Setting up readonly root ####"

# We can add "noreadonly" as kernel argument to bypass readonly root

# Disable unused systemd service that will fail
systemctl disable man-db-restart-cache-update.service 2>> "${LOG_FILE}" || log "Cannot disable man-db-restart-cache-update.service" "ERROR"

# Enable readonly root
set_conf_value /etc/sysconfig/readonly-root READONLY yes

# Change default label of stateful partition to something less than 15 chars so XFS can hold that label
# Those should already be set by the VMv4 kickstart file
set_conf_value /etc/sysconfig/readonly-root STATE_LABEL STATEFULRW 

rm -f /etc/statetab.d/{snmp,nm,qemu,cockpit,rsyslog,prometheus,node_exporter,ztl} > /dev/null 2>&1
rm -f /etc/rwtab.d/{tuned,issue,ztl,haproxy,ztl} > /dev/null 2>&1
# statetab will be persistent volumes stored on a partition which label must match the
# STATE_LABEL= directive in /etc/sysconfig/readonly-root (defaults to stateless-state)
# Those dirs are stateful across reboots
# Keep in mind we need to label a partition with
# xfs_admnin -L STATEFULRW /dev/disk/by-uuid/{some_uuid}
# find uuid with lsblk -f
echo "/etc/snmp" >> /etc/statetab.d/snmp 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/snmp" "ERROR"
echo "/etc/NetworkManager/system-connections" >> /etc/statetab.d/nm 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/nm" "ERROR"
echo "/etc/prometheus/conf.d" >> /etc/statetab.d/prometheus 2>> "${LOG_FILE}" || log "Cannot add /etc/prometheus/conf.d to /etc/statetab.d/prometheus" "ERROR"
echo "/var/lib/prometheus" >> /etc/statetab.d/prometheus 2>> "${LOG_FILE}" || log "Cannot add /var/lib/prometheus to /etc/statetab.d/prometheus" "ERROR"
echo "/var/lib/node_exporter"  >> /etc/statetab.d/node_exporter 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/node_exporter" "ERROR"
echo "/var/lib/rsyslog" >> /etc/statetab.d/rsyslog 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/rsyslog" "ERROR"
# cockpit
echo "/var/lib/pcp" >> /etc/statetab.d/cockpit 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/cockpit" "ERROR"
echo "/etc/pcp" >> /etc/statetab.d/cockpit 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/cockpit" "ERROR"
# cockpit RHEL10 specific
echo "/etc/cockpit/ws-certs.d" >> /etc/statetab.d/cockpit 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/cockpit" "ERROR"

# dnf cache
echo "/var/lib/dnf" >> /etc/statetab.d/dnf 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/dnf" "ERROR"
# For DNF to work we'd need /var/cache/dnf but obviously /var/cache overrides this
echo "/var/cache" >> /etc/statetab.d/dnf 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/dnf" "ERROR"
echo "/var/lib/kdump" >> /etc/statetab.d/kdump 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/kdump" "ERROR"
# TPM
echo "/var/lib/tpm2-tss" >> /etc/statetab.d/tpm 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/tpm" "ERROR" 
# fail2ban
echo "/var/lib/fail2ban" >> /etc/statetab.d/fail2ban 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/fail2ban" "ERROR"


if [ "${target}" == "hv" ]; then
    log "Configuring specific HV stateless settings"
    echo "Configuring specific HV Stateless" 2>> "${LOG_FILE}" || log "Cannot configure HV stateless" "ERROR"

    # Don't put images into /var/lib/libvirt/images since it will be mounted as stateless partition
    # so if there were to be disk images, stateless partition would fill
    # libvirt needs the following directories to be RW in order to work
    # /var/lib/libvirt/dnsmasq
    # /var/lib/libvirt/filesystems
    # /var/lib/libvirt/swtpm
    # /var/lib/libvirt/boot
    # /var/lib/libvirt/network
    # /etc/libvirt

    echo "/var/lib/libvirt" >> /etc/statetab.d/qemu 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/qemu" "ERROR"
    echo "/etc/libvirt" >> /etc/statetab.d/qemu 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/qemu" "ERROR"
    
    # Move default pool to data so we don't 
    [ ! -d /data ] && mkdir /data
    sed -i 's#/var/lib/libvirt/images#/data#g' /etc/libvirt/storage/default.xml 2>> "${LOG_FILE}" || log "Cannot change /var/lib/libvirt/images to /data in images.xml" "ERROR"
    semanage fcontext -a -t virt_image_t "/data(/.*)?" 2>> "${LOG_FILE}" || log "Cannot set virt_image_t on /data" "ERROR"
fi

# Keep logs persistent too
echo "/var/log" > /etc/statetab.d/log 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/log" "ERROR"
sed -i 's:dirs\(.*\)/var/log:#/dirs\1/var/log # Configured in /etc/statetab to be persistent:g' /etc/rwtab 2>> "${LOG_FILE}" || log "Cannot comment out /var/log in /etc/rwtab" "ERROR"

# Those dirs are stateful until reboot
# Size is 1/2 of system RAM
echo "dirs /var/log/tuned" >> /etc/rwtab.d/tuned 2>> "${LOG_FILE}" || log "Cannot create /etc/rwtab.d/tuned" "ERROR"
echo "files /etc/issue" >> /etc/rwtab.d/issue 2>> "${LOG_FILE}" || log "Cannot create /etc/rwtab.d/issue" "ERROR"
# Deal with password updates in RO systems, example error: Dec 23 09:08:34 host.local pwhistory_helper[4115]: Cannot create /etc/security/opasswd temp file: Read-only file system
echo "dirs /etc/security" >> /etc/rwtab.d/issue 2>> "${LOG_FILE}" || log "Cannot create /etc/rwtab.d/issue" "ERROR"

if [ "${target}" == "ztl" ]; then
    log "Configuring specific ZTL stateless settings"
    echo "dirs /etc/wireguard" >> /etc/rwtab.d/ztl 2>> "${LOG_FILE}" || log "Cannot create /etc/rwtab.d/ztl" "ERROR"
    echo "dirs /var/lib/haproxy" >> /etc/rwtab.d/haproxy 2>> "${LOG_FILE}" || log "Cannot create /etc/rwtab.d/haproxy" "ERROR"
    echo "/etc/firewalld/zones" >> /etc/statetab.d/ztl 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/ztl" "ERROR"
    echo "/var/ztl" >> /etc/statetab.d/ztl 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/ztl" "ERROR"
    echo "/etc/systemd/system" >> /etc/statetab.d/ztl 2>> "${LOG_FILE}" || log "Cannot create /etc/statetab.d/ztl" "ERROR"
    echo "dirs /var/ztl_upgrade" >> /etc/rwtab.d/ztl 2>> "${LOG_FILE}" || log "Cannot create /etc/rwtab.d/ztl" "ERROR"
fi

# Optional for xauth support
#echo "files /root" >> /etc/rwtab.d/xauth                # X11 forwarding (xauth)
# NPF-MOD-USER: Change the username to whatever fits !!!
#echo "files /home/npfmonitor" >> /etc/rwtab.d/xauth     # X11 forwarding (xauth) user


# Update grub to add ro and remove rw
grubby --update-kernel=ALL --args="ro" 2>> "${LOG_FILE}" || log "Cannot update kernel to ro" "ERROR"
grubby --update-kernel=ALL --remove-args="rw" 2>> "${LOG_FILE}" || log "Cannot remove rw from kernel" "ERROR"
grub2-mkconfig -o /boot/grub2/grub.cfg 2>> "${LOG_FILE}" || log "Cannot update grub.cfg" "ERROR"

# Make sure we mount any xfs filesystems as ro (/boot and /)
# This won't affect the stateful label mounted devices

# Change mount options for any mountpoint containing images, Change all other mountpoints to ro and add noexec,nosuid,nodev
# Don't touch swap or fat FS. 
 awk -i inplace '{
    if ($1 ~ "^#" || $1 == "") { print $0; next };                                  # Skip commented / empty lines
    if ($3 ~ "swap") { print $0; next };                                            # Skip swap FS
    if ($3 ~ "fat") { next };                                                       # Skip fat (vfat) FS (efi)
    if ($2 ~ "/data") { $4="defaults,rw,noexec,nosuid,nodev,noatime,nodiratime"; print $0; next };    # Change defaults to /data mountpoints
    if ($2 != "/" && $4 !~ "noexec") { $4=$4",noexec" };                            # Add noexec to all except /
    if ($2 != "/" && $4 !~ "nosuid") { $4=$4",nosuid" };                            # Add nosuid to all except /
    if ($2 != "/" && $4 !~ "nodev") { $4=$4",nodev" };                              # Add nodev to all except /
    if ($4 !~ "ro|rw") { $4=$4",ro" };                                              # Update any rw instance to ro
    sub("rw","ro"); print $0
}' /etc/fstab 2>> "${LOG_FILE}" || log "Cannot update /etc/fstab" "ERROR"
#sed -i 's/xfs\(\s*\)defaults/xfs\1defaults,ro/g' /etc/fstab
# Also remount all vfat systems (/boot/efi) if exist as ro
#sed -i 's/vfat\(\s*\)/vfat\1ro,/g' /etc/fstab


# The following patch is only necessary for readonly-root < 10.11.6 that comes with RHEL < 9.4
# Let's not execute it anymore
patch_readonly_root() {
# Fix for statetab file not supporting space in dir name
# See our PR at https://github.com/fedora-sysv/initscripts/pull/471
# Patch created via  diff -auw /usr/libexec/readonly-root /tmp/readonly-root > /tmp/readonly-root.npf.patch
    dnf install -y patch
    cat << 'EOF' > /tmp/readonly-root.npf.patch
--- /usr/libexec/readonly-root  2022-08-24 10:42:13.000000000 +0200
+++ /tmp/readonly-root  2024-01-23 13:20:36.167603560 +0100
@@ -1,4 +1,4 @@
-#!/usr/bin/bash
+#!/bin/bash
 #
 # Set up readonly-root support.
 #
@@ -184,17 +184,17 @@
                                mount -n --bind $bindmountopts "$STATE_MOUNT/$file" "$file"
                        fi

-                       for path in $(grep -v "^#" "$file" 2>/dev/null); do
+                       while read path ; do
                                mount_state "$path"
                                selinux_fixup "$path"
-                       done
+                       done < <(grep -v "^#" "$file" 2>/dev/null)
                done

                if [ -f "$STATE_MOUNT/files" ] ; then
-                       for path in $(grep -v "^#" "$STATE_MOUNT/files" 2>/dev/null); do
+                       while read path ; do
                                mount_state "$path"
                                selinux_fixup "$path"
-                       done
+                       done < <(grep -v "^#" "$STATE_MOUNT/files" 2>/dev/null)
                fi
        fi

EOF
    patch -l /usr/libexec/readonly-root < /tmp/readonly-root.npf.patch
}


RHEL_VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
if [ "${RHEL_VERSION}" == "9.0" ] || [ "${RHEL_VERSION}" == "9.1" ] || [ "${RHEL_VERSION}" == "9.2" ] || [ "${RHEL_VERSION}" == "9.3" ]; then
    patch_readonly_root
fi

## Post install
# Remove /etc/resolv.conf file since we don't want it in our image
# See man NetworkManager.conf rc-manager for more info about this
if [ -f /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf 2>> "${LOG_FILE}" || log "Cannot remove /etc/resolv.conf" "ERROR"
fi
ln -s /run/NetworkManager/resolv.conf /etc/resolv.conf 2>> "${LOG_FILE}" || log "Cannot link /run/NetworkManager/resolv.conf to /etc/resolv.conf" "ERROR"


if [ "${SCRIPT_GOOD}" == false ]; then
    echo "#### WARNING Installation FAILED ####"
    exit 1
else
    echo "System is now readonly"
    echo ""
    echo "On modifications, please use 'mount -o remount,rw /'"
    echo ""
    echo "Once finished, please seal system with command"
    echo ""
    echo "rm -f ~/.bash_history; history -c; reboot"
    exit 0
fi