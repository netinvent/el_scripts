[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![GitHub Release](https://img.shields.io/github/release/netinvent/el_scripts.svg?label=Latest)](https://github.com/netinvent/el_scripts/releases/latest)
[![Python linter](https://github.com/netinvent/el_scripts/actions/workflows/pylint.yml/badge.svg)](https://github.com/netinvent/el_scripts/actions/workflows/pylint.yml)
[![Bash linter](https://github.com/netinvent/el_scripts/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/netinvent/el_scripts/actions/workflows/shellcheck.yml)


## Enterprise Linux configuration collection

This script collection is designed to work on:
- Redhat / AlmaLinux / RockyLinux / CentOS and other EL8, EL9 or EL10 clones
- Debian 12


### Enterprise Linux configurator script

The script allows to configure an existing Enterprise Linux in order to be compliant with ANSSI BP-028 profiles, and configure various enhancements. The script is already included in the kickstart file.

To configure an existing setup, you can use the following  
>[!WARNING]
>Danger Will Robinson - This one liner executes code you should download and review first unless you trust this repo, your dns and any intermediate proxy
```sh
curl -sSfL https://raw.githubusercontent.com/netinvent/el_scripts/main/el_configurator.sh | bash -
```

>[!NOTE]
>A more secure way of doing
```
curl -OL https://raw.githubusercontent.com/netinvent/el_scripts/main/el_configurator.sh
## Manual code review (or sha256sum check)
bash ./el_configurator.sh
```


Adding Prometheus node_exporter, the script will also add two new metrics:
- `el_configurator_setup_date` which will contain the timestamp of the last el_configurator run
- `el_configurator_state` which will contain state (0=Success, 1=Failure/Missing) of last run

The `el_configurator` script will also provide the following setups:

- Optional packages if physical machine
    - pre-configured smartmontools daemon
    - Optional IT8613 support
    - Intel TCO Watchdog support
    - Tuned config profiles npf-eco and npf-perf
    - Qemu guest agent setup on KVM machines
- Optional enabling serial console on tty and grub interface
    - Add `resize_term` and `resize_term2` scripts which allow to deal with tty resizing in terminal
- Optional steps if DHCP internet is found
    - Installation of non standard packages
    - ANSSI-BP028 SCAP Profile configuration with report
    - Prometheus Node exporter installation
    - Setup firewall
    - Setup fail2ban for SSH
    - Tune SSH keepalives
- Cleanup of image after setup


All variables in `el_configurator` script can be overridden by kernel arguments that have the `NPF_` prefix. 
Example, in order to override `SCAP_PROFILE` variable, set the following kernel argument: `NPF_SCAP_PROFILE=myvalue`

### RHEL specific Kickstart file

The kickstart file contains a python script which handles automagic partitioning and other small adjustemnts as pre script, and a machine setup script as post script, that will install additions and configure the system.  

With the pre-script, kickstart will handle MBR, GPT and LVM style partitioning, while being able to autosize partitions.  

The python script is to be executed as `%pre --interpreter=/bin/python3` script and will create the following:

Automatic setup of machines with

- Dynamic partition schema depending on selected target:
  - `hv`: Hypervisor layout with 30GB root partition and `/var/lib/livirt/images` maximum partition size
  - `hv-stateless`: The same as above but with a 30GB size partition with label `STATEFULRW` for stateful storage
  - `stateless`: A 50% size root partition and 50% size partition with label `STATEFULRW` for stateful storage
  - `generic`: A 100% size root partition
  - `web`: A secure web server (subset of ANSSI BP-028-High)
  - `anssi`: ANSSI BP-028-High compatible partition schema

Of course, you can adjust those values or create new partition schemas directly in the python script.

The kickstart post-script section includes the `el_configurtor.sh` script.

- Optional setups on virtual machines
    - Exclusion of firmware packages


##### Technical notes about the kickstart script

Instead of relying on anaconda for partitioning, the script will handle partitioning via parted to allow usage of non mounted partitions for readonly-root setups with stateful partitions which should not be mounted via fstab.

The script can also optionally reserve 5% disk space at the end of physical disk, in order to have some reserved space left for SSD drives.

If the installation fails for some reason, the logs will be found in `/tmp/prescript.log`

##### Restrictions

Using LVM partitioning is incompatible with stateless partitioning since the latter requires partitions without mountpoints.  
As of today, the python script only uses a single disk. Multi disk support can be added on request.

##### Troubleshooting

When anaconda install fails, you have to change the terminal (CTRL+ALT+F2) in order to check file `/tmp/prescript.log`.  
Using a serial console, you'll have to use ESC+TAB in order to change terminal.

When installing on an existing disk, the script is not capable to unload LVM partitions, hence it may zero the disk, but the kernel will still think the LVM partitions exist.  
In that case, just reboot and reinstall, since the disk has been emptied, everything will work properly.

## Other scripts

### Setup Hypervisor

Setup KVM environment including X11 forwarding and bridging on EL 9.

### Setup OPNSense

Download and install OPNSense firewall and passthrough PCI NICS according to their address on EL 9.

### Setup Readonly

Transform a EL 9 machine into readonly, especially if hypervisor exists.

### Setup Prometheus

Setup and run prometheus, including blackbox_exporter, ipmi_exporter and snmp_exporter

### Setup simplehelp

Setup simplehelp service, compatible with readonly linux
