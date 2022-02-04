#!/bin/bash

# Check /etc/security/faillock.conf - deny=5 shows twice

# Need to check if sshd starts - if not, might need:
#	ausearch -c 'sshd' --raw | audit2allow -M my-sshd
#   semodule -X 300 -i my-sshd.pp

############################################################
# Required configuration
############################################################
#
#  An active network connection is required and dnf repos
#  must be configured and accessible
#
#  The following partitions are required to be compliant and
#  for this script to run successfully:
#  
#  "/home"
#  "/tmp"
#  "/var"
#  "/var/log"
#  "/var/log/audit"
#  "/var/tmp"
#  
#  Additionally change the variables as necessary in the
#  next section and also edit the warning banner as
#  necessary in files/issue 
#
############################################################
# Variables
############################################################
MAX_LOGON_ATTEMPTS='5'
LOGON_ATTEMPT_DURATION='1800' #30-minutes
LOCKOUT_DURATION='1800'

PW_MIN_UC=2
PW_MIN_LC=2
PW_MIN_NUM=2
PW_MIN_OTHER=2
PW_MAX_CLASS_REPEAT=3
PW_MAX_REPEAT=3
PW_MIN_AGE=2
PW_MAX_AGE=90
PW_HIST=24
PW_MIN_LENGTH=15

############################################################
# Variables
############################################################
RED='\033[0;31m'
LTRED='\033[1;31m'
YELLOW='\033[1;33m'
ORANGE='\033[0;33m'
BLUE='\033[1;34m'
NC='\033[0m'
FAIL="${RED}FAILED:${NC}"
WARN="${ORANGE}WARNING:${NC}"
FIX="${YELLOW}FIXING:${NC}"
NOTE="${BLUE}NOTE:${NC}"
shopt -s expand_aliases
alias echo='echo -e' 

############################################################
# Functions
############################################################
partition () {
	# $1 = STIG ID
	# $2 = partition path
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -Ei "\s${2}\s" /etc/fstab > /dev/null; then
		echo
		echo "${FAIL} ${2} is not on its own partition.  Reinstall with the required partition layout."
		echo
		exit
	fi
}

aide_add_option () {
	# $1 = STIG ID
	# $2 = file path
	# $3 = Label
	# $4 = option
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -Ei "${3} = .*${4}" "${2}" > /dev/null; then
		echo "${FIX} Adding ${4} to ${3} in ${2}"
		sed -ri "s/^${3} .*/&+${4}/I" "${2}"
	fi
}

change_umask () {
	# $1 = STIG ID
	# $2 = file path
	# $3 = mode
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if grep -Ei "umask [[:digit:]]{3}" "${2}" | grep -iv "umask ${3}" > /dev/null; then
		echo "${FIX} setting UMASK to ${3} in ${2}"
		sed -ri "s/(UMASK.*)[[:digit:]]{3}/\1${3}/I" "${2}"
	fi
}

grub_setting () {
	# $1 = STIG ID
	# $2 = grub setting
	if ! [ -z "${1}" ]; then echo "Checking: $1"; fi
	if ! grub2-editenv list | grep "${2}" > /dev/null; then
		echo "${FIX} Setting GRUB2 arguemnt ${2}"
		grubby --update-kernel=ALL --args="${2}"
	fi
	if ! grep "${2}" /etc/default/grub > /dev/null; then
		echo "${FIX} settng ${2}  in /etc/default/grub"
		sed -ri "s/fips=1/fips=1 ${2}/I" /etc/default/grub
	fi
}

install_file () {
	# $1 = STIG ID
	# $2 = file path
	# $3 = file name
	# $4 = mode
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! test -f "${2}/${3}"; then
		echo "${FIX} installing ${3} to ${2}"
		install -o root -g root -m $4 files/${3} ${2}
	elif ! cmp "files/${3}" "${2}/${3}" > /dev/null 2>&1; then
		echo "${FIX} ${2}/${3} exists, moving previous version to backup"
		mv -f ${2}/${3} backup
		install -o root -g root -m $4 files/${3} ${2}
		#echo "${WARN} ${2}/${3} exists, but not as expected.  Verify file for compliance"
	fi
}

package_install () {
	# $1 = STIG ID
	# $2 = package
	if ! [ -z "${1}" ]; then echo "Checking: $1"; fi
	if ! dnf list installed ${2} 2>&1 | grep ${2} > /dev/null; then
		echo "${FIX} Installing ${2}"
		dnf install -y ${2} > /dev/null
	fi 	
}

package_remove () {
	# $1 = STIG ID
	# $2 = package
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if dnf list installed ${2} 2>&1 | grep ${2} > /dev/null; then
		echo "${FIX} Removing ${2}"
		dnf remove -y ${2} > /dev/null
	fi 	
}

pam_add_line () {
	# $1 = STIG ID
	# $2 = full file path
	# $3 = type
	# $4 = control
	# $5 = module
	# $6 = option
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -E "^${3}.*${4}.*${5}.*${6}" ${2} > /dev/null; then
		echo "${FIX} ${2} adding ${3} ${4} ${5} ${6}"
		sed -ri "0,/^${3}/s/^${3}/${3}     ${4}     ${5}     ${6}\n&/I" "${2}"
	fi
}

pam_settings_add () {
	# $1 = STIG ID
	# $2 = full file path
	# $3 = type
	# $4 = control
	# $5 = module
	# $6 = option
	option=${6////\\/}
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -E "^${3}.*${4}.*${5}.*${6}" ${2} > /dev/null; then
		echo "${FIX} ${2} setting ${6} on ${3} ${4} ${5}"
		sed -ri "s/^(${3}.*${4}.*${5}.*)/\1 ${option}/" ${2}
	fi
}

pam_settings_remove () {
	# $1 = STIG ID
	# $2 = full file path
	# $3 = type
	# $4 = control
	# $5 = module
	# $6 = option
	# $7 = option to remove
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if grep -E "^${3}.*${4}.*${5}.*${6}.*${7}" ${2} > /dev/null; then
		echo "${FIX} ${2} removing setting ${7} on ${3} ${4} ${5} ${6}"
		sed -ri "s/^(${3}.*${4}.*${5}.*${6}.*)\s${7}/\1/I" ${2}
	fi
	if grep -E "^${3}.*${4}.*${5}.*${7}.*${6}" ${2} > /dev/null; then
		echo "${FIX} ${2} removing setting ${7} on ${3} ${4} ${5} ${6}"
		sed -ri "s/^(${3}.*${4}.*${5}.*)\s${7}(.*${6})/\1\2/I" ${2}
	fi
}

pam_change_control () {
	# $1 = STIG ID
	# $2 = full file path
	# $3 = type
	# $4 = control
	# $5 = module
	# $6 = option
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -E "^${3}.*${4}.*${5}.*${6}" ${2} > /dev/null; then
		echo "${FIX} ${2} setting ${4} on ${3} ${5} ${6}"
		sed -ri "s/^(${3}\s+)\S+(\s+${5}.*${6}.*)/\1${4}\2/" ${2}
	fi
}

partition_option_disable () {
	# $1 = STIG ID
	# $2 = partition
	# $3 = option
	part=${2////\\/}
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -Ei " ${2}.*no${3}" /etc/fstab > /dev/null; then
		echo "${FIX} setting $3 for partion $2 in /etc/fstab"
		if grep -Ei " ${2}.*defaults" /etc/fstab > /dev/null; then
			sed -ri "s/( ${part}\s+\w+\s+)\S+/\1rw,suid,dev,exec,auto,nouser,async/I" /etc/fstab
		fi
		sed -ri "s/( ${part}\s+\w+\s+)(\S*,|\s)${3}/\1\2no${3}/I" /etc/fstab
		mount -o remount $2
	fi
}

remove_line () {
	# $1 = STIG ID
	# $2 = full file path
	# $3 = line pattern to remove
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if grep -Ei "${3}" "${2}" > /dev/null; then
		echo "${FIX} removing lines containing $3 from $2"
		sed -ri "/${3}/Id" "${2}"
	fi
}

service_disable_stop () {
	# $1 = STIG ID
	# $2 = service
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if systemctl is-enabled $2 2>&1 | grep -i "no such file or directory" > /dev/null; then
		return
	fi
	if ! systemctl is-enabled $2 2>&1 | grep -i "disabled" > /dev/null; then
		echo "${FIX} Disabling and stopping $2"
		systemctl disable --now $2 > /dev/null
	fi
}

service_enable_start () {
	# $1 = STIG ID
	# $2 = service
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! systemctl status $2 | grep -Ei "Active: active \(running)" > /dev/null; then
		echo "${FIX} Enabling and starting $2"
		systemctl enable --now $2 > /dev/null
	fi
}

service_mask () {
	# $1 = STIG ID
	# $2 = service
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! systemctl status $2 | grep -i "Loaded: masked" > /dev/null; then
		echo "${FIX} masking service $2"
		systemctl mask $2 > /dev/null
		systemctl daemon-reload
	fi
}

service_mask_force () {
	# $1 = STIG ID
	# $2 = service
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! systemctl status $2 | grep -i "Loaded: masked" > /dev/null; then
		echo "${FIX} masking service $2"
		ln -sf /dev/null /etc/systemd/system/${2}
		systemctl daemon-reload
	fi
}

variable_bare () {
	# $1 = STIG ID
	# $2 = full file path
	# $3 = variable
	variable=${3////\\/}
	grepvar=${3//\*/\\*}
	grepvar=${grepvar//[/\\[}
	grepvar=${grepvar//\$/\\\$}
	grepvar=${grepvar//+/\\+}
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -Ei -- "^${grepvar}\s*$" ${2} > /dev/null 2>&1; then
		echo "${FIX} setting ${3} in ${2}"
		if grep -Ei -- "^#\s*${grepvar}" ${2} > /dev/null 2>&1; then
			sed -ri "s/^#\s*${variable}.*/${variable}/I" ${2}
		else
			sed -i -e '$a\' ${2} > /dev/null 2>&1
			echo "${3}" >> ${2}
		fi
	fi
}

variable_equal () {
	# $1 = STIG ID
	# $2 = full file path
	# $3 = variable
	# $4 = value
	value=${4////\\/}
	value=${value//./\\.}
	value=${value//\*/\\*}
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -Ei "^\s*${3}=${4}$" ${2} > /dev/null; then
		echo "${FIX} setting ${3} to ${4} in ${2}"
		if grep -Ei "^\s*${3}=" ${2} > /dev/null; then
			sed -ri "s/^(\s*)${3}.*/\1${3}=${value}/I" ${2}	
		elif grep -Ei "^#\s*${3}=" ${2} > /dev/null; then
			sed -ri "s/^#\s*${3}=.*/${3}=${value}/I" ${2}
		else
			sed -i -e '$a\' ${2} > /dev/null 2>&1
			echo "${3}=${4}" >> ${2}
		fi
	fi
}

variable_space_equal_space () {
	# $1 = STIG ID
	# $2 = full file path
	# $3 = variable
	# $4 = value
	value=${4////\\/}
	value=${value//./\\.}
	value=${value//\*/\\*}
	if ! [ -z "${1}" ]; then echo "Checking: $1"; fi
	if ! grep -Ei "^${3}\s+=\s+${4}$" ${2} > /dev/null 2>&1; then
		echo "${FIX} setting ${3} to ${4} in ${2}"
		if grep -Ei "^${3}\s+=" ${2} > /dev/null 2>&1; then
			sed -ri "s/^${3}\s.*/${3} = ${value}/I" ${2}	
		elif grep -Ei "^#\s*${3}\s+=" ${2} > /dev/null 2>&1; then
			sed -ri "s/^#\s*${3}\s+=.*/${3} = ${value}/I" ${2}
		else
			sed -i -e '$a\' ${2} > /dev/null 2>&1
			echo "${3} = ${4}" >> ${2}
		fi
	fi
}

variable_equal_inline () {  # does not require beginning of line, nor replaces whole line
	# $1 = STIG ID
	# $2 = full file path
	# $3 = variable
	# $4 = value
	value=${4////\\/}
	value=${value//./\\.}
	value=${value//\*/\\*}
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -Ei -- "${3}=${4}" ${2} > /dev/null; then
		echo "${FIX} setting ${3} to ${4} in ${2}"
		sed -ri "s/${3}\S* /${3}=${value}/I" ${2}
	fi
}

variable_space () {
	# $1 = STIG ID
	# $2 = full file path
	# $3 = variable
	# $4 = value
	value=${4////\\/}
	value=${value//./\\.}
	value=${value//\*/\\*}
	grepvar=${3//\*/\\*}
	if ! [ -z ${1} ]; then echo "Checking: $1"; fi
	if ! grep -Ei "^${grepvar}\s+${4}$" ${2} > /dev/null 2>&1; then
		echo "${FIX} setting ${3} to ${4} in ${2}"
		if grep -Ei "^${grepvar}\s" ${2} > /dev/null 2>&1; then
			sed -ri "s/^${3}\s.*/${3} ${value}/I" ${2}	
		elif grep -Ei "^#\s*${grepvar}\s+" ${2} > /dev/null 2>&1; then
			sed -ri "s/^#\s*${3}\s.*/${3} ${value}/I" ${2}
		else
			sed -i -e '$a\' ${2} > /dev/null 2>&1
			echo "${3} ${4}" >> ${2}
		fi
	fi
}

############################################################
# Check FIPS enablement
############################################################
echo "Checking: RHEL-08-010020"
if ! fips-mode-setup --check | grep 'FIPS mode is enabled' > /dev/null; then
    echo "${FIX} Enabling FIPS mode"
	sudo fips-mode-setup --enable
	echo
	echo "Reboot and run again"
	echo
	exit
fi
if ! grub2-editenv list | grep fips=1 > /dev/null; then
	echo "${FAIL} Kernel is not configured to use FIPS. (RHEL-08-010020)"
fi
if ! cat /proc/sys/crypto/fips_enabled | grep 1 > /dev/null; then
	echo "${FAIL} System is not in FIPS mode. (RHEL-08-010020)"
fi

############################################################
# Check GRUB password
############################################################
if test -f /sys/firmware/efi; then
	# System is using EFI
	echo "Checking: RHEL-08-010140"
	if ! grep -i 'GRUB2_PASSWORD=grub.pbkdf2.sha512.' /boot/efi/centos/user.cfg > /dev/null; then
		echo
		echo "${FAIL} Generate an encrypted grub2 password with the command: grub2-setpassword"
		echo "Then re-run this script."
		echo
		exit
	fi
else
	# System is using BIOS
	echo "Checking: RHEL-08-010150"
	if ! grep -i 'GRUB2_PASSWORD=grub.pbkdf2.sha512.' /boot/grub2/user.cfg > /dev/null 2>&1; then
		echo
		echo "${FAIL} Generate an encrypted grub2 password with the command: grub2-setpassword"
		echo "Then re-run this script."
		echo
		exit
	fi
fi

############################################################
# Copy files for backup
############################################################
backup () {	cp -p $1 backup > /dev/null 2>&1; }
if test -d backup; then
	echo "Backup directory exists.  Delete or rename and re-run."
	exit
fi
mkdir backup
backup /etc/aide.conf 
backup /etc/audit/auditd.conf
backup /etc/audit/rules.d/audit.rules
backup /etc/bashrc
backup /etc/chrony.conf
backup /etc/csh.cshrc
backup /etc/crypto-policies/back-ends/opensshserver.config
backup /etc/crypto-policies/back-ends/opensslcnf.config
backup /etc/default/grub
backup /etc/default/useradd
backup /etc/dnf/dnf.conf
backup /etc/fapolicyd/fapolicyd.conf
backup /etc/fapolicyd/fapolicyd.rules
backup /etc/fstab
backup /etc/gdm/custom.conf
backup /etc/grub.d/01_users
backup /etc/hosts
backup /etc/login.defs
backup /etc/modprobe.d/blacklist.conf
backup /etc/pam.d/password-auth
backup /etc/pam.d/postlogin
backup /etc/pam.d/system-auth
backup /etc/postfix/main.cf
backup /etc/profile
backup /etc/rsyslog.conf
backup /etc/security/faillock.conf
backup /etc/security/limits.d/core.conf
backup /etc/security/limits.d/maxlogins.conf
backup /etc/security/pwquality.conf
backup /etc/shells
backup /etc/ssh/sshd_config
backup /etc/sudoers 
backup /etc/sysconfig/sshd
backup /etc/sysctl.d/70-ipv6.conf
backup /etc/sysctl.d/99-sysctl.conf
backup /etc/systemd/coredump.conf
backup /etc/systemd/system.conf
backup /etc/tmux.conf
backup /etc/usbguard/usbguard-daemon.conf

############################################################
# Check required partitions
############################################################
partition "RHEL-08-010800" "/home"
partition "RHEL-08-010543" "/tmp"
partition "RHEL-08-010540" "/var"
partition "RHEL-08-010541" "/var/log"
partition "RHEL-08-010542" "/var/log/audit"
partition "RHEL-08-010544" "/var/tmp"

partition_option_disable "RHEL-08-010580" "/boot"          "dev"
partition_option_disable ""               "/home"          "dev"
partition_option_disable ""               "/tmp"           "dev"
partition_option_disable ""               "/var"           "dev"
partition_option_disable ""               "/var/log"       "dev"
partition_option_disable ""               "/var/log/audit" "dev"
partition_option_disable ""               "/var/tmp"       "dev"

# tmpfs is not normally listed in /etc/fstab.  This will add the line
if ! grep tmpfs /etc/fstab > /dev/null; then
	variable_bare            "RHEL-08-040120" "/etc/fstab"     "tmpfs /dev/shm tmpfs defaults 0 0"
fi
partition_option_disable ""               "/dev/shm"       "dev"
partition_option_disable "RHEL-08-040123" "/tmp"           "dev"
partition_option_disable "RHEL-08-040126" "/var/log"       "dev"
partition_option_disable "RHEL-08-040129" "/var/log/audit" "dev"
partition_option_disable "RHEL-08-040132" "/var/tmp"       "dev"

partition_option_disable "RHEL-08-040122" "/dev/shm"       "exec"
partition_option_disable "RHEL-08-010590" "/home"          "exec"
partition_option_disable "RHEL-08-040125" "/tmp"           "exec"
partition_option_disable "RHEL-08-040128" "/var/log"       "exec"
partition_option_disable "RHEL-08-040131" "/var/log/audit" "exec"
partition_option_disable "RHEL-08-040134" "/var/tmp"       "exec"

if ! test -f /sys/firmware/efi; then
	partition_option_disable "RHEL-08-010571" "/boot"          "suid"
else
	partition_option_disable "RHEL-08-010572" "/boot/efi"      "suid"
fi
partition_option_disable "RHEL-08-040121" "/dev/shm"       "suid"
partition_option_disable "RHEL-08-010570" "/home"          "suid"
partition_option_disable "RHEL-08-040124" "/tmp"           "suid"
partition_option_disable "RHEL-08-040127" "/var/log"       "suid"
partition_option_disable "RHEL-08-040130" "/var/log/audit" "suid"
partition_option_disable "RHEL-08-040133" "/var/tmp"       "suid"

############################################################
# Check aide
############################################################
package_install "RHEL-08-010360" "aide"
install_file    ""               "/etc/cron.daily" "aide" "755"

variable_bare   "RHEL-08-030650" "/etc/aide.conf" "# Audit Tools"
variable_bare   ""               "/etc/aide.conf" "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512"
variable_bare   ""               "/etc/aide.conf" "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512"
variable_bare   ""               "/etc/aide.conf" "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512"
variable_bare   ""               "/etc/aide.conf" "/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512"
variable_bare   ""               "/etc/aide.conf" "/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512"
variable_bare   ""               "/etc/aide.conf" "/usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512"
variable_bare   ""               "/etc/aide.conf" "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512"

aide_add_option "RHEL-08-040300" "/etc/aide.conf" "CONTENT" "xattrs"
aide_add_option "RHEL-08-040310" "/etc/aide.conf" "CONTENT" "acl"

if ! [ -f "/var/lib/aide/aide.db.gz" ]; then
	echo "Initializing aide"
	aide --init
	mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

############################################################
# Check audit
############################################################
package_install "RHEL-08-030180" "audit"

variable_space_equal_space "RHEL-08-030040" "/etc/audit/auditd.conf" "disk_error_action"   "SYSLOG"
#variable_space_equal_space "RHEL-08-030050" "/etc/audit/auditd.conf" "max_log_file_action" "SYSLOG"
variable_space_equal_space "RHEL-08-030050" "/etc/audit/auditd.conf" "max_log_file_action" "KEEP_LOGS"
variable_space_equal_space "RHEL-08-030060" "/etc/audit/auditd.conf" "disk_full_action"    "SYSLOG"
variable_space_equal_space "RHEL-08-030062" "/etc/audit/auditd.conf" "name_format"         "HOSTNAME"
variable_space_equal_space "RHEL-08-030730" "/etc/audit/auditd.conf" "space_left"          "25%"
variable_space_equal_space "RHEL-08-030731" "/etc/audit/auditd.conf" "space_left_action"   "EMAIL"

variable_bare "RHEL-08-030122" "/etc/audit/rules.d/audit.rules" "--loginuid-immutable"

variable_bare "RHEL-08-030170" "/etc/audit/rules.d/audit.rules" "-w /etc/group            -p wa -k identity"
variable_bare "RHEL-08-030160" "/etc/audit/rules.d/audit.rules" "-w /etc/gshadow          -p wa -k identity"
variable_bare "RHEL-08-030150" "/etc/audit/rules.d/audit.rules" "-w /etc/passwd           -p wa -k identity"
variable_bare "RHEL-08-030140" "/etc/audit/rules.d/audit.rules" "-w /etc/security/opasswd -p wa -k identity"
variable_bare "RHEL-08-030130" "/etc/audit/rules.d/audit.rules" "-w /etc/shadow           -p wa -k identity"
variable_bare "RHEL-08-030171" "/etc/audit/rules.d/audit.rules" "-w /etc/sudoers          -p wa -k identity"
variable_bare "RHEL-08-030172" "/etc/audit/rules.d/audit.rules" "-w /etc/sudoers.d/       -p wa -k identity"
variable_bare "RHEL-08-030590" "/etc/audit/rules.d/audit.rules" "-w /var/log/faillock     -p wa -k logins"
variable_bare "RHEL-08-030600" "/etc/audit/rules.d/audit.rules" "-w /var/log/lastlog      -p wa -k logins"

variable_bare "RHEL-08-030570" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/chacl                   -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030250" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/chage                   -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage"
variable_bare "RHEL-08-030260" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/chcon                   -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030410" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/chsh                    -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
variable_bare "RHEL-08-030400" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/crontab                 -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab"
variable_bare "RHEL-08-030370" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/gpasswd                 -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd"
variable_bare "RHEL-08-030580" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/kmod                    -F perm=x -F auid>=1000 -F auid!=unset -k modules"
variable_bare "RHEL-08-030300" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/mount                   -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount"
variable_bare "RHEL-08-030350" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/newgrp                  -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
variable_bare "RHEL-08-030290" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/passwd                  -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd"
variable_bare "RHEL-08-030330" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/setfacl                 -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030280" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/ssh-agent               -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh"
variable_bare "RHEL-08-030190" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/su                      -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change"
variable_bare "RHEL-08-030550" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/sudo                    -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
variable_bare "RHEL-08-030301" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/bin/umount                  -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount"
variable_bare "RHEL-08-030320" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh"
variable_bare "RHEL-08-030340" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/pam_timestamp_check    -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check"
variable_bare "RHEL-08-030311" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/postdrop               -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
variable_bare "RHEL-08-030312" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/postqueue              -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
variable_bare "RHEL-08-030313" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/semanage               -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
variable_bare "RHEL-08-030314" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/setfiles               -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
variable_bare "RHEL-08-030316" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/setsebool              -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
variable_bare "RHEL-08-030317" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/unix_chkpwd            -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
variable_bare "RHEL-08-030310" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/unix_update            -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
variable_bare "RHEL-08-030315" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/userhelper             -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
variable_bare "RHEL-08-030560" "/etc/audit/rules.d/audit.rules" "-a always,exit -F path=/usr/sbin/usermod                -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod"

variable_bare "RHEL-08-030490" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S chmod                             -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S chmod                             -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030480" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S chown                             -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S chown                             -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030470" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S creat             -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S creat             -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S creat             -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S creat             -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare "RHEL-08-030390" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S delete_module                     -F auid>=1000 -F auid!=unset -k module_chng"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S delete_module                     -F auid>=1000 -F auid!=unset -k module_chng"
variable_bare "RHEL-08-030000" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S execve            -C uid!=euid    -F euid=0                    -k execpriv"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S execve            -C uid!=euid    -F euid=0                    -k execpriv"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S execve            -C gid!=egid    -F egid=0                    -k execpriv"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S execve            -C gid!=egid    -F egid=0                    -k execpriv"
variable_bare "RHEL-08-030540" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S fchmod                            -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S fchmod                            -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030530" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S fchmodat                          -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S fchmodat                          -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030520" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S fchown                            -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S fchown                            -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030510" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S fchownat                          -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S fchownat                          -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030380" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S finit_module                      -F auid>=1000 -F auid!=unset -k module_chng"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S finit_module                      -F auid>=1000 -F auid!=unset -k module_chng"
variable_bare "RHEL-08-030240" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S fremovexattr                      -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S fremovexattr                      -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S fremovexattr                      -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S fremovexattr                      -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030230" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S fsetxattr                         -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S fsetxattr                         -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S fsetxattr                         -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S fsetxattr                         -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030460" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S ftruncate         -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S ftruncate         -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S ftruncate         -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S ftruncate         -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare "RHEL-08-030360" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S init_module                       -F auid>=1000 -F auid!=unset -k module_chng"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S init_module                       -F auid>=1000 -F auid!=unset -k module_chng"
variable_bare "RHEL-08-030500" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S lchown                            -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S lchown                            -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030200" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S lremovexattr                      -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S lremovexattr                      -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S lremovexattr                      -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S lremovexattr                      -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030220" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S lsetxattr                         -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S lsetxattr                         -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S lsetxattr                         -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S lsetxattr                         -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030302" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S mount                             -F auid>=1000 -F auid!=unset -k privileged-mount"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S mount                             -F auid>=1000 -F auid!=unset -k privileged-mount"
variable_bare "RHEL-08-030440" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S open              -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S open              -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S open              -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S open              -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare "RHEL-08-030450" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare "RHEL-08-030430" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S openat            -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S openat            -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S openat            -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S openat            -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare "RHEL-08-030240" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S removexattr                       -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S removexattr                       -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S removexattr                       -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S removexattr                       -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030361" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S rename                            -F auid>=1000 -F auid!=unset -k delete"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S rename                            -F auid>=1000 -F auid!=unset -k delete"
variable_bare "RHEL-08-030362" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S renameat                          -F auid>=1000 -F auid!=unset -k delete"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S renameat                          -F auid>=1000 -F auid!=unset -k delete"
variable_bare "RHEL-08-030363" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S rmdir                             -F auid>=1000 -F auid!=unset -k delete"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S rmdir                             -F auid>=1000 -F auid!=unset -k delete"
variable_bare "RHEL-08-030270" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S setxattr                          -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S setxattr                          -F auid=0                    -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S setxattr                          -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S setxattr                          -F auid>=1000 -F auid!=unset -k perm_mod"
variable_bare "RHEL-08-030420" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S truncate          -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S truncate          -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S truncate          -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S truncate          -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
variable_bare "RHEL-08-030364" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S unlink                            -F auid>=1000 -F auid!=unset -k delete"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S unlink                            -F auid>=1000 -F auid!=unset -k delete"
variable_bare "RHEL-08-030365" "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b32 -S unlinkat                          -F auid>=1000 -F auid!=unset -k delete"
variable_bare ""               "/etc/audit/rules.d/audit.rules" "-a always,exit -F arch=b64 -S unlinkat                          -F auid>=1000 -F auid!=unset -k delete"

TEMP="-e 2"
if ! grep -Ei "^\s*[^#]" /etc/audit/rules.d/audit.rules | tail -1 | grep -F -- "$TEMP" > /dev/null; then
	remove_line   "RHEL-08-030121" "/etc/audit/rules.d/audit.rules" "$TEMP"
	variable_bare ""               "/etc/audit/rules.d/audit.rules" "$TEMP"
fi
service_enable_start "RHEL-08-030181" "auditd"

############################################################
# Check chrony
############################################################
variable_space "RHEL-08-030741" "/etc/chrony.conf" "port"    "0"
variable_space "RHEL-08-030741" "/etc/chrony.conf" "cmdport" "0"
variable_space "RHEL-08-030740" "/etc/chrony.conf" "server"  "10.10.10.10 iburst maxpoll 16"
remove_line    ""               "/etc/chrony.conf" "^pool"
echo "${WARN} /etc/chrony.conf has a template entry for server 10.10.10.10 - update to a vaild server"

############################################################
# Check coredump
############################################################
service_disable_stop "RHEL-08-010670" "kdump"
service_mask         "RHEL-08-010672" "systemd-coredump.socket"

variable_space       "RHEL-08-010673" "/etc/security/limits.d/core.conf" "* hard core"    "0"

variable_equal       "RHEL-08-010674" "/etc/systemd/coredump.conf"       "Storage"        "none"
variable_equal       "RHEL-08-010675" "/etc/systemd/coredump.conf"       "ProcessSizeMax" "0"

############################################################
# Check ctrl-alt-del
############################################################
service_mask_force "RHEL-08-040170" "ctrl-alt-del.target"
variable_equal     "RHEL-08-040172" "/etc/systemd/system.conf" "CtrlAltDelBurstAction" "none"

############################################################
# Check faillock
############################################################
package_install      "RHEL-08-010171" "policycoreutils"      
package_install      ""               "policycoreutils-python-utils"                 

echo "Checking: RHEL-08-020027"
if ! [ -d "/var/log/faillock" ]; then
	echo "${FIX} creating directory /var/log/faillock"
	mkdir /var/log/faillock
fi
if !  ls -Zd /var/log/faillock | grep -Ei ":faillog_t:" > /dev/null; then
	echo "${FIX} setting secontext for /var/log/failllock"
	semanage fcontext -a -t faillog_t "/var/log/faillock(/.*)?" > /dev/null
	restorecon -R -v /var/log/faillock
fi

variable_space_equal_space "RHEL-08-020011" "/etc/security/faillock.conf" "deny"           "${MAX_LOGON_ATTEMPTS}"
variable_space_equal_space "RHEL-08-020013" "/etc/security/faillock.conf" "fail_interval"  "${LOGON_ATTEMPT_DURATION}"
variable_space_equal_space "RHEL-08-020013" "/etc/security/faillock.conf" "unlock_time"    "${LOCKOUT_DURATION}"
variable_space_equal_space "RHEL-08-020017" "/etc/security/faillock.conf" "dir"            "/var/log/faillock"
variable_bare              "RHEL-08-020019" "/etc/security/faillock.conf" "silent"         ""
variable_bare              "RHEL-08-020021" "/etc/security/faillock.conf" "audit"          ""
variable_bare              "RHEL-08-020023" "/etc/security/faillock.conf" "even_deny_root" ""


############################################################
# Check fapolicy
############################################################
package_install      "RHEL-08-040135" "fapolicyd"    

variable_space_equal_space "RHEL-08-040137" "/etc/fapolicyd/fapolicyd.conf"  "permissive"              "1"
variable_bare              ""               "/etc/fapolicyd/fapolicyd.rules" "deny perm=any all : all"

echo "${WARN} fapolicyd is set to permissive mode.  Once whitelist is confirmed, set permissive=0 in /etc/fapolicyd/fapoplicy.conf"

if ! test -f "/etc/fapolicyd/fapolicyd.mounts"; then
	echo "${FIX} adding mounts to fapolicyd.mounts"
	mount | egrep '^tmpfs| ext4| ext3| xfs' | awk '{ printf "%s\n", $3 }' > /etc/fapolicyd/fapolicyd.mounts
fi

service_enable_start "RHEL-08-040136" "fapolicyd"                  

############################################################
# Check firewall
############################################################
package_install "RHEL-08-040100" "firewalld"

echo "Checking: RHEL-08-040090"
if ! firewall-cmd --list-all | grep -Ei "target: drop" > /dev/null; then
	echo "${FIX} setting firewall target to drop"
	firewall-cmd --permanent --set-target=DROP > /dev/null
	firewall-cmd --reload > /dev/null
fi

service_enable_start "RHEL-08-040101" "firewalld"

############################################################
# Check GNOME
############################################################
echo "Checking: if GNOME and dconf are installed"
if dnf list installed gdm 2>&1 | grep gdm > /dev/null; then
	if dnf list installed dconf 2>&1 | grep dconf > /dev/null; then
		GDM=1
	else
		echo
		echo "${FAIL} GNOME is installed but dconf is not.  Install dconf then restart."
		echo
		exit
	fi
else
	GDM=0
fi

if [[ $GDM == 1 ]]; then
	echo "Checking: RHEL-08-010820"
	if ! grep -Ei "AutomaticLoginEnable=false" /etc/gdm/custom.conf > /dev/null; then
		echo "${FIX} Adding AutomaticLoginEnable=false in [daemon] in /etc/gdm/custom.conf"
		sed -ri "/^\[daemon]/a AutomaticLoginEnable=false" /etc/gdm/custom.conf
	fi
	install_file  "RHEL-08-010050" "/etc/dconf/db/local.d" "01-banner-message" "644"
	install_file  "RHEL-08-020050" "/etc/dconf/db/local.d" "00-screensaver"    "644"
	install_file  "RHEL-08-040171" "/etc/dconf/db/local.d" "00-disable-CAD"    "644"
	install_file  "RHEL-08-020031" "/etc/dconf/db/local.d" "00-lock-delay"     "644"
	install_file  "RHEL-08-020032" "/etc/dconf/db/local.d" "02-login-screen"   "644"
		
	variable_bare "RHEL-08-020080" "/etc/dconf/db/local.d/locks/session" "/org/gnome/desktop/screensaver/lock-delay"
	variable_bare "RHEL-08-020081" "/etc/dconf/db/local.d/locks/session" "/org/gnome/desktop/session/idle-delay"
	variable_bare "RHEL-08-020081" "/etc/dconf/db/local.d/locks/session" "/org/gnome/desktop/screensaver/lock-enabled"
	
	dconf update
fi

############################################################
# Check GRUB
############################################################
if test -f /sys/firmware/efi; then
	# System is using EFI
	variable_equal "RHEL-08-010141" "/etc/grub.d/01_users" "set superusers" "\"grubroot\""
	grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg > /dev/null
	
else
	# System is using BIOS
	variable_equal "RHEL-08-010141" "/etc/grub.d/01_users" "set superusers" "\"grubroot\""
	grub2-mkconfig -o /boot/grub2/grub.cfg > /dev/null
fi
grub_setting "RHEL-08-010421" "page_poison=1"
grub_setting "RHEL-08-010422" "vsyscall=none"
grub_setting "RHEL-08-010423" "slub_debug=P"
grub_setting "RHEL-08-030601" "audit=1"
grub_setting "RHEL-08-030602" "audit_backlog_limit=8192"
grub_setting "RHEL-08-040004" "pti=on"
grub_setting "Disabling IPv6" "ipv6.disable=1"

############################################################
# Check IP settings
############################################################
if ip a | grep inet6 > /dev/null; then
	variable_space_equal_space "Disabling IPv6" "/etc/sysctl.d/70-ipv6.conf" "net.ipv6.conf.all.disable_ipv6"     "1"
	variable_space_equal_space ""               "/etc/sysctl.d/70-ipv6.conf" "net.ipv6.conf.default.disable_ipv6" "1"

	remove_line                ""               "/etc/hosts"                 "::1"

	sysctl --load /etc/sysctl.d/70-ipv6.conf > /dev/null
	# more under GRUB section
fi

############################################################
# Check modprobe
############################################################
blacklist () {
	variable_bare "$1" "/etc/modprobe.d/blacklist.conf" "install ${2} /bin/true"
	variable_bare ""   "/etc/modprobe.d/blacklist.conf" "blacklist ${2}"
}

blacklist "RHEL-08-040021" "atm"
blacklist "RHEL-08-040022" "can"
blacklist "RHEL-08-040023" "sctp"
blacklist "RHEL-08-040024" "tipc"
blacklist "RHEL-08-040025" "cramfs"
blacklist "RHEL-08-040026" "firewire-core"
blacklist "RHEL-08-040080" "usb-storage"
blacklist "RHEL-08-040111" "bluetooth"

############################################################
# Check OpenSSHServer
############################################################
package_install       "RHEL-08-040159" "openssh-server"

variable_equal_inline      "RHEL-08-010290" "/etc/crypto-policies/back-ends/opensshserver.config" "-oMACs"    "hmac-sha2-512,hmac-sha2-256 "
variable_equal_inline      "RHEL-08-010291" "/etc/crypto-policies/back-ends/opensshserver.config" "-oCiphers" "aes256-ctr,aes192-ctr,aes128-ctr "

variable_space_equal_space "RHEL-08-010294" "/etc/crypto-policies/back-ends/opensslcnf.config" "MinProtocol" "TLSv1.2"


############################################################
# Check pam.d and UMASK
############################################################
pam_add_line               "RHEL-08-020026" "/etc/pam.d/password-auth"     "auth"           "required"             "pam_faillock.so"  "authfail"
pam_add_line               ""               "/etc/pam.d/password-auth"     "auth"           "required"             "pam_faillock.so"  "preauth"
pam_add_line               ""               "/etc/pam.d/password-auth"     "account"        "required"             "pam_faillock.so"  ""
pam_add_line               "RHEL-08-020025" "/etc/pam.d/system-auth"       "auth"           "required"             "pam_faillock.so"  "authfail"
pam_add_line               ""               "/etc/pam.d/system-auth"       "auth"           "required"             "pam_faillock.so"  "preauth"
pam_add_line               ""               "/etc/pam.d/system-auth"       "account"        "required"             "pam_faillock.so"  ""

pam_settings_add           "RHEL-08-010130" "/etc/pam.d/password-auth"     "password"       "sufficient"           "pam_unix.so"      "rounds=5000"
pam_settings_add           "RHEL-08-010131" "/etc/pam.d/system-auth"       "password"       "sufficient"           "pam_unix.so"      "rounds=5000"
pam_settings_add           "RHEL-08-020100" "/etc/pam.d/password-auth"     "password"       "requisite"            "pam_pwquality.so" "retry=3"
pam_settings_add           ""               "/etc/pam.d/system-auth"       "password"       "requisite"            "pam_pwquality.so" "retry=3"
pam_settings_add           "RHEL-08-020220" "/etc/pam.d/password-auth"     "password"       "requisite"            "pam_pwquality.so" "remember=$PW_HIST"
pam_settings_add           ""               "/etc/pam.d/system-auth"       "password"       "requisite"            "pam_pwquality.so" "remember=$PW_HIST"
pam_settings_add           "RHEL-08-020028" "/etc/pam.d/password-auth"     "auth"           "required"             "pam_faillock.so"  "dir=/var/log/faillock"

pam_settings_remove        "RHEL-08-020332" "/etc/pam.d/password-auth"     ""               ""                     ""                 ""                  "nullok"
pam_settings_remove        "RHEL-08-020331" "/etc/pam.d/system-auth"       ""               ""                     ""                 ""                  "nullok"

pam_change_control         "RHEL-08-020340"	"/etc/pam.d/postlogin"         "session"        "required"             "pam_lastlog.so"   "showfailed"
pam_settings_remove        ""               "/etc/pam.d/postlogin"         "session"        "required"             "pam_lastlog.so"   "showfailed"        "silent"
							
variable_space_equal_space "RHEL-08-020110" "/etc/security/pwquality.conf" "ucredit"        "-$PW_MIN_UC"
variable_space_equal_space "RHEL-08-020120" "/etc/security/pwquality.conf" "lcredit"        "-$PW_MIN_LC"
variable_space_equal_space "RHEL-08-020130" "/etc/security/pwquality.conf" "dcredit"        "-$PW_MIN_NUM"
variable_space_equal_space "RHEL-08-020230" "/etc/security/pwquality.conf" "ocredit"        "-$PW_MIN_OTHER"
variable_space_equal_space "RHEL-08-020140" "/etc/security/pwquality.conf" "maxclassrepeat" "$PW_MAX_CLASS_REPEAT"
variable_space_equal_space "RHEL-08-020150" "/etc/security/pwquality.conf" "maxrepeat"      "$PW_MAX_REPEAT"
variable_space_equal_space "RHEL-08-020160" "/etc/security/pwquality.conf" "minclass"       "4"
variable_space_equal_space "RHEL-08-020110" "/etc/security/pwquality.conf" "difok"          "8"
variable_space_equal_space "RHEL-08-020230" "/etc/security/pwquality.conf" "minlen"         "$PW_MIN_LENGTH"
variable_space_equal_space "RHEL-08-020230" "/etc/security/pwquality.conf" "dictcheck"      "1"

variable_space             "RHEL-08-020190" "/etc/login.defs"              "PASS_MIN_DAYS"  "$PW_MIN_AGE"
variable_space             "RHEL-08-020200" "/etc/login.defs"              "PASS_MAX_DAYS"  "$PW_MAX_AGE"
variable_space             "RHEL-08-020231" "/etc/login.defs"              "PASS_MIN_LEN"   "$PW_MIN_LENGTH"
variable_space             "RHEL-08-020230" "/etc/login.defs"              "FAIL_DELAY"     "4"
variable_space             "RHEL-08-020351" "/etc/login.defs"              "UMASK"          "077"

change_umask               "RHEL-08-020353" "/etc/bashrc"                  "077"
change_umask               ""               "/etc/csh.cshrc"               "077"
change_umask               ""               "/etc/profile"                 "077"

############################################################
# Check rng
############################################################
package_install      "RHEL-08-010472" "rng-tools"
service_enable_start "RHEL-08-010471" "rngd"

############################################################
# Check rsyslogd
############################################################
package_install "RHEL-08-030670" "rsyslog"
package_install "RHEL-08-030680" "rsyslog-gnutls"
variable_space  "RHEL-08-010070" "/etc/rsyslog.conf"   "auth.*;authpriv.*;daemon.*"  "/var/log/secure"          
systemctl restart rsyslog > /dev/null

############################################################
# Check SELinux
############################################################
echo "Checking: RHEL-08-010170"
if ! getenforce | grep 'Enforcing' > /dev/null; then
    echo "${FAIL} SELinux is not active and in Enforcing mode.  Modify /etc/selinux/config and reboot to fix."
	echo "This script does not modify the SELinux setting.  This is a CAT II finding."
	echo
fi
############################################################
# Check SSHD
############################################################
variable_space "RHEL-08-010040" "/etc/ssh/sshd_config" "Banner"                 "/etc/issue"
variable_space "RHEL-08-010200" "/etc/ssh/sshd_config" "ClientAliveCountMax"    "0"
variable_space "RHEL-08-010500" "/etc/ssh/sshd_config" "StrictModes"            "yes"
variable_space "RHEL-08-010510" "/etc/ssh/sshd_config" "Compression"            "delayed"
variable_space "RHEL-08-010520" "/etc/ssh/sshd_config" "IgnoreUserKnownHosts"   "yes"
variable_space "RHEL-08-010521" "/etc/ssh/sshd_config" "KerberosAuthentication" "no"
variable_space "RHEL-08-010550" "/etc/ssh/sshd_config" "PermitRootLogin"        "no"
variable_space "RHEL-08-010830" "/etc/ssh/sshd_config" "PermitUserEnvironment"  "no"
variable_space "RHEL-08-010830" "/etc/ssh/sshd_config" "PermitEmptyPasswords"   "no"
variable_space "RHEL-08-040161" "/etc/ssh/sshd_config" "RekeyLimit"             "1G 1h"
variable_space "RHEL-08-040340" "/etc/ssh/sshd_config" "X11Forwarding"          "no"
variable_space "RHEL-08-040341" "/etc/ssh/sshd_config" "X11UseLocalhost"        "yes"
variable_space "RHEL-08-010201" "/etc/ssh/sshd_config" "ClientAliveInterval"    "600"
variable_space "RHEL-08-010522" "/etc/ssh/sshd_config" "GSSAPIAuthentication"   "no"
variable_space "RHEL-08-020350" "/etc/ssh/sshd_config" "PrintLastLog"           "yes"

variable_equal "RHEL-08-010292" "/etc/sysconfig/sshd"  "SSH_USE_STRONG_RNG"     "32"

service_enable_start "RHEL-08-040160" "sshd"

############################################################
# Check sudoers
############################################################
variable_bare "RHEL-08-010383" "/etc/sudoers" "Defaults !targetpw"
variable_bare ""               "/etc/sudoers" "Defaults !rootpw"
variable_bare ""               "/etc/sudoers" "Defaults !runaspw"
variable_equal "RHEL-08-010384" "/etc/sudoers" "Defaults timestamp_timeout" "1800"

############################################################
# Check sysctl
############################################################
variable_space_equal_space "RHEL-08-010374" "/etc/sysctl.d/99-sysctl.conf" "fs.protected_hardlinks"                    "1"
variable_space_equal_space "RHEL-08-010373" "/etc/sysctl.d/99-sysctl.conf" "fs.protected_symlinks"                     "1"
variable_space_equal_space "RHEL-08-010671" "/etc/sysctl.d/99-sysctl.conf" "kernel.core_pattern"                       "|/bin/false"
variable_space_equal_space "RHEL-08-010375" "/etc/sysctl.d/99-sysctl.conf" "kernel.dmesg_restrict"                     "1"
variable_space_equal_space "RHEL-08-010372" "/etc/sysctl.d/99-sysctl.conf" "kernel.kexec_load_disabled"                "1"
variable_space_equal_space "RHEL-08-040283" "/etc/sysctl.d/99-sysctl.conf" "kernel.kptr_restrict"                      "1"
variable_space_equal_space "RHEL-08-010376" "/etc/sysctl.d/99-sysctl.conf" "kernel.perf_event_paranoid"                "2"
variable_space_equal_space "RHEL-08-010430" "/etc/sysctl.d/99-sysctl.conf" "kernel.randomize_va_space"                 "2"
variable_space_equal_space "RHEL-08-040281" "/etc/sysctl.d/99-sysctl.conf" "kernel.unprivileged_bpf_disabled"          "1"
variable_space_equal_space "RHEL-08-040282" "/etc/sysctl.d/99-sysctl.conf" "kernel.yama.ptrace_scope"                  "1"
variable_space_equal_space "RHEL-08-040286" "/etc/sysctl.d/99-sysctl.conf" "net.core.bpf_jit_harden"                   "2"
variable_space_equal_space "RHEL-08-040279" "/etc/sysctl.d/99-sysctl.conf" "net.ipv4.conf.all.accept_redirects"        "0"
variable_space_equal_space "RHEL-08-040239" "/etc/sysctl.d/99-sysctl.conf" "net.ipv4.conf.all.accept_source_route"     "0"
variable_space_equal_space "RHEL-08-040286" "/etc/sysctl.d/99-sysctl.conf" "net.ipv4.conf.all.forwarding"              "0"
variable_space_equal_space "RHEL-08-040285" "/etc/sysctl.d/99-sysctl.conf" "net.ipv4.conf.all.rp_filter"               "1"
variable_space_equal_space "RHEL-08-040220" "/etc/sysctl.d/99-sysctl.conf" "net.ipv4.conf.all.send_redirects"          "0"
variable_space_equal_space "RHEL-08-040209" "/etc/sysctl.d/99-sysctl.conf" "net.ipv4.conf.default.accept_redirects"    "0"
variable_space_equal_space "RHEL-08-040249" "/etc/sysctl.d/99-sysctl.conf" "net.ipv4.conf.default.accept_source_route" "0"
variable_space_equal_space "RHEL-08-040270" "/etc/sysctl.d/99-sysctl.conf" "net.ipv4.conf.default.send_redirects"      "0"
variable_space_equal_space "RHEL-08-040230" "/etc/sysctl.d/99-sysctl.conf" "net.ipv4.icmp_echo_ignore_broadcasts"      "1"
variable_space_equal_space "RHEL-08-040284" "/etc/sysctl.d/99-sysctl.conf" "user.max_user_namespaces"                  "0"

sysctl --system > /dev/null

############################################################
# Check tmux
############################################################
package_install "RHEL-08-040100" "tmux"

variable_space  "RHEL-08-020040" "/etc/tmux.conf" "set -g lock-command"    "vlock"
variable_space  "RHEL-08-020070" "/etc/tmux.conf" "set -g lock-after-time" "900"
			    
variable_bare   "RHEL-08-020041" "/etc/bashrc"    "[ -n \"\$PS1\" -a -z \"\$TMUX\" ] && exec tmux"
			    
remove_line     "RHEL-08-020042" "/etc/shells"    "tmux"

############################################################
# Check usbguard
############################################################
package_install "RHEL-08-040139" "usbguard"

variable_equal  "RHEL-08-030603" "/etc/usbguard/usbguard-daemon.conf" "AuditBackend" "LinuxAudit"

echo "Checking: RHEL-08-040140"
if ! [ -s /etc/usbguard/rules.conf ]; then
	echo "{$FIX} generating usbguard rules"
	usbguard generate-policy > /etc/usbguard/rules.conf
fi

service_enable_start "RHEL-08-040141" "usbguard"

############################################################
# Remove Packages
############################################################
package_remove "RHEL-08-040001" "abrt"
package_remove "RHEL-08-040360" "*ftp*"
package_remove "RHEL-08-040370" "gssproxy"
package_remove "RHEL-08-040380" "iprutils"
package_remove "RHEL-08-040010" "rsh-server"
package_remove "RHEL-08-040002" "sendmail"
package_remove "RHEL-08-040000" "telnet-server"
package_remove "RHEL-08-040190" "tftp-server"
package_remove "RHEL-08-040390" "tuned"

############################################################
# File Permissions
############################################################
echo "Checking: RHEL-08-010490"
if [[ -n $(find /etc/ssh/ssh_host*key -perm /044 -o -perm /022 -o -perm /011) ]]; then
	echo "${FIX} setting /etc/ssh/ssh_host*key to mode 0600"
	chmod 0600 /etc/ssh/ssh_host*key
fi

echo "Checking: RHEL-08-010731"
if [[ -n $(find /home/*/[^.]* -perm /4004 -o -perm /2022 -o -perm /1001) ]]; then
	echo "${FIX} chmod all /home/*/* files to no greater than 0750"
	chmod g-w,o-rwx,-t -- $(find /home/*/[^.]* -perm /4004 -o -perm /2022 -o -perm /1001)
fi

echo "Checking: RHEL-08-010770"
if [[ -n $(find /home/*/.[^.]* -perm /4004 -o -perm /2022 -o -perm /1011) ]]; then
	echo "${FIX} chmod all /home/*/.* files to no greater than 0740"
	chmod g-wx,o-rwx,-t -- $(find /home/*/.[^.]* -perm /4004 -o -perm /2022 -o -perm /1011)
fi

############################################################
# Current user account settings
############################################################
users=$(awk -F: '{ if ( ( $3 >= 1000 && $3 <= 60000 && $7 != "/sbin/nologin") || $3 == 0) print $1 }' /etc/passwd)

echo "Checking: RHEL-08-020180"
for user in $users; do
	if grep "^${user}:" /etc/shadow | cut -f 4 -d: | grep -v $PW_MIN_AGE > /dev/null; then
		echo "${FIX} setting minimum password age to ${PW_MIN_AGE} for ${user}"
		chage -m $PW_MIN_AGE $user
	fi
done

echo "Checking: RHEL-08-020210"
for user in $users; do
if grep "^${user}:" /etc/shadow | cut -f 5 -d: | grep -v $PW_MAX_AGE > /dev/null; then
echo "${FIX} setting maximum password age to ${PW_MAX_AGE} for ${user}"
chage -M $PW_MAX_AGE $user
fi
done

############################################################
# Misc Settings
############################################################
install_file         "RHEL-08-010060" "/etc"                                  "issue"             "644"
package_install      "RHEL-08-010390" "openssl-pkcs11"  
variable_equal       "RHEL-08-010371" "/etc/dnf/dnf.conf"                     "localpkg_gpgcheck" "True"
variable_space       "RHEL-08-020024" "/etc/security/limits.d/maxlogins.conf" "* hard maxlogins"  "10"
variable_equal       "RHEL-08-020260" "/etc/default/useradd"                  "inactive"          "35"
service_disable_stop "RHEL-08-040070" "autofs"
service_mask         "RHEL-08-040180" "debug-shell"

# Needed to send email 
package_install            "Additional settings" "mailx"
package_install            ""                    "postfix"
variable_space_equal_space ""                    "/etc/postfix/main.cf" "inet_protocols" "ipv4"
service_enable_start       ""                    "postfix"


echo "Complete"


