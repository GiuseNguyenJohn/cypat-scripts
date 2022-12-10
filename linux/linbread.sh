#!/bin/bash
# Author: John Nguyen

# TODO:
# DONE - vsftpd - disable write access, changing share permissions, disable users, SSL enabled, lost file restored (2nd forensics question
# DONE - Updates: check daily, software update source includes security updates
# DONE - Kernel: ASLR enabled, NX enabled
# Dirty Pipe CVE remediation
# Killing a netcat backdoor (cron job created by lawrence that uses dash shell)
# DONE - Uninstalled Nginx, NFS, ophcrack, nc binary
# DONE - Password min and max age (/etc/login.defs)
# DONE - UFW enabled
# Applications: update (Thunderbird), install p7zip desktop, Firefox HTTPS-only mode enabled for all windows
# DONE - Users: Change weak password, remove unauthorized user, add user to new group, make users not administrators, disable root login through GDM

###########################################
#---------------) Colors (----------------#
###########################################

C=$(printf '\033')
RED="${C}[1;31m"
SED_RED="${C}[1;31m&${C}[0m"
GREEN="${C}[1;32m"
SED_GREEN="${C}[1;32m&${C}[0m"
YELLOW="${C}[1;33m"
SED_YELLOW="${C}[1;33m&${C}[0m"
SED_RED_YELLOW="${C}[1;31;103m&${C}[0m"
BLUE="${C}[1;34m"
SED_BLUE="${C}[1;34m&${C}[0m"
ITALIC_BLUE="${C}[1;34m${C}[3m"
LIGHT_MAGENTA="${C}[1;95m"
SED_LIGHT_MAGENTA="${C}[1;95m&${C}[0m"
LIGHT_CYAN="${C}[1;96m"
SED_LIGHT_CYAN="${C}[1;96m&${C}[0m"
LG="${C}[1;37m" #LightGray
SED_LG="${C}[1;37m&${C}[0m"
DG="${C}[1;90m" #DarkGray
SED_DG="${C}[1;90m&${C}[0m"
NC="${C}[0m"
UNDERLINED="${C}[5m"
ITALIC="${C}[3m"

###########################################
#---------) Parsing parameters (----------#
###########################################

ALL_MODULES=(
update \
update_apps_services \
change_user_passwords
configure_ssh \
# configure_samba \
configure_network \
configure_password_policy \
# configure_vsftpd \
# configure_apache2 \
delete_media \
# download_mozilla_ppa \
enable_ufw \
remove_packages \
stop_services \
)
# Modules not in ALL_MODULES: print_usage remove_users add_user configure_new_group
HELP="${GREEN}Harden and secure an Ubuntu 18, 20 or Fedora 36 machine.
${NC}This script parses the README.txt file, then implements security measures ${DG}(AV, hardens applications, removes packages, firewall, system configs, removes users) ${NC}and outputs logs of changes being made.
    ${GREEN}Options
        ${YELLOW}-A ${BLUE} Execute all modules
        ${YELLOW}-u <USER> ${BLUE} Add new user
    ${GREEN}Modules
        ${YELLOW}-d 'user1,user2, ...' ${BLUE} Delete unauthorized users
		${YELLOW}-g ${BLUE} Add new group and users to the group
		${YELLOW}-s ${BLUE} Configure Samba (/etc/smb.conf)
		${YELLOW}-n ${BLUE} Configure network settings (/etc/sysctl.conf)
		${YELLOW}-a ${BLUE} Configure apache2 (/etc/apache2/apache2.conf)
    ${GREEN}Misc.
        ${YELLOW}-h ${BLUE} To show this message${NC}
"
if uname 2>/dev/null | grep -qi 'Fedora' || /usr/bin/uname 2>/dev/null | grep -qi 'Fedora'; then FEDORA="1"; else FEDORA=""; fi

###########################################
#------------) Main functions (-----------#
###########################################

print_usage (){
	echo "${HELP}"
}

add_user (){
	echo "${GREEN}[+] Adding new user!${NC}"
	useradd esinclair
}

change_user_passwords (){
	echo "${GREEN}[+] Changing weak passwords!${NC}"
	USERS=$(awk -F: '{ print $1}' /etc/passwd | (readarray -t ARRAY; IFS=' '; echo "${ARRAY[*]}"))
	for USER in $USERS; do
		usermod --password $(echo n3w_passwd123^ | openssl passwd -1 -stdin) $USER
		# expire passwords and force change next logon
		passwd -e $USER
	done
}

# change_user_perm (){
# 	echo "[+] Changing user permissions!"
# 	deluser ulfric sudo
# }

configure_new_group (){
	echo "${GREEN}[+] Adding new group and users!${NC}"
	groupadd dragonfire
	for USER in "emunson" "gareth" "jeff" "mwheeler" "dhenderson" "lsinclair" "esinclair"; do
		usermod -a -G dragonfire $USER
	done
}

configure_ssh (){
	echo "${GREEN}[+] Configuring SSH securely (/etc/ssh/sshd_config)!${NC}"
	cp /etc/ssh/sshd_config /etc/ssh/sshd_config.old
	chmod 0700 /etc/ssh/sshd_config
	sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
	sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config
	sed -i "s/DisableForwarding no/DisableForwarding yes/g" /etc/ssh/sshd_config
	sed -i "s/PermitEmptyPasswords yes/PermitEmptyPasswords no/g" /etc/ssh/sshd_config
	systemctl enable sshd
	systemctl restart sshd
}

configure_samba () {
	echo "${GREEN}[+] Configuring samba (/etc/smb.conf)!${NC}"
	# Files: /etc/smb.conf, /etc/rc.d/init.d/smb, /etc/logrotate.d/samba, /etc/pam.d/samba
	cp /etc/smb.conf /etc/smb.conf.old
	chmod 0700 /etc/smb.conf
	# https://www.linuxtopia.org/online_books/linux_system_administration/securing_and_optimizing_linux/chap29sec284.html
	sed -i "s/^.*encrypt passwords = .*$/encrypt passwords = True/g" /etc/smb.conf
	sed -i "s/^.*security = .*$/security = user/g" /etc/smb.conf
	sed -i "s/^.*smb passwd file = .*$/smb passwd file = \/etc\/smbpasswd/g" /etc/smb.conf
	sed -i "s/^.*dns proxy = .*$/dns proxy = no/g" /etc/smb.conf
	sed -i "s/^.*bind interfaces only = .*$/bind interfaces only = True/g" /etc/smb.conf
	sed -i "s/^.*hosts deny = .*$/host deny = ALL/g" /etc/smb.conf
	# https://www.linuxtopia.org/online_books/linux_system_administration/securing_and_optimizing_linux/chap29sec286.html
	chmod 0700 /etc/smbpasswd
	systemctl enable smbd
	systemctl enable nmbd
	systemctl restart nmbd
	systemctl restart smbd
}

configure_network (){
	echo "${GREEN}[+] Configuring network settings (/etc/sysctl.conf)!${NC}"
	cp /etc/sysctl.conf /etc/sysctl.conf.old
	chmod 0700 /etc/sysctl.conf
	# enable TCP/IP SYN cookies
	sed -i "s/^.*net.ipv4.tcp_syncookies.*$/net.ipv4.tcp_syncookies=1/g" /etc/sysctl.conf
	# Do not accept ICMP redirects (prevent MITM attacks)
	sed -i "s/^.*net.ipv4.conf.all.accept_redirects.*$/net.ipv4.conf.all.accept_redirects=0/g" /etc/sysctl.conf
	sed -i "s/^.*net.ipv6.conf.all.accept_redirects.*$/net.ipv6.conf.all.accept_redirects=0/g" /etc/sysctl.conf
	# Prevent IP spoofing
	sed -i "s/^.*net.ipv4.conf.all.rp_filter.*$/net.ipv4.conf.all.rp_filter=1/g" /etc/sysctl.conf
	sed -i "s/^.*net.ipv4.conf.default.rp_filter.*$/net.ipv4.conf.default.rp_filter=1/g" /etc/sysctl.conf
	# Ignore ICMP broadcast requests
	sed -i "s/^.*net.ipv4.icmp_echo_ignore_broadcasts.*$/net.ipv4.icmp_echo_ignore_broadcasts=1/g" /etc/sysctl.conf
	# kernel protections
	echo "kernel.exec-shield = 1 # CHANGED" >> /etc/sysctl.conf
	echo "kernel.randomize_va_space = 1 # CHANGED" >> /etc/sysctl.conf
	sysctl -p
}

configure_password_policy (){
	echo "${GREEN}[+] Configuring password policy (/etc/login.defs)!${NC}"
	cp /etc/login.defs /etc/login.defs.old
	chmod 0700 /etc/login.defs
	sed -i "s/PASS_MAX_DAYS/PASS_MAX_DAYS   90 #/g"
	sed -i "s/PASS_MIN_DAYS/PASS_MIN_DAYS   10 #/g"
	# make sure only the user has access to their home directory
	sed -i "s/UMASK/UMASK       077 #/g"
}

configure_vsftpd (){
	echo "${GREEN}[+] Configuring vsftpd (/etc/vsftpd.conf)!${NC}"
	# Files: /etc/vsftpd.conf /etc/ftpusers /etc/user_list
	cp /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.old
	chmod 0700 /etc/vsftpd/vsftpd.conf
	# https://likegeeks.com/ftp-server-linux/#:~:text=You%20can%20secure%20your%20FTP,users%20to%20access%20the%20service.&text=The%20file%20%2Fetc%2Fvsftpd.,files%20and%20restart%20your%20service.
	sed -i "s/^.*write_enable.*$/write_enable=NO/g" /etc/vsftpd.conf
	sed -i "s/^.*anonymous_enable.*$/anonymous_enable=NO/g" /etc/vsftpd.conf
	sed -i "s/^.*chroot_local_user.*$/chroot_local_user=YES/g" /etc/vsftpd.conf
	sed -i "s/^.*ssl_enable.*$/ssl_enable=YES/g" /etc/vsftpd.conf
	# TODO: deny root ftp login
	systemctl enable vsftpd
	systemctl restart vsftpd

}

configure_apache2 (){
	echo "${GREEN}[+] Configuring apache2 (/etc/apache2/apache2.conf)${NC}"
	# Files: /etc/apache2/conf-enabled/security.conf
	# 		 /etc/apache2/apache2.conf
	cp /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-enabled/security.conf.old
	cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.old
	chmod 0700 /etc/apache2/apache2.conf
	# https://hostadvice.com/how-to/how-to-harden-your-apache-web-server-on-ubuntu-18-04/
	sed -i "s/ServerTokens/ServerTokens Prod  # /g" /etc/apache2/conf-enabled/security.conf
	sed -i "s/ServerSignature/ServerSignature Off # /g" /etc/apache2/conf-enabled/security.conf
	# https://linuxhint.com/secure_apache_server/
	systemctl enable apache2
	systemctl restart apache2
}

configure_sql (){
	echo "${GREEN}[+] Configuring SQL (/etc/mysql/my.cnf)${NC}"
	# Files:

	# https://www.techrepublic.com/article/how-to-harden-mysql-security-with-a-single-command/
	# https://blog.0daylabs.com/2014/01/09/12-steps-for-hardening-mysql-from-attackers/
	# https://www.tecmint.com/mysql-mariadb-security-best-practices-for-linux/
	# https://medium.com/linode-cube/5-essential-steps-to-hardening-your-mysql-database-591e477bbbd7
	mysql_secure_installation
	chmod 0700 /etc/mysql/my.cnf
	echo "set-variable=local-infile=0" >> /etc/mysql/my.cnf
	systemctl restart mysql
}

delete_media (){
	echo "${RED}[+] Deleting media files!${NC}"
	find /home -type f -name "*.mp[34]" -exec bash -c "rm -rf \"{}\" && echo \"	[+] Removed {}!\"" \;
}

disable_root_login_gdm (){
	echo "${RED}[+] Disabling root login for gdm3! (/etc/pam.d/gdm)${NC}"
	# https://unix.stackexchange.com/questions/447632/how-to-prevent-root-login-from-gnome-3-login-screen-arch-linux
	echo "auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so" >> /etc/pam.d/gdm
	echo "auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so" >> /etc/pam.d/gdm-autologin
	echo "auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so" >> /etc/pam.d/gdm-fingerprint
	echo "auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so" >> /etc/pam.d/gdm-password
	echo "auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so" >> /etc/pam.d/gdm-smartcard
}

download_mozilla_ppa (){
	echo "${GREEN}[+] Downloading Mozilla from PPA!${NC}"
	snap remove firefox
	add-apt-repository ppa:mozillateam/ppa
	apt install firefox
}

enable_ufw (){
	echo "${GREEN}[+] Enabling and configuring firewall!${NC}"
	ufw enable
	ufw default allow outgoing
	ufw default deny incoming
}

remove_users (){
	echo "${RED}[+] Removing unauthorized users!${NC}"
	for USER in "$@"; do
    	userdel -f "${USER}"
	done
}

remove_packages (){
	echo "${RED}[+] Removing bad packages!${NC}"
	apt remove -y "gameconqueror" "*wireshark*" "*telnet*" "*tightvnc*" "*nikto*" "*medusa*" "*crack*" "*nmap*" "*fakeroot*" "*logkeys*" "*john*" "*frostwire*" "vuze" "*net-tools*" "*weplab*" "pyrit"
	apt remove -y "tcpdump" "telnet" "deluge" "hydra" "hydra-gtk" "nmap" "ophcrack" "nginx" "nfs" "ophcrack"
}

stop_services (){
	echo "${RED}[+] Disabling bad services!${NC}"
	systemctl stop pure-ftpd
	systemctl disable pure-ftpd
}

update (){
	echo "${GREEN}[+] Updating and upgrading system!${NC}"
	# configure automatic updates for apt
	echo "APT::Periodic::Update-Package-Lists \"1\";
	APT::Periodic::Download-Upgradeable-Packages \"0\";
	APT::Periodic::AutocleanInterval \"0\";" > /etc/apt/apt.conf.d/10periodic
	apt update -y && apt upgrade -y
}

update_apps_services (){
	echo "${GREEN}[+] Updating apps and services!${NC}"
	apt install -y firefox ssh vim tree guake libapache2-mod-security2 libapache2-mod-evasive thunderbird perl
}

while getopts "Aud:gsn" options; do
	case "${options}" in
    	A)
        	echo "[+] Executing all modules!"
			for MODULE in "${ALL_MODULES[@]}"; do
				$MODULE
			done
        	;;
    	u)
        	add_user
        	;;
		d)
		  	# convert comma-separated list into bash array
		 	IFS=',' read -ra USERS <<< "${OPTARG}"
			remove_users "${USERS[@]}"
			;;
		g)
			configure_new_group
			;;
		s)
			configure_samba
			;;
		n)
			configure_network
			;;
    	*)
        	print_usage
        	;;
	esac
done

if [ $OPTIND -eq 1 ]; then
	print_usage
fi