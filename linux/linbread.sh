#!/bin/bash
# Author: John Nguyen

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
configure_ssh \
configure_samba \
configure_network \
configure_ftp \
delete_media \
enable_ufw \
remove_packages \
stop_services \
update_apps_services \
update \
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
    ${GREEN}Misc.
        ${YELLOW}-h ${BLUE} To show this message${NC}
"

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

change_user_passwd (){
	echo "${GREEN}[+] Changing weak passwords!${NC}"
	USERS=(jhopper jbyers kwheeler mbrenner wbyers mmayfield bhargrove bnewby sowens rbuckley mbauman argyle emunson gareth jeff cpowell hwheeler ocallahan sbingham dantonov alexei )
	for USER in "${USERS[@]}"; do
		usermod --password $(echo n3w_passwd123$ | openssl passwd -1 -stdin) $USER
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
	mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old
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
	# https://www.linuxtopia.org/online_books/linux_system_administration/securing_and_optimizing_linux/chap29sec284.html
	sed -i "s/encrypt passwords = .*$/encrypt passwords = True/g" /etc/smb.conf
	sed -i "s/security = .*$/security = user/g" /etc/smb.conf
	sed -i "s/smb passwd file = .*$/smb passwd file = \/etc\/smbpasswd/g" /etc/smb.conf
	sed -i "s/dns proxy = .*$/dns proxy = no/g" /etc/smb.conf
	sed -i "s/bind interfaces only = .*$/bind interfaces only = True/g" /etc/smb.conf
	sed -i "s/hosts deny = .*$/host deny = ALL/g" /etc/smb.conf
	# https://www.linuxtopia.org/online_books/linux_system_administration/securing_and_optimizing_linux/chap29sec286.html
	chmod 600 /etc/smbpasswd
}

configure_network (){
	echo "${GREEN}[+] Configuring network settings (/etc/sysctl.conf)!${NC}"
	cp /etc/sysctl.conf /etc/sysctl.conf.old
	# enable TCP/IP SYN cookies
	sed -i "s/^.*net.ipv4.tcp_syncookies.*$/net.ipv4.tcp_syncookies=1/g" /etc/sysctl.conf
	# Do not accept ICMP redirects (prevent MITM attacks)
	sed -i "s/^.*net.ipv4.conf.all.accept_redirects.*$/net.ipv4.conf.all.accept_redirects=0/g" /etc/sysctl.conf
	sed -i "s/^.*net.ipv6.conf.all.accept_redirects.*$/net.ipv6.conf.all.accept_redirects=0/g" /etc/sysctl.conf
}

# params: none
# tested
delete_media (){
	echo "${RED}[+] Deleting media files!${NC}"
	find /home -type f -name "*.mp[34]" -exec bash -c "rm -rf \"{}\" && echo \"	[+] Removed {}!\"" \;
}

enable_ufw (){
	echo "${GREEN}[+] Enabling and configuring firewall!${NC}"
	ufw enable
	ufw default allow outgoing
	ufw default deny incoming
}

# params: none
remove_users (){
	echo "${RED}[+] Removing unauthorized users!${NC}"
	for USER in "$@"; do
    	userdel -f "${USER}"
	done
}

remove_packages (){
	echo -e "${RED}[+] Removing bad packages!${NC}"
	apt remove -y "gameconqueror" "*wireshark*" "*ftp*" "*telnet*" "*tightvnc*" "*nikto*" "*medusa*" "*crack*" "*nmap*" "*fakeroot*" "*logkeys*" "*john*" "*frostwire*" "vuze" "*samba*" "*netcat*" "*weplab*" "pyrit"
	apt remove -y "tcpdump" "telnet" "deluge" "hydra" "hydra-gtk" "nmap"
}

stop_services (){
	echo "${RED}[+] Disabling bad services!${NC}"
	systemctl stop pure-ftpd
	systemctl disable pure-ftpd
}

update (){
	echo "${GREEN}[+] Updating and upgrading system!${NC}"
	apt update -y && apt upgrade -y
}

update_apps_services (){
	echo "${GREEN}[+] Updating apps and services!${NC}"
	apt install -y firefox openssh vim
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