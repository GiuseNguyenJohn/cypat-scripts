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

ALL_MODULES="delete_media"
HELP="${GREEN}Harden and secure an Ubuntu 18, 20 or Debian 10 machine.
${NC}This script parses the README.txt file, then implements security measures ${DG}(AV, hardens applications, removes packages, firewall, system configs, removes users) ${NC}and outputs logs of changes being made.
    ${GREEN}Options
        ${YELLOW}-A ${BLUE} Execute all modules
        ${YELLOW}-u <USER> ${BLUE} Add new user
        ${YELLOW}-U <USER> ${BLUE} Add new user as an administrator
    ${GREEN}Modules
        ${YELLOW}-m ${BLUE} Delete media files (mp3, mp4)
        ${YELLOW}-f ${BLUE} Enable firewall and enforce firewall rules
        ${YELLOW}-p ${BLUE} Delete disallowed packages
        ${YELLOW}-d ${BLUE} Delete unauthorized users
    ${GREEN}Misc.
        ${YELLOW}-h ${BLUE} To show this message
"

###########################################
#------------) Main functions (-----------#
###########################################


delete_media_files (){
    local CMD="sh -c '(rm -f {} && printf ${RED}\"    Deleted {}\") || printf \"Failed to remove {}\"'"
    printf ${RED}"[+] Deleting Media..."$NC
    find / -name "*.mp[34]" -exec $CMD \;
}

forensics_1 (){
	echo "[+] Solving forensics question 1!"
	mv /home/dovahkiin/Desktop/Forensics\ Question\ 1.txt /home/dovahkiin/Desktop/Forensics\ Question\ 1.txt.old
	sed "s/<Type Answer Here>/$(id paarthurnax | cut -c '5-8')/g" /home/dovahkiin/Desktop/Forensics\ Question\ 1.txt.old > /home/dovahkiin/Desktop/Forensics\ Question\ 1.txt
}

forensics_2 (){
	echo "[+] Solving forensics question 2!"
	mv /home/dovahkiin/Desktop/Forensics\ Question\ 2.txt /home/dovahkiin/Desktop/Forensics\ Question\ 2.txt.old
	sed "s/<Type Answer Here>/$(locate '*.mp3' | head -n 1 | cut -d '0' -f 1)/g" /home/dovahkiin/Desktop/Forensics\ Question\ 2.txt.old > /home/dovahkiin/Desktop/Forensics\ Question\ 2.txt
}

delete_media (){
	echo "[+] Deleting media files!"
	find /home -type f -name "*.mp3" -exec bash -c "rm -rf \"{}\" && echo \"	[+] Removed {}!\"" \;
}

remove_users (){
	echo "[+] Removing unauthorized users!"
	for USER in ballen sheogorath; do
    	userdel -f "${USER}"
	done
}

remove_packages (){
	echo "[+] Removing bad packages!"
	apt remove manaplus
	apt remove gameconqueror
}

stop_ftpd (){
	echo "[+] Disabling bad services!"
	systemctl stop pure-ftpd
	systemctl disable pure-ftpd
}

enable_ufw (){
	echo "[+] Enabling and configuring firewall!"
	ufw enable
	ufw default allow outgoing
	ufw default deny incoming
}

add_user (){
	echo "[+] Adding new user!"
	useradd belethor
}

configure_ssh (){
	echo "[+] Configuring SSH securely!"
	mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old
	sed "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config.old > /etc/ssh/sshd_config
}

change_user_passwd (){
	echo "[+] Changing weak passwords!"
	usermod --password $(echo n3w_passwd123$ | openssl passwd -1 -stdin) esbern
}

change_user_perm (){
	echo "[+] Changing user permissions!"
	deluser ulfric sudo
}

update (){
	echo "[+] Updating and upgrading system!"
	apt update -y && apt upgrade -y
}

update_apps_services (){
	echo "[+] Updating apps and services!"
	apt install firefox
	apt install openssh
}

while getopts "Afu" options; do
	case "${options}" in
    	A)
        	echo "[+] Executing all modules!"
        	forensics_1
        	forensics_2
        	delete_media
        	remove_users
        	remove_packages
        	stop_ftpd
        	enable_ufw
        	add_user
        	configure_ssh
        	change_user_passwd
        	change_user_perm
        	update
        	update_apps_services
        	;;
    	f)
        	forensics_1
        	forensics_2
        	;;
    	u)
        	update
        	update_firefox
        	;;
    	*)
        	print_usage
        	;;
	esac
done

if [ $OPTIND -eq 1 ]; then
	print_usage
fi
