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

delete_media (){
    local CMD="sh -c '(rm -f {} && printf ${RED}\"    Deleted {}\") || printf \"Failed to remove {}\"'"
    printf ${RED}"[+] Deleting Media..."$NC
    find / -name "*.mp[34]" -exec $CMD \;
}
