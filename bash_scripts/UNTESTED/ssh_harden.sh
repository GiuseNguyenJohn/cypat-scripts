#!/bin/bash
# Author: John Nguyen
# This script hardens the config file "/etc/ssh/sshd_config", inserts
# "restrict, " before every key in "~/.ssh/authorized_keys" and
# reloads OpenSSH.

RED="31"
GREEN="32"
BOLDGREEN="\e[1;${GREEN}m"
BOLDRED="\e[1;${RED}m"
ENDCOLOR="\e[0m"

FAILED=$false

#######################################
# Checks the exit code of last command and reports success or failure
# Globals:
#     BOLDGREEN, BOLDRED, ENDCOLOR
# Arguments:
#     command name
# Outputs:
#     Writes output to stdout
# Returns:
#     0 if command exited successfully, 1 if failed.
#######################################
function check_status() {
if [ "$?" -eq "0" ]; then
    echo -e "${BOLDGREEN}SUCCESS: ${1} ${ENDCOLOR}"
else
    echo -e "${BOLDRED}FAILED: ${1} ${ENDCOLOR}"
    FAILED=$true
    exit 1
fi
}

# create backup file
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
check_status "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak"

# overwrite the config file
cat ./config_files/sshd_config_HARDENED.txt > /etc/ssh/sshd_config
check_status "cat ./config_files/sshd_config_HARDENED.txt > /etc/ssh/sshd_config"

# test config syntax
sshd -t
check_status "sshd -t // test sshd_config syntax"

# reload sshd
systemctl reload sshd.service
check_status "systemctl reload sshd.service"

# Exit with explicity exit code
if [[ "$FAILED" -eq "$true" ]]; then
    exit 1
else
    exit 0
fi