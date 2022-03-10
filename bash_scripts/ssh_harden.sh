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
    echo -e "${BOLDGREEN}SUCCESS: ${1} ${ENDCOLOR}}"
else
    echo -e "${BOLDRED}FAILED: ${1} ${ENDCOLOR}}"
    return 1
fi
}
