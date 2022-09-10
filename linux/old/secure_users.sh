#!/bin/bash
# Author: John Nguyen
# This script...
# - disables login for root
# - deletes unauthorized users
# - adds new users

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

#######################################
#          MAIN CODE GOES HERE        #
#######################################

# TODO: Disable login for root

# TODO: call python script that deletes unauthorized
#       users and add new users

# TODO: change shell of service accounts to /usr/sbin/nologin

# Exit with explicity exit code
if [[ "$FAILED" -eq "$true" ]]; then
    exit 1
else
    exit 0
fi
