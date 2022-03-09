#!/bin/bash

# Author: John Nguyen
# This script lists packages, and lets the user add any packages to be removed.
# Then, it uses 'apt' and 'dpkg' to remove said packages along with a list
# of default bad packages

RED="31"
GREEN="32"
BOLDGREEN="\e[1;${GREEN}m"
BOLDRED="\e[1;${RED}m"
ENDCOLOR="\e[0m"

BAD_PACKAGES=("wireshark" "*ftp*" "*telnet*" "*tightvnc*"
    "*nikto*" "*medusa*" "*crack*" "*nmap*" "*fakeroot*"
    "*logkeys*" "*john*" "*frostwire*" "vuze" "*samba*"
    "*netcat*" "*weplab*" "pyrit" "irssi")

#######################################
# Remove packages with 'apt'
# Globals:
#     BAD_PACKAGES
# Arguments:
#     List of package names
# Outputs:
#     Writes errors to stderr
# Returns:
#     0 if all packages removed successfully, 1 if failed.
#######################################
function remove_apt() {
    local FAILED=$false
    for PACKAGE in "$@"; do
        apt purge "$PACKAGE" 1> /dev/null # To debug, remove redirect
        if [ "$?" -eq "0" ]; then
            echo -e "${BOLDGREEN}apt removed: ${PACKAGE} ${ENDCOLOR}"
        else
            echo -e "${BOLDRED}apt failed to remove ${PACKAGE} ${ENDCOLOR}"
            FAILED=$true
        fi
    done
    if [ "$FAILED" -eq $true ]; then
        return 1
    fi
}
#######################################
# Checks the exit code of last command and reports success or failure
# Globals:
#
# Arguments:
#     command name
# Outputs:
#     Writes output to stdout
# Returns:
#     0 if all packages removed successfully, 1 if failed.
#######################################
function check_status() {
if [ "$?" -eq "0" ]; then
    echo -e "${BOLDGREEN}SUCCESS: ${1} ${ENDCOLOR}}"
else
    echo -e "${BOLDRED}FAILED: ${1} ${ENDCOLOR}}"
    return 1
fi
}

# Remove default bad packages
remove_apt "$BAD_PACKAGES"

# Write installed packages to file
dpkg --list > installed_packages.txt
check_status "dpkg --list"

# Read package names seperated by spaces and remove
echo "Enter a list of packages to remove seperated by spaces:"
read -a NEW_BAD_PACKAGES
remove_apt "${NEW_BAD_PACKAGES[@]}"

# Remove broken packages
apt-get clean
check_status "apt-get clean"
apt-get autoremove
check_status "apt-get autoremove"
apt-get -f install
check_status "apt-get -f install"
dpkg --configure -a
check_status "dpkg --configure -a"