#!/bin/bash

# Author: John Nguyen
# This script lists packages, and lets the user add any packages to be removed.
# Then, it uses 'apt' and 'dpkg' to remove said packages along with a list
# of default bad packages

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
            echo "apt removed: ${PACKAGE}"
        else
            echo "apt failed to remove ${PACKAGE}"
            FAILED=$true
        fi
    done
    if [ "$FAILED" -eq $true ]; then
        return 1
    fi
}

# Remove default bad packages
remove_apt "$BAD_PACKAGES"

# Write installed packages to file
dpkg --list > installed_packages.txt
if [ "$?" -eq "0" ]; then
    echo "dpkg wrote installed packages to 'installed_packages.txt'."
else
    echo "dpkg failed to list packages"
fi

# Read package names seperated by spaces and remove
echo "Enter a list of packages to remove seperated by spaces:"
read -a NEW_BAD_PACKAGES
remove_apt "${NEW_BAD_PACKAGES[@]}"

# Remove broken packages
apt-get clean
apt-get autoremove
apt-get -f install
dpkg --configure -a
