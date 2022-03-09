#!/bin/bash

# Author: John Nguyen
# This script lists packages, and lets the user add any packages to be removed.
# Then, it uses 'apt' and 'dpkg' to remove said packages along with a list
# of default bad packages

BAD_PACKAGES="wireshark "

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
        apt purge "$PACKAGE" 1> /dev/null
    done
    if [ "$?" -eq "0" ]; then
        echo "apt removed: ${PACKAGE}"
    else
        echo "apt failed to remove ${PACKAGE}"
        FAILED=$true
    fi
    if [ FAILED -eq $true ]; then
        return 1
    fi
}

# 
dpkg --list > installed_packages.txt
if [ "$?" -eq "0" ]; then
    echo "dpkg wrote installed packages to 'installed_packages.txt'."
else
    echo "dpkg failed to list packages"
fi
# Remove broken packages
apt-get clean
apt-get autoremove
apt-get -f install
dpkg --configure -a
