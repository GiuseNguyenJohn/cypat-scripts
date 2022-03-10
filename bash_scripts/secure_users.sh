#!/bin/bash
# Author: John Nguyen
# This script disables login for root, deletes unauthorized
# users, adds new users, and changes the password of all users.

RED="31"
GREEN="32"
BOLDGREEN="\e[1;${GREEN}m"
BOLDRED="\e[1;${RED}m"
ENDCOLOR="\e[0m"

FAILED=$false