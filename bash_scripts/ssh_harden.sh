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