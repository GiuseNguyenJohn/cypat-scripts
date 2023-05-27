#!/bin/bash
# Script to set up ansible playbook for fedora

dnf install -y ansible vim git
ansible-galaxy collection install devsec.hardening
cp -r /home/liveuser/.ansible/devsec/hardening .
cd hardening
cp ../site.yml .
# ansible-playbook -i ../inventory.ini ./site.yml