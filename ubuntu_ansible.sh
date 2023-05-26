#!/bin/bash
# Script to install ansible and playbooks to harden Ubuntu and Fedora according to CIS and STIG guidelines

sudo apt install -y git ansible
git clone https://github.com/ansible-lockdown/UBUNTU22-CIS.git
# already have inventory file
# copy and paste command below
# ansible-playbook -i inventory.ini ./UBUNTU22-CIS/site.yml | tee output.txt
