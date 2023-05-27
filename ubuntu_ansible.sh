#!/bin/bash
# Script to install ansible and playbooks to harden Ubuntu and Fedora according to CIS and STIG guidelines

apt install -y git ansible vim
git clone https://github.com/ansible-lockdown/UBUNTU22-CIS.git
git clone https://github.com/ansible-lockdown/UBUNTU20-STIG.git
sed -i "s/ubtu22cis_rule_1_9: true/ubtu22cis_rule_1_9: false/g" ./UBUNTU22-CIS/defaults/main.yml
# already have inventory file
# copy and paste command below

# sudo ansible-playbook -i inventory.ini ./UBUNTU22-CIS/site.yml | tee output.txt

# sudo ansible-playbook -i inventory.ini ./UBUNTU20-STIG/site.yml | tee output.txt
# disabled 010450, 010216
