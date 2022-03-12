"""Linux Script for Cyberpatriot"""

import os

permissions = """#!/bin/bash

chown root:root /etc/passwd
chmod 644 /etc/passwd
chown root:root /etc/shadow
chmod o-rwx,g-wx /etc/shadow
chown root:root /etc/group
chmod 644 /etc/group
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-
chown root:root /etc/shadow-
chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-
chown root:root /etc/gshadow-
chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-

chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net

chmod 0600 /etc/securetty
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinetd.conf
chmod 400 /etc/inetd.d
chmod 644 /etc/hosts.allow
chmod 440 /etc/sudoers
echo "Finished changing permissions"
"""

find_bad_packs = """#!/bin/bash
#Looks at the package names and saves those that are deemed dangerous
echo "Bad Packages:" > badPackages.txt
( dpkg-query --list | grep -e "john" -e "Crack" -e "logkeys" -e "Hydra" -e "nginx" -e "Trojan" -e "password crack" -e "hack" -e "Hack" -e "telnetd" -e "fakeroot" -e "samba" -e "nmap" -e "crack" >> badPackages.txt ) &
(dpkg-query --list | grep -e "server" >> servers.txt; echo "Finished looking for bad known programs") &

#This will take all of the packages and store them in a file to be viewed later.
echo "" > allThePackages.txt
(dpkg-query --list >> allThePackages.txt) &
"""

security_tools = """#!/bin/bash
#install the needed programs like rkhunter, tree, etc
apt-get install rkhunter tree debsums libpam-cracklib chkrootkit clamav lynis -y
"""

vsftpd = """#!/bin/bash
# VSFTPD
echo -n "Should VSFTP Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
     apt-get -y install vsftpd > /dev/null 2>&1 
     # Disable anonymous uploads
      sed -i '/^anon_upload_enable/ c\anon_upload_enable no   #' /etc/vsftpd.conf # outdated?
      sed -i '/^anonymous_enable/ c\anonymous_enable=NO  #' /etc/vsftpd.conf
      # FTP user directories use chroot
      sed -i '/^chroot_local_user/ c\chroot_local_user=YES  #' /etc/vsftpd.conf
      service vsftpd restart
else
      dpkg --purge vsftpd > /dev/null 2>&1 
fi
"""

apache2 = """#!/bin/bash
# Apache2
echo -n "Should Apache2 Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
     apt-get install apache2 libapache2-mod-php5  > /dev/null 2>&1 
file=$( echo /etc/apache2/conf-enabled/security.conf )
#replace ServerTokens and ServerSignature
sed -i 's/ServerTokens/ServerTokens Prod  # /g' $file
sed -i 's/ServerSignature/ServerSignature Off # /g' $file
echo "<Directory />
            Options -Indexes 
        </Directory>" >> $file
#Critical File Permissions
    chown -R root:root /etc/apache2
    chown -R root:root /etc/apache

    #Secure Apache 2
    if [[ -e /etc/apache2/apache2.conf ]]; then
        echo \<Directory \> >> /etc/apache2/apache2.conf
        echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
        echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
        echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
        echo \<Directory \/\> >> /etc/apache2/apache2.conf
        echo UserDir disabled root >> /etc/apache2/apache2.conf
    fi
else
    apt-get purge apache2.*
    apt autoremove
fi
"""

php = """#!/bin/bash
Php
echo -n "Should PHP5 Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
     apt-get install python-software-properties -y > /dev/null 2>&1 
    add-apt-repository ppa:ondrej/php5-oldstable
    apt-get update -y > /dev/null 2>&1 
    apt-get install -y php5 > /dev/null 2>&1 
    file=$(echo /etc/php5/apache2/php.ini)

    #At the end of each of these lines is a ; instead of a #, this is b/c this configuration has different syntax than bash and the ; tells it to comment the rest out.

    sed -i 's/expose_php/expose_php=Off ; /g' $file
sed -i 's/allow_url_fopen/allow_url_fopen=Off ; /g' $file
sed -i 's/allow_url_include/allow_url_include=Off ; /g' $file
#disable_functions 
sed -i 's/disable_functions=/disable_functions=exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec,/g' $file
sed -i 's/upload_max_filesize/upload_max_filesize = 2M ; /g' $file
sed -i 's/max_execution_time/max_execution_time = 30 ; /g' $file
sed -i 's/max_input_time/max_input_time = 60 ; /g' $file
else
      dpkg --purge php5 > /dev/null 2>&1 
fi
"""

ssh = """#!/bin/bash
# SSH
echo -n "Should SSH Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
apt-get install ssh openssh-server openssh-client -y
#goes and replaces the /etc/ssh/sshd_config with clean one
echo "Replacing /etc/ssh/sshd_config" >> WorkProperly.txt
cp /etc/ssh/sshd_config /etc/ssh/.sshd_config
echo "# Package generated configuration file
# See the sshd_config(5) manpage for details
# What ports, IPs and protocols we listen for
Port 22
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes
# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 768
# Logging
SyslogFacility AUTH
LogLevel INFO
# Authentication:
LoginGraceTime 120
PermitRootLogin no
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile	%h/.ssh/authorized_keys
# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes
# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no
# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no
# Change to no to disable tunnelled clear text passwords
#PasswordAuthentication yes
# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no
#MaxStartups 10:30:60
#Banner /etc/issue.net
# Allow client to pass locale environment variables
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of \"PermitRootLogin without-password\".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes" > /etc/ssh/sshd_config
service ssh restart
echo "" >> WorkProperly.txt
echo "Finished with SSH"

else
    dpkg --purge ssh openssh-server openssh-client > /dev/null 2>&1 
fi
"""

netcat = """#!/bin/bash
#Determines if there are any netcat backdoors running, and will delete some of them
echo "netcat backdoors:" >> netcat_warnings.txt
netstat -ntlup | grep -e "netcat" -e "nc" -e "ncat" >> netcat_warnings.txt

#goes and grabs the PID of the first process that has the name netcat. Kills the executable, doesn’t go and kill the item in one of the crons. Will go through until it has removed all netcats.
a=0;
for i in $(netstat -ntlup | grep -e "netcat" -e "nc" -e "ncat"); do
    if [[ $(echo $i | grep -c -e "/") -ne 0  ]]; then
        badPID=$(ps -ef | pgrep $( echo $i  | cut -f2 -d'/'));
        realPath=$(ls -la /proc/$badPID/exe | cut -f2 -d'>' | cut -f2 -d' ');
        cp $realPath $a
        echo "$realPath $a" >> netcat_warnings.txt;
        a=$((a+1));
        rm $realPath;
        kill $badPID;
    fi
done
echo "" >> netcat_warnings.txt
echo "Finished looking for Netcat Backdoors"
"""

cron = """#!/bin/bash
#Remove any bad files that are in the users cron in /var/spool/cron/crontabs
for i in $(ls /var/spool/cron/crontabs); do
    cp /var/spool/cron/crontabs/$i $(pwd)/$i;
    rm /var/spool/cron/crontabs/$i;
done
echo "finished removing files in /var/spool/cron/crontabs"


#Make cron.allow and at.allow and deleting cron.deny and at.deny
/bin/rm -f /etc/cron.deny
/bin/rm -f /etc/at.deny
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
/bin/chown root:root /etc/cron.allow
/bin/chown root:root /etc/at.allow
/bin/chmod 400 /etc/at.allow
/bin/chmod 400 /etc/cron.allow
echo "Finished creating cron/at.allow and deleting cron/at.deny"
"""

remove_bad_packs = """#!/bin/bash
packageName=("john" "telnetd" "logkeys" "hydra" "fakeroot" "nmap" "crack" "medusa" "nikto" "tightvnc" "bind9" "avahi" "cupsd" "postfix" "nginx" "frostwire" "vuze" "samba" "apache2" "ftp" "vsftpd" "netcat" "openssh" "weplab" "pyrit" "mysql" "php5" "proftpd-basic" "filezilla" "postgresql" "irssi")

dpkgName=("john john-data" "openbsd-inetd telnetd" "logkeys" " hydra-gtk hydra" "fakeroot libfakeroot" "nmap zenmap" "crack crack-common" "libssh2-1 medusa" "" "xtightvncviewer" "bind9 bind9utils" "avahi-autoipd avahi-daemon avahi-utils" "cups cups-core-drivers printer-driver-hpcups cupsddk indicator-printers printer-driver-splix hplip printer-driver-gutenprint bluez-cups printer-driver-postscript-hp cups-server-common cups-browsed cups-bsd cups-client cups-common cups-daemon cups-ppdc cups-filters cups-filters-core-drivers printer-driver-pxljr printer-driver-foo2zjs foomatic-filters cups-pk-helper" "postfix" "nginx nginx-core nginx-common" "frostwire" "azureus vuze" "samba samba-common samba-common-bin" "apache2 apache2.2-bin" "ftp" "vsftpd" "netcat-traditional netcat-openbsd" "openssh-server openssh-client ssh" "weplab" "pyrit" "mysql-server php5-mysql" "php5" "proftpd-basic" "filezilla" "postgresql" "irssi")

#FIND NIKTO PACKAGE NAME
#FIND TIGHTVNC PACKAGE NAME
#HOW DO YOU REMOVE JUST THE SERVER PART OF CUPS
#Can’t install frostwire with apt-get, but can remove it with that name

#automatically attempts to remove known bad programs that would never be allowed on a computer (and brings up option for others)
#yes | dpkg --remove john	#//password cracker
#yes | dpkg --remove telnetd	#//insecure server
#yes | dpkg --remove logkeys		#//keylogger
#yes | dpkg --remove Hydra	#//password cracker
#yes | dpkg --remove hydra
#yes | dpkg --remove fakeroot
#yes | dpkg --remove nmap	#//unnecessary polling tool
#yes | dpkg --remove Crack	#//password cracker
#yes | dpkg --remove crack
#yes | dpkg --remove medusa	#//brute force password cracker
#yes | dpkg --remove nikto 	#//polling tool/possible hacking tool
#yes | dpkg --remove tightvnc		#//remote desktop

tLen=${#packageName[@]}		#syntax to find total length of array
for (( i=0; $i<$tLen; i++)); do
    if [[ $(dpkg-query --list | grep -ic ${packageName[$i]}) -ne 0 ]]; then
echo -n "Remove ${packageName[$i]} ? [Y/N]" #the -n option means don’t add new line after output
read option
if [[ $option =~ ^[Yy]$ ]]; then
            dpkg --purge ${dpkgName[$i]}  
fi
fi
done;
"""

sus_files_and_dirs = """#!/bin/bash
#Looks and sees if there are any illegal media files found on the computer in the home folder
echo "Media files:" > mediaFiles.txt
( for i in "*.jpg" "*.mp4" "*.mp6" "*.mp3" "*.mov" "*.png" "*.jpeg" "*.gif" "*.zip" "*.wav" "*.tif" "*.wmv" "*.avi" "*.mpeg" "*.tiff" "*.tar"; do find /home -name $i >> mediaFiles.txt; done; echo "" >> mediaFiles.txt ; echo "Done looking for bad media files" ) &

#Looks and sees if there are any illegal media files found on the computer as a total
echo "Media files:" > allMediaFiles.txt
( for i in "*.jpg" "*.mp4" "*.mp6" "*.mp3" "*.mov" "*.png" "*.jpeg" "*.gif" "*.wav" "*.tif" "*.tiff" "*.wmv" "*.avi" "*.mpeg"; do find / -name $i >> allMediaFiles.txt; done; echo "" >> allMediaFiles.txt ; echo "Done looking for bad media files" ) &

#Uses find, looks for type of regular file that has either permissions of suid of 2000 or 4000
echo "Suspicious SUID permission files" > suspectFind.txt
find / -type f \( -perm -04000 -o -perm -02000 \) >> suspectFind.txt 
echo "" >> suspectFind.txt
echo "Finished looking for suspicious files with SUID permissions"


#Finds files that appear to be placed down by no one. Would tell you if someone placed down something, then removed their user leaving that file around
( echo "Finding files with no Family" >> suspectFind.txt; find / \( -nouser -o -nogroup \) >> suspectFind.txt; echo "" >> suspectFind.txt; echo "Finished looking for suspicious file with no user/group" ) &

#finds directories that can be written by anyone, anywhere
( echo "finding world writable files" >> worldWrite.txt; find / -perm -2 ! -type l -ls >> worldWrite.txt; echo "Finished looking for world writable files") &
"""

scan_with_tools = """#!/bin/bash
#Runs rkhunter and saves any warnings
(echo "rkhunter says:" >> rkhunter.txt; rkhunter -c --rwo >> rkhunter.txt; echo "" >> rkhunter.txt; echo "Finished rkhunter scan" ) &
disown; sleep 2; 

#run chkrootkit and save output into Warnings
( echo "Chkrootkit found (NOTE There may be false positives):" >> chkrootkit.txt; chkrootkit -q >> chkrootkit.txt; echo "" >> chkrootkit.txt; echo "Finished chkrootkit scan" ) &
disown; sleep 2; 


#runs Debsums to check and see if there are any weirdly changed files around
( echo "Debsums says:" >> debsums.txt; debsums -a -s >> debsums.txt 2>&1; echo "" >> debsums.txt; echo "Finished debsums scan" ) &
disown; sleep 2; 


#install Clamav onto the computer and begin running it
#apt-get install clamav	gets installed earlier
( freshclam; clamscan -r --bell -i / >> Clamav.txt; echo "Finished Clamav scanning" ) &
disown; sleep 2; 

#Starts lynis, which helps in securing computer
( lynis -c -Q >> LynisOutput.txt; echo "Finished Lynis" ) &
disown; sleep 2;

#Save all of the currently running services to be looked at later
( service --status-all 2>&1 | grep "+" >> Services.txt 2>&1 ; echo “Finished Printing out services” ) &
"""

tree_home_and_set_pass_policy = """#!/bin/bash
#Looks at the entire list of users so you can see what they all have
( tree /home >> homeDirectory.txt; echo "Finished saving entire home directory" ) &

#Add password policy
sed -i 's/PASS_MAX_DAYS\t159/PASS_MAX_DAYS\t90/g' /etc/login.defs
sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t10/g' /etc/login.defs

sed -i 's/password\trequisite\t\t\tpam_cracklib.so/password\trequisite\t\t\tpam_cracklib.so ucredit=-1 lcredit=-1 ocredit=-1 dcredit=-1/g' /etc/pam.d/common-password


#echo "password requisite pam_cracklib.so retry=3 minlen=6 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1" >> /etc/pam.d/common-password
#The sed command above should add the necessary stuff

echo "#auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit silent " >> /etc/pam.d/common-auth
echo "password requisite pam_pwhistory.so use_authtok remember=24" >>  /etc/pam.d/common-password

#echo "Finished Password Policy"

#Add basic lockout policy
cp /etc/pam.d/common-auth /etc/pam.d/common-auth~
echo "auth [success=1 default=ignore] pam_unix.so nullok_secure 
auth required pam_deny.so 	#was requisite
auth required pam_permit.so
auth required pam_tally2.so onerr=fail deny=3 unlock_time=1800" > /etc/pam.d/common-auth
echo "Lockout policy enabled"
"""

hosts = """#!/bin/bash
#This clears out the HOST file so that unintentional/malicious networks are accidentally accessed.
echo "Clearing HOSTS file"
#echo $(date): Clearing HOSTS file >> Warnings.txt
cp /etc/hosts hosts
echo 127.0.0.1	localhost > /etc/hosts
echo 127.0.1.1	ubuntu  >> /etc/hosts

echo ::1     ip6-localhost ip6-loopback >> /etc/hosts
echo fe00::0 ip6-localnet >> /etc/hosts
echo ff00::0 ip6-mcastprefix >> /etc/hosts
echo ff02::1 ip6-allnodes >> /etc/hosts
echo ff02::2 ip6-allrouters >> /etc/hosts
"""

cookie = """#!/bin/bash
#enable cookie protection
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0 
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0 
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 1

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Hide kernel pointers
kernel.kptr_restrict = 2

# Enable panic on OOM
vm.panic_on_oom = 1

# Reboot kernel ten seconds after OOM
kernel.panic = 10
echo "#### ipv4 networking and equivalent ipv6 parameters ####
## TCP SYN cookie protection (default)
## helps protect against SYN flood attacks
## only kicks in when net.ipv4.tcp_max_syn_backlog is reached
net.ipv4.tcp_syncookies = 1
## protect against tcp time-wait assassination hazards
## drop RST packets for sockets in the time-wait state
## (not widely supported outside of linux, but conforms to RFC)
##CALLED TIME-WAIT ASSASSINATION PROTECTION
net.ipv4.tcp_rfc1337 = 1
## sets the kernels reverse path filtering mechanism to value 1(on)
## will do source validation of the packet's recieved from all the interfaces on the machine
## protects from attackers that are using ip spoofing methods to do harm
net.ipv4.conf.all.rp_filter = 1
net.ipv6.conf.all.rp_filter = 1
## tcp timestamps
## + protect against wrapping sequence numbers (at gigabit speeds)
## + round trip time calculation implemented in TCP
## - causes extra overhead and allows uptime detection by scanners like nmap
## enable @ gigabit speeds
net.ipv4.tcp_timestamps = 0
#net.ipv4.tcp_timestamps = 1
## log martian packets
net.ipv4.conf.all.log_martians = 1
## ignore echo broadcast requests to prevent being part of smurf attacks (default)
net.ipv4.icmp_echo_ignore_broadcasts = 1
## ignore bogus icmp errors (default)
net.ipv4.icmp_ignore_bogus_error_responses = 1
## send redirects (not a router, disable it)
net.ipv4.conf.all.send_redirects = 0
## ICMP routing redirects (only secure)
#net.ipv4.conf.all.secure_redirects = 1 (default)
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
" >> /etc/sysctl.conf
sysctl --system > /dev/null
echo "Enabled Cookie Protection"
"""

daily_updates = """#!/bin/bash
#makes updates happen daily
echo "APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"0\";
APT::Periodic::AutocleanInterval \"0\";" > /etc/apt/apt.conf.d/10periodic
echo "Checks for updates automatically"
"""

path_var = """#!/bin/bash
#Cleans out the path file in case it has been modified to point to illegal places, makes a copy to the desktop in case you wanted to see it
cp /etc/environment $(pwd)/environment
echo "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" > /etc/environment
echo "Finished cleaning the PATH"
"""

dns_cache = """#!/bin/bash
#restart all of the DNS caches to clear out any unwanted connections
/etc/init.d/dnsmasq restart > cacheClearing.txt
/etc/init.d/nscd -i hosts >> cacheClearing.txt #some others said reload or restart would do the same thing
/etc/init.d/nscd reload >> cacheClearing.txt
rndc flush >> cacheClearing.txt	#this clears the cache when bind9 is installed
echo "Clearing computer cache:" >> cacheClearing.txt
#These next few clear out the cache on the computer
free >> cacheClearing.txt
sync && echo 3 > /proc/sys/vm/drop_caches
#echoing the 3 in drop_caches tells the system to ___________________
echo "After" >> cacheClearing.txt
free >> cacheClearing.txt
echo "Finished restarting caches"
service xinetd reload
"""

lock_root = """#!/bin/bash
#Lock people from logging straight into the root account
passwd -l root
echo "Finished locking the root account"
"""

firewall = """#!/bin/bash
echo "This will attempt to turn on firewall and turn on logging" > Firewall.txt
echo "Starting Download of ufw, this may take a while"
#Turns the firewall on, resets ufw to default, the turns logging on high, and adds in some standard rules. Firestarter package might be good gui for ufw
apt-get install ufw -y >> /dev/null 2>&1
(ufw enable  >> Firewall.txt; yes | ufw reset  >> Firewall.txt; ufw enable  >> Firewall.txt; ufw allow http; ufw allow https; ufw deny 23; ufw deny 2049; ufw deny 515; ufw deny 111; ufw logging high >> Firewall.txt; echo "" >> Firewall.txt) &
#The little & at the end will cause this entire section of code to be run synchronously with the rest of this script, meaning that it will execute in the background while the rest of this script continues on. NOTE: IF YOU CLOSE THE TERMINAL, IT WILL TERMINATE THIS BACKGROUND PROCESS AS WELL.
echo "Working on ufw"
#allow http - means
#allow https - means
#deny 23 - means
#deny 2049 - means
#deny 515 - means
#deny 111 - means
"""

aliases_and_ctrlaltdel = """#!/bin/bash
#Remove unwanted alias
echo "Bad Aliases:" > AliasesAndFunctions.txt
for i in $(echo $(alias | grep -vi -e "alias egrep='egrep --color=auto'" -e "alias fgrep='fgrep --color=auto'" -e "alias grep='grep --color=auto'" -e "alias l='ls -CF'" -e "alias la='ls -A'" -e "alias ll='ls -alF'" -e "alias ls='ls --color=auto'" | cut -f 1 -d=) | cut -f 2 -d ' ') ; do 
    echo $(alias | grep -e $i)  >> AliasesAndFunctions.txt;
    unalias $i;
done
echo "Finished unaliasing"

#Save what's a function currently
echo "" >> AliasesAndFunctions.txt
echo "Functions:" >> AliasesAndFunctions.txt
declare -F >> AliasesAndFunctions.txt
echo "Saved functions"

#Clears out the control-alt-delete, as this could possibly be a problem
echo "# control-alt-delete - emergency keypress handling
#
# This task is run whenever the Control-Alt-Delete key combination is
# pressed, and performs a safe reboot of the machine.
description	\"emergency keypress handling\"
author		\"Scott James Remnant <scott@netsplit.com>\"
start on control-alt-delete
task
exec false" > /etc/init/control-alt-delete.conf
echo "Finished cleaning control-alt-delete"
"""

sudoers = """#!/bin/bash
#goes and replaces the /etc/sudoers file with a clean one
if [[ $(ls -la /etc | grep -ic sudoers) -ne 0 ]]; then
    echo "Replacing /etc/sudoers" >> WorkProperly.txt
cp /etc/sudoers /etc/.sudoers
echo "#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"
# Host alias specification
# User alias specification
# Cmnd alias specification
# User privilege specification
root	ALL=(ALL:ALL) ALL
# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL
# See sudoers(5) for more information on \"#include\" directives:
#includedir /etc/sudoers.d" > /etc/sudoers
echo "#
# As of Debian version 1.7.2p1-1, the default /etc/sudoers file created on
# installation of the package now includes the directive:
# 
# 	#includedir /etc/sudoers.d
# 
# This will cause sudo to read and parse any files in the /etc/sudoers.d 
# directory that do not end in '~' or contain a '.' character.
# 
# Note that there must be at least one file in the sudoers.d directory (this
# one will do), and all files in this directory should be mode 0440.
# 
# Note also, that because sudoers contents can vary widely, no attempt is 
# made to add this directive to existing sudoers files on upgrade.  Feel free
# to add the above directive to the end of your /etc/sudoers file to enable 
# this functionality for existing installations if you wish!
#" > /etc/sudoers.d/README

#Looks to see if there are any sudo configurations in sudoers.d. If there are, these are generally viruses and should be deleted. However, just in case they aren’t, this moves them to the folder that the script is currently running in.
for i in $(ls /etc/sudoers.d | grep -vi -e "\." -e "README" -e "total") ; do
    #Badname=$(ls /etc/sudoers.d | grep -v -e "\." -e "README" -e "total");	used to work when there also a -c, but would flip if nothing there
    cp /etc/sudoers.d/$i $(pwd)/$i		#/etc/sudoers.d/$Badname $(pwd)/$Badname;
    rm /etc/sudoers.d/$i			#/etc/sudoers.d/$Badname;
    echo $i " was a found file that shouldn't be there, copied and removed it" >> WorkProperly.txt
done
echo "" >> WorkProperly.txt

echo "Finished with sudoers, fixed main sudoers and cleaned README and tried to delete any other ones"
fi
"""
		 

bash_scripts = {'permissions':permissions, 'find_bad_packs':find_bad_packs, 'security_tools':security_tools, 'vsftpd':vsftpd, 
                'apache2':apache2, 'php':php, 'ssh':ssh, 'netcat':netcat, 'remove_bad_packs':remove_bad_packs, 'sus_files_and_dirs':sus_files_and_dirs, 
                'scan_with_tools':scan_with_tools, 'hosts':hosts, 'cron':cron, 'cookie':cookie, 'daily_updates':daily_updates,
                'path_var':path_var, 'dns_cache':dns_cache, 'lock_root':lock_root, 'firewall':firewall, 'aliases_and_ctrlaltdel':aliases_and_ctrlaltdel, 
                'sudoers':sudoers}

def make_file(filename, text):
    """writes text to a file with chosen name"""
    with open(filename, 'w') as file:
        file.write(text)

def run(filename):
    """Takes a list of commands as input and runs them"""
    a = os.popen(f'./{filename}')
    print(a)
    
def update():
    """update and upgrade system"""
    run(["apt-get update -y && apt-get upgrade -y"])

def make_all_files():
    """create bash scripts"""
    for name, script in bash_scripts.items():
        make_file(name, script)
        
def make_all_executable():
    """make all bash scripts executable from command line"""
    for name in bash_scripts.keys():
        os.popen(f'chmod +x {name}')

def run_all_modules():
    for module in bash_scripts.keys():
        run(module)


# VAR NAMES: permissions, find_bad_packs, security_tools, vsftpd, apache2,
# 			 php, ssh, netcat, remove_bad_packs, sus_files_and_dirs, scan_with_tools,
#			 tree_home_and_set_pass_policy, hosts, cron, cookie, daily_updates,
#			 path_var, dns_cache, lock_root, firewall, aliases_and_ctrlaltdel, sudoers
#	
# CALL FUNCTIONS HERE:

make_all_files()
make_all_executable()
run(cookie)
