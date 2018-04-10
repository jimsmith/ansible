#!/bin/bash

#Variables
hostname=`hostname`
newhost=GENPACTTESTLAB
requester_user=req1234567
region=`curl http://169.254.169.254/latest/meta-data/placement/availability-zone/`

#Set hostname
echo hostname
sed -i "s/$hostname/$newhost/g" /etc/sysconfig/network

#Create sunteam user without password and add to root group
adduser sunteam --user-group
#passwd --d sunteam
usermod -a -G root sunteam

#Set sunteam public key
user=`whoami`
mkdir /home/sunteam/.ssh
chown -R $user:$user /home/sunteam/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDE1xDcbUvivZsVeRytYG7sYIoThnKMMD6vZrYQ0IrVtrnWqibVZtDP/3xi0dbc2jnSOzMamo5JZco4wzDXCc86gwLcL7L9Qx4LNua8PX9GmsXvYNWlGm0SHnQXpO8VUldGG90n5x5Ag1eiwYuO98YyPGbTbfKVObciiKR3a9xQDUzVq1ZkuMv9ZP6f2TTEQcQIlXNLRHsTWs2wB5L0kT3Ass7fDpBXha8xCVFRvO5NWpWquU6Yd+kkiW3XnV2h13BCYT+pxgk88efh7eQhrSSWiua3Lvqc1YrdUPR1EI5kxD7y7iPd8IeXe3LPSNh90P8IPOpnAlr95Gpt9x+l69j7 sunteam@ip-182-95-61-18.usa.corp.ad" >> /home/sunteam/.ssh/id_rsa.pub
chmod 700 /home/sunteam/.ssh
chown -R sunteam:sunteam /home/sunteam/.ssh

#Create requester_user without password
adduser $requester_user
#passwd --d $requester_user

#Generate ssh key for requester user
sudo -u $requester_user ssh-keygen -t rsa -b 2048 -f /home/$requester_user/.ssh/id_rsa -P ""

#Install required packages
yum -y install  curl net-snmp audit

# This script detects platform and architecture, then downloads and installs the matching Deep Security Agent package
if type curl >/dev/null 2>&1; then
  SOURCEURL='https://dsm.genpact.com:443'
  curl $SOURCEURL/software/deploymentscript/platform/linux/ -o /tmp/DownloadInstallAgentPackage --insecure --silent --tlsv1.2

  if [ -s /tmp/DownloadInstallAgentPackage ]; then
    if echo '31A52951335226FCD8BF73F58EBED5860E8298A3B396DC0D747052791ECEDBE1  /tmp/DownloadInstallAgentPackage' | sha256sum -c; then
      . /tmp/DownloadInstallAgentPackage
      Download_Install_Agent
    else
      echo "Failed to validate the agent installation script."
      logger -t Failed to validate the agent installation script
      false
    fi
  else
     echo "Failed to download the agent installation script."
     logger -t Failed to download the Deep Security Agent installation script
     false
  fi
else
  echo Please install CURL before running this script
  logger -t Please install CURL before running this script
  false
fi
sleep 15
/opt/ds_agent/dsa_control -r

#Activate policy depending on the region
if [[ $region == us* ]] ;
then
        /opt/ds_agent/dsa_control -a dsm://hb.genpact.com:443/ "policyid:23"
elif [[ $region == ap* ]];
then
        /opt/ds_agent/dsa_control -a dsm://hb.genpact.com:443/ "policyid:32"
elif [[ $region == eu* ]];
then
        /opt/ds_agent/dsa_control -a dsm://hb.genpact.com:443/ "policyid:41"
fi

#Session timeout 

echo "TMOUT=900" >> /etc/bashrc
echo "TMOUT=900" >> /etc/profile

sed -i '/ClientAliveInterval/d' /etc/ssh/sshd_config 
sed -i '/#ClientAliveCountMax/d' /etc/ssh/sshd_config
sed -i '/#PermitRootLogin/d' /etc/ssh/sshd_config

echo "ClientAliveInterval 900" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config

#pkg installtion 

yum -y install ntsysv

#password policy

sed -i '/ChallengeResponseAuthentication/d' /etc/ssh/sshd_config 
echo "ChallengeResponseAuthentication yes" >> /etc/ssh/sshd_config

sed -i '/PasswordAuthentication/d' /etc/ssh/sshd_config 
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

echo "auth         required      pam_tally2.so deny=3" >> /etc/pam.d/common-auth

systemctl reload sshd
systemctl stop firewalld
systemctl enable sshd.service
#chkconfig sshd on
systemctl enable ufw.service

 echo "|-----------------------------------------------------------------|
|                       GENPACT                                   |
| This system is for the use of authorized users only.           |
| Individuals using this computer system without authority, or in |
| excess of their authority, are subject to having all of their   |
| activities on this system monitored and recorded by system      |
| personnel.                                                      |
|                                                                 |
| In the course of monitoring individuals improperly using this   |
| system, or in the course of system maintenance, the activities  |
| of authorized users may also be monitored.                      |
|                                                                 |
| Anyone using this system expressly consents to such monitoring  |
| and is advised that if such monitoring reveals possible         |
| evidence of criminal activity, system personnel may provide the |
| evidence of such monitoring to law enforcement officials.       |
|-----------------------------------------------------------------|
" > /etc/motd

 echo "|-----------------------------------------------------------------|
|                       GENPACT                                   |
| This system is for the use of authorized users only.           |
| Individuals using this computer system without authority, or in |
| excess of their authority, are subject to having all of their   |
| activities on this system monitored and recorded by system      |
| personnel.                                                      |
|                                                                 |
| In the course of monitoring individuals improperly using this   |
| system, or in the course of system maintenance, the activities  |
| of authorized users may also be monitored.                      |
|                                                                 |
| Anyone using this system expressly consents to such monitoring  |
| and is advised that if such monitoring reveals possible         |
| evidence of criminal activity, system personnel may provide the |
| evidence of such monitoring to law enforcement officials.       |
|-----------------------------------------------------------------|
" > /etc/issue

##### User Password Policy #####

sed -i '/PASS_MAX_DAYS/d' /etc/login.defs
sed -i '/PASS_MIN_DAYS/d' /etc/login.defs

echo "PASS_MAX_DAYS  90
PASS_MIN_DAYS     0
LOGIN_RETRIES     3
LOGIN_TIMEOUT     60 " >> /etc/login.defs

yum -y install libpwquality

sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
sed -i '14 a password    requisite     pam_pwquality.so try_first_pass retry=3 type= minlen=8 lcredit=1 ucredit=1 dcredit=1 ocredit=0' /etc/pam.d/common-password

sed -i '/use_authtok/d' /etc/pam.d/common-password
sed -i '14 a password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512 remember=5' /etc/pam.d/common-password

chown root:root /etc/passwd
chown root:root /etc/shadow
chmod 644 /etc/passwd
chmod 400 /etc/shadow

mkdir /home/backup/
cp -rp /etc/passwd /home/backup/passwd.old
cp -rp /etc/shadow /home/backup/shadow.old

for user in lp news uucp games ; do /usr/sbin/userdel -r $user; done
for group in lp news uucp games ; do /usr/sbin/groupdel  $group; done

awk -F: '($3 == 0) { print $1 }' /etc/passwd

#### NTP Service ####

sed -i '/server/d' /etc/ntp.conf
echo "server  58.2.47.148" >> /etc/ntp.conf

#service ntpd start
#chkconfig ntpd on 
#sysv-rc-conf ntp on
#ntpq -pn > /var/tmp/ntp.log

iptables -F
ip6tables -F

#ufw stop
ufw disable


systemctl list-unit-files -t service | egrep -i 'telnet|rsync|finger|rsh|login' > /var/tmp/chk_log

sed -i '/^tty/d' /etc/securetty

echo tty1 >> /etc/securetty

chmod 700 /etc/snmp/snmpd.conf

chmod 644 /usr/share/man

chmod 644 /usr/share/info

find / -name "*sh" -print -exec ls -lL {} \; | grep -i rws > /var/tmp/sh_log

find / -perm 4000 |more > /var/tmp/4000_log

find / -perm 2000 |more > /var/tmp/2000_log

chmod -R 700 /etc/cron.daily/

chmod -R 700 /etc/cron.monthly/

echo "-a exit,always -S unlink -S rmdir" >> /etc/audit/audit.rules

service auditd restart 

auditctl -l > /var/tmp/audit_logs

echo "sshd : ALL" >> /etc/hosts.allow

echo "ALL: ALL" >> /etc/hosts.deny

touch /etc/cron.allow


##### Syslog Service #####

echo "*.*     @182.95.255.105" >> /etc/rsyslog.conf

service rsyslog restart


echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
modprobe -r usb-storage

#Os upgradation 

yum -y update

yum -y upgrade


#TREND Micro#

yum -y install wget



