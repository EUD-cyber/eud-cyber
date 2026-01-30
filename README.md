# eud-cyber
This github if created for the cyber education on danish technical colleges to create a safe and automated lab environment for the students to pratice in, but its free for all to download and play with

This script is testet with proxmox 9.1 and 9.1.1

just git clone this site and run  run install.sh \
then 3 options \
1 full install \
2 mini install requires, 4 cores, 32 gb memory, 500 gb hdd \
3 install mulitple labs on single proxmox or proxmox cluster 

Remember when the vm is created and started the cloud-init goes to work so it can be some time before all things work, to check this use proxmox and login to the vm and type "cloud-init status" if it "running" grap a cop of coffee and wait for it to be "done"

<img width="798" height="468" alt="image" src="https://github.com/user-attachments/assets/775c2eaa-e9af-4ec5-8daf-6e31d3102e4e" />


passwords: 

opnsense \
user: root pass: opnsense 

guacamole \
user: guacadmin pass: guacadmin 

ubuntu \
user: ubuntu pass: Password1! 

wazuh \
user: wazuh-user pass: wazuh \
webuser: admin webpass: admin

api on guacamole that pulls status on the juiceshop docker and can start and stop them from the gui \
the api is listing on port 5000 on guacvm and the tasks.html uses that for pulling the status \


missing \
  Problem with the WIN2025 image, needs more testing, gets no ip adresse \
  kali don't install the apps after reboot, its a service needs testing \
  option 3 install multilab not done yet \
  mini installer needs to be updated with the new config, so delete and create again with the specs
 
  
Network \
  guacvm \
    vmbri0  static/dhcp \
    oobm  172.20.0.1/24 \
  opnsense \
    vmbri0  static/dhcp \
    lan1  192.168.1.1/24 \
    lan2  192.168.2.1/24 \
    oobm  172.20.0.2/24 \
  vulnsrv01 \
    lan1  192.168.1.20/24 \
    oobm  172.20.0.10/24 \
  vulnsrv02 \
    lan2 192.168.2.21/24 \
    oobm 172.20.0.21/24 \
  kali01 \
    lan1  192.168.1.100/24 \
    oobm  172.20.0.11/24  \
  client01 \
    lan1 192.168.1.120/24 \
    oobm 172.20.0.15 \
  wazuh
    lan2 192.168.2.20/24 \
    oobm 172.20.0.20 \
  appsrv01 \
    lan2 192.168.2.25/24 \
    oobm 172.20.0.25 \
  server2025 \
    lan2 192.168.2.22/24 \
    oobm 172.20.0.22/24 
    
