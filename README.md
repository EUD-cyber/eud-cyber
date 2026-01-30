# eud-cyber
cyber eud

This script is testet with proxmox 9.1

run install.sh \
then 3 options \
1 full install \
2 mini install requires, 4 cores, 32 gb memory, 500 gb hdd \
3 install mulitple labs on single proxmox or proxmox cluster \

<img width="762" height="512" alt="image" src="https://github.com/user-attachments/assets/993d4ccf-8124-481c-bb50-134729f64d9c" />



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
  ip address validation on vm opnsense and guacvm \
  Problem with the WIN2025 image, needs more testing, gets no ip adresse
  kali don't install the apps after reboot, its a service needs testing
  option 3 install multilab not done yet
  
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
    
