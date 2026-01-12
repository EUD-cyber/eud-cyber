# eud-cyber
cyber eud

This script is testet with proxmox 9.1

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

appsrv01\
  freeradius \
   user: administrator pass: radius
  openldap \
   user: admin pass: Password1! 


missing \
  ip address validation on vm opnsense and guacvm \
  download cloud img to default folder and check if exits on each vm creation \
  all input first so the script will run without input after \
  no docker on vulnsrv01 \
  Problem with the WIN11 image, needs more testing 
  
Network \
  guacvm \
    vmbri0  static/dhcp \
    oobm  172.20.0.1/24 \
  opnsense \
    vmbri0  static/dhcp \
    lan1  192.168.1.1/24 \
    lan2  10.0.0.1/24 \
    oobm  172.20.0.2/24 \
  vulnsrv01 \
    lan1  192.168.1.20 \
    oobm  172.20.0.10/24 \
  vulnsrv02 \
    lan2 192.168.2.21/24 \
    oobm 172.20.0.21/24 \
  kali01 \
    lan1  192.168.1.100/24 \
    oobm  172.20.0.11/24  \
  wazuh
    lan2 192.168.2.20/24 \
    oobm 172.20.0.20 \
  appsrv01 \
    lan2 192.168.2.25/24 \
    oobm 172.20.0.25 \
  win11 (not done yet) \
    lan1  192.168.1.101/24 (not done yet) \
    oobm 172.20.0.12/24 (not done yet) \
  server2025 (not done yet) \
    lan2 192.168.2.22/24 \
    oobm 172.20.0.22/24 
    
