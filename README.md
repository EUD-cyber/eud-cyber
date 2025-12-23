# eud-cyber
cyber eud

This script is testet with proxmox 9.1


missing \
  ip address validation on vm opnsense and guacvm \
  download cloud img to default folder and check if exits on each vm creation \
  all input first so the script will run without input after \

Network \
  guacvm \
    vmbri0  static/dhcp \
    oobm  172.20.0.1/24 \
  opnsense \
    vmbri0  static/dhcp \
    lan1  192.168.1.1/24 \
    lan2  10.0.0.1/24 (not done yet) \
    oobm  172.20.0.2/24  (not done yet) \
  vulnsrv01 \
    lan1  192.168.1. \
    oobm  172.20.0.10/24 \
  kali01 (not done yet) \
    lan1  192.168.1.100/24
    oobm  172.20.0.11/24  \
  win11 (not done yet) \
    lan1  192.168.1.101/24 (not done yet) \
    oobm 172.20.0.12/24 (not done yet) \
  server2025 (not done yet) \
    lan2 10.0.0.2/24 (not done yet) \
    oobm 172.20.0.20/24 (not done yet)
    
