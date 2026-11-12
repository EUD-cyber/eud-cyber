# eud-cyber

Automated CyberLab environment for technical education.

## Install

Run as root on a Proxmox host:

```bash
git clone https://github.com/EUD-cyber/eud-cyber.git
cd eud-cyber
bash install.sh
```

Choose image source, storage and WAN bridge, then Big or Mini and 1-16 labs.
Both profiles include OPNsense, GUACVM, Kali01 and VulnSrv01 and have the same
optional VMs. Only the hardware allocation differs. The menu reads VM defaults
from their scripts; editable Mini overrides remain in the root `install.sh`.
It displays basis requirements and updates the total as optional VMs are selected.

All OPNsense installers finish in the foreground. Remaining VMs install
sequentially, lab by lab, in the `deploy-all` tmux session.

```bash
tmux attach -t deploy-all
tail -f INSTALLFILES/deploy.log
```

## Repository layout

```text
install.sh              Main entry point, choices and Mini hardware overrides
README.md
INSTALLFILES/           Deployment, VM scripts, cloud-init, assets, docs and tests
.github/                GitHub workflows (must stay at the repository root)
```

Runtime logs and downloaded images are created inside `INSTALLFILES/`.
Run standalone support scripts and tests from that directory.

Legacy files have an `_archive` suffix and are not used by the current installer.
See [the archive inventory](INSTALLFILES/ARCHIVE.md) before deleting them manually.
No archived file is automatically deleted.

Existing compatibility notes: Proxmox 9.1, 9.1.1 and 9.2.

## Existing deployments

This repository move does not rewrite files inside VMs that are already installed.
Existing MrNobody updaters must use the new
`main/INSTALLFILES/TESTFILES/ATTACKER-V2` source path.

Cloud-init snippets cached on a Proxmox host can still contain the old download
URLs. Before reusing an older snippet for a new lab, refresh it from the matching
template in `INSTALLFILES/<VM>/`. Existing VMs are not modified automatically.

## After installation

Remember when the vm is created and started, the cloud-init goes to work so it can be some time before all things work, to check this use proxmox and login to the vm and type "cloud-init status" if it "running" grap a cup of coffee and wait for it to be "done"


When the GUACVM is up and running and the cloud-init is done, just https://ip_address (the ip adresse you gave it on the installation) \
Then theres a guacamole/nat connection to all vm's on either ssh, gui, vnc or rdp, for there you can start labs on the vm's (docker compose) 

passwords: 

opnsense \
user: root pass: opnsense 

guacamole \
user: guacadmin pass: guacadmin 

ubuntu \
user: ubuntu pass: Password1! 

wazuh \
user: ubuntu pass: Password1! \
webuser: admin webpass: Password1?

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
  kali02 \
    lan1  192.168.1.150/24 \
    oobm  172.20.0.100/24 \
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
    
