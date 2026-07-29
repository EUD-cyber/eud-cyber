window.CYBERLAB_SESSIONS = [
  {
    name: "FortiManager",
    description: "Central Fortinet management",
    address: "192.168.10.2",
    category: "Fortinet",
    icon: "FMG",
    connections: [
      { type: "HTTPS", label: "Åbn FMG Web GUI", url: "https://10.134.71.15:3001", newTab: true },
      { type: "SSH", label: "Åbn FMG SSH", url: "/guacamole/", newTab: true, note: "Indsæt senere den direkte Guacamole connection-URL." }
    ]
  },
  {
    name: "FortiAnalyzer",
    description: "Logging and analytics",
    address: "192.168.10.3",
    category: "Fortinet",
    icon: "FAZ",
    connections: [
      { type: "HTTPS", label: "Åbn FAZ Web GUI", url: "https://10.134.71.15:3002", newTab: true },
      { type: "SSH", label: "Åbn FAZ SSH", url: "/guacamole/", newTab: true }
    ]
  },
  {
    name: "FortiGate",
    description: "Next-generation firewall",
    address: "192.168.10.4",
    category: "Fortinet",
    icon: "FG",
    connections: [
      { type: "HTTPS", label: "Åbn FortiGate Web GUI", url: "https://10.134.71.15:3003", newTab: true },
      { type: "SSH", label: "Åbn FortiGate SSH", url: "/guacamole/", newTab: true }
    ]
  },
  {
    name: "Windows Server",
    description: "Active Directory and services",
    address: "192.168.20.10",
    category: "Windows",
    icon: "WIN",
    connections: [
      { type: "RDP", label: "Åbn RDP", url: "/guacamole/", newTab: true }
    ]
  },
  {
    name: "Kali Linux",
    description: "Security testing workstation",
    address: "192.168.30.10",
    category: "Linux",
    icon: "KALI",
    connections: [
      { type: "SSH", label: "Åbn SSH", url: "/guacamole/", newTab: true },
      { type: "VNC", label: "Åbn Desktop", url: "/guacamole/", newTab: true }
    ]
  },
  {
    name: "Proxmox",
    description: "Virtualization platform",
    address: "192.168.40.10",
    category: "Infrastructure",
    icon: "PVE",
    connections: [
      { type: "HTTPS", label: "Åbn Proxmox", url: "https://10.134.71.15:3004", newTab: true },
      { type: "SSH", label: "Åbn Proxmox SSH", url: "/guacamole/", newTab: true }
    ]
  }
];
