window.CYBERLAB_SESSIONS = [
  {
    name: "Kali01",
    description: "Kali linux",
    address: "192.168.1.100",
    category: "Linux",
    icon: "KALI01",
    connections: [
      { type: "VNC", label: "Kali01 User01 VNC", url: "/guacamole/#/client/NgBjAHBvc3RncmVzcWw" , newTab: true, note: "VNC connection for Kali01 user01"  },
      { type: "VNC", label: "Kali01 User02 VNC", url: "/guacamole/#/client/MTMAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "VNC connection for Kali01 user02"   },
      { type: "VNC", label: "Kali01 User03 VNC", url: "/guacamole/#/client/MTQAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "VNC connection for Kali01 user03"   },
      { type: "VNC", label: "Kali01 User04 VNC", url: "/guacamole/#/client/MTUAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "VNC connection for Kali01 user04"   },
      { type: "SSH", label: "Kali01 SSH", url: "/guacamole/#/client/MgBjAHBvc3RncmVzcWw", newTab: true, note: "SSH connection for Kali01" }
    ]
  },
  {
    name: "Kali02",
    description: "Kali linux",
    address: "192.168.1.150",
    category: "Linux",
    icon: "KALI02",
    connections: [
      { type: "VNC", label: "Kali02 User01 VNC", url: "/guacamole/#/client/MjEAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "VNC connection for Kali02 user01"  },
      { type: "VNC", label: "Kali02 User02 VNC", url: "/guacamole/#/client/MjIAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "VNC connection for Kali02 user02"   },
      { type: "VNC", label: "Kali02 User03 VNC", url: "/guacamole/#/client/MjMAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "VNC connection for Kali02 user03"   },
      { type: "VNC", label: "Kali02 User04 VNC", url: "/guacamole/#/client/MjQAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "VNC connection for Kali02 user04"   },
      { type: "SSH", label: "Kali02 SSH", url: "/guacamole/#/client/MjAAYwBwb3N0Z3Jlc3Fs", newTab: true, note: "SSH connection for Kali02" }
    ]
  },

  {
    name: "Client01",
    description: "Ubuntu desktop",
    address: "192.168.1.120",
    category: "Linux",
    icon: "CLIENT01",
    connections: [
      { type: "RDP", label: "Client01 User01 RDP", url: "/guacamole/#/client/MTAAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "RDP connection for Client01 user01"  },
      { type: "RDP", label: "Client01 User02 RDP", url: "/guacamole/#/client/MTYAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "RDP connection for Client01 user02"   },
      { type: "RDP", label: "Client01 User03 RDP", url: "/guacamole/#/client/MTcAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "RDP connection for Client01 user03"   },
      { type: "RDP", label: "Client01 User04 RDP", url: "/guacamole/#/client/MTgAYwBwb3N0Z3Jlc3Fs" , newTab: true, note: "RDP connection for Client01 user04"   },
      { type: "SSH", label: "Client01 SSH", url: "/guacamole/#/client/OQBjAHBvc3RncmVzcWw", newTab: true, note: "SSH connection for Client01" }
    ]


  },
  {
    name: "Vulnsrv01",
    description: "Ubuntu server",
    address: "192.168.1.20",
    category: "Linux",
    icon: "VULNSRV01",
    connections: [
      { type: "SSH", label: "Vuln-srv01 SSH", url: "/guacamole/#/client/MTIAYwBwb3N0Z3Jlc3Fs", newTab: true }
    ]
  },
 {
    name: "Vulnsrv02",
    description: "Ubuntu server",
    address: "192.168.1.21",
    category: "Linux",
    icon: "VULNSRV02",
    connections: [
      { type: "SSH", label: "Vuln-srv02 SSH", url: "/guacamole/#/client/NQBjAHBvc3RncmVzcWw", newTab: true }
    ]
  },
{
    name: "Appsrv01",
    description: "Ubuntu server",
    address: "192.168.1.25",
    category: "Linux",
    icon: "APPSRV01",
    connections: [
      { type: "SSH", label: "App-srv01 SSH", url: "/guacamole/#/client/MQBjAHBvc3RncmVzcWw", newTab: true }
    ]
  },

  {
    name: "Wazuh",
    description: "Wazuh SIEM",
    address: "192.168.1.20",
    category: "Linux",
    icon: "WAZUH",
    connections: [
      { type: "HTTPS", label: "Wazuh GUI", port: 3001, newTab: true },
      { type: "SSH", label: "Wazuh SSH", url: "/guacamole/#/client/NABjAHBvc3RncmVzcWw", newTab: true }
    ]
  },

  {
    name: "Opnsense",
    description: "Opnsense Firewall",
    address: "192.168.1.1",
    category: "Firewall",
    icon: "OPNSENSE",
    connections: [
      { type: "HTTPS", label: "Opnsense GUI", port: 3002, newTab: true },
      { type: "SSH", label: "Opnsense SSH", url: "/guacamole/#/client/OABjAHBvc3RncmVzcWw", newTab: true }
    ]
  },


  {
    name: "Guacamole",
    description: "Guacamole session server gui",
    address: "172.20.0.1",
    category: "Linux",
    icon: "GUAC",
    connections: [
      { type: "HTTPS", label: "Guacamole GUI", url: "/guacamole", newTab: true },
    ]
  }
];
