"""Read local MrNobody deployment settings without executing shell or transport."""

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from ipaddress import IPv4Address, ip_network
from urllib.parse import urlsplit


DEPLOYMENT_FILE = Path("/etc/mrnobody/deployment.conf")
MASTER_URL = re.compile(
    r"https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?"
    r"(:([0-9]{1,5}))?(/[A-Za-z0-9._~%/+-]*)?"
)


LAB_MASTER_URL = re.compile(MASTER_URL.pattern.replace("https://", "https?://", 1))


@dataclass(frozen=True)
class DeploymentConfig:
    role: str = "standalone"
    master_url: str = ""
    config_status: str = "default"
    lab_http: bool = False
    lab_mode: bool = False
    lab_networks: tuple = ()
    lab_control_origins: tuple = ()

    def destination_suggestions(self):
        """Editable receiver hints only; never execution or target defaults."""
        empty = {"host": "", "ipv4": "", "url": ""}
        if self.role != "agent" or self.config_status != "loaded" or not self.master_url:
            return empty
        host = urlsplit(self.master_url).hostname or ""
        try:
            ipv4 = str(IPv4Address(host))
        except ValueError:
            ipv4 = ""
        return {"host": host, "ipv4": ipv4, "url": self.master_url}

    def public_status(self):
        """Report configuration only; never imply a Master connection exists."""
        return {
            "role": self.role,
            "config_status": self.config_status,
            "master_url_configured": bool(self.master_url),
            "transport_enabled": None if self.role == "agent" and self.config_status == "loaded" and self.master_url else False,
            "lab_http_enabled": self.lab_http,
            "lab_mode_enabled": self.lab_mode,
            "master_scheme": "https" if self.master_url.startswith("https://") else "http" if self.master_url.startswith("http://") else None,
        }


def _parse(text):
    values = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or key not in {"MRNOBODY_ROLE", "MRNOBODY_MASTER_URL", "MRNOBODY_LAB_HTTP", "MRNOBODY_LAB_MODE", "MRNOBODY_LAB_NETWORKS", "MRNOBODY_LAB_CONTROL_ORIGINS"} or key in values:
            raise ValueError("Unknown, duplicate or malformed deployment setting")
        # Parse quoting only. No shell sourcing, variable expansion or commands.
        parts = shlex.split(value, comments=False, posix=True)
        if len(parts) > 1:
            raise ValueError("Deployment setting must contain one value")
        values[key] = parts[0] if parts else ""

    flag = values.get("MRNOBODY_LAB_HTTP", "0")
    if flag not in {"0", "1"}:
        raise ValueError("Lab HTTP flag must be 0 or 1")
    lab_http = flag == "1"
    role = values.get("MRNOBODY_ROLE", "standalone")
    master_url = values.get("MRNOBODY_MASTER_URL", "")
    # The lab installer rejects Master; provisioning uses the Single VM flow.
    if role not in {"standalone", "agent", "master"}:
        raise ValueError("Unsupported deployment role")
    if master_url:
        match = (LAB_MASTER_URL if lab_http else MASTER_URL).fullmatch(master_url)
        if not match or not 1 <= int(match.group(3) or "443") <= 65535:
            raise ValueError("Invalid HTTPS Master URL")
    mode = values.get('MRNOBODY_LAB_MODE', '0')
    if mode not in {'0', '1'}:
        raise ValueError('Invalid lab mode flag')
    networks = tuple(values.get('MRNOBODY_LAB_NETWORKS', '').split(',')) if values.get('MRNOBODY_LAB_NETWORKS') else ()
    private = tuple(ip_network(cidr) for cidr in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    if len(networks) > 16:
        raise ValueError('Too many lab networks')
    for value in networks:
        network = ip_network(value, strict=True)
        if network.version != 4 or not any(network.subnet_of(parent) for parent in private):
            raise ValueError('Lab networks must be explicit RFC1918 IPv4 CIDRs')
    if mode == '1' and (role not in {'master', 'agent'} or not lab_http or not networks):
        raise ValueError('Lab mode requires explicit Master/agent, lab HTTP and private networks')
    control_origins = tuple(values.get('MRNOBODY_LAB_CONTROL_ORIGINS', '').split(',')) if values.get('MRNOBODY_LAB_CONTROL_ORIGINS') else ()
    if len(control_origins) > 16:
        raise ValueError('Too many lab control origins')
    for value in control_origins:
        url = urlsplit(value)
        if (len(value) > 255 or not LAB_MASTER_URL.fullmatch(value) or url.path
                or url.port == 0):
            raise ValueError('Lab control origins must be exact HTTP(S) origins without paths')
    return DeploymentConfig(role, master_url, "loaded", lab_http, mode == '1', networks, control_origins)


def load_deployment_config(path=DEPLOYMENT_FILE):
    """Missing files preserve legacy behavior; invalid settings remain inactive.

    This is a startup snapshot. A service restart is needed after editing the
    file. Future transport must require valid settings before enabling itself.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return DeploymentConfig()
    except (OSError, UnicodeError):
        return DeploymentConfig(config_status="invalid")
    try:
        config = _parse(text)
        if config.lab_mode:
            import os
            import stat
            info = Path(path).lstat()
            if Path(path).is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8192:
                raise ValueError('Unsafe Lab Mode configuration')
            if os.name == 'posix' and (info.st_uid != 0 or info.st_mode & 0o022):
                raise ValueError('Lab Mode requires root-owned non-writable configuration')
        return config
    except (OSError, ValueError):
        return DeploymentConfig(config_status="invalid")
