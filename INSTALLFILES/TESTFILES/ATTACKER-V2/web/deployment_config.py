"""Read local MrNobody deployment settings without executing shell or transport."""

from dataclasses import dataclass
from pathlib import Path
import re
import shlex


DEPLOYMENT_FILE = Path("/etc/mrnobody/deployment.conf")
MASTER_URL = re.compile(
    r"https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?"
    r"(:([0-9]{1,5}))?(/[A-Za-z0-9._~%/+-]*)?"
)


@dataclass(frozen=True)
class DeploymentConfig:
    role: str = "standalone"
    master_url: str = ""
    config_status: str = "default"

    def public_status(self):
        """Report configuration only; never imply a Master connection exists."""
        return {
            "role": self.role,
            "config_status": self.config_status,
            "master_url_configured": bool(self.master_url),
            "transport_enabled": False,
        }


def _parse(text):
    values = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or key not in {"MRNOBODY_ROLE", "MRNOBODY_MASTER_URL"} or key in values:
            raise ValueError("Unknown, duplicate or malformed deployment setting")
        # Parse quoting only. No shell sourcing, variable expansion or commands.
        parts = shlex.split(value, comments=False, posix=True)
        if len(parts) > 1:
            raise ValueError("Deployment setting must contain one value")
        values[key] = parts[0] if parts else ""

    role = values.get("MRNOBODY_ROLE", "standalone")
    master_url = values.get("MRNOBODY_MASTER_URL", "")
    # The lab installer rejects Master; provisioning uses the Single VM flow.
    if role not in {"standalone", "agent", "master"}:
        raise ValueError("Unsupported deployment role")
    if master_url:
        match = MASTER_URL.fullmatch(master_url)
        if not match or not 1 <= int(match.group(3) or "443") <= 65535:
            raise ValueError("Invalid HTTPS Master URL")
    return DeploymentConfig(role, master_url, "loaded")


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
        return _parse(text)
    except ValueError:
        return DeploymentConfig(config_status="invalid")
