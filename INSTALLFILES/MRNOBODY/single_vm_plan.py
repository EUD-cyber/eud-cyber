#!/usr/bin/env python3
"""Plan one MrNobody VM with optional read-only host checks. No deployment."""
import ipaddress
import json
import os
from pathlib import Path
import re

from .single_vm_host import BRIDGE, STORAGE, check_host_plan, inspect_host


NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
MASTER_URL = re.compile(
    r"https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?"
    r"(:([0-9]{1,5}))?(/[A-Za-z0-9._~%/+-]*)?"
)


def validate_plan(value):
    """Validate explicit Single VM input; never reserve or create anything."""
    required = {"role", "vmid", "name", "bridge", "ipv4", "gateway", "dns",
                "cpu", "memory_mib", "disk_expansion", "disk_storage", "snippet_storage"}
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - {"master_url"}:
        raise ValueError("Planen mangler felter eller indeholder ukendte felter.")
    if not all(isinstance(value[key], str) for key in required - {"vmid", "cpu", "memory_mib"}):
        raise ValueError("Rolle, navn og netværksfelter skal være tekst.")
    role = value["role"]
    if role not in {"standalone", "agent", "master"}:
        raise ValueError("Single VM-rollen skal være standalone, agent eller master.")
    # Proxmox pve-vmid schema: github.com/proxmox/pve-common/blob/master/src/PVE/JSONSchema.pm
    if type(value["vmid"]) is not int or not 100 <= value["vmid"] <= 999_999_999:
        raise ValueError("VMID skal være et heltal mellem 100 og 999999999.")
    if not NAME.fullmatch(value["name"]):
        raise ValueError("VM-navnet skal være 1-63 bogstaver/tal/bindestreg uden bindestreg i enderne.")
    if not BRIDGE.fullmatch(value["bridge"]):
        raise ValueError("Bridge skal være 1-15 bogstaver/tal/punktum/underscore/bindestreg.")
    try:
        if "/" not in value["ipv4"]:
            raise ValueError("IPv4 kræver en eksplicit netmaske, fx /24.")
        address = ipaddress.IPv4Interface(value["ipv4"])
        gateway = ipaddress.IPv4Address(value["gateway"]) if value["gateway"] else None
        dns = ipaddress.IPv4Address(value["dns"])
    except ValueError as exc:
        raise ValueError("Angiv gyldig IPv4/CIDR, valgfri IPv4-gateway og IPv4-DNS.") from exc
    if address.ip.is_unspecified or address.ip.is_multicast or address.ip.is_loopback or address.ip == ipaddress.IPv4Address("255.255.255.255"):
        raise ValueError("VM-adressen skal være en unicast-adresse på VM-netværket.")
    if address.network.prefixlen < 31 and address.ip in (address.network.network_address, address.network.broadcast_address):
        raise ValueError("VM-adressen må ikke være netværks- eller broadcastadressen.")
    if dns.is_unspecified or dns.is_multicast or dns == ipaddress.IPv4Address("255.255.255.255"):
        raise ValueError("DNS skal være en unicast-adresse.")
    if gateway is not None:
        if gateway not in address.network or gateway == address.ip:
            raise ValueError("Gateway skal være en anden adresse på samme subnet.")
        if gateway.is_unspecified or gateway.is_multicast or gateway.is_loopback or (address.network.prefixlen < 31 and gateway in (address.network.network_address, address.network.broadcast_address)):
            raise ValueError("Gateway skal være en gyldig hostadresse.")
    if any(type(value[key]) is not int or value[key] < 1 for key in ("cpu", "memory_mib")):
        raise ValueError("CPU og RAM (MiB) skal være positive heltal.")
    if not re.fullmatch(r"[1-9][0-9]*[GMT]", value["disk_expansion"]):
        raise ValueError("Diskudvidelse skal være fx 32G og lægges til image-disken.")
    if any(not STORAGE.fullmatch(value[key]) for key in ("disk_storage", "snippet_storage")):
        raise ValueError("Angiv gyldige storage-ID'er til disk og snippets.")
    master_url = value.get("master_url", "")
    if not isinstance(master_url, str):
        raise ValueError("Master-URL skal være tekst.")
    if master_url:
        match = MASTER_URL.fullmatch(master_url)
        if role != "agent" or not match or not 1 <= int(match.group(3) or "443") <= 65535:
            raise ValueError("Kun agent kan have en Master-URL; brug HTTPS uden login, query eller fragment.")
    return dict(kind="single-vm-preview", deployment_enabled=False, role=role,
                vmid=value["vmid"], name=value["name"], bridge=value["bridge"],
                ipv4=str(address), gateway=str(gateway) if gateway else "", dns=str(dns),
                master_url=master_url, cpu=value["cpu"], memory_mib=value["memory_mib"],
                disk_expansion=value["disk_expansion"], disk_storage=value["disk_storage"],
                snippet_storage=value["snippet_storage"])


def hardware_defaults(environ=None, source=None):
    """Read the active shared installer's defaults, never source its shell."""
    environ = os.environ if environ is None else environ
    source = Path(__file__).with_name("mrnobody_installer.sh").read_text(encoding="utf-8") if source is None else source
    result = {}
    for key, field, setting in (
        ("cpu", "CORES", "MRNOBODY_CPU"),
        ("memory_mib", "MEMORY", "MRNOBODY_MEM"),
        ("disk_expansion", "DISK_SIZE", "MRNOBODY_HDD"),
    ):
        match = re.search(r'^' + field + r'="\$\{' + setting + r':-([^}]+)\}"', source, re.M)
        if not match:
            raise ValueError(f"Kan ikke læse hardware-standard: {field}.")
        value = environ.get(setting) or match[1]
        result[key] = value if key == "disk_expansion" else int(value)
    return result


def interactive_preview(default_bridge="", read=input, write=print, *, offline=False):
    """Show a plan, optionally check the host, then return without deployment."""
    write("Single VM / MrNobody - kun forhåndsvisning")
    write("Ingen VM oprettes, og intet reserveres. Master-installation er endnu ikke aktiveret.")
    write("Q i et felt vender tilbage.")

    def ask(label, default=""):
        answer = read(label + (f" [{default}]" if default != "" else "") + ": ").strip()
        if answer.lower() == "q":
            raise EOFError
        return answer or str(default)

    try:
        try:
            defaults = hardware_defaults()
            inventory = None if offline else inspect_host()
        except (ValueError, OSError) as exc:
            write(f"Forhåndsvisning stoppet: {exc}")
            ask("Enter for at vende tilbage")
            return None
        if inventory is None:
            write("OFFLINE: Kun input valideres; værten kontrolleres ikke.")
            disk_default, snippet_default = os.environ.get("LVM", ""), os.environ.get("LOCAL", "")
        else:
            for label, key in (("Bridges", "bridges"), ("Disk-storage (images)", "disk_storages"),
                               ("Snippet-storage", "snippet_storages")):
                write(label + ": " + ", ".join(inventory[key]))
            default_bridge = default_bridge if default_bridge in inventory["bridges"] else ""
            def preferred(setting, key):
                choices = inventory[key]
                value = os.environ.get(setting, "")
                return value if value in choices else choices[0] if len(choices) == 1 else ""
            disk_default, snippet_default = preferred("LVM", "disk_storages"), preferred("LOCAL", "snippet_storages")
        while True:
            try:
                role = ask("Rolle: standalone/agent/master", "master")
                raw = dict(
                    role=role, vmid=int(ask("VMID (reserveres ikke)")),
                    name=ask("VM-navn", f"mrnobody-{role}" if role in {"standalone", "agent", "master"} else ""),
                    bridge=ask("Bridge", default_bridge), ipv4=ask("IPv4/CIDR"),
                    gateway=ask("Gateway (tom er tilladt)"), dns=ask("DNS (IPv4)"),
                    cpu=int(ask("vCPU", defaults["cpu"])),
                    memory_mib=int(ask("RAM (MiB)", defaults["memory_mib"])),
                    disk_expansion=ask("Diskudvidelse (+SIZE, fx 32G)", defaults["disk_expansion"]),
                    disk_storage=ask("Disk-storage", disk_default),
                    snippet_storage=ask("Snippet-storage", snippet_default),
                    master_url=ask("Master-URL (valgfri HTTPS)") if role == "agent" else "",
                )
                plan = validate_plan(raw)
                plan["host_check"] = dict(status="not_checked", reserved=False) if inventory is None else check_host_plan(plan, inventory)
                break
            except ValueError as exc:
                write(f"Ugyldig plan: {exc}")
                write("Prøv igen, eller Q for at vende tilbage.")
        write(json.dumps(plan, ensure_ascii=False, indent=2))
        write("Værtskontrol er et øjebliksbillede. Kapacitet og netværksadgang er ikke afprøvet.")
        write("Ingen indstillinger er gemt eller sendt til deploy.sh.")
        ask("Enter for at vende tilbage til menuen")
        return plan
    except (EOFError, KeyboardInterrupt):
        write("\nForhåndsvisning afsluttet uden deployment.")
        return None
