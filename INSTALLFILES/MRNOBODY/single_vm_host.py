"""Read-only Proxmox inventory for Single VM previews; never reserve resources."""
from datetime import datetime, timezone
import json
import os
import re
import shutil
import subprocess


BRIDGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")
STORAGE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*[A-Za-z0-9]")


def _storages(text):
    lines = [line.split() for line in text.splitlines() if line.strip()]
    # pvesm's fixed status columns: Name, Type, Status, then capacity figures.
    if not lines or lines[0][:3] != ["Name", "Type", "Status"]:
        raise ValueError("Ukendt storage-output fra pvesm.")
    names = set()
    for fields in lines[1:]:
        if len(fields) < 3 or not STORAGE.fullmatch(fields[0]) or fields[2] not in {"active", "inactive", "disabled"}:
            raise ValueError("Ugyldigt storage-output fra pvesm.")
        if fields[2] == "active":
            names.add(fields[0])
    return sorted(names)


def inspect_host(run=None, which=None):
    """Take a snapshot using fixed read commands, without shell interpolation."""
    run = subprocess.run if run is None else run
    which = shutil.which if which is None else which

    def read(argv):
        try:
            result = run(argv, check=True, capture_output=True, text=True, encoding="utf-8",
                         timeout=10, env=dict(os.environ, LC_ALL="C", LANG="C"))
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(f"Kan ikke læse værtsdata med {argv[0]}.") from exc
        if not isinstance(result.stdout, str):
            raise ValueError("Værtsdata er ikke tekst.")
        return result.stdout

    try:
        guests = json.loads(read(["pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"]))
        links = json.loads(read(["ip", "-j", "link", "show", "type", "bridge"]))
    except json.JSONDecodeError as exc:
        raise ValueError("Værten returnerede ugyldig JSON.") from exc
    if not isinstance(guests, list) or any(
        not isinstance(vm, dict) or type(vm.get("vmid")) is not int
        or not 100 <= vm["vmid"] <= 999_999_999 for vm in guests
    ):
        raise ValueError("Ugyldigt cluster-inventory; VMID kan ikke kontrolleres.")
    if not isinstance(links, list) or any(
        not isinstance(link, dict) or not isinstance(link.get("ifname"), str)
        or not BRIDGE.fullmatch(link["ifname"]) for link in links
    ):
        raise ValueError("Ugyldigt bridge-inventory.")
    bridges = {link["ifname"] for link in links}
    if which("ovs-vsctl"):
        ovs = read(["ovs-vsctl", "--timeout=5", "list-br"]).splitlines()
        if any(not BRIDGE.fullmatch(name) for name in ovs):
            raise ValueError("Ugyldigt Open vSwitch bridge-inventory.")
        bridges.update(ovs)
    disks = _storages(read(["pvesm", "status", "--content", "images"]))
    snippets = _storages(read(["pvesm", "status", "--content", "snippets"]))
    if not bridges or not disks or not snippets:
        raise ValueError("Værten skal have bridge samt aktiv images- og snippets-storage.")
    return dict(vmids=sorted({vm["vmid"] for vm in guests}), bridges=sorted(bridges),
                disk_storages=disks, snippet_storages=snippets,
                checked_at_utc=datetime.now(timezone.utc).isoformat())


def check_host_plan(plan, inventory):
    """Check a validated plan against a snapshot. This does not reserve a VMID."""
    if "lab" in plan:
        from .single_vm_plan import lab_network_defaults
        network = lab_network_defaults(plan["lab"])
        if any(network[key] not in inventory["bridges"] for key in ("bridge", "bridge1", "bridge2")):
            raise ValueError("Labbet skal have eksisterende LAN1-, LAN2- og OOBM-bridges.")
    if plan["vmid"] in inventory["vmids"]:
        raise ValueError("VMID findes allerede i clusteret; vælg et andet.")
    for field, available, label in (
        ("bridge", "bridges", "Bridge"),
        ("disk_storage", "disk_storages", "Disk-storage"),
        ("snippet_storage", "snippet_storages", "Snippet-storage"),
    ):
        if plan[field] not in inventory[available]:
            raise ValueError(f"{label} er ikke tilgængelig på denne vært.")
    return dict(status="checked", checked_at_utc=inventory["checked_at_utc"],
                vmid_free=True, bridge_exists=True, disk_storage_active=True,
                snippet_storage_active=True, reserved=False,
                capacity_checked=False, network_reachability_checked=False)
