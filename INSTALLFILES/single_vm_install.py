"""Install only the selected VM using the lab's existing shared installer."""
import json
import os
from pathlib import Path
import re
import subprocess

from installer_menu import VMS, assignment, positive_integer, disk_gib, summary
from MRNOBODY.single_vm_host import inspect_host


ROOT = Path(__file__).resolve().parent


def ask_lab(read=input, write=print):
    while True:
        value = read("Labnummer [1] (Enter = lab1, Q = tilbage): ").strip()
        if value.lower() == "q":
            return None
        try:
            lab = positive_integer(value or "1", "Labnummer")
            if lab > 16:
                raise ValueError("Labnummer skal være 1-16.")
            return lab
        except ValueError as exc:
            write(str(exc))


def single_environment(choice, profiles, environ=None):
    """Use the exact overrides captured alongside the displayed profile row."""
    if choice.get("profile") not in {"Big", "Mini"}:
        raise ValueError("Vælg Big eller Mini.")
    vm = next((vm for vm in VMS if vm[0] == choice.get("vm")), None)
    if vm is None:
        raise ValueError("Ukendt VM.")
    if (vm[0] == "MRNOBODY" and choice.get("role") not in {"master", "agent", "standalone"}) or (vm[0] != "MRNOBODY" and choice.get("role") is not None):
        raise ValueError("Ugyldigt rollevalg.")
    row = next(row for row in profiles[choice["profile"]]["rows"] if row["tag"] == vm[0])
    env = dict(os.environ if environ is None else environ)
    for _, prefix, _, _, _ in VMS:
        for kind in ("CPU", "MEM", "HDD"):
            env.pop(prefix + "_" + kind, None)
    settings = row["settings"]
    allowed = {vm[1] + "_" + kind for kind in ("CPU", "MEM", "HDD")}
    if settings.keys() - allowed:
        raise ValueError("Ugyldige hardwarevariabler for VM'en.")
    for key, value in settings.items():
        disk_gib(value, key) if key.endswith("_HDD") else positive_integer(value, key)
        env[key] = str(value)
    env["SPEC"] = choice["profile"]
    return vm, row, env


def check_lab_vm(vm, lab, env, *, root=ROOT, run=subprocess.run):
    """Require existing networks and reject a duplicate VM before any writes."""
    if type(lab) is not int or not 1 <= lab <= 16:
        raise ValueError("Labnummer skal være 1-16.")
    source = (root / vm[3]).read_text(encoding="utf-8")
    inventory = inspect_host(run=run)
    bridges = {name.replace("${LAB}", str(lab)) for name in
               re.findall(r'^\w+="(lab\$\{LAB\}_[a-z0-9]+)"', source, re.M)}
    if vm[0] in {"OPNSENSE", "GUACVM"}:
        bridges.add(env.get("BRIDGE", ""))
    if not bridges <= set(inventory["bridges"]):
        raise ValueError("Labbet mangler bridges: " + ", ".join(sorted(bridges - set(inventory["bridges"]))))
    for key, available in (("LVM", "disk_storages"), ("LOCAL", "snippet_storages")):
        if env.get(key) not in inventory[available]:
            raise ValueError("Den valgte storage er ikke tilgængelig: " + key)
    result = run(["pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"],
                 check=True, capture_output=True, text=True, timeout=10)
    guests = json.loads(result.stdout)
    if not isinstance(guests, list) or any(not isinstance(guest, dict) for guest in guests):
        raise ValueError("Ugyldigt VM-inventory.")
    name = assignment(source, "BASE_NAME").replace("${LAB}", str(lab))
    for guest in guests:
        existing = str(guest.get("name", ""))
        if existing.lower() == name.lower() or existing.lower().startswith(name.lower() + "-"):
            raise ValueError(f"{name} findes allerede (VMID {guest.get('vmid')}). Ingen ekstra VM oprettet.")


def execute_lab_vm(vm, lab, env, *, root=ROOT, run=subprocess.run):
    """Run only per-VM preparation and the selected installer, in the foreground."""
    scripts = []
    if vm[0] == "OPNSENSE":
        scripts.append("OPNSENSE/generate_config.sh")
    elif vm[0] == "GUACVM":
        scripts.append("GUACVM/GUACVM_ip.sh")
    scripts.append(vm[3])
    # Validate the complete per-VM plan before starting configuration.
    for script in scripts:
        if not (root / script).is_file():
            raise ValueError("Mangler installationsfil: " + script)
    (root / "LOGS").mkdir(exist_ok=True)
    for script in scripts:
        run(["bash", str(root / script), str(lab)], cwd=root, env=env, check=True)


def install_single_vm(choice, profiles, read=input, write=print):
    try:
        vm, row, env = single_environment(choice, profiles)
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise ValueError("Start hovedinstalleren som root på Proxmox.")
        write(f"Single VM: {vm[2]} / {choice['profile']} | {summary(row)}")
        lab = None
        if choice.get("role") != "master":
            lab = ask_lab(read=read, write=write)
            if lab is None:
                return
            check_lab_vm(vm, lab, env)
        if vm[0] == "MRNOBODY":
            from installer_menu import install_single_master
            install_single_master(choice["role"], environ=env, lab=lab)
            return
        execute_lab_vm(vm, lab, env)
        write(f"{vm[2]} / {choice['profile']} er installeret i lab{lab}.")
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        write(f"Single VM-installation stoppet: {exc}")
    except (EOFError, KeyboardInterrupt):
        write("Afbrudt.")
    try:
        read("Enter for at vende tilbage til menuen: ")
    except (EOFError, KeyboardInterrupt):
        pass
