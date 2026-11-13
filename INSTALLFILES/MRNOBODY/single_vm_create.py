"""Create one stopped MrNobody VM through the Single VM flow."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shlex
import re
import subprocess

from .single_vm_host import check_host_plan, inspect_host
from .single_vm_plan import interactive_preview, validate_plan


def normalized_plan(value):
    if not isinstance(value, dict) or value.get("kind") != "single-vm-preview" or value.get("deployment_enabled") is not False:
        raise ValueError("Oprettelse kræver en Single VM-plan.")
    # Never trust a saved host_check snapshot; inspect the host again below.
    return validate_plan({key: item for key, item in value.items()
                          if key not in {"kind", "deployment_enabled", "host_check"}})


def render_userdata(template, plan, *, source_ref=None, instance_id=None):
    if source_ref is not None:
        if source_ref != "main" and not re.fullmatch(r"[0-9a-fA-F]{40}", source_ref):
            raise ValueError("Guest-kilden skal være main eller en fuld commit-SHA.")
        original = 'BASE_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/INSTALLFILES/TESTFILES/ATTACKER-V2"'
        if template.count(original) != 1:
            raise ValueError("Cloud-init mangler en entydig GitHub-kilde.")
        template = template.replace(original, original.replace("/main/", "/" + source_ref + "/"))
    newline = "\r\n" if "\r\n" in template else "\n"
    for key, default, value in (("MRNOBODY_ROLE", "standalone", plan["role"]),
                                ("MRNOBODY_MASTER_URL", "", plan["master_url"])):
        anchor = f'      {key}="{default}"{newline}'
        if template.count(anchor) != 1:
            raise ValueError(f"Cloud-init mangler et entydigt felt: {key}.")
        template = template.replace(anchor, f"      {key}={shlex.quote(value)}{newline}")
    if plan.get("lab_http", False):
        if plan["role"] != "agent" or "MRNOBODY_LAB_HTTP=" in template:
            raise ValueError("Lab HTTP kan ikke indsættes entydigt for agenten.")
        anchor = f"      MRNOBODY_MASTER_URL={shlex.quote(plan['master_url'])}{newline}"
        if template.count(anchor) != 1:
            raise ValueError("Cloud-init mangler Master-URL til lab HTTP.")
        template = template.replace(anchor, anchor + '      MRNOBODY_LAB_HTTP="1"' + newline)
    if instance_id is not None:
        if not re.fullmatch(r"[0-9a-f]{16}", instance_id):
            raise ValueError("Ugyldigt Single VM-instance-ID.")
        identity = json.dumps(dict(vmid=plan["vmid"],role=plan["role"],instance_id=instance_id))
        entry = newline.join([
            "write_files:", "",
            "  - path: /etc/mrnobody/single-vm.json", "    owner: root:root",
            "    permissions: '0600'", "    content: |", "      " + identity, "",
        ])
        if template.count("write_files:") != 1:
            raise ValueError("Cloud-init mangler et entydigt write_files-felt.")
        template = template.replace("write_files:", entry)
        if len(re.findall(r"(?m)^  condition: true(?=\r?$)", template)) != 1 or template.count("power_state:") != 1:
            raise ValueError("Cloud-init mangler automatisk poweroff.")
    return template


def create_vm(value, image, *, run=None, inspect=None, template=None, write=print, source_ref=None):
    """Recheck resources, write a unique snippet and create a stopped VM.

    Failures after qm create is attempted preserve the VM/snippet for inspection.
    No existing VM is modified or destroyed, and this function never starts one.
    """
    plan = normalized_plan(value)
    run = subprocess.run if run is None else run
    inspect = inspect_host if inspect is None else inspect
    check_host_plan(plan, inspect())
    image = Path(image).resolve(strict=True)
    if not image.is_file() or any(char in str(image) for char in (",", "\n", "\r", "\0")):
        raise ValueError("Angiv en lokal cloud-image-fil uden komma eller kontroltegn.")
    template = Path(__file__).with_name("mrnobody_userdata.yaml").read_bytes().decode("utf-8") if template is None else template
    instance_id = secrets.token_hex(8)
    userdata = render_userdata(template, plan, source_ref=source_ref, instance_id=instance_id)

    def command(argv, timeout=10):
        return run(argv, check=True, capture_output=True, text=True, encoding="utf-8",
                   timeout=timeout, env=dict(os.environ, LC_ALL="C", LANG="C")).stdout

    info = json.loads(command(["qemu-img", "info", "--output=json", str(image)]))
    if (not isinstance(info, dict) or info.get("format") not in {"raw", "qcow2"}
            or info.get("backing-filename") or info.get("full-backing-filename")):
        raise ValueError("Brug en selvstændig raw/qcow2 cloud-image uden backing-fil.")
    filename = f"mrnobody_single_{plan['vmid']}_{instance_id}.yaml"
    volume = f"{plan['snippet_storage']}:snippets/{filename}"
    snippet = Path(command(["pvesm", "path", volume]).strip())
    if not snippet.is_absolute() or snippet.name != filename or not snippet.parent.is_dir():
        raise ValueError("Snippet-storage returnerede ikke en eksisterende snippets-mappe.")
    owned = attempted = False
    try:
        with snippet.open("x", encoding="utf-8", newline="") as handle:
            owned = True
            handle.write(userdata)
        snippet.chmod(0o600)
        # A second check narrows the gap between preview and actual VM creation.
        check_host_plan(plan, inspect())
        ipconfig = "ip=" + plan["ipv4"]
        if plan["gateway"]:
            ipconfig += ",gw=" + plan["gateway"]
        argv = [
            "qm", "create", str(plan["vmid"]), "--name", plan["name"],
            "--description", f"MRNOBODY_SINGLE_VM:{instance_id}:{plan['role']}",
            "--memory", str(plan["memory_mib"]), "--cores", str(plan["cpu"]),
            "--cpu", "host", "--ostype", "l26", "--net0", "virtio,bridge=" + plan["bridge"],
            "--scsihw", "virtio-scsi-pci",
            "--scsi0", f"{plan['disk_storage']}:0,import-from={image}",
            "--ide2", plan["disk_storage"] + ":cloudinit", "--boot", "order=scsi0",
            "--agent", "enabled=1", "--onboot", "0", "--ciupgrade", "1",
            "--ipconfig0", ipconfig, "--nameserver", plan["dns"], "--cicustom", "user=" + volume,
        ]
        write(f"Opretter VM {plan['vmid']}; cloud-init: {snippet}")
        attempted = True
        command(argv, timeout=1200)
        command(["qm", "disk", "resize", str(plan["vmid"]), "scsi0", "+" + plan["disk_expansion"]], timeout=120)
    except BaseException:
        if owned and not attempted:
            snippet.unlink()
        if attempted:
            write(f"Kontrollér VM {plan['vmid']} og {snippet}. Ingen automatisk sletning er udført.")
        raise
    return dict(vmid=plan["vmid"], role=plan["role"], instance_id=instance_id, created=True, started=False,
                snippet=str(snippet), guest_installation_completed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, help="Eksisterende lokal Ubuntu cloud-image")
    parser.add_argument("--create", action="store_true", help="Tillad VM-oprettelse efter plan og bekræftelse")
    parser.add_argument("--source-ref", help="Guest-filer fra main eller en fuld commit-SHA")
    args = parser.parse_args()
    if args.create and (not args.image or not hasattr(os, "geteuid") or os.geteuid() != 0):
        parser.error("--create kræver root på Proxmox og --image.")
    plan = interactive_preview(default_bridge=os.environ.get("BRIDGE", ""),
                               return_label="Enter for at fortsætte")
    if plan is None or not args.create:
        return 0
    try:
        if input(f"Skriv OPRET {plan['vmid']} for at oprette den slukkede VM: ").strip() != f"OPRET {plan['vmid']}":
            print("Afbrudt. Ingen VM oprettet.")
            return 0
        result = create_vm(plan, args.image, source_ref=args.source_ref)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print("VM oprettet, men ikke startet. Gæsteinstallationen er endnu ikke kørt.")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Oprettelse stoppet: {type(exc).__name__}. Kontrollér eventuel VM og snippet.")
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EOFError, KeyboardInterrupt):
        print("\nAfbrudt.")
        raise SystemExit(130)
