#!/usr/bin/env python3
"""CyberLab profiles and individual lab VMs with shared hardware settings."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import subprocess

# Tag, resource variable prefix, display name, shared installer, always included.
VMS = [
    ("OPNSENSE", "OPNSENSE", "OPNsense", "OPNSENSE/OPNSENSE_installer.sh", True),
    ("GUACVM", "GUACVM", "GUACVM", "GUACVM/GUACVM_installer.sh", True),
    ("KALI01", "KALI01", "Kali01", "KALI01/KALI01_installer.sh", True),
    ("VULNSRV01", "VULNSRV01", "VulnSrv01", "VULNSRV01/VULNSRV01_installer.sh", True),
    ("VULNSRV02", "VULNSRV02", "VulnSrv02", "VULNSRV02/VULNSRV02_installer.sh", False),
    ("KALI02", "KALI02", "Kali02", "KALI02/KALI02_installer.sh", False),
    ("APPSRV01", "APPSRV01", "AppSrv01", "APPSRV01/APPSRV01_installer.sh", False),
    ("CLIENT01", "CLIENT01", "Client01", "CLIENT01/CLIENT01_installer.sh", False),
    ("WAZUH", "WAZUH", "Wazuh", "WAZUH/WAZUH_installer.sh", False),
    ("TPOT", "TPOT01", "T-Pot", "TPOT01/TPOT01_installer.sh", False),
    ("MRNOBODY", "MRNOBODY", "MrNobody", "MRNOBODY/mrnobody_installer.sh", False),
]
OPTIONS = [vm[0] for vm in VMS if not vm[4]]


def positive_integer(value, label):
    if not re.fullmatch(r"[1-9][0-9]*", str(value)):
        raise ValueError(f"{label} skal være et positivt heltal.")
    return int(value)


def disk_gib(value, label):
    match = re.fullmatch(r"([1-9][0-9]*)([GMT])", str(value))
    if not match:
        raise ValueError(f"{label} skal være en størrelse som 32G.")
    return int(match[1]) * {"M": 1 / 1024, "G": 1, "T": 1024}[match[2]]


def assignment(source, variable):
    match = re.search(r"^" + re.escape(variable) + r"=(.*)$", source, re.M)
    if not match:
        raise ValueError(f"Mangler hardwarefeltet {variable} i VM-scriptet.")
    return match[1].split("#", 1)[0].strip().strip('"\'')


def hardware(root, profile, environ=None):
    environ = os.environ if environ is None else environ
    rows = []
    for tag, prefix, name, relative, base in VMS:
        source = (root / relative).read_text(encoding="utf-8")
        values = {}
        for kind, field in [("CPU", "CORES"), ("MEM", "RAM" if prefix == "OPNSENSE" else "MEMORY"), ("HDD", "DISK_SIZE")]:
            expression = assignment(source, field)
            match = re.fullmatch(r"\$\{" + prefix + "_" + kind + r":-([^}]+)\}", expression)
            # Only parse known declarations; never source a script or eval shell.
            if not match:
                raise ValueError(f"Kan ikke læse {relative}: {field}. Forventede en hardware-standard.")
            values[kind] = environ.get(prefix + "_" + kind) or match[1]
        cores = positive_integer(values["CPU"], prefix + "_CPU")
        memory = positive_integer(values["MEM"], prefix + "_MEM")
        sockets = 1
        if re.search(r"^SOCKETS=", source, re.M):
            sockets = positive_integer(assignment(source, "SOCKETS"), prefix + " sockets")
            if environ.get(prefix + "_CPU"):
                rule = 'if [[ -n "${' + prefix + '_CPU:-}" ]]; then SOCKETS=1; fi'
                if rule not in source:
                    raise ValueError(f"Ukendt CPU/socket-regel i {relative}.")
                sockets = 1
        rows.append(dict(tag=tag, name=name, base=base, cpu=cores * sockets,
                         memory_mib=memory, disk_gib=disk_gib(values["HDD"], prefix + "_HDD"),
                         settings={prefix + "_" + kind: values[kind] for kind in ("CPU", "MEM", "HDD")
                                   if environ.get(prefix + "_" + kind)}))
    return dict(profile=profile, rows=rows)


def totals(rows, selected=(), labs=1, base_only=False):
    included = [r for r in rows if r["base"] or (not base_only and r["tag"] in selected)]
    return dict(cpu=sum(r["cpu"] for r in included) * labs,
                memory_mib=sum(r["memory_mib"] for r in included) * labs,
                disk_gib=sum(r["disk_gib"] for r in included) * labs,
                vms=len(included) * labs)


def fmt(value):
    return f"{value:g}"


def summary(value):
    return f'{value["cpu"]} vCPU | {fmt(value["memory_mib"] / 1024)} GiB RAM | +{fmt(value["disk_gib"])} GiB disk'


def validate_selection(value):
    if not isinstance(value, dict) or value.get("profile") not in ("Big", "Mini"):
        raise ValueError("Ugyldig profil fra menuen.")
    labs = value.get("labs")
    if type(labs) is not int or not 1 <= labs <= 16:
        raise ValueError("Antal labs skal være 1-16.")
    selected = value.get("components")
    if not isinstance(selected, list) or any(not isinstance(c, str) or c not in OPTIONS for c in selected):
        raise ValueError("Ugyldigt VM-tilvalg fra menuen.")
    return dict(profile=value["profile"], labs=labs,
                components=[tag for tag in OPTIONS if tag in selected])


class Menu:
    def __init__(self, profiles):
        self.profiles = profiles
        self.profile = "Big"
        self.labs = 1
        self.selected = set()
        self.stage = "profile"
        self.cursor = 0
        self.single_cursor = 0
        self.vm_cursor = 0
        self.single_profile = "Big"

    def single_choice(self, role=None):
        return dict(kind="single-install", vm=VMS[self.vm_cursor][0],
                    profile=self.single_profile, role=role)

    def text(self, screen, y, text, highlighted=False):
        import curses
        height, width = screen.getmaxyx()
        if 0 <= y < height - 1:
            screen.addnstr(y, 2, text, max(0, width - 4), curses.A_REVERSE if highlighted else curses.A_NORMAL)

    def draw(self, screen):
        screen.erase()
        height, width = screen.getmaxyx()
        if height < 24 or width < 76:
            self.text(screen, 0, "Terminalen skal være mindst 76 kolonner og 24 linjer.")
            self.text(screen, 2, "Udvid vinduet, eller tryk Q for at annullere.")
            screen.refresh()
            return False
        rows = self.profiles[self.profile if self.profile != "Single VM" else "Big"]["rows"]
        self.text(screen, 0, "CyberLab - " + ("Størrelse og minimumskrav" if self.stage == "profile" else "Tilvalg"))
        self.text(screen, 1, "=" * min(width - 4, 84))
        if self.stage == "profile":
            for index, profile in enumerate(("Big", "Mini", "Single VM")):
                if profile == "Single VM":
                    self.text(screen, 3 + index, "(*) Single VM" if self.profile == profile else "( ) Single VM", self.profile == profile)
                    continue
                minimum = totals(self.profiles[profile]["rows"], base_only=True)
                self.text(screen, 3 + index, f'{"(*)" if profile == self.profile else "( )"} {profile:4} Min./lab: {summary(minimum)}', profile == self.profile)
            self.text(screen, 6, f"Antal labs: {self.labs}  (+/- ændrer, 1-16)")
            self.text(screen, 8, "Basis - altid med (pr. lab)")
            self.text(screen, 9, f'{"VM":18} {"vCPU":>6} {"RAM GiB":>10} {"Disk +GiB":>11}')
            for index, row in enumerate(r for r in rows if r["base"]):
                self.text(screen, 10 + index, f'{row["name"]:18} {row["cpu"]:6} {fmt(row["memory_mib"] / 1024):>10} {fmt(row["disk_gib"]):>11}')
            self.text(screen, 16, f'Minimum, {self.labs} lab(s): {summary(totals(rows, labs=self.labs, base_only=True))}')
            self.text(screen, 18, "MrNobody i Big/Mini: agent/slave (også i fremtidig Custom).")
            self.text(screen, 19, "S: Single VM - vælg VM, Big/Mini og labnummer [1].")
            self.text(screen, 21, "Op/ned: Big/Mini/Single VM | Enter: vælg | Q/Esc: annullér")
        elif self.stage == "single":
            self.text(screen, 3, "Single VM")
            for index, vm in enumerate(VMS):
                self.text(screen, 5 + index, vm[2], index == self.vm_cursor)
            self.text(screen, 18, "Tilføj én VM til et eksisterende lab. Labnummer [1].")
            self.text(screen, 21, "Op/ned: vælg VM | Enter: Big/Mini | B: tilbage | Q: stop")
        elif self.stage == "single-size":
            vm = VMS[self.vm_cursor]
            self.text(screen, 3, "Single VM - " + vm[2])
            for index, profile in enumerate(("Big", "Mini")):
                row = next(row for row in self.profiles[profile]["rows"] if row["tag"] == vm[0])
                self.text(screen, 5 + index, profile + ": " + summary(row), profile == self.single_profile)
            self.text(screen, 9, "Samme CPU, RAM og diskvariabler som Big/Mini-labbet.")
            self.text(screen, 10, "Disk er udvidelse af image-disken (+GiB).")
            self.text(screen, 12, "Næste: " + ("Master / Slave / Standalone" if vm[0] == "MRNOBODY" else "labnummer [1]"))
            self.text(screen, 21, "Op/ned: Big/Mini | Enter: fortsæt | B: VM-liste | Q: stop")
        elif self.stage == "single-role":
            self.text(screen, 3, "Single VM - MrNobody / " + self.single_profile)
            self.text(screen, 5, "Master - opret én VM", self.single_cursor == 0)
            self.text(screen, 6, "Slave/agent - forbind til Master", self.single_cursor == 1)
            self.text(screen, 7, "Standalone - kør uden Master", self.single_cursor == 2)
            self.text(screen, 9, "Master: valgt bridge samt spørgsmål om IP, gateway og DNS.")
            self.text(screen, 10, "Slave/Standalone: statiske LAN1/LAN2/OOBM-værdier fra labbet.")
            self.text(screen, 12, "VM installeres, slukker, får snapshot og startes igen.")
            self.text(screen, 14, "Slave spørger også om Master-adresse og HTTP/HTTPS.")
            row = next(row for row in self.profiles[self.single_profile]["rows"] if row["tag"] == "MRNOBODY")
            self.text(screen, 17, summary(row))
            self.text(screen, 21, "Op/ned: vælg | Enter: fortsæt | B: tilbage | Q: stop")
        else:
            self.text(screen, 3, f"Profil: {self.profile} | Labs: {self.labs} | 4 basis-VM'er inkluderet")
            self.text(screen, 5, f'{"Tilvalg (pr. lab)":22} {"vCPU":>6} {"RAM GiB":>10} {"Disk +GiB":>11}')
            for index, row in enumerate(r for r in rows if not r["base"]):
                marker = "[x]" if row["tag"] in self.selected else "[ ]"
                self.text(screen, 6 + index, f'{marker} {row["name"]:18} {row["cpu"]:6} {fmt(row["memory_mib"] / 1024):>10} {fmt(row["disk_gib"]):>11}', index == self.cursor)
            base = totals(rows, base_only=True)
            all_one = totals(rows, self.selected)
            extra = {key: all_one[key] - base[key] for key in base}
            self.text(screen, 15, "Basis/lab:   " + summary(base))
            self.text(screen, 16, "Tilvalg/lab: " + summary(extra))
            total = totals(rows, self.selected, self.labs)
            self.text(screen, 18, f'I alt, {total["vms"]} VM: {summary(total)}', True)
            self.text(screen, 20, "MrNobody: agent/slave. Master kræver fremtidig Single VM.")
            self.text(screen, 21, "Op/ned: flyt | Space: vælg | B: tilbage | Enter: fortsæt | Q: stop")
        self.text(screen, 22, "vCPU=kerner x sockets | Disk=udvidelse | Ekskl. Proxmox/image")
        screen.refresh()
        return True

    def handle(self, key):
        import curses
        if key in (27, ord("q"), ord("Q")):
            return "cancel"
        if self.stage == "profile":
            if key in (curses.KEY_UP, curses.KEY_DOWN, ord(" ")):
                choices = ("Big", "Mini", "Single VM")
                step = -1 if key == curses.KEY_UP else 1
                self.profile = choices[(choices.index(self.profile) + step) % len(choices)]
            elif key in (ord("+"), ord("="), curses.KEY_RIGHT):
                self.labs = min(16, self.labs + 1)
            elif key in (ord("-"), curses.KEY_LEFT):
                self.labs = max(1, self.labs - 1)
            elif key in (ord("s"), ord("S")):
                self.profile = "Single VM"
                self.stage = "single"
            elif key in (10, 13, curses.KEY_ENTER):
                self.stage = "single" if self.profile == "Single VM" else "options"
        elif self.stage == "single":
            if key in (curses.KEY_UP, curses.KEY_DOWN):
                self.vm_cursor = (self.vm_cursor + (-1 if key == curses.KEY_UP else 1)) % len(VMS)
            elif key in (ord("b"), ord("B"), curses.KEY_LEFT):
                self.stage = "profile"
            elif key in (10, 13, curses.KEY_ENTER):
                self.stage = "single-size"
        elif self.stage == "single-size":
            if key in (curses.KEY_UP, curses.KEY_DOWN, ord(" ")):
                self.single_profile = "Mini" if self.single_profile == "Big" else "Big"
            elif key in (ord("b"), ord("B"), curses.KEY_LEFT):
                self.stage = "single"
            elif key in (10, 13, curses.KEY_ENTER):
                if VMS[self.vm_cursor][0] == "MRNOBODY":
                    self.stage = "single-role"
                else:
                    return self.single_choice()
        elif self.stage == "single-role":
            if key in (curses.KEY_UP, curses.KEY_DOWN):
                self.single_cursor = (self.single_cursor + (-1 if key == curses.KEY_UP else 1)) % 3
            elif key in (ord("b"), ord("B"), curses.KEY_LEFT):
                self.stage = "single-size"
            elif key in (10, 13, curses.KEY_ENTER):
                return self.single_choice(("master", "agent", "standalone")[self.single_cursor])
        else:
            if key == curses.KEY_UP:
                self.cursor = (self.cursor - 1) % len(OPTIONS)
            elif key == curses.KEY_DOWN:
                self.cursor = (self.cursor + 1) % len(OPTIONS)
            elif key == ord(" "):
                tag = OPTIONS[self.cursor]
                self.selected.symmetric_difference_update({tag})
            elif key in (ord("b"), ord("B"), curses.KEY_LEFT):
                self.stage = "profile"
            elif key in (10, 13, curses.KEY_ENTER):
                return "accept"
        return None

    def run(self, screen):
        import curses
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.keypad(True)
        while True:
            ready = self.draw(screen)
            key = screen.getch()
            if not ready and key not in (27, ord("q"), ord("Q")):
                continue
            action = self.handle(key)
            if action == "cancel":
                return None
            if isinstance(action, dict) and action.get("kind") == "single-install":
                return action
            if action == "accept":
                return validate_selection(dict(profile=self.profile, labs=self.labs,
                                               components=[c for c in OPTIONS if c in self.selected]))


def single_menu_plan(role, read=input, write=print, *, lab=None, environ=None):
    """Master asks for networking; lab roles reuse the shared static defaults."""
    from MRNOBODY.single_vm_host import inspect_host, check_host_plan
    from MRNOBODY.single_vm_plan import validate_plan, hardware_defaults, lab_network_defaults
    if role not in {"master", "agent", "standalone"}:
        raise ValueError("Ukendt Single VM-rolle.")
    environ = os.environ if environ is None else environ
    inventory = inspect_host()
    bridge, disk, snippets = (environ.get(key, "") for key in ("BRIDGE", "LVM", "LOCAL"))
    if (role == "master" and bridge not in inventory["bridges"]) or disk not in inventory["disk_storages"] or snippets not in inventory["snippet_storages"]:
        raise ValueError("De oprindelige bridge/storage-valg er ikke tilgængelige. Kontrollér hovedinstallerens valg og snippets-understøttelse.")
    used = set(inventory["vmids"])
    vmid = next((value for value in range(9000, 999_999_999 + 1) if value not in used), None)
    write("Installer MrNobody " + {"master":"Master", "agent":"slave/agent", "standalone":"standalone"}[role])
    write(f"Storage: {disk}")
    if role == "master":
        write(f"Bridge: {bridge} | VMID: {vmid}")
    labs = []
    if role != "master":
        labs = sorted({int(match[1]) for name in inventory["bridges"]
                       if (match := re.fullmatch(r"lab([1-9][0-9]*)_lan1", name))
                       and all(lab_network_defaults(int(match[1]))[key] in inventory["bridges"]
                               for key in ("bridge", "bridge1", "bridge2"))})
        if not labs:
            raise ValueError("Ingen komplette lab-netværk med LAN1/LAN2/OOBM. Opret labbet først.")
    write("Q annullerer.")
    while True:
        try:
            answers = []
            lab_fields = {}
            if role == "master":
                for label in ("IP-adresse/subnet (fx 192.0.2.10/24)", "Gateway (tom er tilladt)", "DNS (IPv4)"):
                    value = read(label + ": ").strip()
                    if value.lower() == "q":
                        return None
                    answers.append(value)
            else:
                if lab is None:
                    from single_vm_install import ask_lab
                    lab = ask_lab(read=read, write=write)
                    if lab is None:
                        return None
                if lab not in labs:
                    raise ValueError("Det valgte lab mangler LAN1/LAN2/OOBM-bridges.")
                vmid = next((value for value in range(lab * 1000, (lab + 1) * 1000) if value not in used), None)
                network = lab_network_defaults(lab)
                lab_fields = dict(lab=lab)
                bridge = network["bridge"]
                answers = [network[key] for key in ("ipv4", "gateway", "dns")]
                write(f"Lab {lab}: LAN1 {network['ipv4']}, LAN2 {network['ipv4_2']}, OOBM {network['ipv4_1']}")
                write(f"VMID: {vmid}")
            if vmid is None:
                raise ValueError("Intet ledigt VMID i det valgte interval.")
            master_url, lab_http = "", False
            if role == "agent":
                host = read("Master IP/værtsnavn (valgfri :port): ").strip()
                if host.lower() == "q":
                    return None
                if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?", host):
                    raise ValueError("Angiv kun Master IP/værtsnavn og valgfri port, uden protokol eller sti.")
                protocol = read("Master-protokol HTTPS/HTTP [HTTPS]: ").strip().lower() or "https"
                if protocol == "q":
                    return None
                if protocol not in {"http", "https"}:
                    raise ValueError("Vælg HTTP eller HTTPS.")
                master_url, lab_http = protocol + "://" + host, protocol == "http"
                if lab_http:
                    write("HTTP-lab: Master skal også have LAB_HTTP=1. Trafikken viser øvelsesnøglen i klartekst.")
            plan = validate_plan(dict(role=role, vmid=vmid, name=f"lab{lab}-MrNobody" if lab_fields else "mrnobody-" + role,
                                      bridge=bridge, ipv4=answers[0], gateway=answers[1], dns=answers[2],
                                      disk_storage=disk, snippet_storage=snippets, master_url=master_url, lab_http=lab_http, **lab_fields, **hardware_defaults(environ=environ)))
            plan["host_check"] = check_host_plan(plan, inventory)
            return plan
        except ValueError as exc:
            write(f"Ugyldigt netværk: {exc}")
            if role != "master":
                lab = None


def master_menu_plan(read=input, write=print, **kwargs):
    return single_menu_plan("master", read=read, write=write, **kwargs)


def install_single_master(role="master", *, environ=None, lab=None):
    """Create, verify, snapshot and start Master with inherited settings."""
    import tempfile
    from urllib.parse import urlsplit
    from MRNOBODY.single_vm_create import create_vm
    from MRNOBODY.single_vm_boot import verify_boot
    result = None
    try:
        image_url = (os.environ if environ is None else environ).get("LINUX_IMG", "")
        if urlsplit(image_url).scheme not in {"http", "https"} or not urlsplit(image_url).netloc:
            raise ValueError("Ubuntu-image mangler. Start via hovedinstalleren.")
        if role == "master":
            plan = master_menu_plan() if environ is None else master_menu_plan(environ=environ)
        else:
            plan = single_menu_plan(role, lab=lab, environ=environ)
        if plan is None:
            return
        with tempfile.TemporaryDirectory(prefix="mrnobody-single-") as temporary:
            image = Path(temporary) / "ubuntu-cloud.img"
            print("Henter den allerede valgte Ubuntu-image...")
            subprocess.run(["curl", "--fail", "--location", "--proto", "=http,https",
                            "--proto-redir", "=http,https", "--output", str(image), image_url],
                           check=True, timeout=1200)
            result = create_vm(plan, image)
        verify_boot(result["vmid"], result["instance_id"])
        print("VM'en har slukket, og First_snapshot er oprettet. Starter VM...")
        subprocess.run(["qm", "start", str(result["vmid"])], check=True, timeout=120)
        print(f"MrNobody {role} VM {result['vmid']} er startet: https://{plan['ipv4'].split('/')[0]}")
        if role == "agent":
            print("Master-adresse og transport er gemt. Agentnøgle og eventuel CA-tillid skal sættes op før agentservicen aktiveres.")

    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"Single VM-installation stoppet: {exc}. Eventuel VM bevares; ingen automatisk sletning.")
    except (EOFError, KeyboardInterrupt):
        print("Afbrudt.")
    if result is not None:
        print(f"VMID: {result['vmid']} | Instance-ID: {result['instance_id']}")
    try:
        input("Enter for at vende tilbage til menuen: ")
    except (EOFError, KeyboardInterrupt):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    resources = commands.add_parser("resources")
    resources.add_argument("profile", choices=["Big", "Mini"])
    resources.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    choose = commands.add_parser("choose")
    choose.add_argument("--profiles", type=Path, required=True)
    choose.add_argument("--output", type=Path, required=True)
    preview = commands.add_parser("single-preview", help="Plan Single VM uden deployment")
    preview.add_argument("--offline", action="store_true", help="Valider kun input uden værtskontrol")
    selection = commands.add_parser("selection")
    selection.add_argument("file", type=Path)
    args = parser.parse_args()
    if args.command == "resources":
        print(json.dumps(hardware(args.root, args.profile)))
    elif args.command == "single-preview":
        from MRNOBODY.single_vm_plan import interactive_preview
        interactive_preview(default_bridge=os.environ.get("BRIDGE", ""), offline=args.offline)
    elif args.command == "selection":
        result = validate_selection(json.loads(args.file.read_text()))
        print("\n".join([result["profile"], str(result["labs"]), *result["components"]]))
    else:
        import curses
        profiles = {entry["profile"]: entry for entry in
                    (json.loads(line) for line in args.profiles.read_text().splitlines() if line)}
        if set(profiles) != {"Big", "Mini"}:
            raise ValueError("Menuen mangler Big/Mini-hardwareværdier.")
        try:
            view = Menu(profiles)
            while True:
                result = curses.wrapper(view.run)
                if isinstance(result, dict) and result.get("kind") == "single-install":
                    from single_vm_install import install_single_vm
                    install_single_vm(result, profiles)
                    continue
                if isinstance(result, str) and result in {"single-install", "single-install-agent", "single-install-standalone"}:
                    if result == "single-install":
                        install_single_master()
                    else:
                        install_single_master(role="agent" if result == "single-install-agent" else "standalone")
                    continue
                if result != "single-preview":
                    break
                from MRNOBODY.single_vm_plan import interactive_preview
                interactive_preview(default_bridge=os.environ.get("BRIDGE", ""))
        except curses.error as exc:
            raise ValueError("Kan ikke åbne menuen. Brug en interaktiv terminal med TERM sat.") from exc
        if result is None:
            return 130
        args.output.write_text(json.dumps(result) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
