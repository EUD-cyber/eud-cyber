#!/usr/bin/env python3
"""CyberLab hardware reader and terminal menu. Never execute VM installers here."""
import argparse
import json
import os
from pathlib import Path
import re
import sys

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
                         memory_mib=memory, disk_gib=disk_gib(values["HDD"], prefix + "_HDD")))
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
        rows = self.profiles[self.profile]["rows"]
        self.text(screen, 0, "CyberLab - " + ("Størrelse og minimumskrav" if self.stage == "profile" else "Tilvalg"))
        self.text(screen, 1, "=" * min(width - 4, 84))
        if self.stage == "profile":
            for index, profile in enumerate(("Big", "Mini")):
                minimum = totals(self.profiles[profile]["rows"], base_only=True)
                self.text(screen, 3 + index, f'{"(*)" if profile == self.profile else "( )"} {profile:4} Min./lab: {summary(minimum)}', profile == self.profile)
            self.text(screen, 6, f"Antal labs: {self.labs}  (+/- ændrer, 1-16)")
            self.text(screen, 8, "Basis - altid med (pr. lab)")
            self.text(screen, 9, f'{"VM":18} {"vCPU":>6} {"RAM GiB":>10} {"Disk +GiB":>11}')
            for index, row in enumerate(r for r in rows if r["base"]):
                self.text(screen, 10 + index, f'{row["name"]:18} {row["cpu"]:6} {fmt(row["memory_mib"] / 1024):>10} {fmt(row["disk_gib"]):>11}')
            self.text(screen, 16, f'Minimum, {self.labs} lab(s): {summary(totals(rows, labs=self.labs, base_only=True))}')
            self.text(screen, 18, "MrNobody i Big/Mini: agent/slave (også i fremtidig Custom).")
            self.text(screen, 19, "Single VM / Master: kommer senere - kan ikke vælges endnu.")
            self.text(screen, 21, "Op/ned: Big/Mini | +/-: labs | Enter: tilvalg | Q/Esc: annullér")
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
                self.profile = "Mini" if self.profile == "Big" else "Big"
            elif key in (ord("+"), ord("="), curses.KEY_RIGHT):
                self.labs = min(16, self.labs + 1)
            elif key in (ord("-"), curses.KEY_LEFT):
                self.labs = max(1, self.labs - 1)
            elif key in (10, 13, curses.KEY_ENTER):
                self.stage = "options"
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
            if action == "accept":
                return validate_selection(dict(profile=self.profile, labs=self.labs,
                                               components=[c for c in OPTIONS if c in self.selected]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    resources = commands.add_parser("resources")
    resources.add_argument("profile", choices=["Big", "Mini"])
    resources.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    choose = commands.add_parser("choose")
    choose.add_argument("--profiles", type=Path, required=True)
    choose.add_argument("--output", type=Path, required=True)
    selection = commands.add_parser("selection")
    selection.add_argument("file", type=Path)
    args = parser.parse_args()
    if args.command == "resources":
        print(json.dumps(hardware(args.root, args.profile)))
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
            result = curses.wrapper(Menu(profiles).run)
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
