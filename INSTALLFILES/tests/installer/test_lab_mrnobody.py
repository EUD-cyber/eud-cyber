"""Offline prompt/worker tests; no real host commands, services or VMs."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("installer_menu", ROOT / "installer_menu.py")
menu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu)


class LabRoleTests(unittest.TestCase):
    def test_roles_profiles_and_all_lab_counts(self):
        from test_installer_menu import FAKE_CURSES, Screen
        rows = menu.hardware(ROOT, "Big", {})["rows"]
        profiles = {p: dict(profile=p, rows=rows) for p in ("Big", "Mini")}
        with patch.dict(sys.modules, {"curses": FAKE_CURSES}):
            for profile in profiles:
                for labs in range(1, 17):
                    for role in ("standalone", "agent"):
                        view = menu.Menu(profiles)
                        view.profile, view.labs = profile, labs
                        view.stage, view.selected = "options", {"MRNOBODY"}
                        screen = Screen([10, *([258] if role == "agent" else []), 10], size=(24, 76))
                        result = view.run(screen)
                        self.assertEqual(result["mrnobody_role"], role)
                        self.assertEqual(result["labs"], labs)
                        self.assertFalse(any("Master -" in line for line in screen.frames[-1].values()))

    def test_back_without_mrnobody_and_rejected_master(self):
        from test_installer_menu import FAKE_CURSES
        with patch.dict(sys.modules, {"curses": FAKE_CURSES}):
            view = menu.Menu({})
            view.stage, view.selected = "options", {"MRNOBODY"}
            view.handle(10)
            self.assertEqual(view.stage, "lab-role")
            view.handle(ord("b"))
            self.assertEqual(view.stage, "options")
            view.selected.clear()
            self.assertEqual(view.handle(10), "accept")
        with self.assertRaises(ValueError):
            menu.validate_selection(dict(profile="Big", labs=1, components=["MRNOBODY"], mrnobody_role="master"))

    def test_master_prompt_normalizes_retries_and_cancels(self):
        for value, expected in [("192.0.2.10", "http://192.0.2.10"),
                                ("master.test:8080", "http://master.test:8080"),
                                ("https://master.test:8443/api/", "https://master.test:8443/api/")]:
            self.assertEqual(menu.master_url(value), expected)
        for invalid in ("", "http://", "https://user:pass@host", "host:0", "host:65536", "$(id)", "host?a=b", "host/#x"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                menu.master_url(invalid)
        answers = iter(["", "bad value", "master.test"])
        output=[]
        self.assertEqual(menu.ask_master_url(read=lambda: next(answers), write=output.append), "http://master.test")
        self.assertEqual(output[0], "Indtast Master IP (x.x.x.x): ")
        self.assertEqual(output[-1], "Indtast Master IP (x.x.x.x): ")
        with self.assertRaises(ValueError):
            menu.ask_master_url(read=lambda: "q", write=lambda _: None)


@unittest.skipUnless(sys.platform == "linux" and shutil.which("bash") and os.geteuid() == 0,
                     "Requires Linux root; all host operations are stubbed")
class ForegroundAndWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.root / "snippets").mkdir()
        for name in ("deploy.sh", "installer_menu.py"):
            source = (ROOT / name).read_text()
            if name == "deploy.sh":
                # Stub host preparation together with all other host operations.
                start = source.index("prepare_host() (\n")
                end = source.index("\n)\n", start) + len("\n)\n")
                source = source[:start] + "prepare_host() { bash host-setup.sh; }\n" + source[end:]
            self.write(name, source)
        self.write("bin/pvesh", "#!/bin/bash\necho '[]'\n")
        self.write("bin/tmux", '''#!/bin/bash
if [[ "$1" == has-session ]]; then exit 1; fi
printf 'tmux\\n' >> events
shift 4
# Simulate stale server values before applying the explicitly passed environment.
export MRNOBODY_ROLE=master MRNOBODY_MASTER_URL=https://stale.test
exec "$@" </dev/null
''')
        for name in ("repo.sh", "host-setup.sh", "open-vswitch-pre.sh", "open-vswitch.sh", "open-vswitch-last.sh",
                     "OPNSENSE/generate_config.sh", "GUACVM/GUACVM_ip.sh", "OPNSENSE/OPNSENSE_installer.sh",
                     "GUACVM/GUACVM_installer.sh", "KALI01/KALI01_installer.sh", "VULNSRV01/VULNSRV01_installer.sh"):
            self.write(name, f'#!/bin/bash\nprintf "%s %s\\n" "{name}" "${{1:-}}" | tee -a events\n')
        # Execute actual validation/rendering; stop before VMID lookup and use
        # temporary snippets instead of the Proxmox directory.
        source = (ROOT / "MRNOBODY/mrnobody_installer.sh").read_text()
        prefix = source.split("# ===== Find next free VMID =====")[0]
        prefix = prefix.replace('SNIPPET_DIR="/var/lib/vz/snippets"', 'SNIPPET_DIR="$(pwd)/snippets"')
        self.write("MRNOBODY/mrnobody_installer.sh", prefix)
        shutil.copyfile(ROOT / "MRNOBODY/mrnobody_userdata.yaml", self.root / "MRNOBODY/mrnobody_userdata.yaml")

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o755)

    def deploy(self, profile="Big", labs=1, role="agent", url="", answers="master.test:8080\n", selected=True):
        env = dict(os.environ, PATH=str(self.bin) + ":" + os.environ["PATH"],
                   MRNOBODY_ROLE=role, MRNOBODY_MASTER_URL=url)
        return subprocess.run(["bash", "deploy.sh", profile, str(labs), *(["MRNOBODY"] if selected else [])],
                              cwd=self.root, env=env, input=answers, text=True, capture_output=True, timeout=20)

    def test_all_labs_roles_profiles_and_closed_worker_stdin(self):
        for profile in ("Big", "Mini"):
            for labs in range(1, 17):
                for role in ("standalone", "agent"):
                    with self.subTest(profile=profile, labs=labs, role=role):
                        (self.root / "events").unlink(missing_ok=True)
                        for path in (self.root / "snippets").glob("*"):
                            path.unlink()
                        result = self.deploy(profile, labs, role, url="https://stale.test" if role == "standalone" else "",
                                             answers="" if role == "standalone" else "master.test:8080\n")
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual("Indtast Master IP (x.x.x.x): " in result.stdout, role == "agent")
                        if role == "agent":
                            self.assertLess(result.stdout.index(f"GUACVM/GUACVM_ip.sh {labs}\n"), result.stdout.index("Indtast Master IP"))
                            self.assertIn("Indtast Master IP (x.x.x.x): [+] Preparing repository", result.stdout)
                        events = (self.root / "events").read_text().splitlines()
                        expected = [f"{script} {lab}" for lab in range(1, labs + 1)
                                    for script in ("OPNSENSE/generate_config.sh", "GUACVM/GUACVM_ip.sh")]
                        self.assertEqual(events[:labs * 2], expected)
                        self.assertLess(events.index("repo.sh "), events.index("tmux"))
                        snippets = list((self.root / "snippets").glob("*.yaml"))
                        self.assertEqual(len(snippets), labs)
                        for snippet in snippets:
                            rendered = snippet.read_text()
                            self.assertIn(f"      MRNOBODY_ROLE={role}\n", rendered)
                            self.assertIn("      MRNOBODY_MASTER_URL=" + ("http://master.test:8080" if role == "agent" else "''") + "\n", rendered)

    def test_wazuh_worker_runs_once_per_lab(self):
        self.write("WAZUH/WAZUH_installer.sh",
                   '#!/bin/bash\nprintf "WAZUH %s\\n" "$1" >> events\n')
        env = dict(os.environ, PATH=str(self.bin) + ":" + os.environ["PATH"])
        for profile, labs in (("Big", 1), ("Mini", 2), ("Big", 16)):
            with self.subTest(profile=profile, labs=labs):
                (self.root / "events").unlink(missing_ok=True)
                result = subprocess.run(
                    ["bash", "deploy.sh", profile, str(labs), "WAZUH", "WAZUH"],
                    cwd=self.root, env=env, input="", text=True, capture_output=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                events = (self.root / "events").read_text().splitlines()
                self.assertEqual([event for event in events if event.startswith("WAZUH ")],
                                 [f"WAZUH {lab}" for lab in range(1, labs + 1)])

    def test_missing_master_eof_stops_before_setup_or_tmux(self):
        result = self.deploy(answers="")
        self.assertNotEqual(result.returncode, 0)
        events = (self.root / "events").read_text()
        self.assertNotIn("repo.sh", events)
        self.assertNotIn("tmux", events)

    @unittest.skipUnless(shutil.which("tmux"), "tmux is not installed")
    def test_real_tmux_server_overrides_stale_settings(self):
        tmux = shutil.which("tmux")
        socket = "mrnobody-test-" + self.root.name
        command = [tmux, "-L", socket, "-f", "/dev/null"]
        self.addCleanup(lambda: subprocess.run(command + ["kill-server"], capture_output=True))
        env = dict(os.environ, MRNOBODY_ROLE="master", MRNOBODY_MASTER_URL="https://stale.test")
        subprocess.run(command + ["new-session", "-d", "-s", "stale", "sleep 30"], env=env, check=True)
        self.write("bin/tmux", f'#!/bin/bash\nexec {tmux} -L {socket} -f /dev/null "$@"\n')
        target = self.root / "MRNOBODY/mrnobody_installer.sh"
        target.write_text("exec </dev/null\n" + target.read_text())
        for role in ("standalone", "agent"):
            for path in (self.root / "snippets").glob("*"):
                path.unlink()
            (self.root / "deploy.log").unlink(missing_ok=True)
            result = self.deploy(role=role, answers="master.test\n" if role == "agent" else "")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if "CyberLab deployment completed." in (self.root / "deploy.log").read_text():
                    break
                time.sleep(0.05)
            self.assertIn("CyberLab deployment completed.", (self.root / "deploy.log").read_text())
            rendered = next((self.root / "snippets").glob("*")).read_text()
            self.assertIn(f"MRNOBODY_ROLE={role}\n", rendered)
            self.assertNotIn("https://stale.test", rendered)

    def test_explicit_https_no_component_and_invalid_role(self):
        result = self.deploy(url="https://master.test:8443/api/", answers="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Indtast Master IP", result.stdout + result.stderr)
        self.assertIn("MRNOBODY_MASTER_URL=https://master.test:8443/api/", next((self.root / "snippets").glob("*")).read_text())
        result = self.deploy(selected=False, answers="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Indtast Master IP", result.stdout + result.stderr)
        for role, url in (("master", ""), ("agent", "http://host:0")):
            (self.root / "events").unlink(missing_ok=True)
            result = self.deploy(role=role, url=url, answers="")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / "events").exists())

    def test_install_shell_consumes_menu_role_and_clears_stale_url(self):
        source = (ROOT.parent / "install.sh").read_text()
        function = source[source.index("select_deployment() {"):].split("\n}\n", 1)[0] + "\n}\n"
        harness = '''set -euo pipefail
INSTALL_DIR="$PWD"
require_file() { test -s "$1"; }
configure_vm_resources() { :; }
die() { echo "$*" >&2; exit 1; }
python3() {
    case "$2" in
        resources) echo '{}' ;;
        choose) cp choice.json "${@: -1}" ;;
        *) command python3 "$@" ;;
    esac
}
''' + function + '''
export MRNOBODY_ROLE=master MRNOBODY_MASTER_URL=https://stale.test
select_deployment
printf '%s\\n' "$SPEC" "$LABCOUNT" "$MRNOBODY_ROLE" "$MRNOBODY_MASTER_URL" "${OPTIONAL_COMPONENTS[@]}"
'''
        for role in ("standalone", "agent"):
            (self.root / "choice.json").write_text(json.dumps(dict(profile="Mini", labs=16,
                components=["WAZUH", "MRNOBODY"], mrnobody_role=role)))
            result = subprocess.run(["bash", "-c", harness], cwd=self.root, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["Mini", "16", role, "", "WAZUH", "MRNOBODY"])


if __name__ == "__main__":
    unittest.main()
