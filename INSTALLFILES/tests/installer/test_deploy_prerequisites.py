"""Run deployment and real host preparation with isolated storage/apt/Proxmox."""
import os
from pathlib import Path
import shutil
import sys
import unittest

import test_lab_mrnobody as fixtures

ROOT = fixtures.ROOT


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "Requires Linux root; package and VM operations are stubbed")
class DeployPrerequisiteTests(unittest.TestCase):
    write = fixtures.ForegroundAndWorkerTests.write
    deploy = fixtures.ForegroundAndWorkerTests.deploy

    def setUp(self):
        fixtures.ForegroundAndWorkerTests.setUp(self)
        # Deliberately exclude the host PATH: even a host with tmux installed
        # must exercise the missing-package case without touching real apt.
        for command in ("bash", "python3", "tee", "dirname", "mkdir", "grep",
                        "sed", "chmod", "cp", "env"):
            (self.bin / command).symlink_to(shutil.which(command))
        self.environment = unittest.mock.patch.dict(os.environ, PATH=str(self.bin))
        self.environment.start()
        self.addCleanup(self.environment.stop)
        (self.bin / "tmux").rename(self.root / "tmux-template")
        self.write("storage.cfg", "dir: local\n    path /var/lib/vz\n    content iso,vztmpl,backup\n")
        source = (ROOT / "deploy.sh").read_text()
        start = source.index("prepare_host() (\n")
        end = source.index("\n)\n", start) + len("\n)\n")
        function = source[start:end]
        function = function.replace('STORAGE_CFG="/etc/pve/storage.cfg"',
                                    'STORAGE_CFG="$PWD/storage.cfg"')
        function = function.replace('STORAGE_PATH="/var/lib/vz"',
                                    'STORAGE_PATH="$PWD/storage"')
        target = self.root / "deploy.sh"
        target.write_text(target.read_text().replace(
            "prepare_host() { bash host-setup.sh; }\n", function))
        self.write("bin/dpkg", '''#!/bin/bash
if [[ "$2" == tmux && ! -x bin/tmux ]]; then exit 1; fi
''')
        self.write("bin/apt-get", '''#!/bin/bash
printf 'apt-get %s\\n' "$*" >> events
if [[ "$1" == "${FAIL_APT:-}" ]]; then exit 42; fi
if [[ "$1" == install && "${SKIP_TMUX:-}" != 1 ]]; then
    cp tmux-template bin/tmux
fi
''')

    def events(self):
        return (self.root / "events").read_text().splitlines()

    def test_clean_host_installs_tmux_before_network_and_worker(self):
        result = self.deploy(selected=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = self.events()
        self.assertLess(events.index("repo.sh "), events.index("apt-get update -qq"))
        self.assertLess(events.index("apt-get update -qq"), events.index("apt-get install -y tmux"))
        self.assertLess(events.index("apt-get install -y tmux"), events.index("open-vswitch-pre.sh "))
        self.assertLess(events.index("open-vswitch-pre.sh "), events.index("tmux"))
        self.assertIn("GUACVM/GUACVM_installer.sh 1", events)
        self.assertIn("content iso,vztmpl,backup,snippets", (self.root / "storage.cfg").read_text())
        self.assertEqual((self.root / "storage/snippets").stat().st_mode & 0o777, 0o755)

    def test_existing_tmux_and_repeat_setup_do_not_invoke_apt(self):
        shutil.copyfile(self.root / "tmux-template", self.bin / "tmux")
        (self.bin / "tmux").chmod(0o755)
        for _ in range(2):
            result = self.deploy(selected=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(any(event.startswith("apt-get") for event in self.events()))
        self.assertEqual((self.root / "storage.cfg").read_text().count(",snippets"), 1)

    def test_apt_failures_stop_before_network_or_vm_install(self):
        for stage in ("update", "install"):
            with self.subTest(stage=stage), unittest.mock.patch.dict(os.environ, FAIL_APT=stage):
                (self.root / "events").unlink(missing_ok=True)
                result = self.deploy(selected=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("open-vswitch-pre.sh ", self.events())
                self.assertNotIn("OPNSENSE/OPNSENSE_installer.sh 1", self.events())
                self.assertNotIn("tmux", self.events())

    def test_successful_package_command_must_supply_tmux(self):
        with unittest.mock.patch.dict(os.environ, SKIP_TMUX="1"):
            result = self.deploy(selected=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Required command not found: tmux", result.stdout + result.stderr)
        self.assertNotIn("open-vswitch-pre.sh ", self.events())

    def test_existing_deployment_stops_before_configuration_or_packages(self):
        self.write("bin/tmux", "#!/bin/bash\nexit 0\n")
        result = self.deploy(selected=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assertFalse((self.root / "events").exists())
        self.assertNotIn("snippets", (self.root / "storage.cfg").read_text())


if __name__ == "__main__":
    unittest.main()
