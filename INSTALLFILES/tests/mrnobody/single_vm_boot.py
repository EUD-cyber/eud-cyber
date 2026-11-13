"""Lifecycle tests with fake Proxmox responses; no guest or HTTP access."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from MRNOBODY import single_vm_boot as boot


class FirstBoot(unittest.TestCase):
    def setUp(self):
        self.instance = "a"*16
        self.elapsed = 0
        self.running = False
        self.snapshot = False
        self.poweroff_after = 10
        self.changed = False
        self.config_reads = 0
        self.fail_action = None
        self.calls = []
        self.output = []

    def run_command(self, argv, **options):
        self.calls.append(argv)
        self.assertTrue(options["check"])
        self.assertFalse(options.get("shell", False))
        action = argv[1]
        if action == self.fail_action:
            raise subprocess.CalledProcessError(1, argv)
        if action == "config":
            self.config_reads += 1
            instance = "b"*16 if self.changed and self.config_reads > 1 else self.instance
            value = f"description: MRNOBODY_SINGLE_VM:{instance}:master\ncicustom: user=local:snippets/mrnobody_single_9000_{instance}.yaml\n"
        elif action == "status":
            if self.running and self.poweroff_after is not None and self.elapsed >= self.poweroff_after:
                self.running = False
            value = "status: running" if self.running else "status: stopped"
        elif action == "listsnapshot":
            value = "First_snapshot\n" if self.snapshot else "current\n"
        elif action == "start":
            self.running = True
            value = ""
        elif action == "snapshot":
            self.assertFalse(self.running)
            self.snapshot = True
            value = ""
        else:
            self.fail("Unexpected command: "+str(argv))
        return type("Result", (), {"stdout": value})()

    def sleep(self, seconds):
        self.elapsed += seconds

    def verify(self, **options):
        return boot.verify_boot(9000, self.instance, run=self.run_command,
                                clock=lambda: self.elapsed, sleep=self.sleep,
                                write=self.output.append, **options)

    def actions(self):
        return [call[1] for call in self.calls]

    def test_guest_poweroff_creates_baseline_without_guest_http_or_shutdown(self):
        result = self.verify()
        self.assertEqual(result["completion_signal"], "guest_poweroff")
        self.assertFalse(result["cloud_init_verified"] or result["health_verified"] or result["started"])
        self.assertEqual(self.elapsed, 10)
        self.assertEqual(result["baseline"], "First_snapshot")
        self.assertNotIn("guest", self.actions())
        self.assertNotIn("shutdown", self.actions())

    def test_timeout_preserves_running_vm_without_snapshot(self):
        self.poweroff_after = None
        with self.assertRaises(TimeoutError):
            self.verify(timeout=10)
        self.assertTrue(self.running)
        self.assertNotIn("snapshot", self.actions())
        self.assertNotIn("stop", self.actions())

    def test_progress_while_waiting(self):
        self.poweroff_after = 65
        self.verify()
        self.assertEqual(sum("installerer stadig" in line for line in self.output), 2)

    def test_running_vm_or_existing_baseline_is_not_modified(self):
        for running, snapshot in ((True, False), (False, True)):
            with self.subTest(running=running, snapshot=snapshot):
                self.running, self.snapshot, self.calls = running, snapshot, []
                self.poweroff_after = None
                with self.assertRaises(ValueError):
                    self.verify()
                self.assertNotIn("start", self.actions())
                self.assertNotIn("snapshot", self.actions())

    def test_wrong_identity_and_invalid_inputs_do_not_start(self):
        with self.assertRaises(ValueError):
            boot.verify_boot(9000, "b"*16, run=self.run_command)
        self.assertNotIn("start", self.actions())
        for vmid, instance in ((True, self.instance), (99, self.instance), (9000, "$(id)")):
            with self.subTest(vmid=vmid), self.assertRaises(ValueError):
                boot.verify_boot(vmid, instance, run=self.run_command)

    def test_identity_change_after_poweroff_prevents_snapshot(self):
        self.changed = True
        with self.assertRaises(ValueError):
            self.verify()
        self.assertNotIn("snapshot", self.actions())

    def test_failed_snapshot_never_deletes_or_forces_stop(self):
        self.fail_action = "snapshot"
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify()
        self.assertNotIn("destroy", self.actions())
        self.assertNotIn("stop", self.actions())

    def test_existing_baseline_blocks_second_run(self):
        self.verify()
        starts = self.actions().count("start")
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.actions().count("start"), starts)


if __name__ == "__main__":
    unittest.main()
