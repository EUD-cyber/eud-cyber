"""Fake Proxmox inventories only: no host commands, VMs or external network."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from MRNOBODY import single_vm_host as host, single_vm_plan as planner

HEADER = "Name Type Status Total (KiB) Used (KiB) Available (KiB) %\n"
IMAGES = HEADER + "local-lvm lvmthin active 100 0 100 0%\nold dir inactive 100 0 100 0%\n"
SNIPPETS = HEADER + "local dir active 100 0 100 0%\ndisabled dir disabled 100 0 100 N/A\n"
SOURCE = 'CORES="' + chr(36) + '{MRNOBODY_CPU:-4}"\nMEMORY="' + chr(36) + '{MRNOBODY_MEM:-4096}"\nDISK_SIZE="' + chr(36) + '{MRNOBODY_HDD:-32G}"\n'


def raw(**changes):
    plan = dict(role="master", vmid=9000, name="mrnobody-master", bridge="vmbr7",
                ipv4="192.0.2.10/24", gateway="192.0.2.1", dns="192.0.2.53",
                cpu=4, memory_mib=4096, disk_expansion="32G",
                disk_storage="local-lvm", snippet_storage="local")
    plan.update(changes)
    return plan


class HostChecks(unittest.TestCase):
    def fixture(self, *, ovs=False, guests=None, links=None, images=IMAGES, snippets=SNIPPETS, changes=None):
        responses = {
            ("pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"): json.dumps([{"vmid":100,"type":"qemu"}] if guests is None else guests),
            ("ip", "-j", "link", "show", "type", "bridge"): json.dumps([{"ifname":"vmbr7"}] if links is None else links),
            ("ovs-vsctl", "--timeout=5", "list-br"): "ovsbr0\n",
            ("pvesm", "status", "--content", "images"): images,
            ("pvesm", "status", "--content", "snippets"): snippets,
        }
        responses.update(changes or {})
        def run(argv, **options):
            self.assertEqual(options["timeout"], 10)
            self.assertTrue(options["check"] and options["capture_output"] and options["text"])
            self.assertFalse(options.get("shell", False))
            self.assertEqual(options["env"]["LC_ALL"], "C")
            self.assertIn(tuple(argv), responses, "Unexpected command")
            return types.SimpleNamespace(stdout=responses[tuple(argv)])
        runner = Mock(side_effect=run)
        result = host.inspect_host(run=runner, which=lambda name: "/usr/bin/ovs-vsctl" if ovs else None)
        return result, runner

    def test_only_fixed_read_commands_and_active_content_storages(self):
        inventory, runner = self.fixture()
        self.assertEqual(runner.call_count, 4)
        self.assertEqual(inventory["disk_storages"], ["local-lvm"])
        self.assertEqual(inventory["snippet_storages"], ["local"])
        self.assertEqual(inventory["bridges"], ["vmbr7"])
        self.assertEqual(inventory["vmids"], [100])

    def test_optional_open_vswitch_is_merged(self):
        inventory, runner = self.fixture(ovs=True)
        self.assertEqual(runner.call_count, 5)
        self.assertEqual(inventory["bridges"], ["ovsbr0", "vmbr7"])

    def test_checked_snapshot_is_not_a_reservation_or_connectivity_check(self):
        inventory, _ = self.fixture()
        plan = planner.validate_plan(raw())
        original = copy.deepcopy((plan, inventory))
        status = host.check_host_plan(plan, inventory)
        self.assertEqual(status["status"], "checked")
        self.assertFalse(status["reserved"])
        self.assertFalse(status["capacity_checked"])
        self.assertFalse(status["network_reachability_checked"])
        self.assertEqual((plan, inventory), original)

    def test_existing_cluster_vm_or_container_id_is_rejected(self):
        for kind in ("qemu", "lxc"):
            inventory, _ = self.fixture(guests=[{"vmid":9000,"type":kind}])
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "VMID"):
                host.check_host_plan(planner.validate_plan(raw()), inventory)

    def test_unknown_bridge_and_wrong_storage_are_rejected(self):
        inventory, _ = self.fixture()
        for changes in (dict(bridge="missing"), dict(disk_storage="local"),
                        dict(snippet_storage="local-lvm"), dict(disk_storage="old")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                host.check_host_plan(planner.validate_plan(raw(**changes)), inventory)

    def test_missing_tools_permission_failures_and_timeout_do_not_pass(self):
        for error in (FileNotFoundError(), PermissionError(),
                      subprocess.CalledProcessError(1, ["pvesh"]),
                      subprocess.TimeoutExpired(["pvesh"], 10)):
            runner = Mock(side_effect=error)
            with self.subTest(error=type(error).__name__), self.assertRaises(ValueError):
                host.inspect_host(run=runner, which=lambda name: None)
            self.assertEqual(runner.call_count, 1)

    def test_malformed_guest_bridge_and_json_data_do_not_pass(self):
        for options in (dict(guests={}), dict(guests=[{"vmid":"100"}]),
                        dict(guests=[{}]), dict(links=[{"ifname":"vmbr7;id"}]),
                        dict(links={}), dict(links=[{}]),
                        dict(changes={("pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"):"not JSON"})):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.fixture(**options)

    def test_missing_or_malformed_storage_stops_preview(self):
        for options in (dict(images=""), dict(images=HEADER), dict(snippets=HEADER),
                        dict(snippets=HEADER+"local dir inactive 0 0 0 0%\n"),
                        dict(images=HEADER+"bad;id lvmthin active 1 0 1 0%\n"),
                        dict(images=HEADER+"local-lvm lvmthin broken 1 0 1 0%\n"),
                        dict(links=[])):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.fixture(**options)

    def test_hardware_defaults_come_from_shared_installer_without_shell(self):
        with patch("os.system", side_effect=AssertionError("No shell")):
            self.assertEqual(planner.hardware_defaults(environ={}, source=SOURCE),
                             dict(cpu=4, memory_mib=4096, disk_expansion="32G"))
            self.assertEqual(planner.hardware_defaults(
                environ={"MRNOBODY_CPU":"2","MRNOBODY_MEM":"2048","MRNOBODY_HDD":"16G"}, source=SOURCE),
                dict(cpu=2, memory_mib=2048, disk_expansion="16G"))
            with self.assertRaises(ValueError):
                planner.hardware_defaults(environ={}, source='CORES="$(id)"')
        self.assertEqual(planner.hardware_defaults(environ={}, source=SOURCE.replace("\n","\r\n"))["cpu"], 4)

    def test_invalid_hardware_and_storage_identifiers(self):
        for changes in (dict(cpu=True), dict(cpu=0), dict(cpu="4"), dict(memory_mib=0),
                        dict(memory_mib=False), dict(disk_expansion="0G"),
                        dict(disk_expansion="32G;id"), dict(disk_expansion="32"),
                        dict(disk_storage="local;id"), dict(snippet_storage=""), dict(snippet_storage=None)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                planner.validate_plan(raw(**changes))

    def test_online_prompt_checks_selected_values_and_reports_snapshot(self):
        inventory, _ = self.fixture()
        answers = iter(["","9000","","","192.0.2.10/24","192.0.2.1","192.0.2.53","","","","","",""])
        output = []
        with patch.object(planner, "inspect_host", return_value=inventory), \
             patch.object(planner, "hardware_defaults", return_value=dict(cpu=4,memory_mib=4096,disk_expansion="32G")):
            plan = planner.interactive_preview("vmbr7", read=lambda prompt: next(answers), write=output.append)
        self.assertEqual(plan["host_check"]["status"], "checked")
        self.assertFalse(plan["deployment_enabled"])
        self.assertEqual((plan["disk_storage"],plan["snippet_storage"]),("local-lvm","local"))
        self.assertIn("Snippet-storage: local", "\n".join(output))

    def test_failed_host_inspection_returns_no_plan(self):
        output = []
        with patch.object(planner, "inspect_host", side_effect=ValueError("Host query failed")), \
             patch.object(planner, "hardware_defaults", return_value=dict(cpu=4,memory_mib=4096,disk_expansion="32G")):
            self.assertIsNone(planner.interactive_preview(read=lambda prompt:"",write=output.append))
        self.assertIn("Forhåndsvisning stoppet", "\n".join(output))
        self.assertNotIn('"status": "checked"', "\n".join(output))


if __name__ == "__main__":
    unittest.main()
