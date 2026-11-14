"""Individual lab VM menus and isolated dispatch; never run real installers."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import installer_menu as menu
import single_vm_install as single
from test_installer_menu import Screen, FAKE_CURSES


class SingleInstallTests(unittest.TestCase):
    def setUp(self):
        source = (ROOT.parent / "install.sh").read_text(encoding="utf-8")
        mini = dict(re.findall(r'export ([A-Z0-9]+_(?:CPU|MEM|HDD))="\$\{[A-Z0-9_]+:-([^}]+)\}"', source))
        self.profiles = {"Big": menu.hardware(ROOT, "Big", {}), "Mini": menu.hardware(ROOT, "Mini", mini)}
        self.env = dict(BRIDGE="vmbr0", LOCAL="local", LVM="local-lvm", LINUX_IMG="https://example.test/ubuntu.img")
        self.inventory = dict(vmids=[1000], bridges=["vmbr0", "lab1_lan1", "lab1_lan2", "lab1_oobm"],
                              disk_storages=["local-lvm"], snippet_storages=["local"])

    def choice(self, vm="CLIENT01", profile="Big", role=None):
        return dict(kind="single-install", vm=vm, profile=profile, role=role)

    def test_every_vm_has_both_sizes_then_only_mrnobody_has_roles(self):
        with patch.dict(sys.modules, {"curses": FAKE_CURSES}):
            for index, vm in enumerate(menu.VMS):
                for profile in ("Big", "Mini"):
                    with self.subTest(vm=vm[0], profile=profile):
                        view = menu.Menu(self.profiles)
                        view.handle(ord("s"))
                        for _ in range(index):
                            view.handle(FAKE_CURSES.KEY_DOWN)
                        view.handle(10)
                        self.assertEqual(view.stage, "single-size")
                        screen = Screen(size=(24, 76))
                        view.draw(screen)
                        for offset, size in enumerate(("Big", "Mini")):
                            row = self.profiles[size]["rows"][index]
                            self.assertIn(menu.summary(row), screen.lines[5 + offset])
                        if profile == "Mini":
                            view.handle(FAKE_CURSES.KEY_DOWN)
                        action = view.handle(10)
                        if vm[0] == "MRNOBODY":
                            self.assertEqual(view.stage, "single-role")
                            for role in ("master", "agent", "standalone"):
                                self.assertEqual(view.handle(10), self.choice(vm[0], profile, role))
                                view.handle(FAKE_CURSES.KEY_DOWN)
                        else:
                            self.assertEqual(action, self.choice(vm[0], profile))

    def test_all_single_screens_fit_minimum_terminal(self):
        view = menu.Menu(self.profiles)
        view.profile = "Single VM"
        with patch.dict(sys.modules, {"curses": FAKE_CURSES}):
            for index in range(len(menu.VMS)):
                view.vm_cursor = index
                for stage in ("single", "single-size", "single-role"):
                    view.stage = stage
                    self.assertTrue(view.draw(Screen(size=(24, 76))))

    def test_enter_defaults_to_lab1_and_invalid_numbers_retry(self):
        reader = Mock(return_value="")
        self.assertEqual(single.ask_lab(read=reader), 1)
        self.assertIn("[1]", reader.call_args.args[0])
        self.assertEqual(single.ask_lab(read=Mock(side_effect=["0", "17", "abc", "2"]), write=lambda value: None), 2)
        self.assertIsNone(single.ask_lab(read=Mock(return_value="q")))

    def test_exact_displayed_overrides_and_topology_survive_switching_sizes(self):
        for vm in menu.VMS:
            for profile in ("Big", "Mini"):
                role = "standalone" if vm[0] == "MRNOBODY" else None
                _, row, env = single.single_environment(self.choice(vm[0], profile, role), self.profiles,
                    dict(self.env, KALI01_CPU="999", MRNOBODY_MEM="999999", CLIENT01_MEM="1"))
                actual = next(row for row in menu.hardware(ROOT, profile, env)["rows"] if row["tag"] == vm[0])
                self.assertEqual((actual["cpu"], actual["memory_mib"], actual["disk_gib"]),
                                 (row["cpu"], row["memory_mib"], row["disk_gib"]))
                self.assertEqual(env["SPEC"], profile)
        _, _, big = single.single_environment(self.choice("KALI01"), self.profiles, self.env)
        self.assertNotIn("KALI01_CPU", big)  # preserve the shared Big two-socket default
        _, _, mini = single.single_environment(self.choice("KALI01", "Mini"), self.profiles, self.env)
        self.assertEqual(mini["KALI01_CPU"], "2")

    def test_user_overrides_are_captured_for_both_display_and_install(self):
        profiles = dict(self.profiles, Big=menu.hardware(ROOT, "Big", dict(CLIENT01_CPU="3", CLIENT01_HDD="512M")))
        _, row, env = single.single_environment(self.choice(), profiles, self.env)
        self.assertEqual((row["cpu"], row["disk_gib"]), (3, 0.5))
        self.assertEqual((env["CLIENT01_CPU"], env["CLIENT01_HDD"]), ("3", "512M"))

    def test_check_all_vm_bridges_and_only_same_vm_blocks_install(self):
        for vm in menu.VMS:
            with self.subTest(vm=vm[0]), patch.object(single, "inspect_host", return_value=self.inventory):
                run = Mock(return_value=types.SimpleNamespace(stdout=json.dumps([dict(vmid=1000, name="lab1-unrelated")])))
                single.check_lab_vm(vm, 1, self.env, run=run)
                source = (ROOT / vm[3]).read_text(encoding="utf-8")
                existing = menu.assignment(source, "BASE_NAME").replace("${LAB}", "1")
                run.return_value.stdout = json.dumps([dict(vmid=1001, name=existing)])
                with self.assertRaisesRegex(ValueError, "findes allerede"):
                    single.check_lab_vm(vm, 1, self.env, run=run)

    def test_missing_lab_network_or_storage_stops_before_write(self):
        vm = next(vm for vm in menu.VMS if vm[0] == "APPSRV01")
        for changes in (dict(bridges=["lab1_oobm"]), dict(disk_storages=[]), dict(snippet_storages=[])):
            with patch.object(single, "inspect_host", return_value=dict(self.inventory, **changes)):
                run = Mock(side_effect=AssertionError("Must stop before another command"))
                with self.assertRaises(ValueError):
                    single.check_lab_vm(vm, 1, self.env, run=run)
                run.assert_not_called()

    def test_dispatch_runs_only_chosen_vm_and_its_specific_setup(self):
        for vm in menu.VMS:
            if vm[0] == "MRNOBODY":
                continue
            with tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                prep = {"OPNSENSE": "OPNSENSE/generate_config.sh", "GUACVM": "GUACVM/GUACVM_ip.sh"}.get(vm[0])
                scripts = ([prep] if prep else []) + [vm[3]]
                for script in scripts:
                    path = root / script
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("fixture")
                run = Mock()
                single.execute_lab_vm(vm, 7, self.env, root=root, run=run)
                self.assertEqual([call.args[0] for call in run.call_args_list],
                                 [["bash", str(root / script), "7"] for script in scripts])
                self.assertTrue(all(call.kwargs["env"] == self.env for call in run.call_args_list))
                self.assertTrue(all(call.kwargs["cwd"] == root for call in run.call_args_list))

    def test_wrapper_passes_default_lab_and_selected_profile_to_only_one_vm(self):
        reader = Mock(return_value="")
        with patch.dict(os.environ, self.env), patch.object(single.os, "geteuid", return_value=0, create=True), \
             patch.object(single, "check_lab_vm") as check, patch.object(single, "execute_lab_vm") as execute:
            single.install_single_vm(self.choice(profile="Mini"), self.profiles, read=reader, write=lambda value: None)
        self.assertEqual(check.call_args.args[1], 1)
        self.assertEqual(execute.call_args.args[0][0], "CLIENT01")
        self.assertEqual(execute.call_args.args[1], 1)
        self.assertEqual(execute.call_args.args[2]["CLIENT01_MEM"], "4096")

    def test_mrnobody_roles_keep_size_and_only_lab_roles_ask_for_lab(self):
        for role in ("master", "agent", "standalone"):
            reader = Mock(return_value="")
            with patch.dict(os.environ, self.env), patch.object(single.os, "geteuid", return_value=0, create=True), \
                 patch.object(single, "check_lab_vm") as check, patch.object(single, "execute_lab_vm") as execute, \
                 patch.object(menu, "install_single_master") as mrnobody:
                single.install_single_vm(self.choice("MRNOBODY", "Mini", role), self.profiles, read=reader, write=lambda value: None)
            self.assertEqual(reader.call_count, 0 if role == "master" else 1)
            self.assertEqual(check.call_count, 0 if role == "master" else 1)
            execute.assert_not_called()
            self.assertEqual(mrnobody.call_args.args, (role,))
            self.assertEqual(mrnobody.call_args.kwargs["lab"], None if role == "master" else 1)
            self.assertEqual(mrnobody.call_args.kwargs["environ"]["MRNOBODY_MEM"], "2048")

    def test_cancel_and_preflight_failure_never_reach_installer(self):
        for answer in ("q", ""):
            with patch.dict(os.environ, self.env), patch.object(single.os, "geteuid", return_value=0, create=True), \
                 patch.object(single, "check_lab_vm", side_effect=ValueError("missing bridge")), \
                 patch.object(single, "execute_lab_vm") as execute:
                single.install_single_vm(self.choice(), self.profiles, read=Mock(return_value=answer), write=lambda value: None)
                execute.assert_not_called()

    def test_main_single_install_returns_to_menu_without_full_lab_dispatch(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            profiles = root / "profiles.jsonl"
            profiles.write_text("\n".join(json.dumps(value) for value in self.profiles.values()), encoding="utf-8")
            output = root / "selection.json"
            actions = [self.choice(), None]
            curses = types.SimpleNamespace(wrapper=lambda run: actions.pop(0), error=RuntimeError)
            argv = ["installer_menu.py", "choose", "--profiles", str(profiles), "--output", str(output)]
            with patch.dict(sys.modules, {"curses": curses}), patch.object(sys, "argv", argv), \
                 patch.object(single, "install_single_vm") as install:
                self.assertEqual(menu.main(), 130)
            install.assert_called_once()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
