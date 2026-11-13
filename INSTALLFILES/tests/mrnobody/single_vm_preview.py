"""Single VM planning contracts; never run Proxmox commands or create VMs."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from MRNOBODY import single_vm_plan as planner

spec = importlib.util.spec_from_file_location("single_preview_menu", ROOT / "installer_menu.py")
menu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu)


class SingleVMPreview(unittest.TestCase):
    def raw(self, **changes):
        value = dict(role="master", vmid=9000, name="mrnobody-master", bridge="vmbr7",
                     ipv4="192.0.2.10/24", gateway="192.0.2.1", dns="192.0.2.53",
                     cpu=4, memory_mib=4096, disk_expansion="32G",
                     disk_storage="local-lvm", snippet_storage="local")
        value.update(changes)
        return value

    def test_valid_master_plan_is_explicitly_inactive(self):
        plan = planner.validate_plan(self.raw())
        self.assertEqual(plan["kind"], "single-vm-preview")
        self.assertFalse(plan["deployment_enabled"])
        self.assertEqual(plan["role"], "master")
        self.assertEqual(plan["ipv4"], "192.0.2.10/24")
        self.assertEqual(plan["bridge"], "vmbr7")

    def test_proxmox_vmid_boundaries_and_point_to_point_subnet(self):
        for vmid in (100, 999_999_999):
            self.assertEqual(planner.validate_plan(self.raw(vmid=vmid))["vmid"], vmid)
        plan = planner.validate_plan(self.raw(ipv4="192.0.2.0/31", gateway="192.0.2.1"))
        self.assertEqual(plan["ipv4"], "192.0.2.0/31")

    def test_optional_gateway_and_agent_url(self):
        for role in ("standalone", "agent", "master"):
            plan = planner.validate_plan(self.raw(role=role, gateway=""))
            self.assertEqual(plan["gateway"], "")
        self.assertEqual(planner.validate_plan(self.raw(role="agent", master_url="https://master.example:8443/api"))["master_url"],
                         "https://master.example:8443/api")

    def test_invalid_identity_and_schema(self):
        for changes in (dict(role="slave"), dict(role="Master"), dict(vmid=True), dict(vmid=0),
                        dict(vmid="9000"), dict(vmid=99), dict(vmid=1_000_000_000), dict(name="-master"), dict(name="master;id"),
                        dict(name="x" * 64), dict(bridge="vmbr7;id"), dict(bridge="x" * 16),
                        dict(bridge="vmbr 7"), dict(name=None), dict(extra="unexpected")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                planner.validate_plan(self.raw(**changes))
        with self.assertRaises(ValueError):
            planner.validate_plan({})
        with self.assertRaises(ValueError):
            planner.validate_plan([])

    def test_invalid_networks(self):
        for changes in (dict(ipv4="192.0.2.10"), dict(ipv4="192.0.2.0/24"),
                        dict(ipv4="192.0.2.255/24"), dict(ipv4="127.0.0.1/8"),
                        dict(ipv4="224.0.0.1/24"), dict(ipv4="0.0.0.0/24"),
                        dict(ipv4="2001:db8::1/64"), dict(ipv4="255.255.255.255/32"), dict(gateway="192.0.3.1"),
                        dict(gateway="192.0.2.10"), dict(gateway="192.0.2.0"),
                        dict(gateway="192.0.2.255"), dict(dns="not-an-ip"),
                        dict(dns="0.0.0.0"), dict(dns="224.0.0.1")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                planner.validate_plan(self.raw(**changes))

    def test_master_url_is_only_an_optional_agent_input(self):
        for role, url in (("master", "https://master.example"), ("standalone", "https://master.example"),
                          ("agent", "http://master.example"), ("agent", "https://user:secret@master.example"),
                          ("agent", "https://master.example?token=secret"), ("agent", "https://master.example/#x"),
                          ("agent", "https://master.example:0"), ("agent", "https://master.example:65536"),
                          ("agent", "$(id)"), ("agent", None)):
            with self.subTest(role=role, url=url), self.assertRaises(ValueError):
                planner.validate_plan(self.raw(role=role, master_url=url))

    def test_prompt_shows_plan_without_commands_or_network(self):
        answers = iter(["", "9000", "", "192.0.2.10/24", "192.0.2.1", "192.0.2.53", "", "", "", "local-lvm", "local", ""])
        output = []
        with patch("subprocess.run", side_effect=AssertionError("unexpected command")), \
             patch("os.system", side_effect=AssertionError("unexpected shell")), \
             patch("socket.create_connection", side_effect=AssertionError("unexpected network")):
            plan = planner.interactive_preview("vmbr7", read=lambda prompt: next(answers), write=output.append, offline=True)
        self.assertEqual(plan["role"], "master")
        self.assertEqual(plan["bridge"], "vmbr7")
        self.assertFalse(plan["deployment_enabled"])
        self.assertEqual(plan["host_check"]["status"], "not_checked")
        self.assertIn("Ingen VM oprettes", "\n".join(output))
        self.assertIn("Ingen indstillinger er gemt", "\n".join(output))

    def test_other_roles_return_before_any_vm_or_network_questions(self):
        for role in ("agent", "standalone"):
            reader = Mock(side_effect=[role])
            plan = planner.interactive_preview("vmbr7", read=reader, write=lambda value: None, offline=True)
            self.assertIsNone(plan)
            self.assertEqual(reader.call_count, 1)

    def test_master_reuses_initial_bridge_and_prompts_for_ip(self):
        answers = iter(["master", "9000", "", "192.0.2.10/24", "192.0.2.1", "192.0.2.53",
                        "", "", "", "local-lvm", "local", ""])
        prompts = []
        def read(prompt):
            prompts.append(prompt)
            return next(answers)
        plan = planner.interactive_preview("vmbr7", read=read, write=lambda value: None, offline=True)
        self.assertEqual(plan["bridge"], "vmbr7")
        self.assertEqual(plan["ipv4"], "192.0.2.10/24")
        self.assertFalse(any(prompt.startswith("Bridge") for prompt in prompts))
        self.assertTrue(any(prompt.startswith("Master IPv4/CIDR") for prompt in prompts))

    def test_cancel_and_invalid_input_do_not_return_a_plan(self):
        for response in ("q", KeyboardInterrupt(), EOFError()):
            reader = Mock(side_effect=response) if isinstance(response, BaseException) else lambda prompt: response
            self.assertIsNone(planner.interactive_preview(read=reader, write=lambda value: None, offline=True))
        answers = iter(["master", "vmbr7", "invalid-vmid", "q"])
        messages = []
        self.assertIsNone(planner.interactive_preview(read=lambda prompt: next(answers), write=messages.append, offline=True))
        self.assertIn("Ugyldig plan", "\n".join(messages))

    def test_single_vm_is_visible_third_profile_and_master_opens_creation(self):
        curses = types.SimpleNamespace(KEY_UP=1001, KEY_DOWN=1002, KEY_LEFT=1003,
                                       KEY_RIGHT=1004, KEY_ENTER=1005)
        with patch.dict(sys.modules, {"curses": curses}):
            view = menu.Menu({"Big": {"rows": []}, "Mini": {"rows": []}})
            view.handle(curses.KEY_DOWN)
            self.assertEqual(view.profile, "Mini")
            view.handle(curses.KEY_DOWN)
            self.assertEqual(view.profile, "Single VM")
            view.handle(10)
            self.assertEqual(view.stage, "single")
            self.assertEqual(view.handle(10), "single-install")
            view.handle(curses.KEY_DOWN)
            self.assertIsNone(view.handle(10))
            self.assertEqual(view.stage, "single")

    def test_master_menu_only_asks_network_and_uses_initial_settings(self):
        from MRNOBODY import single_vm_host as host
        inventory = dict(vmids=[9000], bridges=["vmbr7"], disk_storages=["local-lvm"],
                         snippet_storages=["local"], checked_at_utc="test")
        prompts = []
        answers = iter(["192.0.2.10/24", "192.0.2.1", "192.0.2.53"])
        def read(prompt):
            prompts.append(prompt)
            return next(answers)
        with patch.object(host, "inspect_host", return_value=inventory), \
             patch.dict(os.environ, {"BRIDGE":"vmbr7", "LVM":"local-lvm", "LOCAL":"local"}):
            plan = menu.master_menu_plan(read=read, write=lambda value: None)
        self.assertEqual(len(prompts), 3)
        self.assertEqual(plan["vmid"], 9001)
        self.assertEqual(plan["bridge"], "vmbr7")
        self.assertEqual(plan["role"], "master")
        self.assertEqual(plan["ipv4"], "192.0.2.10/24")

    def test_menu_master_downloads_selected_image_without_configuration_questions(self):
        from MRNOBODY import single_vm_create as creator
        result = dict(vmid=9000, instance_id="a"*16)
        with patch.object(menu, "master_menu_plan", return_value=planner.validate_plan(self.raw())), \
             patch.object(creator, "create_vm", return_value=result) as create, \
             patch.dict(os.environ, {"LINUX_IMG":"https://images.example/ubuntu.img"}), \
             patch.object(menu.subprocess, "run") as download, \
             patch("builtins.input", return_value="") as read, patch("builtins.print"):
            menu.install_single_master()
        self.assertEqual(read.call_count, 1)
        self.assertEqual(create.call_args.args[0]["role"], "master")
        self.assertEqual(download.call_args.args[0][-1], "https://images.example/ubuntu.img")
        self.assertTrue(download.call_args.kwargs["check"])

    def test_master_cancel_stops_before_image_download_or_creation(self):
        from MRNOBODY import single_vm_create as creator
        with patch.object(menu, "master_menu_plan", return_value=None), \
             patch.dict(os.environ, {"LINUX_IMG":"https://images.example/ubuntu.img"}), \
             patch.object(menu.subprocess, "run") as download, \
             patch.object(creator, "create_vm") as create:
            menu.install_single_master()
        download.assert_not_called()
        create.assert_not_called()

    def test_failed_download_does_not_create_master(self):
        from MRNOBODY import single_vm_create as creator
        with patch.object(menu, "master_menu_plan", return_value=planner.validate_plan(self.raw())), \
             patch.dict(os.environ, {"LINUX_IMG":"https://images.example/ubuntu.img"}), \
             patch.object(menu.subprocess, "run", side_effect=subprocess.CalledProcessError(22, ["curl"])), \
             patch.object(creator, "create_vm") as create, \
             patch("builtins.input", return_value=""), patch("builtins.print"):
            menu.install_single_master()
        create.assert_not_called()

    def test_menu_preview_never_reaches_lab_selection_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            assert root.resolve().parent == ROOT.resolve()
            profiles = root / "profiles.jsonl"
            profiles.write_text('{"profile":"Big","rows":[]}\n{"profile":"Mini","rows":[]}\n')
            selection = root / "selection.json"
            views = []

            def wrapper(run):
                view = run.__self__
                views.append(view)
                if len(views) == 1:
                    view.profile, view.labs, view.selected = "Mini", 3, {"MRNOBODY"}
                    return "single-preview"
                self.assertIs(view, views[0])
                self.assertEqual((view.profile, view.labs, view.selected), ("Mini", 3, {"MRNOBODY"}))
                return menu.validate_selection(dict(profile=view.profile, labs=view.labs, components=list(view.selected)))

            curses = types.SimpleNamespace(wrapper=wrapper, error=RuntimeError)
            argv = ["installer_menu.py", "choose", "--profiles", str(profiles), "--output", str(selection)]
            with patch.dict(sys.modules, {"curses": curses}), patch.object(sys, "argv", argv), \
                 patch.dict(os.environ, {"BRIDGE": "vmbr7"}), \
                 patch.object(planner, "interactive_preview", return_value=planner.validate_plan(self.raw())) as preview:
                self.assertEqual(menu.main(), 0)
                preview.assert_called_once_with(default_bridge="vmbr7")
            self.assertEqual(json.loads(selection.read_text()), dict(profile="Mini", labs=3, components=["MRNOBODY"]))

    def test_cli_preview_works_without_profiles_or_host_tools(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            assert root.resolve().parent == ROOT.resolve()
            before = set(root.iterdir())
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "installer_menu.py"), "single-preview", "--offline"],
                input="\n".join(["", "9000", "", "192.0.2.10/24", "192.0.2.1", "192.0.2.53", "", "", "", "local-lvm", "local", ""]) + "\n",
                cwd=root, env=dict(os.environ, BRIDGE="vmbr7"), capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            output = result.stdout[result.stdout.index("{"):]
            plan, _ = json.JSONDecoder().raw_decode(output)
            self.assertEqual(plan["role"], "master")
            self.assertFalse(plan["deployment_enabled"])
            self.assertEqual(set(root.iterdir()), before)


if __name__ == "__main__":
    unittest.main()
