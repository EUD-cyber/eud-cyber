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
                     ipv4="192.0.2.10/24", gateway="192.0.2.1", dns="192.0.2.53")
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
        answers = iter(["", "9000", "", "", "192.0.2.10/24", "192.0.2.1", "192.0.2.53", ""])
        output = []
        with patch("subprocess.run", side_effect=AssertionError("unexpected command")), \
             patch("os.system", side_effect=AssertionError("unexpected shell")), \
             patch("socket.create_connection", side_effect=AssertionError("unexpected network")):
            plan = planner.interactive_preview("vmbr7", read=lambda prompt: next(answers), write=output.append)
        self.assertEqual(plan["role"], "master")
        self.assertEqual(plan["bridge"], "vmbr7")
        self.assertFalse(plan["deployment_enabled"])
        self.assertIn("Ingen VM oprettes", "\n".join(output))
        self.assertIn("Ingen indstillinger er gemt", "\n".join(output))

    def test_cancel_and_invalid_input_do_not_return_a_plan(self):
        for response in ("q", KeyboardInterrupt(), EOFError()):
            reader = Mock(side_effect=response) if isinstance(response, BaseException) else lambda prompt: response
            self.assertIsNone(planner.interactive_preview(read=reader, write=lambda value: None))
        answers = iter(["master", "invalid-vmid", "q"])
        messages = []
        self.assertIsNone(planner.interactive_preview(read=lambda prompt: next(answers), write=messages.append))
        self.assertIn("Ugyldig plan", "\n".join(messages))

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
                [sys.executable, "-B", str(ROOT / "installer_menu.py"), "single-preview"],
                input="\n9000\n\n\n192.0.2.10/24\n192.0.2.1\n192.0.2.53\n\n",
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
