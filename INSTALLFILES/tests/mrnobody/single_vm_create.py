"""Simulated Single VM creation only: never call real Proxmox commands."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "TESTFILES/ATTACKER-V2/web"))
from MRNOBODY import single_vm_create as creator, single_vm_plan as planner
from deployment_config import load_deployment_config


class CreateSingleVM(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        assert self.root.resolve().parent == ROOT.resolve()
        self.snippets = self.root / "snippets"
        self.snippets.mkdir()
        self.image = self.root / "ubuntu.img"
        self.image.write_bytes(b"fixture, not a real image")
        self.plan = planner.validate_plan(dict(
            role="master",vmid=9000,name="mrnobody-master",bridge="vmbr7",
            ipv4="192.0.2.10/24",gateway="192.0.2.1",dns="192.0.2.53",
            cpu=4,memory_mib=4096,disk_expansion="32G",
            disk_storage="local-lvm",snippet_storage="local"))
        self.inventory = dict(vmids=[100],bridges=["vmbr7"],disk_storages=["local-lvm"],
                              snippet_storages=["local"],checked_at_utc="fixture")
        self.inspect = Mock(return_value=self.inventory)
        self.template = 'write_files:\n\n      MRNOBODY_ROLE="standalone"\n      MRNOBODY_MASTER_URL=""\nremaining: unchanged\npower_state:\n  mode: poweroff\n  condition: true\n'
        self.calls = []
        self.info = dict(format="qcow2", **{"virtual-size":2147483648})
        self.fail_action = None

    def run_command(self, argv, **options):
        self.calls.append(argv)
        self.assertTrue(options["check"])
        self.assertFalse(options.get("shell", False))
        self.assertGreater(options["timeout"], 0)
        if argv[:2] == ["qemu-img","info"]:
            return types.SimpleNamespace(stdout=json.dumps(self.info))
        if argv[:2] == ["pvesm","path"]:
            return types.SimpleNamespace(stdout=str(self.snippets / argv[2].split("/")[-1])+"\n")
        self.assertEqual(argv[0], "qm")
        self.assertIn(argv[1], {"create","disk"})
        if self.fail_action == argv[1]:
            raise subprocess.CalledProcessError(1, argv)
        return types.SimpleNamespace(stdout="")

    def create(self, **changes):
        options = dict(run=self.run_command,inspect=self.inspect,template=self.template,write=lambda line:None)
        options.update(changes)
        return creator.create_vm(self.plan,self.image,**options)

    def test_agent_http_opt_in_is_written_only_to_generated_config(self):
        for scheme in ("http", "https"):
            value = dict(self.plan)
            value.update(role="agent", master_url=scheme+"://master.test", lab_http=scheme=="http")
            rendered = creator.render_userdata(self.template, value, instance_id="a"*16)
            self.assertIn("MRNOBODY_ROLE=agent", rendered)
            self.assertIn("MRNOBODY_MASTER_URL="+scheme+"://master.test", rendered)
            self.assertEqual('MRNOBODY_LAB_HTTP="1"' in rendered, scheme=="http")
            self.assertNotIn("MRNOBODY_LAB_HTTP", self.template)

    def test_creates_only_selected_vm_with_one_bridge_and_no_start(self):
        result = self.create()
        self.assertEqual(self.inspect.call_count, 2)
        self.assertTrue(result["created"])
        self.assertFalse(result["started"] or result["guest_installation_completed"])
        command = next(argv for argv in self.calls if argv[:2] == ["qm","create"])
        self.assertEqual(command[2],"9000")
        for key, value in (("--net0","virtio,bridge=vmbr7"),("--onboot","0"),
                           ("--memory","4096"),("--cores","4"),("--boot","order=scsi0"),
                           ("--ipconfig0","ip=192.0.2.10/24,gw=192.0.2.1")):
            self.assertEqual(command[command.index(key)+1],value)
        self.assertNotIn("--net1",command)
        self.assertNotIn("--net2",command)
        self.assertIn("local-lvm:0,import-from="+str(self.image.resolve()),command)
        self.assertEqual(self.calls[-1],["qm","disk","resize","9000","scsi0","+32G"])
        self.assertFalse(any("start" in argv or "destroy" in argv for argv in self.calls))
        rendered = Path(result["snippet"]).read_text()
        self.assertIn("MRNOBODY_ROLE=master",rendered)
        self.assertIn("  condition: true",rendered)
        self.assertIn(result["instance_id"],rendered)
        self.assertIn("MRNOBODY_SINGLE_VM:"+result["instance_id"]+":master",command)
        self.assertIn("  condition: true",self.template)

    def test_lab_roles_create_three_static_interfaces_and_keep_role_config(self):
        for role in ("agent", "standalone"):
            self.calls.clear()
            raw = {key: value for key, value in self.plan.items()
                   if key not in {"kind", "deployment_enabled", "host_check"}}
            raw.update(role=role, lab=3, master_url="https://master.test" if role == "agent" else "")
            self.plan = planner.validate_plan(raw)
            self.inventory["bridges"] = ["lab3_lan1", "lab3_oobm", "lab3_lan2"]
            result = self.create()
            command = next(argv for argv in self.calls if argv[:2] == ["qm", "create"])
            for key, value in (("--net0", "virtio,bridge=lab3_lan1"),
                               ("--net1", "virtio,bridge=lab3_oobm"),
                               ("--net2", "virtio,bridge=lab3_lan2"),
                               ("--ipconfig0", "ip=192.168.1.254/24,gw=192.168.1.1"),
                               ("--ipconfig1", "ip=172.20.0.254/24"),
                               ("--ipconfig2", "ip=192.168.2.254/24"),
                               ("--nameserver", "192.168.1.1")):
                self.assertEqual(command[command.index(key) + 1], value)
            rendered = Path(result["snippet"]).read_text()
            self.assertIn("MRNOBODY_ROLE=" + role, rendered)
            self.assertIn("MRNOBODY_MASTER_URL=" + ("https://master.test" if role == "agent" else "''"), rendered)

    def test_missing_secondary_bridge_prevents_any_creation(self):
        raw = {key: value for key, value in self.plan.items()
               if key not in {"kind", "deployment_enabled", "host_check"}}
        self.plan = planner.validate_plan(dict(raw, role="agent", lab=3))
        self.inventory["bridges"] = ["lab3_lan1", "lab3_oobm"]
        with self.assertRaisesRegex(ValueError, "LAN1"):
            self.create()
        self.assertEqual(self.calls, [])

    def test_forged_saved_check_is_ignored_and_existing_vmid_stops_everything(self):
        self.plan["host_check"] = {"status":"checked","vmid_free":True}
        self.inspect.return_value = dict(self.inventory,vmids=[9000])
        with self.assertRaises(ValueError):
            self.create()
        self.assertEqual(self.calls,[])
        self.assertEqual(list(self.snippets.iterdir()),[])

    def test_second_check_detects_race_and_removes_only_own_snippet(self):
        self.inspect.side_effect = [self.inventory,dict(self.inventory,vmids=[9000])]
        with self.assertRaises(ValueError):
            self.create()
        self.assertFalse(any(argv[0]=="qm" for argv in self.calls))
        self.assertEqual(list(self.snippets.iterdir()),[])

    def test_failed_create_or_resize_preserves_snippet_and_never_destroys(self):
        for failure in ("create","disk"):
            with self.subTest(failure=failure):
                self.calls = []
                self.fail_action = failure
                before = set(self.snippets.iterdir())
                with self.assertRaises(subprocess.CalledProcessError):
                    self.create()
                self.assertEqual(len(set(self.snippets.iterdir())-before),1)
                self.assertFalse(any("destroy" in argv or "start" in argv for argv in self.calls))

    def test_snippet_collision_never_overwrites_or_deletes_existing_file(self):
        target = self.snippets / ("mrnobody_single_9000_" + "a"*16 + ".yaml")
        target.write_text("existing VM data")
        with patch.object(creator.secrets,"token_hex",return_value="a"*16), self.assertRaises(FileExistsError):
            self.create()
        self.assertEqual(target.read_text(),"existing VM data")
        self.assertFalse(any(argv[0]=="qm" for argv in self.calls))

    def test_backing_images_and_unsupported_formats_stop_before_snippet(self):
        for info in (dict(format="qcow2",**{"backing-filename":"another-disk"}),
                     dict(format="vmdk"), [], dict(format="qcow2",**{"full-backing-filename":"/private/disk"})):
            self.info = info
            with self.subTest(info=info), self.assertRaises(ValueError):
                self.create()
            self.assertEqual(list(self.snippets.iterdir()),[])

    def test_renderer_checks_anchors_preserves_line_endings_and_master_is_recognized(self):
        for newline in ("\n","\r\n"):
            rendered = creator.render_userdata(self.template.replace("\n",newline),self.plan)
            self.assertIn("MRNOBODY_ROLE=master"+newline,rendered)
            self.assertIn("remaining: unchanged"+newline,rendered)
        with self.assertRaises(ValueError):
            creator.render_userdata(self.template.replace('      MRNOBODY_ROLE="standalone"\n',""),self.plan)
        config = self.root / "deployment.conf"
        config.write_text("MRNOBODY_ROLE=master\nMRNOBODY_MASTER_URL=''\n")
        loaded = load_deployment_config(config)
        self.assertEqual((loaded.role,loaded.config_status),("master","loaded"))
        self.assertFalse(loaded.public_status()["transport_enabled"])

    def test_explicit_commit_source_does_not_change_lab_template(self):
        source = 'BASE_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/INSTALLFILES/TESTFILES/ATTACKER-V2"\n'
        template = self.template + source
        sha = "a" * 40
        rendered = creator.render_userdata(template,self.plan,source_ref=sha)
        self.assertIn("/"+sha+"/INSTALLFILES/",rendered)
        self.assertIn("/main/INSTALLFILES/",template)
        for ref in ("feature/branch","../other","https://other.example","$(id)"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                creator.render_userdata(template,self.plan,source_ref=ref)

    def test_plain_lab_selection_cannot_be_used_for_single_vm_creation(self):
        with self.assertRaises(ValueError):
            creator.create_vm(dict(profile="Big",components=["MRNOBODY"]),self.image,
                              run=Mock(side_effect=AssertionError("unexpected command")))
        with self.assertRaises(ValueError):
            creator.normalized_plan(dict(self.plan,deployment_enabled=True))

    def test_cli_requires_explicit_create_and_confirmation(self):
        with patch.object(sys,"argv",["single_vm_create"]), \
             patch.object(creator,"interactive_preview",return_value=self.plan), \
             patch.object(creator,"create_vm") as create:
            self.assertEqual(creator.main(),0)
            create.assert_not_called()
        with patch.object(sys,"argv",["single_vm_create","--create","--image",str(self.image)]), \
             patch.object(creator.os,"geteuid",return_value=0,create=True), \
             patch.object(creator,"interactive_preview",return_value=self.plan), \
             patch("builtins.input",return_value="NO"),patch("builtins.print"), \
             patch.object(creator,"create_vm") as create:
            self.assertEqual(creator.main(),0)
            create.assert_not_called()


if __name__ == "__main__":
    unittest.main()

