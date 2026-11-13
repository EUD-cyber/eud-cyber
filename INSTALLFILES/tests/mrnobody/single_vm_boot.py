"""First-boot lifecycle checks with fake Proxmox/QGA responses only."""
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from MRNOBODY import single_vm_boot as boot


class FirstBoot(unittest.TestCase):
    def setUp(self):
        self.instance = "a"*16
        self.identity = dict(vmid=9000,instance_id=self.instance,role="master")
        self.report = dict(state="ready",identity=self.identity,cloud_init="done",marker=True,
                           health=dict(status="ok",service="MrNobody Incident Platform",
                                       deployment=dict(role="master",config_status="loaded")))
        self.responses = []
        self.calls = []
        self.running = self.existing_snapshot = self.early_stop = self.shutdown_stays_running = False
        self.changed_identity = self.fail_action = None
        self.agent_failures = self.config_reads = 0
        self.elapsed = 0

    def sleep(self, seconds):
        self.elapsed += seconds

    def run_command(self, argv, **options):
        self.calls.append(argv)
        self.assertTrue(options["check"])
        self.assertFalse(options.get("shell",False))
        self.assertGreater(options["timeout"],0)
        self.assertEqual(argv[0],"qm")
        action = argv[1]
        if action == self.fail_action:
            raise subprocess.CalledProcessError(1,argv)
        if action == "config":
            self.config_reads += 1
            instance = self.changed_identity if self.changed_identity and self.config_reads > 1 else self.instance
            value = f"description: MRNOBODY_SINGLE_VM:{instance}:master\ncicustom: user=local:snippets/mrnobody_single_9000_{instance}.yaml\n"
        elif action == "status":
            value = "status: running" if self.running else "status: stopped"
        elif action == "listsnapshot":
            value = "First_snapshot baseline\n" if self.existing_snapshot else "current\n"
        elif action == "start":
            self.running = not self.early_stop
            value = ""
        elif action == "guest":
            if self.agent_failures:
                self.agent_failures -= 1
                raise subprocess.CalledProcessError(1,argv)
            self.assertIn("--synchronous",argv)
            self.assertEqual(argv[-2],"-c")
            compile(argv[-1],"<guest probe>","exec")
            result = self.responses.pop(0) if self.responses else dict(exited=True,exitcode=0,**{"out-data":json.dumps(self.report)})
            value = result if isinstance(result,str) else json.dumps(result)
        elif action == "shutdown":
            self.assertIn("--forceStop",argv)
            self.assertEqual(argv[argv.index("--forceStop")+1],"0")
            self.running = self.shutdown_stays_running
            value = ""
        elif action == "snapshot":
            self.assertFalse(self.running)
            self.assertEqual(argv[3],"First_snapshot")
            self.existing_snapshot = True
            value = ""
        else:
            self.fail("Unexpected mutation: "+str(argv))
        return type("Result",(),{"stdout":value})()

    def verify(self, **kwargs):
        return boot.verify_boot(9000,self.instance,run=self.run_command,clock=lambda:self.elapsed,
                                sleep=self.sleep,write=lambda value:None,**kwargs)

    def actions(self):
        return [argv[1] for argv in self.calls]

    def test_verified_first_boot_shuts_down_before_snapshot_and_stays_stopped(self):
        result = self.verify()
        self.assertTrue(result["cloud_init_verified"] and result["health_verified"])
        self.assertFalse(result["started"] or self.running)
        self.assertEqual(result["baseline"],"First_snapshot")
        self.assertLess(self.actions().index("start"),self.actions().index("shutdown"))
        self.assertLess(self.actions().index("shutdown"),self.actions().index("snapshot"))
        self.assertNotIn("stop",self.actions())
        self.assertNotIn("destroy",self.actions())

    def test_agent_startup_and_cloud_init_running_are_retried(self):
        self.agent_failures = 1
        self.responses = [dict(exited=True,exitcode=0,**{"out-data":json.dumps(dict(state="waiting"))})]
        self.verify()
        self.assertEqual(self.elapsed,10)
        self.assertEqual(self.actions().count("guest"),3)

    def test_running_vm_or_existing_snapshot_is_not_started_or_overwritten(self):
        for running,existing in ((True,False),(False,True)):
            self.calls=[]
            self.running,self.existing_snapshot=running,existing
            with self.subTest(running=running,existing=existing), self.assertRaises(ValueError):
                self.verify()
            self.assertNotIn("start",self.actions())
            self.assertNotIn("snapshot",self.actions())

    def test_wrong_instance_or_invalid_inputs_do_not_start_anything(self):
        with self.assertRaises(ValueError):
            boot.verify_boot(9000,"b"*16,run=self.run_command,sleep=self.sleep)
        self.assertNotIn("start",self.actions())
        for vmid,instance in ((True,self.instance),(99,self.instance),(9000,"$(id)")):
            with self.subTest(vmid=vmid,instance=instance),self.assertRaises(ValueError):
                boot.verify_boot(vmid,instance,run=Mock(side_effect=AssertionError("Unexpected command")))

    def test_cloud_init_error_wrong_guest_or_failed_health_never_get_a_baseline(self):
        original=json.loads(json.dumps(self.report))
        bad_reports = [
            dict(state="error",reason="cloud-init"),
            dict(original,identity=dict(self.identity,instance_id="b"*16)),
            dict(original,cloud_init="running"),dict(original,marker=False),
            dict(original,health={"status":"error"}),dict(original,health=[]),
            dict(original,health=dict(original["health"],deployment=[])),
            dict(original,health=dict(original["health"],deployment=dict(role="agent",config_status="loaded"))),
        ]
        for report in bad_reports:
            self.calls=[]
            self.running=False
            self.report=report
            with self.subTest(report=report),self.assertRaises(ValueError):
                self.verify()
            self.assertNotIn("shutdown",self.actions())
            self.assertNotIn("snapshot",self.actions())
            self.assertTrue(self.running)

    def test_timeout_or_early_poweroff_never_get_a_baseline(self):
        self.agent_failures=100
        with self.assertRaises(TimeoutError):
            self.verify(timeout=10)
        self.assertNotIn("snapshot",self.actions())
        self.assertTrue(self.running)
        self.calls=[]
        self.running=False
        self.early_stop=True
        with self.assertRaises(ValueError):
            self.verify()
        self.assertNotIn("snapshot",self.actions())

    def test_malformed_agent_results_or_execution_failure_stop_verification(self):
        for value in ("not JSON",[],dict(exited=True,exitcode=1),
                      dict(exited=True,exitcode=0,**{"out-data":"not JSON"}),
                      dict(exited=True,exitcode=0,**{"out-truncated":True}),
                      dict(exited="false",exitcode=0)):
            self.calls=[]
            self.running=False
            self.responses=[value]
            with self.subTest(value=value),self.assertRaises(ValueError):
                self.verify()
            self.assertNotIn("snapshot",self.actions())

    def test_identity_change_prevents_shutdown(self):
        self.changed_identity="b"*16
        with self.assertRaises(ValueError):
            self.verify()
        self.assertNotIn("shutdown",self.actions())
        self.assertNotIn("snapshot",self.actions())
        self.assertTrue(self.running)

    def test_shutdown_or_snapshot_failure_never_forces_stop_or_deletes(self):
        for failure in ("shutdown","snapshot"):
            self.calls=[]
            self.running=False
            self.fail_action=failure
            with self.subTest(failure=failure),self.assertRaises(subprocess.CalledProcessError):
                self.verify()
            self.assertNotIn("stop",self.actions())
            self.assertNotIn("destroy",self.actions())
        self.fail_action=None
        self.calls=[]
        self.running=False
        self.shutdown_stays_running=True
        with self.assertRaises(ValueError):
            self.verify()
        self.assertNotIn("snapshot",self.actions())

    def test_existing_baseline_blocks_a_second_run(self):
        self.verify()
        starts=self.actions().count("start")
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.actions().count("start"),starts)


class GuestProbe(unittest.TestCase):
    def probe(self,state=None,returncode=0,marker=True):
        state=dict(status="done",errors=[],recoverable_errors={},extended_status="done") if state is None else state
        marker_file=Mock()
        marker_file.is_file.return_value=marker
        marker_file.stat.return_value=Mock(st_size=1)
        identity=Mock()
        identity.read_text.return_value=json.dumps(dict(vmid=9000,instance_id="a"*16,role="master"))
        path=lambda value: marker_file if value=="/opt/nordic-attack/INSTALL_COMPLETE" else identity
        health=dict(status="ok",service="MrNobody Incident Platform",deployment=dict(role="master",config_status="loaded"))
        with patch.object(boot.subprocess,"run",return_value=Mock(returncode=returncode,stdout=json.dumps(state))) as command, \
             patch.object(boot,"Path",side_effect=path), \
             patch.object(boot.urllib.request,"urlopen",side_effect=lambda *args,**kwargs:io.BytesIO(json.dumps(health).encode())) as request:
            report=boot.guest_probe()
        self.assertEqual(command.call_args.args[0],["cloud-init","status","--format","json"])
        if report["state"]=="ready":
            self.assertEqual(request.call_args.args[0],"https://127.0.0.1/api/health")
        return report

    def test_done_marker_and_loopback_health_return_ready(self):
        self.assertEqual(self.probe()["state"],"ready")

    def test_running_cloud_init_waits_without_claiming_success(self):
        self.assertEqual(self.probe(state=dict(status="running"))["state"],"waiting")

    def test_cloud_init_error_degraded_or_missing_marker_never_pass(self):
        for options in (dict(returncode=2),dict(state=dict(status="done",errors=["failed"])),
                        dict(state=dict(status="done",recoverable_errors={"x":["failed"]})),
                        dict(state=dict(status="done",extended_status="degraded done")),
                        dict(marker=False),dict(state=[])):
            with self.subTest(options=options):
                self.assertEqual(self.probe(**options)["state"],"error")


if __name__=="__main__":
    unittest.main()
