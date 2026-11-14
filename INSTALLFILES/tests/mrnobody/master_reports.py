"""Bounded outbound report transfer and real Flask download routes; no sockets/jobs."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

WEB=Path(__file__).resolve().parents[2]/"TESTFILES/ATTACKER-V2/web"
sys.path.insert(0,str(WEB))
from flask import Flask
from master_api import install_master_api
from master_registry import Registry, Unauthorized, MAX_REPORT_BYTES
from deployment_config import DeploymentConfig
import agent_client as agent


class Reports(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=WEB.parents[2])
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.db=self.root/"registry.sqlite3"
        self.store=Registry(self.db)
        self.token=self.store.issue("slave-1")
        self.store.register("slave-1",self.token,"Lab1")
        self.item=dict(id="MRN-test",status="complete",report_type="standalone_phase",phase_id="01",
                       started="2026-11-14T12:00:00Z",completed="2026-11-14T12:01:00Z")
        self.snapshot=dict(schema_version=1,report_type="standalone_phase",phase_id="01",
                           incident=dict(id="MRN-test",status="complete",started=self.item["started"],ended=self.item["completed"]),
                           secret="NEVER-COPY",note="<script>alert(1)</script>")
        self.store.sync_reports("slave-1",self.token,[self.item])
        self.config=DeploymentConfig("master","","loaded",True)
        self.app=Flask(__name__)
        install_master_api(self.app,lambda:self.config,self.db)
        self.client=self.app.test_client()
        self.url="/api/master/agents/slave-1/reports/MRN-test"

    def post(self,ident=None,content=None,token=None,peer="10.1.0.5"):
        return self.client.post("/api/master/agents/report-transfer",base_url="http://master.test",
            environ_overrides={"REMOTE_ADDR":peer},headers={"Authorization":"Bearer "+(token or self.token)},
            json=dict(agent_id="slave-1",protocol_version=1,report_id=ident,content=content))

    def get(self,suffix="",scheme="https",peer="10.1.0.5"):
        return self.client.get(self.url+suffix,base_url=scheme+"://master.test",environ_overrides={"REMOTE_ADDR":peer})

    def upload(self):
        self.assertEqual(self.post().json["report_id"],"MRN-test")
        response=self.post("MRN-test",self.snapshot)
        self.assertEqual(response.status_code,200)
        self.assertIsNone(response.json["report_id"])

    def test_outbound_transfer_persists_and_html_json_are_safe_and_identical(self):
        self.upload()
        cached=Registry(self.db).read_report("slave-1","MRN-test")
        self.assertNotIn("NEVER-COPY",cached["content"])
        response=self.get("?download=1")
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json,json.loads(cached["content"]))
        self.assertIn('attachment; filename="MRN-test.json"',response.headers["Content-Disposition"])
        self.assertEqual(hashlib.sha256(response.data).hexdigest(),response.headers["X-Report-SHA256"])
        self.assertEqual(response.headers["Cache-Control"],"no-store")
        page=self.get()
        self.assertEqual(page.status_code,200)
        self.assertIn("MrNobody Incident Report",page.text)
        self.assertNotIn("<script>",page.text)
        self.assertIn("sandbox",page.headers["Content-Security-Policy"])
        self.assertEqual(self.store.list_agents()[0]["available_reports"],["MRN-test"])
        self.assertIsNone(self.post().json["report_id"])

    def test_identity_revocation_scope_and_roles(self):
        self.assertEqual(self.get().status_code,404)
        self.assertEqual(self.post(token="x"*43).status_code,401)
        self.assertEqual(self.post(peer="198.51.100.2").status_code,403)
        self.upload()
        self.assertEqual(self.get(peer="198.51.100.2").status_code,403)
        self.assertEqual(self.get(scheme="http").status_code,403)
        other=self.store.issue("slave-2")
        self.store.register("slave-2",other,"Lab2")
        with self.assertRaises(Unauthorized):
            self.store.transfer_report("slave-2",self.token)
        self.assertIsNone(self.store.read_report("slave-2","MRN-test"))
        for role in ("agent","standalone"):
            self.config=DeploymentConfig(role,"","loaded",True)
            self.assertEqual(self.get().status_code,404)
            self.assertEqual(self.post().status_code,404)
        self.config=DeploymentConfig("master","","loaded",True)
        self.store.revoke("slave-1")
        self.assertEqual(self.post().status_code,401)
        self.assertEqual(self.get().status_code,404)

    def test_bad_unlisted_mismatched_running_and_oversize_snapshots(self):
        for ident in ("../secret","MRN-unlisted"):
            self.assertEqual(self.post(ident,self.snapshot).status_code,400)
        for key,value in (("schema_version",2),("incident",[])):
            invalid=copy.deepcopy(self.snapshot); invalid[key]=value
            self.assertEqual(self.post("MRN-test",invalid).status_code,400)
        invalid=copy.deepcopy(self.snapshot); invalid["incident"]["status"]="failed"
        self.assertEqual(self.post("MRN-test",invalid).status_code,400)
        invalid=copy.deepcopy(self.snapshot); invalid["note"]="x"*(MAX_REPORT_BYTES+4096)
        self.assertEqual(self.post("MRN-test",invalid).status_code,413)
        running=dict(self.item,status="running")
        self.store.sync_reports("slave-1",self.token,[running])
        self.assertIsNone(self.post().json["report_id"])
        self.assertEqual(self.post("MRN-test",self.snapshot).status_code,400)

    def test_inventory_change_prunes_cache_and_retries_missing_content(self):
        self.upload()
        self.store.sync_reports("slave-1",self.token,[dict(self.item,status="failed")])
        self.assertIsNone(self.store.read_report("slave-1","MRN-test"))
        self.assertEqual(self.post().json["report_id"],"MRN-test")
        self.store.sync_reports("slave-1",self.token,[])
        self.assertIsNone(self.post().json["report_id"])

    def test_agent_reads_only_bounded_named_regular_snapshots_and_scrubs(self):
        path=self.root/"MRN-test.json"
        path.write_text(json.dumps(self.snapshot))
        result=agent.read_report_snapshot("MRN-test",self.root)
        self.assertNotIn("secret",result)
        for ident in ("../registry","MRN-other","/etc/passwd"):
            with self.assertRaises((ValueError,OSError)):
                agent.read_report_snapshot(ident,self.root)
        path.write_bytes(b"x"*(MAX_REPORT_BYTES+1))
        with self.assertRaises(ValueError):
            agent.read_report_snapshot("MRN-test",self.root)
        path.unlink()
        try:
            path.symlink_to(self.db)
        except OSError:
            self.skipTest("Windows requires symlink privilege; Linux CI covers it.")
        with self.assertRaises(ValueError):
            agent.read_report_snapshot("MRN-test",self.root)

    def test_agent_refuses_requests_outside_its_finalized_inventory(self):
        sender=agent.AgentTransport(agent.AgentConfig("http://master.test","slave-1","Lab1",self.token,lab_http=True))
        with patch.object(agent,"collect_report_metadata",return_value=[self.item]), patch.object(sender,"post",side_effect=[{},dict(report_id="MRN-other")]), patch.object(agent,"read_report_snapshot") as read:
            with self.assertRaises(agent.FatalAgentError):
                sender.sync_reports()
            read.assert_not_called()

    def test_nginx_only_exact_transfer_routes_allow_larger_body(self):
        source=(WEB.parent/"nginx/nordic-incident.conf").read_text()
        self.assertEqual(source.count("location = /api/master/agents/report-transfer {"),2)
        self.assertEqual(source.count("client_max_body_size 2052k;"),2)


if __name__=="__main__":
    unittest.main()
