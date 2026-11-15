"""Isolated Flask/SQLite receiver tests; no listeners, services or VM operations."""
import io
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from flask import Flask

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"TESTFILES/ATTACKER-V2/web"))
from master_api import install_master_api
from master_registry import Registry

URL="/api/master/receiver/events"


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"master"/"registry.sqlite3"
        self.store=Registry(self.path,clock=lambda:100)
        self.token=self.store.issue("agent-1")
        self.store.register("agent-1",self.token,"Lab1")
        self.config=types.SimpleNamespace(role="master",config_status="loaded",lab_http=False)
        self.app=Flask(__name__)
        self.app.testing=True
        install_master_api(self.app,lambda:self.config,self.path)
        self.client=self.app.test_client()
        self.data=dict(protocol_version=1,agent_id="agent-1",campaign_id="MRN-test-1",
                       event_type="http_test",timestamp="2026-11-15T12:30:00+01:00",bytes=128,synthetic=True)

    def post(self,data=None,token=None,base="https://master.test",peer="10.1.2.3",headers=None,**kwargs):
        auth={"Authorization":"Bearer "+(self.token if token is None else token)}
        auth.update(headers or {})
        if isinstance(data,bytes):
            kwargs["data"]=data
        else:
            kwargs["json"]=self.data if data is None else data
        return self.client.post(URL,base_url=base,headers=auth,
                                environ_overrides={"REMOTE_ADDR":peer},**kwargs)

    def rows(self):
        with sqlite3.connect(self.path) as db:
            db.row_factory=sqlite3.Row
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='receiver_events'").fetchone():
                return []
            return [dict(row) for row in db.execute("SELECT * FROM receiver_events ORDER BY id")]

    def test_commit_persistence_utc_receipt_and_no_heartbeat_side_effect(self):
        before=self.store.list_agents()
        response=self.post()
        self.assertEqual(response.status_code,200)
        result=response.get_json()
        row,=self.rows()
        self.assertEqual(row,dict(id=result["event_id"],agent_id="agent-1",campaign_id="MRN-test-1",
                                  event_type="http_test",timestamp="2026-11-15T11:30:00+00:00",
                                  bytes=128,received_at=result["received_at"],status="received"))
        self.assertTrue(result["accepted"])
        self.assertEqual(Registry(self.path,clock=lambda:100).list_agents(),before)
        self.assertNotIn(self.token.encode(),self.path.read_bytes())
        self.assertNotIn(self.token,response.get_data(as_text=True))
        # A newly installed app/registry instance still sees the committed event.
        other=Flask("restarted")
        install_master_api(other,lambda:self.config,self.path)
        self.assertEqual(len(self.rows()),1)
        second=other.test_client().post(URL,base_url="https://master.test",
            headers={"Authorization":"Bearer "+self.token},json=self.data,
            environ_overrides={"REMOTE_ADDR":"10.1.2.3"})
        self.assertEqual(second.status_code,200)
        self.assertEqual(self.rows()[0],row)
        self.assertNotEqual(second.get_json()["event_id"],row["id"])
        self.assertEqual(self.store.heartbeat("agent-1",self.token)["accepted"],True)

    def test_event_types_boundaries_and_retry_appends_receipts(self):
        for kind,count in (("http_test",0),("beacon",2**31-1),("exfil",1)):
            for _ in range(2):
                self.assertEqual(self.post(dict(self.data,event_type=kind,bytes=count)).status_code,200)
        self.assertEqual(len(self.rows()),6)
        self.assertEqual(len({r["id"] for r in self.rows()}),6)

    def test_authentication_bound_to_registered_nonrevoked_agent(self):
        self.assertEqual(self.post(token="x"*43).status_code,401)
        self.assertEqual(self.post(dict(self.data,agent_id="unknown")).status_code,401)
        pending=self.store.issue("pending")
        self.assertEqual(self.post(dict(self.data,agent_id="pending"),token=pending).status_code,409)
        self.store.revoke("agent-1")
        self.assertEqual(self.post().status_code,401)
        self.assertEqual(self.rows(),[])

    def test_inactive_roles_and_invalid_configs_do_not_initialize_receiver(self):
        for role,status in (("agent","loaded"),("standalone","loaded"),("master","invalid"),("master","default")):
            self.config.role,self.config.config_status=role,status
            self.assertEqual(self.post().status_code,404)
        self.assertEqual(self.rows(),[])

    def test_lab_network_https_http_opt_in_and_untrusted_forwarding(self):
        self.assertEqual(self.post(base="http://master.test").status_code,403)
        self.config.lab_http=True
        self.assertEqual(self.post(base="http://master.test").status_code,200)
        for peer,headers in (("8.8.8.8",{}),("8.8.8.8",{"X-Real-IP":"10.0.0.1"}),
                             ("127.0.0.1",{"X-Real-IP":"8.8.8.8"}),
                             ("127.0.0.1",{"X-Real-IP":"invalid"})):
            self.assertEqual(self.post(peer=peer,headers=headers).status_code,403)
        self.config.lab_http=False
        self.assertEqual(self.post(base="http://master.test",headers={"X-Forwarded-Proto":"https"}).status_code,403)
        self.assertEqual(self.post(base="http://master.test",peer="127.0.0.1",
                                  headers={"X-Forwarded-Proto":"https","X-Real-IP":"10.0.0.1"}).status_code,200)

    def test_strict_schema_metadata_only_and_invalid_values(self):
        bad=[{},[],dict(self.data,command="id"),dict(self.data,payload="secret"),
             dict(self.data,status="received"),dict(self.data,received_at=1)]
        for key,values in {
            "agent_id":["../escape",None,[]], "campaign_id":["",None,[],"../escape","x"*102],
            "event_type":["command",{},[],None], "protocol_version":[True,0,"1"],
            "synthetic":[False,1,"true"], "bytes":[True,-1,2**31,1.5,"128",None],
            "timestamp":[None,[],"", "2026-11-15T12:30:00", "2026-02-30T12:00:00Z",
                         "2026-11-15T12:00:00+24:00","2026-11-15T12:00:00+01:60",
                         "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"]
        }.items():
            bad.extend(dict(self.data,**{key:v}) for v in values)
        for data in bad:
            with self.subTest(data=data):
                self.assertEqual(self.post(data).status_code,400)
        self.assertEqual(self.rows(),[])

    def test_json_duplicates_malformed_and_size_limits(self):
        for raw in (b'no JSON',b'\xff',b'{"bytes":1,"bytes":2}',b'{"bytes":NaN}'):
            self.assertEqual(self.post(data=raw,content_type="application/json").status_code,400)
        self.assertEqual(self.post(data=b"x",content_type="text/plain").status_code,415)
        self.assertEqual(self.post(data=b"x"*4097,content_type="application/json").status_code,413)
        # WSGI terminated stream covers a body without Content-Length.
        response=self.client.open(URL,method="POST",base_url="https://master.test",
            headers={"Authorization":"Bearer "+self.token,"Content-Type":"application/json"},
            environ_overrides={"REMOTE_ADDR":"10.0.0.1","wsgi.input":io.BytesIO(b"x"*4097),
                               "wsgi.input_terminated":True,"CONTENT_LENGTH":""})
        self.assertEqual(response.status_code,413)
        self.assertEqual(self.rows(),[])

    def test_method_restriction_and_storage_failure_never_acknowledged(self):
        self.assertEqual(self.client.delete(URL).status_code,405)
        self.assertEqual(self.client.put(URL).status_code,405)
        with patch.object(Registry,"receive_event",side_effect=sqlite3.OperationalError("private details")):
            result=self.post()
            self.assertEqual(result.status_code,503)
            self.assertNotIn("private details",result.get_data(as_text=True))
        self.path.unlink()
        self.assertEqual(self.post().status_code,503)
        self.assertFalse(self.path.exists())

    def test_concurrent_receipts_are_persisted_without_lost_rows(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _:Registry(self.path).receive_event(self.data,self.token),range(12)))
        self.assertEqual(len(self.rows()),12)
        self.assertEqual(len({r["event_id"] for r in results}),12)

    def test_failed_insert_rolls_back_and_does_not_acknowledge(self):
        self.assertEqual(self.post().status_code,200)
        before=self.rows()
        with sqlite3.connect(self.path) as db:
            db.execute("""CREATE TRIGGER receiver_failure BEFORE INSERT ON receiver_events
                BEGIN SELECT RAISE(ABORT, 'test disk failure'); END""")
        result=self.post()
        self.assertEqual(result.status_code,503)
        self.assertEqual(self.rows(),before)

    def test_http_proxy_path_preserves_lab_boundary_and_body_limit(self):
        source=(ROOT/"TESTFILES/ATTACKER-V2/nginx/nordic-incident.conf").read_text()
        block=source.split("location = "+URL+" {",1)[1].split("}",1)[0]
        for expected in ("client_max_body_size 4k;","X-Real-IP $remote_addr;","X-Forwarded-Proto http;"):
            self.assertIn(expected,block)


if __name__=="__main__":
    unittest.main()
