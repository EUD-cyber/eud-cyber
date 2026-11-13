"""Offline registry and actual route-handler tests, without Flask or network."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
WEB=ROOT/"TESTFILES/ATTACKER-V2/web"
sys.path.insert(0,str(WEB))
import master_registry as registry_module
from master_registry import Registry,Unauthorized,Conflict,Unavailable,HEARTBEAT_INTERVAL

fake_flask=types.ModuleType("flask")
fake_flask.jsonify=lambda value:value
fake_flask.request=types.SimpleNamespace()
with patch.dict(sys.modules,{"flask":fake_flask}):
    spec=importlib.util.spec_from_file_location("registry_api_under_test",WEB/"master_api.py")
    api=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)


class RegistryCases(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        assert self.root.resolve().parent==ROOT.resolve()
        self.path=self.root/"private"/"registry.sqlite3"
        self.now=100
        self.store=Registry(self.path,clock=lambda:self.now)

    def test_construction_and_unauthorized_missing_store_do_not_create_files(self):
        self.assertFalse(self.path.exists())
        with self.assertRaises(Unavailable):
            self.store.heartbeat("agent-1","x"*43)
        self.assertFalse(self.path.exists())

    def test_issue_stores_hash_only_and_private_permissions(self):
        token=self.store.issue("agent-1")
        self.assertEqual(len(token),43)
        self.assertNotIn(token.encode(),self.path.read_bytes())
        entry,=self.store.list_agents()
        self.assertEqual(entry["status"],"pending")
        self.assertNotIn("token",entry)
        self.assertNotIn("token_hash",entry)
        if os.name=="posix":
            self.assertEqual(self.path.stat().st_mode&0o777,0o600)
            self.assertEqual(self.path.parent.stat().st_mode&0o777,0o700)

    def test_duplicate_issue_does_not_replace_existing_credentials(self):
        token=self.store.issue("agent-1")
        with self.assertRaises(Conflict):
            self.store.issue("agent-1")
        self.store.register("agent-1",token,"Lab1-MrNobody")

    def test_registration_is_idempotent_and_persists_across_instances(self):
        token=self.store.issue("agent-1")
        result=self.store.register("agent-1",token,"Lab1-MrNobody")
        self.assertEqual(result["heartbeat_interval"],HEARTBEAT_INTERVAL)
        self.now=130
        self.store.register("agent-1",token,"Lab1-Renamed")
        entry,=Registry(self.path,clock=lambda:130).list_agents()
        self.assertEqual(entry["registered_at"],100)
        self.assertEqual(entry["last_seen_at"],130)
        self.assertEqual(entry["name"],"Lab1-Renamed")

    def test_token_is_bound_to_issued_agent_and_unknown_agents_cannot_enroll(self):
        one=self.store.issue("agent-1")
        two=self.store.issue("agent-2")
        for agent_id,token in (("agent-2",one),("unknown",one),("agent-1",two),("agent-1","x"*43)):
            with self.subTest(agent=agent_id),self.assertRaises(Unauthorized):
                self.store.register(agent_id,token,"MrNobody")
        self.assertTrue(all(row["status"]=="pending" for row in self.store.list_agents()))

    def test_heartbeat_requires_registration_and_uses_server_time(self):
        token=self.store.issue("agent-1")
        with self.assertRaises(Conflict):
            self.store.heartbeat("agent-1",token)
        self.store.register("agent-1",token,"Lab1")
        self.now=131
        self.assertEqual(self.store.heartbeat("agent-1",token)["server_time"],131)
        self.now=120
        self.assertEqual(self.store.heartbeat("agent-1",token)["server_time"],131)

    def test_online_offline_and_revocation(self):
        token=self.store.issue("agent-1")
        self.store.register("agent-1",token,"Lab1")
        self.now=191
        self.assertEqual(self.store.list_agents()[0]["status"],"offline")
        self.store.heartbeat("agent-1",token)
        self.assertEqual(self.store.list_agents()[0]["status"],"online")
        self.store.revoke("agent-1")
        for operation in (lambda:self.store.register("agent-1",token,"Lab1"),
                          lambda:self.store.heartbeat("agent-1",token)):
            with self.assertRaises(Unauthorized):
                operation()
        self.assertEqual(self.store.list_agents()[0]["status"],"revoked")

    def test_invalid_id_or_name_never_creates_an_unissued_identity(self):
        for agent_id in ("","../agent","Agent-UPPER","x"*65,"bad';drop table agents;"):
            with self.subTest(agent=agent_id),self.assertRaises(ValueError):
                self.store.issue(agent_id)
        self.assertFalse(self.path.exists())
        token=self.store.issue("agent-1")
        for name in ("","<script>bad()</script>","name with space","x"*64):
            with self.subTest(name=name),self.assertRaises(ValueError):
                self.store.register("agent-1",token,name)
        self.assertEqual(self.store.list_agents()[0]["status"],"pending")

    def test_cli_is_master_only_and_does_not_issue_on_agents(self):
        deployment=types.ModuleType("deployment_config")
        deployment.load_deployment_config=lambda:types.SimpleNamespace(role="agent",config_status="loaded")
        with patch.object(sys,"argv",["master_registry","issue","agent-1"]), \
             patch.object(registry_module.os,"geteuid",return_value=0,create=True), \
             patch.dict(sys.modules,{"deployment_config":deployment}), \
             patch("sys.stderr",io.StringIO()),patch.object(registry_module,"Registry") as factory:
            with self.assertRaises(SystemExit):
                registry_module.main()
            factory.assert_not_called()

    def test_cli_issues_one_credential_response_only_after_master_gate(self):
        deployment=types.ModuleType("deployment_config")
        deployment.load_deployment_config=lambda:types.SimpleNamespace(role="master",config_status="loaded")
        fake=types.SimpleNamespace(issue=lambda agent_id:"x"*43)
        output=io.StringIO()
        with patch.object(sys,"argv",["master_registry","issue","agent-1"]), \
             patch.object(registry_module.os,"geteuid",return_value=0,create=True), \
             patch.dict(sys.modules,{"deployment_config":deployment}), \
             patch("sys.stdout",output),patch.object(registry_module,"Registry",return_value=fake):
            self.assertEqual(registry_module.main(),0)
        self.assertEqual(len(output.getvalue().splitlines()),1)
        self.assertEqual(json.loads(output.getvalue())["agent_id"],"agent-1")

    def test_concurrent_heartbeats_do_not_lose_newer_last_seen(self):
        token=self.store.issue("agent-1")
        self.store.register("agent-1",token,"Lab1")
        def send(value):
            return Registry(self.path,clock=lambda:value).heartbeat("agent-1",token)
        with ThreadPoolExecutor(max_workers=4) as executor:
            results=list(executor.map(send,range(110,122)))
        self.assertEqual(len(results),12)
        self.assertEqual(self.store.list_agents()[0]["last_seen_at"],121)


class API(unittest.TestCase):
    def setUp(self):
        RegistryCases.setUp(self)
        self.routes={}
        self.methods={}
        routes,methods=self.routes,self.methods
        class App:
            def route(self,url,**options):
                def decorate(function):
                    routes[url]=function
                    methods[url]=options["methods"]
                    return function
                return decorate
        self.config=types.SimpleNamespace(role="master",config_status="loaded")
        api.install_master_api(App(),lambda:self.config,self.path)
        self.token=self.store.issue("agent-1")

    def call(self,kind="register",data=None,*,raw=None,token=None,secure=True,remote="198.51.100.8",forwarded=None,length="auto",is_json=True):
        if data is None:
            data=dict(agent_id="agent-1",protocol_version=1)
            if kind=="register":
                data["name"]="Lab1"
        body=json.dumps(data).encode() if raw is None else raw
        headers={"Authorization":"Bearer "+(self.token if token is None else token)}
        if forwarded is not None:
            headers["X-Forwarded-Proto"]=forwarded
        request=types.SimpleNamespace(is_secure=secure,remote_addr=remote,headers=headers,is_json=is_json,
                                     content_length=len(body) if length=="auto" else length,stream=io.BytesIO(body))
        with patch.object(api,"request",request):
            return self.routes["/api/master/agents/"+kind]()

    def test_real_flask_adapter_when_dependencies_are_available(self):
        try:
            from flask import Flask,jsonify,request
        except ImportError:
            self.skipTest("Real Flask adapter runs in CI with the existing dependencies")
        app=Flask("master-registry-integration")
        api.install_master_api(app,lambda:self.config,self.path)
        headers={"Authorization":"Bearer "+self.token}
        with patch.object(api,"jsonify",jsonify),patch.object(api,"request",request):
            client=app.test_client()
            response=client.post("/api/master/agents/register",base_url="https://master.test",
                                 headers=headers,json=dict(agent_id="agent-1",name="Lab1",protocol_version=1))
            self.assertEqual(response.status_code,200)
            self.assertTrue(response.get_json()["registered"])
            response=client.post("/api/master/agents/heartbeat",base_url="https://master.test",
                                 headers=headers,json=dict(agent_id="agent-1",protocol_version=1))
            self.assertEqual(response.status_code,200)
            self.assertNotIn(self.token,response.get_data(as_text=True))
            self.assertEqual(client.get("/api/master/agents/heartbeat",base_url="https://master.test").status_code,405)

    def test_api_register_heartbeat_roundtrip_and_only_two_post_routes(self):
        result,status=self.call()
        self.assertEqual(status,200)
        self.assertTrue(result["registered"])
        self.assertNotIn(self.token,json.dumps(result))
        result,status=self.call("heartbeat")
        self.assertEqual(status,200)
        self.assertTrue(result["accepted"])
        self.assertEqual(len(self.routes),2)
        self.assertTrue(all(value==["POST"] for value in self.methods.values()))

    def test_role_gating_keeps_standalone_agent_and_invalid_config_inactive(self):
        for role,status in (("standalone","loaded"),("agent","loaded"),("master","invalid"),("master","default")):
            self.config.role,self.config.config_status=role,status
            with self.subTest(role=role,status=status):
                self.assertEqual(self.call()[1],404)
        self.assertEqual(self.store.list_agents()[0]["status"],"pending")

    def test_tls_is_required_and_forwarded_proto_only_trusted_from_loopback(self):
        self.assertEqual(self.call(secure=False)[1],403)
        self.assertEqual(self.call(secure=False,forwarded="https")[1],403)
        self.assertEqual(self.call(secure=False,remote="127.0.0.1",forwarded="https")[1],200)
        self.assertEqual(self.call(secure=False,remote="127.0.0.1",forwarded="http")[1],403)

    def test_wrong_unknown_and_revoked_keys_are_unauthorized(self):
        self.assertEqual(self.call(token="x"*43)[1],401)
        self.assertEqual(self.call(data=dict(agent_id="unknown",name="Lab1",protocol_version=1))[1],401)
        self.store.revoke("agent-1")
        self.assertEqual(self.call()[1],401)

    def test_payload_schema_protocol_and_duplicate_keys_are_rejected(self):
        bad=[{},[],dict(agent_id="agent-1",name="Lab1",protocol_version=True),
             dict(agent_id="agent-1",name="Lab1",protocol_version=2),
             dict(agent_id="agent-1",name="Lab1",protocol_version=1,token="not allowed"),
             dict(agent_id="../agent",name="Lab1",protocol_version=1)]
        for data in bad:
            with self.subTest(data=data):
                self.assertEqual(self.call(data=data)[1],400)
        self.assertEqual(self.call(raw=b'{"agent_id":"agent-1","agent_id":"other","name":"Lab1","protocol_version":1}')[1],400)
        self.assertEqual(self.call(raw=b'not JSON')[1],400)

    def test_body_limit_is_enforced_even_without_content_length(self):
        self.assertEqual(self.call(raw=b"x"*4097)[1],413)
        self.assertEqual(self.call(raw=b"x"*4097,length=None)[1],413)
        self.assertEqual(self.call(is_json=False)[1],415)

    def test_heartbeat_before_registration_is_a_conflict(self):
        self.assertEqual(self.call("heartbeat")[1],409)

    def test_missing_or_broken_registry_does_not_auto_initialize(self):
        missing=self.path.parent/"missing.sqlite3"
        self.path=missing
        # Install a fresh handler pointing at the missing file.
        class App:
            def route(inner,url,**options):
                def register(fn):
                    self.routes[url]=fn
                    return fn
                return register
        api.install_master_api(App(),lambda:self.config,missing)
        self.assertEqual(self.call()[1],503)
        self.assertFalse(missing.exists())


if __name__=="__main__":
    unittest.main()
