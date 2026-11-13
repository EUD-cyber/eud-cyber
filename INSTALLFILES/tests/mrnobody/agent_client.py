"""Outbound agent tests. TLS handshakes use MemoryBIO, never real sockets."""
from dataclasses import replace
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import types
import unittest
import urllib.error
from urllib.parse import urlsplit
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
WEB=ROOT/"TESTFILES/ATTACKER-V2/web"
sys.path.insert(0,str(WEB))
import agent_client as agent
from deployment_config import DeploymentConfig

FIXTURES=Path(__file__).with_name("fixtures")
CERT=FIXTURES/"agent-test-cert.pem"
KEY=FIXTURES/"agent-test-key.pem"


class Response(io.BytesIO):
    status=200


class Stop:
    def __init__(self,after):
        self.after,self.waits,self.done=after,[],False
    def is_set(self):
        return self.done
    def wait(self,seconds):
        self.waits.append(seconds)
        if len(self.waits)>=self.after:
            self.done=True
        return self.done


class Sender:
    def __init__(self,steps):
        self.steps=iter(steps)
        self.calls=[]
    def post(self,kind):
        self.calls.append(kind)
        value=next(self.steps)
        if isinstance(value,Exception):
            raise value
        return value


def config(**changes):
    value=agent.AgentConfig("https://master.test","agent-1","Lab1-MrNobody","x"*43,str(CERT.resolve()))
    return replace(value,**changes)


def reply(kind="register",**changes):
    result=dict(agent_id="agent-1",protocol_version=1,server_time=100)
    result.update(dict(registered=True,heartbeat_interval=30) if kind=="register" else dict(accepted=True))
    result.update(changes)
    return result


class Configuration(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        assert self.root.resolve().parent==ROOT.resolve()
        self.path=self.root/"agent.json"
        self.deployment=DeploymentConfig("agent","https://master.test","loaded")

    def save(self,**changes):
        data=dict(agent_id="agent-1",token="x"*43,protocol_version=1,heartbeat_interval=30,ca_file=str(CERT.resolve()))
        data.update(changes)
        self.path.write_text(json.dumps(data),encoding="utf-8")
        self.path.chmod(0o600)

    def test_long_issued_id_keeps_identity_and_uses_bounded_default_display_name(self):
        self.save(agent_id="a"*64)
        loaded=agent.load_agent_config(self.path,self.deployment)
        self.assertEqual(loaded.agent_id,"a"*64)
        self.assertEqual(loaded.name,"a"*63)

    def test_http_mode_is_visible_in_check_output_without_any_network(self):
        self.save()
        output=io.StringIO()
        deployment=DeploymentConfig("agent","http://master.test","loaded",True)
        with patch.object(sys,"argv",["agent_client","--check","--credentials",str(self.path)]), \
             patch.object(agent,"load_deployment_config",return_value=deployment), \
             patch("sys.stdout",output):
            self.assertEqual(agent.main(),0)
        result=json.loads(output.getvalue())
        self.assertFalse(result["tls_verify"])
        self.assertTrue(result["lab_http"])
        self.assertNotIn("x"*43,output.getvalue())

    def test_operator_credential_response_can_be_loaded_without_exposing_key(self):
        self.save()
        loaded=agent.load_agent_config(self.path,self.deployment)
        self.assertEqual(loaded.name,"agent-1")
        self.assertNotIn("x"*43,repr(loaded))

    def test_wrong_role_or_missing_master_url_fails_before_reading_credentials(self):
        for deployment in (DeploymentConfig(),DeploymentConfig("master","","loaded"),
                           DeploymentConfig("agent","","loaded"),DeploymentConfig("agent","https://master.test","invalid")):
            with self.subTest(deployment=deployment),self.assertRaises(agent.FatalAgentError):
                agent.load_agent_config(self.path,deployment)

    def test_unknown_fields_weak_credentials_and_protocol_overrides_are_refused(self):
        for changes in (dict(token="weak"),dict(agent_id="../agent"),dict(name="<script>x</script>"),
                        dict(protocol_version=True),dict(heartbeat_interval=1),dict(insecure=True),
                        dict(ca_file="relative.pem"),dict(ca_file=False)):
            self.save(**changes)
            with self.subTest(changes=changes),self.assertRaises(agent.FatalAgentError):
                agent.load_agent_config(self.path,self.deployment)

    def test_oversized_or_nonprivate_credentials_are_refused(self):
        self.path.write_bytes(b"x"*8193)
        self.path.chmod(0o600)
        with self.assertRaises(agent.FatalAgentError):
            agent.load_agent_config(self.path,self.deployment)
        if os.name=="posix":
            self.save()
            self.path.chmod(0o644)
            with self.assertRaises(agent.FatalAgentError):
                agent.load_agent_config(self.path,self.deployment)


class Protocol(unittest.TestCase):
    def test_http_requires_explicit_lab_opt_in_and_https_stays_verified(self):
        opener=Mock()
        opener.open.return_value=Response(json.dumps(reply()).encode())
        transport=agent.AgentTransport(config(master_url="http://master.test",lab_http=True),opener)
        transport.post("register")
        self.assertEqual(opener.open.call_args.args[0].full_url,"http://master.test/api/master/agents/register")
        with self.assertRaises(agent.FatalAgentError):
            agent.AgentTransport(config(master_url="http://master.test"),Mock())
        secure=agent.AgentTransport(config(lab_http=True),Mock())
        self.assertTrue(secure.context.check_hostname)
        self.assertEqual(secure.context.verify_mode,ssl.CERT_REQUIRED)

    def test_https_post_headers_payload_and_prefix(self):
        opener=Mock()
        opener.open.return_value=Response(json.dumps(reply()).encode())
        client=agent.AgentTransport(config(master_url="https://master.test/prefix/"),opener)
        client.post("register")
        request=opener.open.call_args.args[0]
        self.assertEqual(request.full_url,"https://master.test/prefix/api/master/agents/register")
        self.assertEqual(request.get_method(),"POST")
        self.assertEqual(request.get_header("Authorization"),"Bearer "+"x"*43)
        self.assertEqual(json.loads(request.data),dict(agent_id="agent-1",name="Lab1-MrNobody",protocol_version=1))
        self.assertEqual(opener.open.call_args.kwargs["timeout"],10)
        self.assertTrue(client.context.check_hostname)
        self.assertEqual(client.context.verify_mode,ssl.CERT_REQUIRED)

    def test_insecure_url_invalid_port_and_redirects_are_refused(self):
        for url in ("http://master.test","https://user:secret@master.test","https://master.test:0","https://master.test:65536"):
            with self.subTest(url=url),self.assertRaises(agent.FatalAgentError):
                agent.AgentTransport(config(master_url=url),Mock())
        with self.assertRaises(agent.FatalAgentError):
            agent.NoRedirect().redirect_request(None,None,302,"redirect",{},"https://other.test/")

    def test_http_and_tls_failures_have_bounded_safe_categories(self):
        cases=[("heartbeat",409,agent.RegistrationRequired),("register",409,agent.FatalAgentError),
               ("register",401,agent.FatalAgentError),("heartbeat",403,agent.FatalAgentError),
               ("register",404,agent.FatalAgentError),("register",429,agent.RetryableAgentError),
               ("heartbeat",503,agent.RetryableAgentError)]
        for kind,status,error in cases:
            opener=Mock()
            opener.open.side_effect=urllib.error.HTTPError("https://master.test",status,"error",{},io.BytesIO(b"private body"))
            with self.subTest(status=status,kind=kind),self.assertRaises(error) as caught:
                agent.AgentTransport(config(),opener).post(kind)
            self.assertNotIn("private body",str(caught.exception))
            self.assertNotIn("x"*43,str(caught.exception))
        for reason,expected in ((TimeoutError(),agent.RetryableAgentError),
                                (ssl.SSLCertVerificationError("test"),agent.FatalAgentError)):
            opener=Mock()
            opener.open.side_effect=urllib.error.URLError(reason)
            with self.assertRaises(expected):
                agent.AgentTransport(config(),opener).post("register")

    def test_unexpected_identity_jobs_or_large_response_never_becomes_work(self):
        for body in (b"not JSON",b"x"*4097,json.dumps(reply(agent_id="other")).encode(),
                     json.dumps(reply(jobs=["forbidden"])).encode(),json.dumps(reply(server_time=True)).encode(),
                     json.dumps(reply(heartbeat_interval=1)).encode()):
            opener=Mock()
            opener.open.return_value=Response(body)
            with self.subTest(body_size=len(body)),self.assertRaises(agent.FatalAgentError):
                agent.AgentTransport(config(),opener).post("register")
        opener=Mock()
        opener.open.return_value=Response(json.dumps(reply("heartbeat")).encode())
        self.assertTrue(agent.AgentTransport(config(),opener).post("heartbeat")["accepted"])


class Reconnection(unittest.TestCase):
    def test_successful_heartbeats_do_not_log_each_interval_or_any_secret(self):
        sender=Sender([None,None,None])
        stop=Stop(3); messages=[]
        agent.run_loop(config(),sender=sender,stop=stop,write=messages.append)
        self.assertEqual(sender.calls,["register","heartbeat","heartbeat"])
        self.assertEqual(stop.waits,[30,30,30])
        self.assertEqual(messages,["Master registered.","Master online."])
        self.assertNotIn("x"*43,str(messages))

    def test_network_failures_back_off_and_reregister_after_recovery(self):
        sender=Sender([agent.RetryableAgentError(),None,None])
        stop=Stop(3)
        agent.run_loop(config(),sender=sender,stop=stop,jitter=lambda low,high:1,write=lambda text:None)
        self.assertEqual(sender.calls,["register","register","heartbeat"])
        self.assertEqual(stop.waits,[5,30,30])

    def test_backoff_is_capped_and_stop_interrupts_wait(self):
        sender=Sender([agent.RetryableAgentError() for _ in range(7)])
        stop=Stop(7)
        agent.run_loop(config(),sender=sender,stop=stop,jitter=lambda low,high:1,write=lambda text:None)
        self.assertEqual(stop.waits,[5,10,20,40,60,60,60])

    def test_registration_reset_and_fatal_errors_do_not_spin(self):
        sender=Sender([None,agent.RegistrationRequired(),None,None])
        stop=Stop(4)
        agent.run_loop(config(),sender=sender,stop=stop,write=lambda text:None)
        self.assertEqual(sender.calls,["register","heartbeat","register","heartbeat"])
        self.assertEqual(stop.waits,[30,5,30,30])
        stop=Stop(1)
        with self.assertRaises(agent.FatalAgentError):
            agent.run_loop(config(),sender=Sender([agent.FatalAgentError("revoked")]),stop=stop)
        self.assertEqual(stop.waits,[])


def handshake(client_context,hostname):
    server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(CERT,KEY)
    ci,co,si,so=ssl.MemoryBIO(),ssl.MemoryBIO(),ssl.MemoryBIO(),ssl.MemoryBIO()
    client=client_context.wrap_bio(ci,co,server_side=False,server_hostname=hostname)
    server=server_context.wrap_bio(si,so,server_side=True)
    client_done=server_done=False
    for _ in range(20):
        if not client_done:
            try:
                client.do_handshake(); client_done=True
            except ssl.SSLWantReadError:
                pass
        if co.pending:
            si.write(co.read())
        if not server_done:
            try:
                server.do_handshake(); server_done=True
            except ssl.SSLWantReadError:
                pass
        if so.pending:
            ci.write(so.read())
        if client_done and server_done:
            return
    raise AssertionError("In-memory TLS handshake did not complete")


class TLS(unittest.TestCase):
    def test_trusted_ca_and_matching_hostname_complete_real_tls_handshake(self):
        handshake(agent.AgentTransport(config(),Mock()).context,"master.test")

    def test_wrong_hostname_or_untrusted_ca_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            handshake(agent.AgentTransport(config(),Mock()).context,"other.test")
        with self.assertRaises(ssl.SSLCertVerificationError):
            handshake(ssl.create_default_context(),"master.test")


class MasterRoundtrip(unittest.TestCase):
    def setUp(self):
        from master_registry import Registry
        fake=types.ModuleType("flask")
        fake.jsonify=lambda value:value
        fake.request=types.SimpleNamespace()
        with patch.dict(sys.modules,{"flask":fake}):
            spec=importlib.util.spec_from_file_location("agent_master_adapter",WEB/"master_api.py")
            self.api=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.api)
        self.temporary=tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        assert self.root.resolve().parent==ROOT.resolve()
        self.path=self.root/"master"/"registry.sqlite3"
        self.store=Registry(self.path,clock=lambda:100)
        self.token=self.store.issue("agent-1")
        self.master_http=False
        self.routes={}
        outer=self
        class App:
            def route(self,url,**options):
                def register(fn):
                    outer.routes[url]=fn
                    return fn
                return register
        self.api.install_master_api(App(),lambda:DeploymentConfig("master","","loaded",self.master_http),self.path)

    def opener(self):
        outer=self
        class Opener:
            def open(self,request,timeout):
                parsed=urlsplit(request.full_url)
                incoming=types.SimpleNamespace(is_secure=parsed.scheme=="https",remote_addr="198.51.100.8",
                    headers={"Authorization":request.get_header("Authorization")},is_json=True,
                    content_length=len(request.data),stream=io.BytesIO(request.data))
                with patch.object(outer.api,"request",incoming):
                    body,status=outer.routes[parsed.path]()
                raw=json.dumps(body).encode()
                if status!=200:
                    raise urllib.error.HTTPError(request.full_url,status,"refused",{},io.BytesIO(raw))
                return Response(raw)
        return Opener()

    def test_https_client_and_actual_registry_handlers_agree(self):
        sender=agent.AgentTransport(config(token=self.token),self.opener())
        sender.post("register")
        sender.post("heartbeat")
        self.assertEqual(self.store.list_agents()[0]["status"],"online")
        self.store.revoke("agent-1")
        with self.assertRaises(agent.FatalAgentError):
            sender.post("heartbeat")

    def test_http_is_accepted_only_when_both_sides_explicitly_opt_in(self):
        with self.assertRaises(agent.FatalAgentError):
            agent.AgentTransport(config(master_url="http://master.test",token=self.token),self.opener())
        sender=agent.AgentTransport(config(master_url="http://master.test",token=self.token,lab_http=True),self.opener())
        with self.assertRaises(agent.FatalAgentError):
            sender.post("register")
        self.assertEqual(self.store.list_agents()[0]["status"],"pending")
        self.master_http=True
        sender.post("register")
        sender.post("heartbeat")
        self.assertEqual(self.store.list_agents()[0]["status"],"online")


class Service(unittest.TestCase):
    def test_http_nginx_exposes_only_exact_agent_endpoints_and_overwrites_proto(self):
        text=(WEB.parent/"nginx/nordic-incident.conf").read_text()
        http=text.split("server {",2)[1]
        self.assertIn("location / { return 301 https://$host$request_uri; }",http)
        for endpoint in ("register","heartbeat"):
            block=http.split("location = /api/master/agents/"+endpoint+" {",1)[1].split("}",1)[0]
            self.assertIn("proxy_set_header X-Forwarded-Proto http;",block)
            self.assertIn("client_max_body_size 4k;",block)
            self.assertIn("proxy_pass http://127.0.0.1:8082;",block)

    def test_unit_is_opt_in_and_restart_stops_on_permanent_errors(self):
        unit=(WEB.parent/"systemd/mrnobody-agent.service").read_text()
        self.assertIn("ConditionPathExists=/etc/mrnobody/agent.json",unit)
        self.assertIn("RestartPreventExitStatus=2",unit)
        self.assertIn("ProtectSystem=strict",unit)
        self.assertIn("NoNewPrivileges=true",unit)
        userdata=(ROOT/"MRNOBODY/mrnobody_userdata.yaml").read_text(encoding="utf-8")
        self.assertNotIn("systemctl enable mrnobody-agent",userdata)
        self.assertNotIn("systemctl start mrnobody-agent",userdata)


if __name__=="__main__":
    unittest.main()
