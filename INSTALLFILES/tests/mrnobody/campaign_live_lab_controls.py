"""Manual campaign Live Lab selection, fixed P03 source and bounded receipt; no targets."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock
from flask import Flask

BASE = Path(__file__).resolve().parents[2] / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
import app as web
import execution
import p06_live_lab as live
from p06_synthetic import create, fixture
from agent_client import AgentConfig, AgentTransport, FatalAgentError
from deployment_config import DeploymentConfig
from master_api import install_master_api
from master_registry import Registry


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = AgentConfig('https://master.lab', 'agent-1', 'Slave', 'x' * 43)
        self.attrs = dict(BASE_DIR=self.root, SCRIPT_DIR=BASE/'scripts', SCENARIO_DIR=BASE/'scenarios',
            STATE_DIR=self.root/'state', LOG_DIR=self.root/'logs', CAMPAIGN_LOG=self.root/'logs/campaign.log',
            CONFIG_FILE=BASE/'config/defaults.conf', campaign_process=None,
            DEPLOYMENT_CONFIG=DeploymentConfig('agent', 'https://master.lab', 'loaded'))

    def start(self, extra, form=False, sid='full-incident', inherited=None, paired=True):
        data = dict(incident_ip='192.168.1.10', ssh_password='runtime-only', rdp_password='windows-only', **extra)
        with patch.multiple(web, **self.attrs), patch.object(web, 'launch') as launch, \
             patch('agent_client.load_agent_config', return_value=self.config,
                   side_effect=None if paired else FatalAgentError('Missing Agent')), patch.dict(os.environ, inherited or {}):
            launch.return_value.pid = 123
            result = web.app.test_client().post('/api/scenario/' + sid + '/start', **({'data':data} if form else {'json':data}))
            return result, launch.call_args.kwargs['env'] if launch.called else None

    def inventory(self, env, platform='linux'):
        access = dict(authenticated=True, user='ubuntu' if platform == 'linux' else 'Administrator',
            protocol='ssh' if platform == 'linux' else 'winrm-https', port=2222 if platform == 'linux' else 5986,
            verification='ssh_session_marker' if platform == 'linux' else 'read_only_windows_identity',
            password='IGNORED-PERSISTED-PASSWORD')
        host = dict(ip='192.168.1.20', platform=platform, authenticated=True, compromised=True,
            access_methods={'ssh' if platform == 'linux' else 'winrm':access})
        path = self.root/'access.json'
        path.write_text(json.dumps(dict(producer='P03', schema_version=2, complete=True,
            run_mode='campaign', incident_id=env['NORDIC_INCIDENT_ID'], hosts=[host])))
        return dict(env, MRN_STARTED='0', NORDIC_BASE_DIR=str(self.root), NORDIC_COMPROMISED_STATE=str(path),
            NORDIC_SSH_USERNAME='ubuntu', NORDIC_RDP_USERNAME='Administrator',
            NORDIC_SSH_PASSWORD='runtime-only', NORDIC_RDP_PASSWORD='windows-only'), path

    def phase(self, env, pid='06'):
        return execution.phase_environment(pid, env, clock=lambda:0, sleep=lambda _:None)

    def test_json_and_multipart_opt_in_are_runtime_only(self):
        for form, value in ((False,True), (True,'true')):
            result, env = self.start(dict(p06_live_lab=value, p11_live_lab=value, beacon_count=1), form)
            self.assertEqual(result.status_code, 200, result.json)
            self.assertEqual(env['MRNOBODY_P06_CAMPAIGN_LIVE_LAB'], '1')
            self.assertTrue(json.loads(env['MRNOBODY_P11_LIVE_CONFIG'])['p11_live_lab'])
            for key in ('p06_live_lab', 'p11_live_lab', 'beacon_count'):
                self.assertNotIn(key, env['MRN_EXECUTION'])

    def test_default_false_and_inherited_flags_never_enable_receipts(self):
        inherited = dict(MRNOBODY_P06_CAMPAIGN_LIVE_LAB='1', MRNOBODY_P06_LIVE_LAB='1',
                         MRNOBODY_P11_LIVE_CONFIG='{"p11_live_lab":true}')
        for data, form in (({},False), ({'p06_live_lab':False,'p11_live_lab':False},False),
                           ({'p06_live_lab':'false','p11_live_lab':'false'},True)):
            result, env = self.start(data, form, inherited=inherited)
            self.assertEqual(result.status_code, 200)
            self.assertTrue(all(key not in env for key in inherited))

    def test_invalid_choices_never_launch(self):
        for data, form in (({'p06_live_lab':'true'},False), ({'p11_live_lab':'false'},False),
                ({'p06_live_lab':'on'},True), ({'p06_live_lab':True,'file':'/etc/shadow'},False),
                ({'p11_live_lab':True,'beacon_count':61},False)):
            result, env = self.start(data, form)
            self.assertEqual(result.status_code, 400, result.json)
            self.assertIsNone(env)
        result, env = self.start({'p06_live_lab':True}, sid='preset-recon-only')
        self.assertEqual(result.status_code, 400)
        self.assertIsNone(env)

    def test_only_p06_receives_selection_and_uses_verified_access_without_staging(self):
        _, original = self.start({'p06_live_lab':True})
        for platform in ('linux','windows'):
            env, _ = self.inventory(original, platform)
            p03 = self.phase(env, '03')
            self.assertNotIn('MRNOBODY_P06_CAMPAIGN_LIVE_LAB', p03)
            output = self.phase(env)
            self.assertEqual(output['MRNOBODY_RUN_MODE'], 'standalone')
            self.assertEqual(output['MRNOBODY_P06_LIVE_LAB'], '1')
            self.assertEqual(output['NORDIC_INCIDENT_IP'], '')
            self.assertEqual(output['MRNOBODY_TARGET'], '192.168.1.20')
            self.assertEqual(output['MRNOBODY_PROTOCOL'], 'ssh' if platform == 'linux' else 'winrm-https')
            self.assertEqual(output['MRNOBODY_PORT'], '2222' if platform == 'linux' else '5986')
            self.assertEqual(output['MRNOBODY_PASSWORD'], 'runtime-only' if platform == 'linux' else 'windows-only')
            self.assertNotIn('MRNOBODY_FILE', output)
            self.assertNotIn('MRNOBODY_REQUIRE_STAGING', output)
            self.assertNotIn('MRNOBODY_STAGING_INCIDENT', output)
            for path in (self.root/'logs').glob('*'):
                self.assertNotIn('IGNORED-PERSISTED-PASSWORD', path.read_text())
                self.assertNotIn('runtime-only', path.read_text())

    def test_stale_incomplete_or_changed_account_p03_cannot_select_a_source(self):
        _, base = self.start({'p06_live_lab':True})
        for change in ({'incident_id':'MRN-other'}, {'complete':False}, {'producer':'P05'}, {'schema_version':1}):
            env, path = self.inventory(base)
            data = json.loads(path.read_text()); data.update(change); path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): self.phase(env)
        env, _ = self.inventory(base)
        env['NORDIC_SSH_USERNAME'] = 'other'
        with self.assertRaises(ValueError): self.phase(env)

    def test_source_is_one_deterministic_host(self):
        _, base = self.start({'p06_live_lab':True})
        env, path = self.inventory(base)
        data = json.loads(path.read_text())
        other = json.loads(json.dumps(data['hosts'][0])); other['ip'] = '192.168.1.10'
        data['hosts'].append(other); path.write_text(json.dumps(data))
        self.assertEqual(self.phase(env)['MRNOBODY_TARGET'], '192.168.1.10')

    def test_generated_fixture_to_real_master_receipt_after_verified_transfer(self):
        _, base = self.start({'p06_live_lab':True})
        env, _ = self.inventory(base); env = self.phase(env)
        incident = env['NORDIC_INCIDENT_ID']; raw = fixture(incident)
        state = self.root/'state/exfiltration.json'; state.parent.mkdir(exist_ok=True)
        data = {key:env.get('MRNOBODY_' + key.upper(), '') for key in ('target','protocol','port','username','password')}
        def prepare(args, **options):
            folder = re.search(r"mkdir -- '([^']+)'", options['input'])[1]
            return SimpleNamespace(returncode=0, stdout=f'P06_CREATED|{folder}/corporate-secret-data.txt|{len(raw)}|{hashlib.sha256(raw).hexdigest()}\n')
        entry = create(data, incident, state, runner=prepare)
        uploads = self.root/'uploads'; uploads.mkdir()
        (uploads/f'{incident}-linux-{data["target"]}.bin').write_bytes(raw)
        entry.update(verified=True,successful=True)
        state.write_text(json.dumps(dict(incident_id=incident,transfers=[entry])))
        store = Registry(self.root/'master/registry.sqlite3'); token = store.issue('agent-1'); store.register('agent-1',token,'Slave')
        app = Flask('receipt'); install_master_api(app, lambda:SimpleNamespace(role='master',config_status='loaded',lab_http=False),store.path)
        class Opener:
            def open(inner, request, timeout):
                result = app.test_client().post('/api/master/agents/p06-file',base_url='https://master.lab',
                    data=request.data,headers=dict(request.header_items()))
                self.assertEqual(result.status_code,200)
                answer=io.BytesIO(result.data);answer.status=200;return answer
        transport=AgentTransport(AgentConfig('https://master.lab','agent-1','Slave',token),opener=Opener())
        ack=live.send(state,uploads,incident,transport)
        event,=store.list_receiver_events(campaign_id=incident)['events']
        self.assertTrue(ack['verified']); self.assertEqual(event['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(event['received_size'],len(raw)); self.assertEqual(event['phase'],'P06')

    def test_live_flags_cannot_be_saved_or_scheduled(self):
        for key in ('p06_live_lab','p11_live_lab'):
            with self.assertRaises(ValueError):
                web.planning.execution(dict(type='campaign',id='full-incident',**{key:True}))

    @unittest.skipUnless(os.name == 'posix', 'Linux process cancellation')
    def test_master_dns_hang_is_killed_and_reaped_on_deadline_and_stop(self):
        real = subprocess.Popen
        for cancelled in (False,True):
            children=[]; stop=threading.Event()
            def spawn(*args, **kwargs):
                child=real([sys.executable,'-c','import time; time.sleep(60)'],**kwargs)
                children.append(child);return child
            timer=threading.Timer(.15,stop.set) if cancelled else None
            if timer: timer.start()
            try:
                started=time.monotonic()
                with patch.object(live.subprocess,'Popen',side_effect=spawn),self.assertRaises(ValueError):
                    live.bounded_receipt({},self.config,stop,timeout=5 if cancelled else .15)
                self.assertLess(time.monotonic()-started,2)
                self.assertIsNotNone(children[0].poll())
            finally:
                if timer: timer.cancel()

    def test_stop_before_dispatch_never_spawns_a_worker(self):
        stop=threading.Event();stop.set()
        with patch.object(live.subprocess,'Popen') as child,self.assertRaises(ValueError):
            live.bounded_receipt({},self.config,stop)
        child.assert_not_called()

    def test_missing_pairing_and_ambiguous_form_selection_never_launch(self):
        result, env = self.start({'p06_live_lab':True}, paired=False)
        self.assertEqual(result.status_code,400);self.assertIsNone(env)
        from werkzeug.datastructures import MultiDict
        with patch.multiple(web,**self.attrs), patch.object(web,'launch') as launch:
            response=web.app.test_client().post('/api/start',data=MultiDict([
                ('p06_live_lab','true'),('p06_live_lab','false')]))
            self.assertEqual(response.status_code,400)
            launch.assert_not_called()

    def test_bounded_worker_identity_and_receipt_must_match(self):
        raw=fixture('MRN-worker-test')
        payload=dict(campaign_id='MRN-worker-test',phase='P06',size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        ack=dict(payload,agent_id=self.config.agent_id,verified=True)
        for change in ({}, {'agent_id':'other'}, {'master_url':'https://other.lab'}, {'ack':dict(ack,verified=False)}):
            result=dict(ack=ack,agent_id=self.config.agent_id,master_url=self.config.master_url,**{})
            result.update(change)
            child=Mock(stdin=io.BytesIO(),stdout=io.BytesIO(json.dumps(result).encode()),returncode=0)
            child.poll.return_value=0
            context=Mock(); context.__enter__=Mock(return_value=child); context.__exit__=Mock(return_value=False)
            with patch.object(live.subprocess,'Popen',return_value=context):
                if change:
                    with self.assertRaises(ValueError): live.bounded_receipt(payload,self.config)
                else:
                    self.assertEqual(live.bounded_receipt(payload,self.config),ack)


if __name__ == '__main__':
    unittest.main()
