"""Campaign opt-in to fixed P11 receipts; no real SSH/WinRM targets."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[2] / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
import app as web
import execution
import p11_live_lab as live
import remote_actions
from agent_client import AgentConfig, AgentTransport, FatalAgentError
from flask import Flask
from master_api import install_master_api
from master_registry import Registry
from werkzeug.serving import make_server


class CampaignLiveLab(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.attrs = dict(BASE_DIR=self.root, SCRIPT_DIR=BASE/'scripts',
            SCENARIO_DIR=BASE/'scenarios', STATE_DIR=self.root/'state',
            LOG_DIR=self.root/'logs', CAMPAIGN_LOG=self.root/'logs/campaign.log',
            CONFIG_FILE=BASE/'config/defaults.conf', campaign_process=None)

    def start(self, data, sid='full-incident', **extra):
        with patch.multiple(web, **self.attrs), patch.object(web, 'launch') as launch, \
             patch('agent_client.load_agent_config', return_value=object()), \
             patch.dict(os.environ, extra):
            launch.return_value.pid = 123
            response = web.app.test_client().post('/api/scenario/'+sid+'/start',
                json=dict(ssh_password='fixture-only', rdp_password='fixture-only',
                          incident_ip='192.168.1.10', **data))
            env = launch.call_args.kwargs['env'] if launch.called else None
            return response, env

    def inventory(self, env):
        hosts = [dict(ip='192.168.1.20', platform='linux', authenticated=True,
            compromised=True, access_methods={'ssh': dict(authenticated=True,
                protocol='ssh', port=22, user='ubuntu', verification='ssh_session_marker')})]
        path = self.root/'access.json'
        path.write_text(json.dumps(dict(producer='P03', schema_version=2, complete=True,
            run_mode='campaign', incident_id=env['NORDIC_INCIDENT_ID'], hosts=hosts)))
        return dict(env, NORDIC_COMPROMISED_STATE=str(path), MRNOBODY_RUN_MODE='campaign',
                    NORDIC_BASE_DIR=str(self.root), NORDIC_SSH_USERNAME='ubuntu',
                    NORDIC_SSH_PASSWORD='fixture-only')

    def invoke(self, *args, **kwargs):
        # Existing campaign retains its fixed target methods and disabled DNS default.
        self.assertEqual(kwargs['env']['MRNOBODY_PERSISTENCE_DNS'], 'disabled')
        return SimpleNamespace(returncode=0, stdout=b'{"result":"success"}')

    def test_full_api_to_campaign_to_real_http_master_receipt(self):
        response, env = self.start(dict(p11_live_lab=True, beacon_count=1,
            profile={'mode':'normal'}))
        self.assertEqual(response.status_code, 200, response.json)
        env['MRN_STARTED'] = '0'
        env = execution.phase_environment('11', env, sleep=lambda _:None, clock=lambda:0)
        self.assertEqual(env['MRNOBODY_RUN_MODE'], 'campaign')
        env = self.inventory(env)
        store = Registry(self.root/'master.sqlite3')
        token = store.issue('slave-1'); store.register('slave-1', token, 'Slave')
        app = Flask(__name__)
        install_master_api(app, lambda: SimpleNamespace(role='master', config_status='loaded', lab_http=True), store.path)
        server = make_server('127.0.0.1', 0, app)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        config = AgentConfig(f'http://localhost:{server.server_port}', 'slave-1', 'Slave', token, lab_http=True)
        sender = AgentTransport(config)
        original_loop = live.run_loop
        def loop(*args, **kwargs):
            return original_loop(*args, **kwargs, post=lambda payload, *_: sender.post('p11-beacon', p11=payload))
        try:
            with patch('agent_client.load_agent_config', return_value=config), \
                 patch.object(live, 'run_loop', side_effect=loop), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(remote_actions.run('11', env, self.invoke), 0)
        finally:
            server.shutdown(); worker.join(); server.server_close()
        event, = store.list_receiver_events(agent_id='slave-1', campaign_id=env['NORDIC_INCIDENT_ID'])['events']
        self.assertEqual((event['phase'], event['sequence'], event['verified']), ('P11', 1, True))
        truth = (self.root/'logs/incident-ground-truth.log').read_text()
        self.assertIn('P11_BEACON_ACK', truth)
        self.assertIn('event_id=' + str(event['id']), truth)
        self.assertIn(env['NORDIC_INCIDENT_ID'], truth)
        self.assertIn('PHASE_COMPLETE', truth)

    def test_default_false_and_inherited_flags_never_enable_live(self):
        for data in ({}, {'p11_live_lab':False}):
            response, env = self.start(data, MRNOBODY_P11_LIVE_CONFIG='{"p11_live_lab":true}',
                                       MRNOBODY_P06_LIVE_LAB='1')
            self.assertEqual(response.status_code, 200, response.json)
            self.assertNotIn('MRNOBODY_P11_LIVE_CONFIG', env)
            self.assertNotIn('MRNOBODY_P06_LIVE_LAB', env)
            with patch.object(live, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(remote_actions.run('11', self.inventory(env), self.invoke), 0)
                run.assert_not_called()

    def test_selection_validation_and_phase_scope(self):
        for change in ({'p11_live_lab':'true'}, {'p11_live_lab':True, 'beacon_count':99},
                       {'p11_live_lab':True, 'action':'cleanup'}, {'live_lab':True}, {'p06_live_lab':'true'}):
            response, env = self.start(change)
            self.assertEqual(response.status_code, 400, response.json); self.assertIsNone(env)
        definition = dict(phases=[{'id':'03'}, {'id':'11'}])
        for phases in ([{'id':'03'}], [{'id':'11'}], [{'id':'03'}, {'id':'11', 'enabled':False}],
                       [{'id':'03'}, {'id':'11', 'parameters':{'action':'cleanup'}}],
                       [{'id':'11'}, {'id':'03'}]):
            with self.assertRaises(ValueError):
                live.campaign_selection({'p11_live_lab':True}, dict(phases=phases), [])
        with patch('agent_client.load_agent_config', side_effect=FatalAgentError('unpaired')), self.assertRaises(ValueError):
            live.campaign_selection({'p11_live_lab':True}, definition, [])
        env = dict(MRN_EXECUTION=json.dumps(dict(definition, target_mode='auto')),
                   MRN_STARTED='0', MRNOBODY_P11_LIVE_CONFIG='{"p11_live_lab":true}')
        self.assertNotIn('MRNOBODY_P11_LIVE_CONFIG', execution.phase_environment('03', env, sleep=lambda _:None, clock=lambda:0))
        self.assertIn('MRNOBODY_P11_LIVE_CONFIG', execution.phase_environment('11', env, sleep=lambda _:None, clock=lambda:0))

    def test_custom_scenario_opt_in_is_runtime_only_and_recon_rejected(self):
        sid = 'custom-' + 'a'*32
        definition = dict(version=1, id=sid, name='Lab campaign',
            description='', target_mode='auto', profile={'mode':'normal'},
            phases=[{'id':p, 'parameters':{}, 'timing':{}} for p in ('01','03','11')])
        with patch.object(web.planning, 'custom', return_value=definition):
            response, env = self.start({'p11_live_lab':True}, sid=sid)
            self.assertEqual(response.status_code, 200, response.json)
            self.assertIn('MRNOBODY_P11_LIVE_CONFIG', env)
            self.assertNotIn('p11_live_lab', env['MRN_EXECUTION'])
            self.assertNotIn('p11_live_lab', json.dumps(definition))
        response, env = self.start({'p11_live_lab':True}, sid='preset-recon-only')
        self.assertEqual(response.status_code, 400); self.assertIsNone(env)

    def test_failures_skips_partial_and_cleanup_do_not_start_beacons(self):
        _, env = self.start({'p11_live_lab':True, 'beacon_count':1})
        env = self.inventory(env)
        with patch('agent_client.load_agent_config', return_value=object()), \
             patch.object(live, 'run', return_value=1) as run, contextlib.redirect_stdout(io.StringIO()):
            for outcome, code in (('failed',1), ('skipped',78), ('partial',80)):
                def invoke(*a, **kw):
                    return SimpleNamespace(returncode=0, stdout=json.dumps({'result':outcome}).encode())
                self.assertEqual(remote_actions.run('11', env, invoke), code)
                run.assert_not_called()
            self.assertEqual(remote_actions.run('11', dict(env, MRNOBODY_ACTION='cleanup'), self.invoke), 1)
            run.assert_not_called()
            self.assertEqual(remote_actions.run('11', env, self.invoke), 1)
            run.assert_called_once()  # ACK failure fails phase even after target success.
        truth = (self.root/'logs/incident-ground-truth.log').read_text()
        self.assertIn('live_lab_receipt_unavailable', truth)

    def test_stop_after_ack_does_not_report_success_or_send_again(self):
        stop = threading.Event()
        calls, events = [], []
        def post(payload, *_):
            calls.append(payload); stop.set()
            return dict(event_id=1, received_at='2026-11-15T12:00:00+00:00')
        code = live.run_loop(SimpleNamespace(agent_id='slave-1'), 'MRN-stop',
            live.settings({'p11_live_lab':True}), post=post, stop=stop,
            record=lambda event, **fields: events.append((event, fields)))
        self.assertEqual(code, 1); self.assertEqual(len(calls), 1)
        self.assertEqual(events[-1][1]['reason'], 'stopped')

    @unittest.skipIf(os.name == 'nt', 'POSIX campaign process-group Stop')
    def test_stop_endpoint_reaps_foreground_campaign_beacon_and_http_child(self):
        # Actual campaign dispatcher and actual hung HTTP subprocess; no target traffic.
        env = self.inventory(dict(NORDIC_INCIDENT_ID='MRN-stop-test',
            MRNOBODY_P11_LIVE_CONFIG=json.dumps({'p11_live_lab':True})))
        source = '''
import json, os, subprocess, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import remote_actions, p11_live_lab
original = subprocess.Popen
def hung(*a, **kw):
    child = original([sys.executable, '-c', 'import time; time.sleep(60)'], **kw)
    Path(sys.argv[2]).write_text(str(child.pid))
    return child
def invoke(*a, **kw):
    return SimpleNamespace(returncode=0, stdout=b'{"result":"success"}')
with patch('agent_client.load_agent_config', return_value=SimpleNamespace(agent_id='slave-1')), patch('p11_live_lab.subprocess.Popen', side_effect=hung):
    raise SystemExit(remote_actions.run('11', os.environ, invoke))
'''
        pidfile = self.root/'http.pid'
        process = subprocess.Popen([sys.executable, '-c', source, str(BASE/'web'), str(pidfile)],
            env=dict(os.environ, **env), start_new_session=True, stdout=subprocess.DEVNULL)
        try:
            deadline = time.monotonic()+5
            while not pidfile.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(pidfile.exists())
            with patch.object(web, 'campaign_process', process):
                response = web.app.test_client().post('/api/stop')
                self.assertEqual(response.status_code, 200)
            process.wait(timeout=3)
            child_pid = int(pidfile.read_text())
            # bounded_post reaps its worker even when the whole group receives TERM.
            with self.assertRaises(ProcessLookupError): os.kill(child_pid, 0)
            truth = (self.root/'logs/incident-ground-truth.log').read_text()
            self.assertIn('reason="stopped"', truth)
            self.assertEqual(truth.count('P11_BEACON_START'), 1)
            self.assertNotIn('P11_BEACON_ACK', truth)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait()


if __name__ == '__main__': unittest.main()
