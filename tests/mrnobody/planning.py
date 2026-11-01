"""Isolated planning/scheduler tests. --bash adds real runners with inert phases.

No network scanning, authentication, staging, exfiltration or impact is executed.
"""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
import app as web
from execution import pace, phase_environment
from planning_api import BusyError, launch
from reports import build_report, read_metadata
from scenario_model import catalogue, plan, validate
from scheduler import Scheduler, Store

CAPS = catalogue(PLATFORM / 'scripts', read_metadata)


def definition(mode='auto', ids=('01', '02')):
    return {'version': 1, 'name': 'Slow lab <scenario>', 'description': 'Synthetic lab only',
            'target_mode': mode, 'profile': {'mode': 'normal', 'duration': 0},
            'phases': [{'id': pid, 'enabled': True, 'parameters': {}, 'timing': {}} for pid in ids]}


class Model(unittest.TestCase):
    def test_gui_metadata_matches_validation_contract(self):
        self.assertEqual(CAPS['06']['dependencies'], ['03', '05'])
        self.assertEqual(CAPS['08']['dependencies'], ['01', '03'])
        self.assertEqual(CAPS['04']['required_fields'], ['source', 'target'])
        self.assertEqual(CAPS['06']['required_fields'], ['file', 'target'])
        for pid, cap in CAPS.items():
            self.assertTrue(set(cap['required_fields']) <= set(cap['fields']))
            if pid == '01':
                continue
            chain = []
            def add(current):
                for dependency in CAPS[current]['dependencies']:
                    add(dependency)
                if current not in chain:
                    chain.append(current)
            add(pid)
            validate(definition(ids=chain), CAPS)
            for required in cap['dependencies']:
                with self.assertRaises(ValueError):
                    validate(definition(ids=[p for p in chain if p != required]), CAPS)

    def test_modes_order_and_dependencies(self):
        value = definition('fixed', ('04', '03'))
        for phase in value['phases']:
            phase['parameters'] = {'target': '192.168.1.20', 'protocol': 'ssh', 'port': 22}
            if phase['id'] == '04': phase['parameters']['source'] = '192.168.1.21'
        self.assertEqual([p['id'] for p in validate(value, CAPS)['phases']], ['04', '03'])
        value['target_mode'] = 'auto'
        with self.assertRaises(ValueError): validate(value, CAPS)
        value = definition(ids=('02', '01'))
        with self.assertRaises(ValueError): validate(value, CAPS)
        value['phases'].reverse()
        self.assertEqual(validate(value, CAPS)['target_mode'], 'auto')

    def test_reject_unsupported_and_secrets(self):
        for params in [{'password': 'NEVER_STORE'}, {'target': '192.168.1.20'}, {'unknown': 'x'}]:
            value = definition(); value['phases'][0]['parameters'] = params
            with self.assertRaises(ValueError): validate(value, CAPS)
        for address in ['8.8.8.8', '127.0.0.1', '192.168.1.2;id', '::1']:
            value = definition('fixed', ('03',)); value['phases'][0]['parameters'] = {'target': address, 'protocol': 'ssh'}
            with self.assertRaises(ValueError): validate(value, CAPS)
        for network in ['10.0.0.0/8', '1.2.3.0/24']:
            value = definition('fixed', ('01',)); value['phases'][0]['parameters'] = {'subnet': network}
            with self.assertRaises(ValueError): validate(value, CAPS)
        value = definition('fixed', ('06',)); value['phases'][0]['parameters'] = {'target': '192.168.1.10', 'file': '/etc/passwd'}
        with self.assertRaises(ValueError): validate(value, CAPS)

    def test_profiles_and_phase_capabilities(self):
        value = definition(); normal = plan(validate(value, CAPS))
        self.assertEqual(normal['phases'][0]['timing'], {})
        value['profile'] = {'mode': 'slow', 'duration': 14400}
        slow = plan(validate(value, CAPS))
        self.assertEqual(sum(p['timing']['duration'] for p in slow['phases']), 14400)
        self.assertGreater(slow['phases'][1]['timing']['start_offset'], 0)
        value['profile'] = {'mode': 'custom', 'duration': 0}
        value['phases'][0]['timing'] = {'start_offset': 30, 'duration': 90, 'delay_min': 1, 'delay_max': 2, 'jitter': .2}
        validate(value, CAPS)
        for timing in [{'unsupported': 1}, {'duration': float('nan')}, {'delay_min': 5, 'delay_max': 1}, {'jitter': 2}]:
            value['phases'][0]['timing'] = timing
            with self.assertRaises(ValueError): validate(value, CAPS)
        self.assertEqual(CAPS['07']['timing'], ['start_offset'])
        self.assertNotIn('file', CAPS['08']['fields'])

    def test_pacing_and_environment(self):
        sleeps = []
        pace(2, 4, {'duration': 40}, 100, sleep=sleeps.append, clock=lambda: 100, uniform=lambda a,b: (a+b)/2)
        self.assertEqual(sleeps, [20])
        value = definition('fixed', ('03',)); value['phases'][0]['parameters'] = {'target': '192.168.1.10', 'protocol': 'ssh'}
        value['phases'][0]['timing'] = {'start_offset': 10}
        env = phase_environment('03', {'MRN_EXECUTION': json.dumps(value), 'MRN_STARTED': '100', 'NORDIC_SSH_PASSWORD': 'SECRET'}, sleep=sleeps.append, clock=lambda: 100)
        self.assertEqual(sleeps[-1], 10)
        self.assertEqual(env['MRNOBODY_PASSWORD'], 'SECRET')
        self.assertEqual(env['MRNOBODY_RUN_MODE'], 'standalone')
        self.assertNotIn('SECRET', env['MRN_EXECUTION'])


class API(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        for name, value in {'BASE_DIR': self.base, 'STATE_DIR': self.base / 'state', 'LOG_DIR': self.base / 'logs',
                            'CAMPAIGN_LOG': self.base / 'logs/campaign.log', 'SCENARIO_DIR': PLATFORM / 'scenarios',
                            'SCRIPT_DIR': PLATFORM / 'scripts', 'PHASE_RUNNER': PLATFORM / 'scripts/run-phase.sh',
                            'CONFIG_FILE': PLATFORM / 'config/defaults.conf', 'campaign_process': None}.items():
            patch.object(web, name, value).start()
        patch.object(web, 'determine_incident_ip', return_value='192.168.1.254').start()
        self.launch = patch.object(web, 'launch', return_value=Mock(pid=123, poll=lambda: None)).start()
        self.client = web.app.test_client()

    def save(self, value=None):
        result = self.client.post('/api/custom-scenarios', json=value or definition())
        self.assertEqual(result.status_code, 201, result.json)
        return result.json

    def test_crud_and_validation(self):
        saved = self.save(); sid = saved['id']
        listing = self.client.get('/api/scenarios').json['scenarios']
        self.assertTrue(any(s['id'] == sid and s['custom'] for s in listing))
        saved['name'] = 'Edited'; saved['phases'][1]['enabled'] = False
        self.assertEqual(self.client.put('/api/custom-scenarios/' + sid, json=saved).status_code, 200)
        duplicate = self.save(saved); self.assertNotEqual(sid, duplicate['id'])
        saved['phases'][0]['parameters']['password'] = 'SECRET'
        self.assertEqual(self.client.put('/api/custom-scenarios/' + sid, json=saved).status_code, 400)
        self.assertEqual(self.client.delete('/api/custom-scenarios/full-incident').status_code, 400)
        self.assertEqual(self.client.delete('/api/custom-scenarios/' + sid).status_code, 200)

    def test_run_now_overlap_and_redaction(self):
        saved = self.save()
        result = self.client.post('/api/executions/run', json={'execution': {'type': 'custom', 'id': saved['id']}, 'credentials': {'ssh_password': 'SUPER_SECRET'}})
        self.assertEqual(result.status_code, 200, result.json)
        _, kwargs = self.launch.call_args
        plan_value = json.loads(kwargs['env']['MRN_EXECUTION'])
        self.assertEqual(plan_value['id'], saved['id'])
        from execution import record
        env = kwargs['env']
        record(self.base, env, 12345)
        overview = self.client.get('/api/execution-status').json
        self.assertEqual(overview['execution']['type'], 'custom')
        self.assertEqual(overview['execution']['id'], saved['id'])
        self.assertNotIn('SUPER_SECRET', json.dumps(overview))
        self.assertNotIn('SUPER_SECRET', json.dumps(plan_value))
        self.assertTrue(kwargs['env']['NORDIC_INCIDENT_ID'].startswith('MRN-'))
        self.assertEqual(self.client.post('/api/executions/run', json={'execution': {'type': 'custom', 'id': saved['id']}}).status_code, 409)
        self.assertNotIn('SUPER_SECRET', web.CAMPAIGN_LOG.read_text())

    def test_builder_p08_existing_multipart_upload_is_runtime_only(self):
        patch.object(web, 'UPLOAD_DIR', self.base / 'runtime' / 'uploads').start()
        saved = self.save(definition(ids=('01', '03', '08')))
        schedule = {'version': 1, 'execution': {'type': 'custom', 'id': saved['id']},
                    'at': '2099-11-01T12:00:00Z', 'interval': 86400, 'enabled': True}
        self.assertEqual(self.client.post('/api/schedules', json=schedule).status_code, 201)
        response = self.client.post(f'/api/scenario/{saved["id"]}/start', data={
            'ssh_password': 'SSH_RUNTIME_SECRET', 'rdp_password': 'RDP_RUNTIME_SECRET',
            'wordlist_users': 'runtime-user',
            'wordlist_file': (io.BytesIO(b'WORDLIST_RUNTIME_SECRET\n'), 'wordlist.txt')})
        self.assertEqual(response.status_code, 200, response.json)
        env = self.launch.call_args.kwargs['env']
        self.assertEqual(env['NORDIC_WORDLIST_USERS'], 'runtime-user')
        self.assertEqual(Path(env['NORDIC_WORDLIST_FILE']).read_bytes(), b'WORDLIST_RUNTIME_SECRET\n')
        for secret in ('SSH_RUNTIME_SECRET', 'RDP_RUNTIME_SECRET', 'WORDLIST_RUNTIME_SECRET', 'runtime-user'):
            self.assertNotIn(secret.encode(), web.planning.store.path.read_bytes())
            self.assertNotIn(secret, env['MRN_EXECUTION'])
            self.assertNotIn(secret, web.CAMPAIGN_LOG.read_text())

    def test_schedules_restart_crud_and_actions(self):
        saved = self.save()
        value = {'version': 1, 'execution': {'type': 'custom', 'id': saved['id']}, 'at': '2026-11-01T12:00:00+01:00', 'interval': 3600, 'enabled': True}
        response = self.client.post('/api/schedules', json=value); self.assertEqual(response.status_code, 201)
        sid = response.json['id']
        self.assertEqual(self.client.post(f'/api/schedules/{sid}/arm', json={'ssh_password': 'LEASE_SECRET'}).status_code, 200)
        self.assertNotIn(b'LEASE_SECRET', web.planning.store.path.read_bytes())
        self.assertEqual(len(Store(web.planning.store.directory).schedules()), 1)
        self.assertEqual(self.client.delete('/api/custom-scenarios/' + saved['id']).status_code, 400)
        self.assertEqual(self.client.post(f'/api/schedules/{sid}/disable', json={}).status_code, 200)
        self.assertFalse(self.client.get('/api/schedules').json['schedules'][0]['enabled'])
        self.assertEqual(self.client.post(f'/api/schedules/{sid}/enable', json={}).status_code, 200)
        self.assertEqual(self.client.post(f'/api/schedules/{sid}/run', json={}).json['status'], 'started')
        metadata = json.loads(self.launch.call_args.kwargs['env']['MRN_OVERVIEW'])
        self.assertEqual(metadata['trigger'], 'scheduler')
        self.assertEqual(metadata['schedule_id'], sid)
        value['interval'] = 0
        self.assertEqual(self.client.put(f'/api/schedules/{sid}', json=value).status_code, 200)
        self.assertNotIn(sid, web.planning.scheduler.credentials)
        self.assertEqual(self.client.delete(f'/api/schedules/{sid}').status_code, 200)
        for broken in [{**value, 'password': 'SECRET'}, {**value, 'at': '2026-11-01T12:00:00'}, {**value, 'interval': 1}]:
            self.assertEqual(self.client.post('/api/schedules', json=broken).status_code, 400)

    def test_standalone_and_builtin_use_existing_routes(self):
        spec = {'type': 'phase', 'id': '03', 'parameters': {'target': '192.168.1.20', 'protocol': 'ssh'}, 'profile': {'mode': 'normal'}}
        result = self.client.post('/api/executions/run', json={'execution': spec, 'credentials': {'password': 'SECRET'}})
        self.assertEqual(result.status_code, 200, result.json)
        self.assertIn('run-phase.sh', str(self.launch.call_args.args))
        from execution import record
        env = self.launch.call_args.kwargs['env']
        record(self.base, env, 12345)
        overview = self.client.get('/api/execution-status').json
        self.assertEqual(overview['execution']['type'], 'phase')
        self.assertEqual(overview['current_phase']['id'], '03')
        self.assertEqual(overview['incident_id'], env['NORDIC_INCIDENT_ID'])
        web.campaign_process = None
        result = self.client.post('/api/executions/run', json={'execution': {'type': 'campaign', 'id': 'full-incident', 'profile': {'mode': 'slow', 'duration': 14400}}, 'credentials': {'ssh_password': 'S', 'rdp_password': 'R'}})
        self.assertEqual(result.status_code, 200, result.json)
        self.assertIn('full-incident.sh', str(self.launch.call_args.args))
        web.campaign_process = None; self.launch.side_effect = BusyError()
        self.assertEqual(self.client.post('/api/executions/run', json={'execution': spec, 'credentials': {'password': 'S'}}).status_code, 409)


class Persistence(unittest.TestCase):
    def test_atomic_claim_once_recurring_skip_and_restart(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            store = Store(Path(tmp))
            base = {'version': 1, 'execution': {'type': 'phase', 'id': '01'}, 'at': '1970-01-01T00:01:40Z', 'enabled': True}
            once = store.save_schedule(base)
            recurring = store.save_schedule(dict(base, interval=60))
            calls = []
            scheduler = Scheduler(store, lambda e,c: calls.append(e) or 'skipped: execution already running', lambda *a: None, clock=lambda: 250)
            scheduler.tick()
            self.assertEqual(len(calls), 2)
            scheduler.tick(); self.assertEqual(len(calls), 2)
            rows = {r['id']: r for r in Store(Path(tmp)).schedules()}
            self.assertFalse(rows[once]['enabled'])
            self.assertEqual(rows[recurring]['next_run'], '1970-01-01T00:04:40+00:00')
            self.assertTrue(rows[recurring]['last_status'].startswith('skipped:'))
            self.assertEqual(Store(Path(tmp)).claim(250), [])

    @unittest.skipIf(os.name == 'nt', 'POSIX file locks are verified on the target Linux CI')
    def test_real_lock_blocks_other_process_until_exit(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            child = launch(Path(tmp), [sys.executable, '-c', 'import time; time.sleep(5)'])
            try:
                with self.assertRaises(BusyError): launch(Path(tmp), [sys.executable, '-c', 'pass'])
            finally:
                child.terminate(); child.wait(timeout=10)
            child = launch(Path(tmp), [sys.executable, '-c', 'pass']); self.assertEqual(child.wait(), 0)


@unittest.skipUnless('--bash' in sys.argv and os.name != 'nt', 'Linux runner fixture reserved for CI')
class RunnerIntegration(API):
    def test_scheduled_custom_generates_normal_report(self):
        # Replace only launch mock with the real wrapper. Every phase is inert.
        self.launch.side_effect = lambda *a, **kw: launch(*a, **kw)
        (self.base / 'scenarios').mkdir(); (self.base / 'scripts').mkdir(); (self.base / 'web').mkdir(); (self.base / 'config').mkdir()
        for source in (PLATFORM / 'web').glob('*.py'): shutil.copy(source, self.base / 'web' / source.name)
        shutil.copy(PLATFORM / 'scenarios/full-incident.sh', self.base / 'scenarios/full-incident.sh')
        for source in (PLATFORM / 'scripts').glob('0*.sh'):
            script = self.base / 'scripts' / source.name
            script.write_text('#!/bin/sh\necho "$MRNOBODY_ATTACK_ID"\nexit 0\n'); script.chmod(0o755)
        conf = (PLATFORM / 'config/defaults.conf').read_text().replace('NORDIC_BASE_DIR="/opt/nordic-attack"', 'NORDIC_BASE_DIR="' + str(self.base) + '"')
        (self.base / 'config/defaults.conf').write_text(conf)
        with patch.object(web, 'SCENARIO_DIR', self.base / 'scenarios'), patch.dict(os.environ, {'NORDIC_BASE_DIR': str(self.base)}):
            saved = self.save()
            value = {'version': 1, 'execution': {'type': 'custom', 'id': saved['id']}, 'at': '1970-01-01T00:00:00Z', 'interval': 0, 'enabled': True}
            sid = self.client.post('/api/schedules', json=value).json['id']
            web.planning.scheduler.tick()
            self.assertEqual(web.campaign_process.wait(timeout=30), 0)
            reports = list((self.base / 'reports').glob('*.json')); self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text())
            self.assertEqual(report['incident']['scenario'], saved['id'])
            self.assertEqual(report['incident']['scenario_name'], saved['name'])
            self.assertEqual(report['execution']['profile']['mode'], 'normal')
            self.assertEqual(report['incident']['status'], 'complete')
            overview = self.client.get('/api/execution-status').json
            self.assertEqual(overview['status'], 'complete')
            self.assertEqual(overview['execution']['schedule_id'], sid)
            self.assertEqual(overview['execution']['trigger'], 'scheduler')
            self.assertEqual(overview['progress']['percent'], 100)
            self.assertEqual(overview['report_id'], report['incident']['id'])
            for format in ('html', 'pdf'):
                response = self.client.get(f'/api/reports/{report["incident"]["id"]}/export/{format}')
                self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]])
