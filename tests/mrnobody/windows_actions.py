"""Offline regression fixtures: no Windows connection or domain changes."""
import copy
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
import windows_actions as actions
from reports import build_report, read_metadata, load_report, save_report
from scenario_model import catalogue, validate, plan, needs_password
from execution import phase_environment, record
# Reuse existing endpoint isolation and launcher doubles.
sys.path.insert(0, str(Path(__file__).parent))
from planning import API

CAPS = catalogue(PLATFORM / 'scripts', read_metadata)
COMMAND = 'Write-Output "TOKEN_DO_NOT_PERSIST"'


def definition(ids=('09', '10'), mode='fixed'):
    return {'version': 1, 'name': 'Windows lab', 'target_mode': mode, 'profile': {'mode': 'normal'},
            'phases': [{'id': pid, 'parameters': {'target': '192.168.1.10', 'protocol': 'winrm-https'} if mode == 'fixed' else {}, 'timing': {}} for pid in ids]}


class Model(unittest.TestCase):
    def test_metadata_dependencies_and_full_campaign(self):
        for pid in ('09', '10'):
            self.assertEqual(CAPS[pid]['dependencies'], ['03'])
            self.assertTrue(CAPS[pid]['credentials'])
            self.assertTrue(CAPS[pid]['standalone'])
            self.assertEqual(CAPS[pid]['timing'], ['start_offset'])
            self.assertNotIn('powershell', CAPS[pid]['fields'])
            self.assertIn(pid, read_metadata(PLATFORM / 'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(','))
        for ids in [('09',), ('10',), ('10', '09')]:
            validate(definition(ids), CAPS)  # Direct targeting needs no discovery.
        validate(definition(('01', '03', '09', '10'), 'auto'), CAPS)
        for ids in [('01', '09', '03'), ('01', '10'), ('10', '01', '03')]:
            with self.assertRaises(ValueError):
                validate(definition(ids, 'auto'), CAPS)

    def test_fields_and_secrets_rejected(self):
        for key, value in [('powershell', COMMAND), ('command', COMMAND), ('password', 'SECRET'),
                           ('protocol', 'rdp'), ('target', '8.8.8.8'), ('timeout', 301)]:
            item = definition(); item['phases'][0]['parameters'][key] = value
            with self.assertRaises(ValueError): validate(item, CAPS)
        value = validate(definition(), CAPS)
        self.assertTrue(needs_password(value, windows=True))
        self.assertFalse(needs_password(value))

    def test_profiles_and_ephemeral_action(self):
        for mode in ('normal', 'slow', 'custom'):
            value = definition(); value['profile'] = {'mode': mode, 'duration': 60 if mode == 'slow' else 0}
            if mode == 'custom': value['phases'][1]['timing'] = {'start_offset': 42}
            value = plan(validate(value, CAPS))
            sleeps = []
            env = phase_environment('10', {'MRN_EXECUTION': json.dumps(value), 'MRN_STARTED': '100',
                                          'NORDIC_RDP_PASSWORD': 'WIN_SECRET', 'MRN_POWERSHELL_SECRET': COMMAND},
                                    sleep=sleeps.append, clock=lambda: 100)
            self.assertEqual(env['MRNOBODY_PASSWORD'], 'WIN_SECRET')
            self.assertEqual(env['MRN_POWERSHELL_SECRET'], COMMAND)
            self.assertNotIn(COMMAND, env['MRN_EXECUTION'])
            self.assertEqual(sleeps[0], 42 if mode == 'custom' else 30 if mode == 'slow' else 0)


class Worker(unittest.TestCase):
    def setUp(self):
        self.env = {'NORDIC_INCIDENT_ID': 'MRN-fixture', 'MRNOBODY_RUN_MODE': 'standalone',
                    'MRNOBODY_TARGET': '192.168.1.10', 'MRNOBODY_PROTOCOL': 'winrm-https',
                    'MRNOBODY_PASSWORD': 'WIN_SECRET', 'MRN_POWERSHELL_SECRET': COMMAND}
        self.target = actions.targets(self.env)[0]

    def test_winrm_transport_and_output_omission(self):
        for code in (0, 1):
            factory = Mock()
            factory.return_value.run_ps.return_value = Mock(status_code=code, std_out=b'TOKEN_DO_NOT_PERSIST', std_err=b'WIN_SECRET')
            result = actions.perform('10', self.target, self.env, factory)
            self.assertEqual(result['result'], 'success' if code == 0 else 'failed')
            self.assertEqual(result['stdout_bytes'], 20)
            self.assertNotIn('TOKEN_DO_NOT_PERSIST', json.dumps(result))
            self.assertNotIn('WIN_SECRET', json.dumps(result))
            self.assertEqual(factory.call_args.args[0], 'https://192.168.1.10:5986/wsman')
            self.assertEqual(factory.call_args.kwargs['transport'], 'ntlm')
            factory.return_value.run_ps.assert_called_once_with(COMMAND)

    def test_ad_idempotence_and_partial_failure_evidence(self):
        for account, group, outcome in [('created_disabled', 'added', 'success'), ('already_exists_unchanged', 'already_member', 'success'), ('created_disabled', 'not_attempted', 'failed')]:
            data = {'account': account, 'group': group, 'result': outcome, 'domain': 'lab.example', 'dc': 'dc.lab.example', 'warning': 'none', 'password': 'DO_NOT_KEEP'}
            factory = Mock()
            factory.return_value.run_ps.return_value = Mock(status_code=0, std_out=json.dumps(data).encode(), std_err=b'')
            result = actions.perform('09', self.target, self.env, factory)
            self.assertEqual((result['account'], result['group'], result['result']), (account, group, outcome))
            self.assertNotIn('DO_NOT_KEEP', json.dumps(result))
        self.assertIn("DomainSID.Value + '-512'", actions.AD_ACTION)
        self.assertIn('-Enabled $false', actions.AD_ACTION)
        self.assertNotIn('Set-ADUser', actions.AD_ACTION)

    def test_scope_and_inventory_not_secret_source(self):
        with self.assertRaises(ValueError): actions.targets(dict(self.env, MRNOBODY_TARGET='8.8.8.8'))
        with self.assertRaises(ValueError): actions.targets(dict(self.env, MRNOBODY_PROTOCOL='rdp'))
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            path = Path(tmp) / 'hosts.json'
            path.write_text(json.dumps({'incident_id': 'MRN-fixture', 'hosts': [{'ip': '192.168.1.10', 'platform': 'windows', 'compromised': True, 'rdp_password': 'INVENTORY_SECRET'}]}))
            rows = actions.targets(dict(self.env, MRNOBODY_RUN_MODE='campaign', NORDIC_COMPROMISED_STATE=str(path)))
            self.assertNotIn('INVENTORY_SECRET', json.dumps(rows))
            path.write_text('{"incident_id":"MRN-old"}')
            with self.assertRaises(ValueError): actions.targets(dict(self.env, MRNOBODY_RUN_MODE='campaign', NORDIC_COMPROMISED_STATE=str(path)))

    def test_timeout_failure_logs_and_permanent_reports(self):
        for pid in ('09', '10'):
            for timeout in (False, True):
                with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                    base = Path(tmp); (base / 'scripts').mkdir()
                    source = next((PLATFORM / 'scripts').glob(pid + '-*.sh'))
                    (base / 'scripts' / source.name).write_bytes(source.read_bytes())
                    env = dict(self.env, NORDIC_BASE_DIR=tmp)
                    invoke = Mock(side_effect=subprocess.TimeoutExpired('hidden', 60)) if timeout else Mock(return_value=Mock(returncode=0, stdout=b'{"result":"success","exit_code":0,"command":"custom_powershell_content_omitted"}'))
                    code = actions.run(pid, env, invoke)
                    self.assertEqual(code, int(timeout))
                    call = invoke.call_args
                    self.assertNotIn(COMMAND, str(call.args))
                    self.assertEqual(call.kwargs['timeout'], 60)
                    state = {'incident_id': env['NORDIC_INCIDENT_ID'], 'phase_id': pid, 'phases': {pid: 'failed' if timeout else 'complete'}}
                    report = build_report(base, env['NORDIC_INCIDENT_ID'], code, env, standalone=state)
                    save_report(base, report)
                    loaded = load_report(base / 'reports', env['NORDIC_INCIDENT_ID'])
                    phase = loaded['phases'][0]
                    self.assertIn('Wazuh', phase['analysis']['detection'][0])
                    self.assertTrue(all(t['url'].startswith('https://attack.mitre.org/techniques/') for t in loaded['mitre_summary']))
                    from report_exports import export_html, export_pdf
                    for view in ('investigation', 'ground-truth'):
                        self.assertIn('MrNobody', export_html(loaded, view))
                        self.assertTrue(export_pdf(loaded, view).startswith(b'%PDF'))
                    for path in base.rglob('*'):
                        if path.is_file():
                            self.assertNotIn(b'TOKEN_DO_NOT_PERSIST', path.read_bytes())
                            self.assertNotIn(b'WIN_SECRET', path.read_bytes())


class Endpoints(API):
    def test_full_incident_optional_powershell_and_scheduler(self):
        import app as web
        for mode in ('normal', 'slow'):
            for enabled in (False, True):
                web.campaign_process = None
                spec = {'type': 'campaign', 'id': 'full-incident', 'profile': {'mode': mode}, 'powershell_enabled': enabled}
                if enabled:
                    response = self.client.post('/api/executions/run', json={'execution': spec, 'credentials': {'ssh_password': 'S', 'rdp_password': 'R'}})
                    self.assertEqual(response.status_code, 400)
                response = self.client.post('/api/executions/run', json={'execution': spec, 'credentials': {'ssh_password': 'S', 'rdp_password': 'R', **({'powershell': COMMAND} if enabled else {})}})
                self.assertEqual(response.status_code, 200, response.json)
                env = self.launch.call_args.kwargs['env']
                ids = [p['id'] for p in json.loads(env['MRN_EXECUTION'])['phases']]
                self.assertIn('09', ids)
                self.assertEqual('10' in ids, enabled)
                self.assertLess(ids.index('03'), ids.index('09'))
                self.assertEqual(env['MRN_POWERSHELL_ENABLED'], '1' if enabled else '0')
        web.campaign_process = None
        spec = {'type': 'campaign', 'id': 'full-incident', 'powershell_enabled': True}
        schedule = {'version': 1, 'execution': spec, 'at': '2030-01-01T00:00:00Z'}
        sid = self.client.post('/api/schedules', json=schedule).json['id']
        web.planning.scheduler.observe = None  # Dispatch-only fixture, no observer thread.
        self.client.post(f'/api/schedules/{sid}/arm', json={'ssh_password':'S', 'rdp_password':'R', 'powershell':COMMAND})
        self.assertEqual(self.client.post(f'/api/schedules/{sid}/run', json={}).json['status'], 'started')
        self.assertEqual(self.launch.call_args.kwargs['env']['MRN_POWERSHELL_ENABLED'], '1')
        self.assertNotIn(b'TOKEN_DO_NOT_PERSIST', web.planning.store.path.read_bytes())

    def test_windows_endpoints_scheduler_serialization_and_overview(self):
        import app as web
        for pid in ('09', '10'):
            web.campaign_process = None
            spec = {'type': 'phase', 'id': pid, 'parameters': definition()['phases'][0]['parameters'], 'profile': {'mode': 'custom'}, 'timing': {'start_offset': 1}}
            response = self.client.post('/api/executions/run', json={'execution': spec, 'credentials': {'password': 'WIN_SECRET', 'powershell': COMMAND}})
            self.assertEqual(response.status_code, 200, response.json)
            env = self.launch.call_args.kwargs['env']
            self.assertNotIn(COMMAND, str(self.launch.call_args.args))
            self.assertNotIn(COMMAND, env['MRN_EXECUTION'])
            self.assertIn('--protocol', self.launch.call_args.args[1])
            record(self.base, env, 123)
            status = self.client.get('/api/execution-status').json
            self.assertEqual(status['current_phase']['id'], pid)
            self.assertNotIn(COMMAND, json.dumps(status))
            schedule = {'version': 1, 'execution': spec, 'at': '2030-01-01T00:00:00Z', 'interval': 60}
            sid = self.client.post('/api/schedules', json=schedule).json['id']
            self.assertEqual(self.client.post(f'/api/schedules/{sid}/arm', json={'rdp_password': 'WIN_SECRET', 'powershell': COMMAND}).status_code, 200)
            self.assertNotIn(b'TOKEN_DO_NOT_PERSIST', web.planning.store.path.read_bytes())
            self.assertTrue(any(s['id'] == sid and s['execution']['id'] == pid for s in self.client.get('/api/schedules').json['schedules']))
            self.client.put(f'/api/schedules/{sid}', json=schedule)
            self.assertNotIn(sid, web.planning.scheduler.credentials)
        web.campaign_process = None
        saved = self.save(definition())
        response = self.client.post('/api/executions/run', json={'execution': {'type': 'custom', 'id': saved['id']}, 'credentials': {'rdp_password': 'WIN_SECRET', 'powershell': COMMAND}})
        self.assertEqual(response.status_code, 200, response.json)
        env = self.launch.call_args.kwargs['env']
        self.assertEqual(env['MRN_POWERSHELL_SECRET'], COMMAND)
        self.assertNotIn(COMMAND, env['MRN_EXECUTION'])
        self.assertNotIn(b'TOKEN_DO_NOT_PERSIST', web.planning.store.path.read_bytes())

    def test_legacy_standalone_cannot_skip_validation(self):
        for data in [{'target': '8.8.8.8', 'protocol': 'winrm-http'}, {'target': '192.168.1.10', 'protocol': 'rdp'}]:
            self.assertEqual(self.client.post('/api/phase/09/run', json=data).status_code, 400)
        self.assertEqual(self.client.post('/api/phase/10/run', json={'target': '192.168.1.10', 'protocol': 'winrm-http'}).status_code, 400)


@unittest.skipIf(os.name == 'nt', 'Real Linux shell runners use inert WinRM fixtures in CI')
class ShellIntegration(unittest.TestCase):
    def test_real_standalone_and_custom_runners_with_fake_winrm(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            base = Path(tmp)
            for directory in ('scripts', 'web', 'scenarios', 'config', 'venv/bin', 'fake'):
                (base / directory).mkdir(parents=True, exist_ok=True)
            for source in (PLATFORM / 'web').glob('*.py'):
                shutil.copy(source, base / 'web' / source.name)
            for source in (PLATFORM / 'scripts').glob('[0-9][0-9]-*.sh'):
                destination = base / 'scripts' / source.name
                if source.name[:2] in {'09', '10'}: shutil.copy(source, destination)
                else: destination.write_text('#!/bin/sh\nexit 0\n')
                destination.chmod(0o755)
            shutil.copy(PLATFORM / 'scripts/run-phase.sh', base / 'scripts/run-phase.sh')
            shutil.copy(PLATFORM / 'scenarios/full-incident.sh', base / 'scenarios/full-incident.sh')
            config = (PLATFORM / 'config/defaults.conf').read_text().replace('NORDIC_BASE_DIR="/opt/nordic-attack"', f'NORDIC_BASE_DIR="{base}"')
            config += '\nNORDIC_PHASE_DELAY_MIN=0\nNORDIC_PHASE_DELAY_MAX=0\n'
            (base / 'config/defaults.conf').write_text(config)
            (base / 'venv/bin/python').symlink_to(sys.executable)
            # Only this fixture module is imported as winrm; no network exists.
            (base / 'fake/winrm.py').write_text('''
import json, os
class Session:
    def __init__(self, endpoint, **kw): self.endpoint = endpoint
    def run_ps(self, command):
        mode = os.environ.get('FIXTURE_AD', 'dc')
        if mode == 'unreachable' or (mode == 'mixed' and '192.168.1.10:' in self.endpoint):
            raise RuntimeError('inert transport failure')
        class Response:
            status_code = 0
            std_err = b'WIN_SECRET'
            std_out = json.dumps({'result':'success', 'account':'already_exists_unchanged', 'group':'already_member', 'domain':'lab.example', 'dc':'dc.lab.example', 'warning':'none'}).encode() if 'Get-ADDomain' in command else b'TOKEN_DO_NOT_PERSIST'
        if 'Get-ADDomain' in command and mode in {'workgroup', 'mixed'}:
            Response.std_out = json.dumps({'result':'skipped', 'account':'not_attempted', 'group':'not_attempted', 'domain':'WORKGROUP', 'dc':'unknown', 'warning':'target_must_be_domain_controller'}).encode()
        if 'Get-ADDomain' in command and mode == 'dc-error':
            Response.std_out = json.dumps({'result':'failed', 'account':'created_disabled', 'group':'not_attempted', 'domain':'lab.example', 'dc':'dc.lab.example', 'warning':'ad_action_failed_check_rights_module_and_dc_logs'}).encode()
        return Response()
''')
            env = dict(os.environ, NORDIC_BASE_DIR=tmp, MRN_POWERSHELL_SECRET=COMMAND,
                       NORDIC_COMPROMISED_STATE=str(base / 'state/compromised-hosts.json'),
                       MRNOBODY_PASSWORD='WIN_SECRET', NORDIC_RDP_PASSWORD='WIN_SECRET',
                       PYTHONPATH=str(base / 'fake'), NORDIC_PHASE_DELAY_MIN='0', NORDIC_PHASE_DELAY_MAX='0')
            for pid in ('09', '10'):
                command = ['bash', str(base / 'scripts/run-phase.sh'), pid, '--target', '192.168.1.10', '--protocol', 'winrm-http']
                result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            value = plan(validate(definition(), CAPS))
            value['id'] = 'custom-' + 'a' * 32
            env.update(MRN_EXECUTION=json.dumps(value), MRN_STARTED='0', NORDIC_INCIDENT_ID='MRN-custom-windows')
            result = subprocess.run(['bash', str(base / 'scenarios/full-incident.sh')], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            paths = list((base / 'reports').glob('*.json'))
            self.assertEqual(len(paths), 3)
            report = load_report(base / 'reports', 'MRN-custom-windows')
            self.assertEqual([p['id'] for p in report['phases'][:2]], ['09', '10'])
            self.assertTrue(all(p['status'] == 'success' for p in report['phases'][:2]))
            # Built-in default includes conditional P09 and leaves P10 disabled.
            access = next((base / 'scripts').glob('03-*.sh'))
            access.write_text('#!/bin/sh\nprintf \'{"incident_id":"%s","hosts":[]}\' "$NORDIC_INCIDENT_ID" > "$NORDIC_COMPROMISED_STATE"\n')
            env.pop('MRN_EXECUTION')
            env.update(NORDIC_INCIDENT_ID='MRN-full-windows', MRN_POWERSHELL_ENABLED='0')
            result = subprocess.run(['bash', str(base / 'scenarios/full-incident.sh')], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            full = load_report(base / 'reports', 'MRN-full-windows')
            p09 = next(p for p in full['phases'] if p['id'] == '09')
            self.assertEqual(p09['status'], 'skipped')
            self.assertTrue(any(e['event'] == 'PHASE_SKIPPED' for e in p09['events']))
            self.assertEqual(next(p for p in full['phases'] if p['id'] == '10')['status'], 'skipped')
            access.write_text('#!/bin/sh\nprintf \'{"incident_id":"%s","hosts":[{"ip":"192.168.1.10","compromised":true,"platform":"windows","access":"rdp"}]}\' "$NORDIC_INCIDENT_ID" > "$NORDIC_COMPROMISED_STATE"\n')
            env.update(NORDIC_INCIDENT_ID='MRN-full-enabled', MRN_POWERSHELL_ENABLED='1')
            result = subprocess.run(['bash', str(base / 'scenarios/full-incident.sh')], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            full = load_report(base / 'reports', 'MRN-full-enabled')
            self.assertTrue(all(p['status'] == 'success' for p in full['phases'] if p['id'] in {'09', '10'}))
            self.assertLess([p['id'] for p in full['phases']].index('10'), [p['id'] for p in full['phases']].index('04'))
            # Both real runner paths must preserve the nonfatal prerequisite
            # state and advance to another phase. No real WinRM module exists.
            for mode in ('workgroup', 'mixed', 'unreachable', 'dc-error'):
                env.update(FIXTURE_AD=mode)
                expected = 'skipped' if mode in {'workgroup', 'mixed'} else 'failure'
                target = '192.168.1.11' if mode == 'mixed' else '192.168.1.10'
                result = subprocess.run(['bash', str(base / 'scripts/run-phase.sh'), '09', '--target', target, '--protocol', 'winrm-http'], env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0 if expected == 'skipped' else 1, result.stdout + result.stderr)
                standalone_path = next(line.removeprefix('Report: ') for line in result.stdout.splitlines() if line.startswith('Report: '))
                standalone = json.loads(Path(standalone_path).read_text())
                self.assertEqual(standalone['phases'][0]['status'], expected)
                self.assertEqual(standalone['incident']['exit_code'], 78 if expected == 'skipped' else 1)
                # Include an inert P04 after P09 in the custom plan.
                spec = definition(('09', '04'))
                spec['phases'][0]['parameters']['target'] = target
                spec['phases'][1]['parameters']['source'] = target
                custom = plan(validate(spec, CAPS)); custom['id'] = 'custom-' + 'b' * 32
                env.update(MRN_EXECUTION=json.dumps(custom), NORDIC_INCIDENT_ID='MRN-custom-' + mode)
                result = subprocess.run(['bash', str(base / 'scenarios/full-incident.sh')], env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0 if expected == 'skipped' else 1, result.stdout + result.stderr)
                custom_report = load_report(base / 'reports', env['NORDIC_INCIDENT_ID'])
                self.assertEqual(custom_report['phases'][0]['status'], expected)
                self.assertEqual(custom_report['phases'][1]['status'], 'success' if expected == 'skipped' else 'not_run')
                env.pop('MRN_EXECUTION')
                access.write_text('#!/bin/sh\nprintf \'{"incident_id":"%s","hosts":[{"ip":"192.168.1.10","compromised":true,"platform":"windows","access":"rdp"},{"ip":"192.168.1.11","compromised":true,"platform":"windows","access":"rdp"}]}\' "$NORDIC_INCIDENT_ID" > "$NORDIC_COMPROMISED_STATE"\n')
                env.update(NORDIC_INCIDENT_ID='MRN-full-' + mode, MRN_POWERSHELL_ENABLED='0')
                result = subprocess.run(['bash', str(base / 'scenarios/full-incident.sh')], env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0 if expected == 'skipped' else 1, result.stdout + result.stderr)
                full = load_report(base / 'reports', env['NORDIC_INCIDENT_ID'])
                p09 = next(p for p in full['phases'] if p['id'] == '09')
                self.assertEqual(p09['status'], expected)
                self.assertEqual(next(p for p in full['phases'] if p['id'] == '04')['status'], 'success' if expected == 'skipped' else 'not_run')
                events = [e['event'] for e in p09['events']]
                self.assertIn('PHASE_SKIPPED' if expected == 'skipped' else 'PHASE_FAILED', events)
                if expected == 'skipped':
                    self.assertNotIn('PHASE_COMPLETE', events)
                    self.assertNotIn('PHASE_FAILED', events)
            for path in [*paths, *(base / 'logs').glob('*')]:
                self.assertNotIn(b'TOKEN_DO_NOT_PERSIST', path.read_bytes())
                self.assertNotIn(b'WIN_SECRET', path.read_bytes())


if __name__ == '__main__':
    unittest.main()
