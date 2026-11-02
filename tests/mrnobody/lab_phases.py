"""Offline P12/P14 contracts. All SSH/WinRM/network calls are fixtures."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
import lab_actions as lab
import remote_actions as remote
import app as web
from execution import phase_environment, snapshot
from reports import build_report, read_metadata, PHASE_ORDER, mitre_url
from report_exports import export_html, export_pdf
from scenario_model import catalogue, validate, plan, needs_password
sys.path.insert(0, str(Path(__file__).parent))
from planning import API

CAPS = catalogue(PLATFORM / 'scripts', read_metadata)


def definition(pid, mode='auto', platform='linux', parameters=None):
    params = dict(platform=platform, **(parameters or {}))
    if mode == 'fixed':
        params.update(target='192.168.1.15', protocol='ssh' if platform == 'linux' else 'winrm-http')
    return dict(version=1, name='Synthetic telemetry', target_mode=mode, profile={'mode': 'normal'},
                phases=([{'id': '01'}, {'id': '03'}] if mode == 'auto' else []) + [{'id': pid, 'parameters': params}])


class LabPhases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-lab-phases',
                        MRNOBODY_RUN_MODE='campaign', NORDIC_RDP_PASSWORD='WINDOWS_SECRET', NORDIC_SSH_PASSWORD='LINUX_SECRET')
        self.inventory(['windows', 'linux'])

    def inventory(self, platforms):
        path = self.base / 'state/compromised-hosts.json'
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(dict(incident_id=self.env['NORDIC_INCIDENT_ID'], hosts=[
            dict(ip=f'192.168.1.{i+15}', platform=p, access='rdp' if p == 'windows' else 'ssh', compromised=True)
            for i, p in enumerate(platforms)])))
        self.env['NORDIC_COMPROMISED_STATE'] = str(path)

    def run_phase(self, pid, result, **overrides):
        invoke = Mock(side_effect=lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(result)))
        with patch.object(lab, 'endpoint', return_value='http://192.168.1.2/mrnobody-beacon/heartbeat'), contextlib.redirect_stdout(io.StringIO()):
            code = remote.run(pid, dict(self.env, **overrides), invoke)
        return code, invoke

    def test_registry_fixed_auto_profiles_dependencies_and_passwords(self):
        for pid in ('12', '14'):
            self.assertEqual(CAPS[pid]['dependencies'], ['03'])
            self.assertTrue(CAPS[pid]['standalone'])
            self.assertEqual(CAPS[pid]['timing'], ['start_offset'])
            for platform in ('windows', 'linux'):
                for mode in ('auto', 'fixed'):
                    for profile in ('normal', 'slow', 'custom'):
                        value = definition(pid, mode, platform)
                        value['profile'] = {'mode': profile}
                        planned = plan(validate(value, CAPS))
                        self.assertEqual(planned['phases'][-1]['parameters']['platform'], platform)
                        self.assertNotIn('duration', planned['phases'][-1].get('timing', {}))
                        self.assertTrue(needs_password(planned, platform == 'windows'))
            invalid = definition(pid)
            invalid['phases'].reverse()
            with self.assertRaises(ValueError): validate(invalid, CAPS)
            invalid = definition(pid, 'fixed')
            invalid['phases'][0]['parameters']['target'] = '8.8.8.8'
            with self.assertRaises(ValueError): validate(invalid, CAPS)
            invalid = definition(pid, 'fixed')
            invalid['phases'][0]['parameters']['protocol'] = 'winrm-http'
            with self.assertRaises(ValueError): validate(invalid, CAPS)

    def test_beacon_validation(self):
        for key, values in {'beacon_interval': [0, 61, float('nan'), float('inf'), True],
                            'beacon_jitter': [-1, .51], 'beacon_count': [0, 21, 1.5],
                            'transport': ['dns', 'ftp'], 'uri_profile': ['../cmd', 'https://evil']}.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    validate(definition('14', parameters={key: value}), CAPS)
        with self.assertRaises(ValueError): lab.configuration('14', {'MRNOBODY_BEACON_INTERVAL': 60, 'MRNOBODY_BEACON_COUNT': 20})
        for key in ('endpoint', 'url', 'command', 'file'):
            with self.assertRaises(ValueError): validate(definition('14', parameters={key: 'test'}), CAPS)
        for key in ('file', 'command', 'password'):
            with self.assertRaises(ValueError): validate(definition('12', parameters={key: 'test'}), CAPS)

    def test_linux_windows_perform_success_and_output_allowlist(self):
        for pid in ('12', '14'):
            env = dict(self.env, MRN_BEACON_ENDPOINT='http://192.168.1.2/mrnobody-beacon/heartbeat')
            output = 'MRN_P12_OK\n' if pid == '12' else ''.join(f'MRN_BEACON={i},ok\n' for i in range(1, 6))
            for platform in ('windows', 'linux'):
                target = dict(target='192.168.1.15', platform=platform, protocol='ssh' if platform == 'linux' else 'winrm-http', port=22 if platform == 'linux' else 5985, username='lab')
                ssh = Mock(return_value=(0, ((output + '\nMRN_REMOTE_EXIT=0__MRN_END__\n').encode(), len(output)), (b'SECRET', 6)))
                session = Mock()
                session.run_ps.return_value = SimpleNamespace(status_code=0, std_out=output.encode(), std_err=b'SECRET')
                result = remote.perform(pid, target, env, session_factory=Mock(return_value=session), ssh=ssh)
                self.assertEqual(result['result'], 'success')
                self.assertNotIn('SECRET', json.dumps(result))
                self.assertNotIn('stdout_preview', result)
        self.assertEqual(lab.evidence('12', 'MRN_P12_OK\nsecret', {})['result'], 'failed')
        self.assertEqual(lab.evidence('14', 'MRN_BEACON=99,ok', {'beacon_count': 1})['result'], 'failed')

    def test_endpoint_is_controller_interface_only(self):
        route = Mock()
        route.__enter__ = Mock(return_value=route)
        route.__exit__ = Mock(return_value=False)
        route.getsockname.return_value = ('192.168.1.2', 1000)
        with patch.object(lab.socket, 'socket', return_value=route):
            self.assertEqual(lab.endpoint({'target': '192.168.1.15'}, 'https', 'status'), 'https://192.168.1.2/mrnobody-beacon/status')
            route.getsockname.return_value = ('8.8.8.8', 1000)
            with self.assertRaises(ValueError): lab.endpoint({'target': '192.168.1.15'}, 'http', 'status')
        nginx = (PLATFORM / 'nginx/nordic-incident.conf').read_text()
        self.assertEqual(nginx.count('location ~ ^/mrnobody-beacon/'), 2)
        self.assertIn('return 403', nginx)
        self.assertIn('return 204', nginx)

    def test_source_selection_skip_failure_fallback_and_partial(self):
        for pid in ('12', '14'):
            for platform in ('windows', 'linux'):
                code, invoke = self.run_phase(pid, {'result': 'success'}, MRNOBODY_PLATFORM=platform)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(invoke.call_args.kwargs['env']['MRN_REMOTE_TARGET'])['platform'], platform)
            self.assertEqual(self.run_phase(pid, {'result': 'failed', 'warning': 'internal_failure'})[0], 1)
            self.assertEqual(self.run_phase(pid, {'result': 'skipped', 'warning': 'target_dependency_unsupported'})[0], 78)
            with patch.object(lab, 'endpoint', return_value='http://192.168.1.2/mrnobody-beacon/heartbeat'), contextlib.redirect_stdout(io.StringIO()):
                results = iter([dict(result='failed', warning='transport_error_details_omitted'), dict(result='success')])
                worker = lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(next(results)))
                self.assertEqual(remote.run(pid, self.env, worker), 0)
        partial = lab.evidence('14', 'MRN_BEACON=1,ok\nMRN_BEACON=2,failed', {'beacon_count': 2})
        self.assertEqual((partial['result'], partial['success_count'], partial['failure_count']), ('failed', 1, 1))
        self.assertEqual(self.run_phase('14', partial)[0], 1)
        self.inventory([])
        for pid in ('12', '14'):
            code, invoke = self.run_phase(pid, {'result': 'success'})
            self.assertEqual(code, 78)
            invoke.assert_not_called()

    def test_fixed_scripts_no_arbitrary_paths_and_powershell_parses(self):
        shell = shutil.which('pwsh') or shutil.which('powershell')
        for pid in ('12', '14'):
            for platform in ('windows', 'linux'):
                source = lab.script(pid, platform, dict(self.env, MRNOBODY_TRANSPORT='https', MRNOBODY_URI_PROFILE='status', MRN_BEACON_ENDPOINT='https://192.168.1.2/mrnobody-beacon/status'))
                for forbidden in ('lsass', '.ssh', 'Login Data', 'Invoke-Expression', 'DownloadString'):
                    self.assertNotIn(forbidden, source)
                if platform == 'windows' and shell:
                    result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', '$s=[Console]::In.ReadToEnd();$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e)|Out-Null;if($e.Count){exit 1}'], input=source, text=True, capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    if pid == '14':
                        # Compile the fixed TLS helper and assign its delegate in
                        # a disposable process. Do not execute the request loop.
                        prefix = source.split('for ($i=1;', 1)[0]
                        compiled = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', prefix], text=True, capture_output=True, timeout=30)
                        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)

    @unittest.skipIf(os.name == 'nt', 'Local Bash fixtures run on Linux CI')
    def test_linux_generated_actions_execute_without_lab_connections(self):
        env = dict(self.env, MRNOBODY_BEACON_COUNT='2', MRNOBODY_BEACON_INTERVAL='1',
                   MRN_BEACON_ENDPOINT='http://192.168.1.2/mrnobody-beacon/heartbeat')
        fake = self.base / 'fake'
        fake.mkdir()
        curl = fake / 'curl'
        # A fixed local executable intercepts every request; no network is used.
        curl.write_text('#!/bin/sh\nprintf 204\n')
        curl.chmod(0o755)
        for pid in ('12', '14'):
            source = lab.script(pid, 'linux', env)
            parsed = subprocess.run(['bash', '-n'], input=source, text=True, capture_output=True, timeout=10)
            self.assertEqual(parsed.returncode, 0, parsed.stderr)
            result = subprocess.run(['bash', '-s'], input=source, env=dict(os.environ, PATH=str(fake)+os.pathsep+os.environ['PATH']), text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(lab.evidence(pid, result.stdout, lab.configuration(pid, env))['result'], 'success')

    def test_reports_exports_mitre_and_live_overview(self):
        (self.base / 'scripts').mkdir()
        for pid, tid in (('12', 'T1552.001'), ('14', 'T1071.001')):
            shutil.copy(next((PLATFORM / 'scripts').glob(pid + '-*.sh')), self.base / 'scripts')
            code, _ = self.run_phase(pid, dict(result='success', success_count=5, failure_count=0))
            state = dict(incident_id=self.env['NORDIC_INCIDENT_ID'], phase_id=pid, status='complete', phases={pid: 'complete'})
            report = build_report(self.base, self.env['NORDIC_INCIDENT_ID'], code, self.env, standalone=state)
            phase = report['phases'][0]
            self.assertEqual(phase['status'], 'success')
            self.assertIn(tid, json.dumps(report))
            self.assertIn(mitre_url(tid), json.dumps(report))
            self.assertIn('benign', json.dumps(report).lower())
            self.assertNotIn('WINDOWS_SECRET', json.dumps(report))
            self.assertIn(tid, export_html(report))
            self.assertTrue(export_pdf(report).startswith(b'%PDF'))
            with patch('execution.report_for', return_value=report):
                launch = dict(incident_id=self.env['NORDIC_INCIDENT_ID'], type='phase', id=pid, phases=[{'id': pid}])
                (self.base / 'runtime').mkdir(exist_ok=True)
                (self.base / 'runtime/execution-overview.json').write_text(json.dumps(launch))
                status = snapshot(self.base, CAPS, None, 0)
                self.assertEqual(status['timeline'][0]['id'], pid)
        self.assertEqual(list(PHASE_ORDER), read_metadata(PLATFORM / 'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(','))


class LabEndpoints(API):
    def test_standalone_custom_full_and_scheduler_validation(self):
        for pid in ('12', '14'):
            for platform in ('windows', 'linux'):
                parameters = definition(pid, 'fixed', platform)['phases'][0]['parameters']
                spec = dict(type='phase', id=pid, target_mode='fixed', parameters=parameters, profile={'mode': 'normal'})
                self.assertEqual(web.planning.execution(spec)['id'], pid)
                web.campaign_process = None
                response = self.client.post('/api/executions/run', json=dict(execution=spec, credentials={'rdp_password': 'RUNTIME_SECRET', 'ssh_password': 'RUNTIME_SECRET'}))
                self.assertEqual(response.status_code, 200, response.get_json())
                self.assertIn('--platform', self.launch.call_args.args[1])
                for mode in ('auto', 'fixed'):
                    saved = self.client.post('/api/custom-scenarios', json=definition(pid, mode, platform))
                    self.assertEqual(saved.status_code, 201, saved.get_json())
                response = self.client.post('/api/schedules', json={'version': 1, 'execution': spec, 'at': '2099-11-01T12:00:00Z', 'interval': 86400, 'enabled': False})
                self.assertEqual(response.status_code, 201, response.get_json())
                web.campaign_process = None
                web.planning.scheduler.observe = None
                result = self.client.post('/api/schedules/' + response.get_json()['id'] + '/run', json={'rdp_password': 'RUNTIME_SECRET', 'ssh_password': 'RUNTIME_SECRET'})
                self.assertEqual(result.status_code, 200, result.get_json())
                self.assertNotIn(b'RUNTIME_SECRET', web.planning.store.path.read_bytes())
        planned = web.planning.definition('full-incident', {'profile': {'mode': 'slow'}})
        self.assertEqual([p['id'] for p in planned['phases']], [p for p in PHASE_ORDER if p not in {'08', '10'}])


if __name__ == '__main__':
    unittest.main()
