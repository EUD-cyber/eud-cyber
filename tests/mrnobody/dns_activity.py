"""Offline P18 contracts. No VM, live resolver or campaign is contacted."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import random
import shutil
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
import dns_actions as dns
import remote_actions as remote
import app as web
from execution import phase_environment, snapshot
from reports import build_report, read_metadata, PHASE_ORDER, redact_environment
from report_exports import export_html, export_pdf
from scenario_model import catalogue, validate, plan, needs_password
sys.path.insert(0, str(Path(__file__).parent))
from planning import API

CAPS = catalogue(BASE / 'scripts', read_metadata)


def definition(mode='auto', platform='linux', **parameters):
    params = dict(platform=platform, **parameters)
    if mode == 'fixed':
        params.update(target='192.168.1.15', protocol='ssh' if platform == 'linux' else 'winrm-http')
    return dict(version=1, name='DNS classroom', target_mode=mode, profile={'mode': 'normal'},
                phases=([{'id': '01'}, {'id': '03'}] if mode == 'auto' else []) + [{'id': '18', 'parameters': params}])


def output(statuses):
    return '\n'.join(f'MRN_DNS={i},{status},{1793627656000+i}' for i, status in enumerate(statuses, 1))


class DNSActivity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-dns-test',
                        NORDIC_LAB_DNS_ENDPOINT='192.168.1.254', MRNOBODY_RUN_MODE='campaign',
                        NORDIC_RDP_PASSWORD='WINDOWS_SECRET', NORDIC_SSH_PASSWORD='LINUX_SECRET')
        self.inventory(['windows', 'linux'])

    def inventory(self, platforms):
        path = self.base / 'state/compromised-hosts.json'
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(dict(incident_id=self.env['NORDIC_INCIDENT_ID'], hosts=[
            dict(ip=f'192.168.1.{15+i}', platform=p, access='rdp' if p == 'windows' else 'ssh', compromised=True)
            for i, p in enumerate(platforms)])))
        self.env['NORDIC_COMPROMISED_STATE'] = str(path)

    def run_phase(self, statuses, **overrides):
        env = dict(self.env, **overrides)
        result = dns.evidence('18', output(statuses), dns.configuration('18', env))
        invoke = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps(result)))
        with contextlib.redirect_stdout(io.StringIO()):
            code = remote.run('18', env, invoke)
        return code, invoke

    def test_registry_profiles_and_auto_fixed_dependencies(self):
        self.assertEqual(CAPS['18']['dependencies'], ['03'])
        self.assertTrue(CAPS['18']['standalone'])
        self.assertEqual(CAPS['18']['timing'], ['start_offset'])
        for platform in ('windows', 'linux'):
            for mode in ('auto', 'fixed'):
                for profile in ('normal', 'slow', 'custom'):
                    value = definition(mode, platform)
                    value['profile'] = {'mode': profile}
                    planned = plan(validate(value, CAPS))
                    self.assertEqual(planned['phases'][-1]['id'], '18')
                    self.assertNotIn('duration', planned['phases'][-1].get('timing', {}))
                    self.assertTrue(needs_password(planned, platform == 'windows'))
        value = definition(); value['phases'].reverse()
        with self.assertRaises(ValueError): validate(value, CAPS)
        value = definition('fixed'); value['phases'][0]['parameters']['target'] = '8.8.8.8'
        with self.assertRaises(ValueError): validate(value, CAPS)
        value = definition('fixed'); value['phases'][0]['parameters']['protocol'] = 'winrm-http'
        with self.assertRaises(ValueError): validate(value, CAPS)

    def test_destination_pattern_and_numeric_validation(self):
        invalid = {'dns_endpoint': ['8.8.8.8', '127.0.0.1', 'resolver.test', '::1'],
                   'dns_domain': ['example.com', 'x.test;echo', 'UPPER.test', 'x.' + 'a'*121 + '.test'],
                   'dns_pattern': ['{seq}', 'x-{seq}.{data}', 'a-{seq}-{seq}', 'x-$(id){seq}'],
                   'dns_interval': [0, -1, 181, float('nan'), float('inf'), True],
                   'dns_jitter': [-.1, .51, True], 'dns_count': [0, 41, 1.5, True],
                   'dns_duration': [0, 241, True], 'dns_behavior': ['interactive', 'http']}
        for key, values in invalid.items():
            for val in values:
                with self.subTest(key=key, val=val), self.assertRaises(ValueError):
                    validate(definition(**{key: val}), CAPS)
        with self.assertRaises(ValueError): dns.configuration('18', {'MRNOBODY_DNS_INTERVAL': 0})
        with self.assertRaises(ValueError): dns.configuration('18', {'MRNOBODY_DNS_INTERVAL': 180})
        for key in ('command', 'payload', 'file', 'transport'):
            with self.assertRaises(ValueError): validate(definition(**{key: 'unsafe'}), CAPS)

    def test_low_slow_jitter_budget_and_fixed_encoding(self):
        config = dns.configuration('18', {'MRNOBODY_DNS_BEHAVIOR': 'low-and-slow', 'MRNOBODY_DNS_JITTER': '.5'})
        self.assertTrue(config['low_and_slow'])
        self.assertEqual(config['dns_interval'], 60)
        delays = dns.schedule(config, random.Random(22))
        self.assertEqual(delays[0], 0)
        self.assertTrue(all(30 <= v <= 90 for v in delays[1:]))
        for env in ({'MRNOBODY_DNS_BEHAVIOR': 'low-and-slow', 'MRNOBODY_DNS_INTERVAL': '29'},
                    {'MRNOBODY_DNS_DURATION': '5'}, {'MRNOBODY_DNS_COUNT': '40', 'MRNOBODY_DNS_INTERVAL': '10'}):
            with self.assertRaises(ValueError): dns.configuration('18', env)
        config = dns.configuration('18', {'MRNOBODY_DNS_BEHAVIOR': 'encoded-marker'})
        for name in dns.queries(config):
            label = name.split('.')[1]
            self.assertEqual(base64.b32decode(label.upper() + '='*((-len(label)) % 8)), b'MRN-EXERCISE-ONLY')
            self.assertLessEqual(len(name), 253)
        self.assertEqual(config['mitre'], 'T1071.004,T1132.001')

    def test_windows_linux_selection_fallback_and_no_access(self):
        for platform in ('windows', 'linux'):
            code, invoke = self.run_phase(['ok']*3, MRNOBODY_PLATFORM=platform)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(invoke.call_args.kwargs['env']['MRN_REMOTE_TARGET'])['platform'], platform)
            self.assertEqual(invoke.call_args.kwargs['timeout'], 315)
            targets = remote.targets(dict(self.env, MRNOBODY_RUN_MODE='standalone', MRNOBODY_PLATFORM=platform,
                                          MRNOBODY_TARGET='10.0.0.20', MRNOBODY_PROTOCOL='ssh' if platform == 'linux' else 'winrm-https'))
            self.assertEqual(targets[0]['platform'], platform)
        results = iter([dict(result='failed', warning='transport_error_details_omitted'), dict(result='success')])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(remote.run('18', self.env, lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(next(results)))), 0)
        self.inventory([])
        code, invoke = self.run_phase(['ok']*3)
        self.assertEqual(code, 78); invoke.assert_not_called()

    def test_result_counts_partial_failure_and_redaction(self):
        config = dns.configuration('18', self.env)
        for statuses, expected in [(['ok']*3, 'success'), (['ok','failed','ok'], 'partial'), (['failed']*3, 'failed'), (['ok'], 'partial'), ([], 'failed')]:
            result = dns.evidence('18', output(statuses) + '\nRAW_PASSWORD=DO_NOT_PERSIST', config)
            self.assertEqual(result['result'], expected)
            self.assertEqual(result['success_count'], statuses.count('ok'))
            self.assertEqual(result['failure_count'], statuses.count('failed'))
            self.assertEqual(result['unattempted_count'], 3-len(statuses))
            self.assertNotIn('DO_NOT_PERSIST', json.dumps(result))
        self.assertEqual(dns.evidence('18', output(['ok']*3).replace('MRN_DNS=2', 'MRN_DNS=1'), config)['result'], 'failed')
        self.assertEqual(self.run_phase(['ok', 'failed', 'ok'])[0], 80)
        self.assertEqual(self.run_phase(['failed']*3)[0], 1)
        logs = (self.base/'logs/incident-ground-truth.log').read_text()
        self.assertIn('DNS_ACTION_PARTIAL', logs)
        self.assertNotIn('WINDOWS_SECRET', logs)
        self.assertNotIn('LINUX_SECRET', logs)

    def test_generated_linux_client_response_validation_without_network(self):
        source = dns.script('18', 'linux', self.env)
        program = source.split("MRN_DNS_PY'\n", 1)[1].rsplit('MRN_DNS_PY', 1)[0]
        compile(program, '<MRN DNS>', 'exec')
        for kind, expected in [('ok', 'success'), ('nxdomain', 'success'), ('timeout', 'failed'), ('wrong-id', 'failed'), ('wrong-question', 'failed'), ('servfail', 'failed'), ('short', 'failed')]:
            client = Mock()
            client.__enter__ = Mock(return_value=client); client.__exit__ = Mock(return_value=False)
            sent = []
            client.send.side_effect = lambda data: sent.append(data)
            def reply(size):
                if kind == 'timeout': raise socket.timeout()
                data = bytearray(sent[-1]); data[2] |= 128
                if kind == 'wrong-id': data[0] ^= 1
                if kind == 'wrong-question': data[-1] ^= 1
                if kind == 'nxdomain': data[3] |= 3
                if kind == 'servfail': data[3] |= 2
                return bytes(data[:2] if kind == 'short' else data)
            client.recv.side_effect = reply
            capture = io.StringIO()
            with patch('socket.socket', return_value=client), patch('time.sleep'), contextlib.redirect_stdout(capture):
                exec(program, {})
            result = dns.evidence('18', capture.getvalue(), dns.configuration('18', self.env))
            self.assertEqual(result['result'], expected, kind)
            client.connect.assert_called_with(('192.168.1.254', 53))

    def test_windows_script_parses_and_transport_evidence(self):
        shell = shutil.which('pwsh') or shutil.which('powershell')
        source = dns.script('18', 'windows', dict(self.env, MRNOBODY_DNS_COUNT='40', MRNOBODY_DNS_INTERVAL='1'))
        self.assertLess(len(source), 16384)
        for forbidden in ('Invoke-Expression', 'DownloadString', 'WriteAll', 'Start-Process'):
            self.assertNotIn(forbidden, source)
        if shell:
            parsed = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', '$s=[Console]::In.ReadToEnd();$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e)|Out-Null;if($e.Count){$e;exit 1}'], input=source, text=True, capture_output=True, timeout=30)
            self.assertEqual(parsed.returncode, 0, parsed.stdout + parsed.stderr)
        session = Mock()
        session.run_ps.return_value = SimpleNamespace(status_code=0, std_out=output(['ok','failed','ok']).encode(), std_err=b'PASSWORD=PRIVATE')
        target = remote.targets(dict(self.env, MRNOBODY_RUN_MODE='standalone', MRNOBODY_PLATFORM='windows', MRNOBODY_TARGET='10.0.0.20'))[0]
        result = remote.perform('18', target, self.env, session_factory=Mock(return_value=session))
        self.assertEqual(result['result'], 'partial')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_linux_transport_framing(self):
        target = dict(platform='linux', target='10.0.0.20')
        for trailer, status in [(b'0', 'success'), (b'78', 'skipped'), (b'1', 'failed')]:
            data = output(['ok']*3).encode() + b'\nMRN_REMOTE_EXIT=' + trailer + b'__MRN_END__'
            ssh = Mock(return_value=(0, (data, len(data)), (b'', 0)))
            self.assertEqual(remote.perform('18', target, self.env, ssh=ssh)['result'], status)
        ssh = Mock(return_value=(255, (b'PASSWORD=PRIVATE', 16), (b'', 0)))
        self.assertEqual(remote.perform('18', target, self.env, ssh=ssh)['result'], 'failed')

    def test_reports_mitre_exports_live_and_historical_compatibility(self):
        (self.base/'scripts').mkdir()
        shutil.copy(BASE/'scripts/18-dns.sh', self.base/'scripts')
        code, _ = self.run_phase(['ok','failed','ok'], MRNOBODY_DNS_BEHAVIOR='encoded-marker')
        state = dict(incident_id=self.env['NORDIC_INCIDENT_ID'], phase_id='18', status='partial', phases={'18':'partial'})
        report = build_report(self.base, self.env['NORDIC_INCIDENT_ID'], code, self.env, standalone=state)
        self.assertEqual(report['incident']['status'], 'partial')
        self.assertEqual(report['phases'][0]['status'], 'partial')
        serialized = json.dumps(report)
        for value in ('T1071.004', 'T1132.001', 'https://attack.mitre.org/techniques/T1071/004/', 'DNS_ACTION_PARTIAL', 'Suricata', 'sample_queries', 'success_count', 'low_and_slow'):
            self.assertIn(value, serialized)
        self.assertIn('T1132.001', export_html(report))
        self.assertTrue(export_pdf(report).startswith(b'%PDF'))
        launch = dict(incident_id=self.env['NORDIC_INCIDENT_ID'], type='phase', id='18', phases=[{'id':'18'}])
        (self.base/'runtime').mkdir(exist_ok=True)
        (self.base/'runtime/execution-overview.json').write_text(json.dumps(launch))
        with patch('execution.report_for', return_value=report):
            live = snapshot(self.base, CAPS, None, 0)
        self.assertEqual(live['status'], 'partial')
        self.assertEqual(live['timeline'][0]['status'], 'partial')
        self.assertTrue(any('Partial' in row for row in live['logs']))
        legacy_id = self.env['NORDIC_INCIDENT_ID']+'-legacy'
        (self.base/'state/campaign.json').write_text(json.dumps(dict(incident_id=legacy_id, status='complete', phases={'03':'complete'})))
        legacy = build_report(self.base, legacy_id, 0, self.env)
        self.assertNotIn('18', [p['id'] for p in legacy['phases']])

    def test_full_order_environment_isolation_and_userdata(self):
        ids = read_metadata(BASE/'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(',')
        self.assertEqual(ids, list(PHASE_ORDER))
        for a,b in [('14','18'), ('18','16'), ('18','04'), ('18','17'), ('18','05'), ('18','06'), ('18','07')]:
            self.assertLess(ids.index(a), ids.index(b))
            value = definition('fixed')
            other = dict(id=a if a!='18' else b, parameters={'target':'10.0.0.2', 'protocol':'ssh'})
            value['phases'] = [value['phases'][0], other] if a!='18' else [other, value['phases'][0]]
            with self.assertRaises(ValueError): validate(value, CAPS)
        value = definition('fixed', dns_interval=12, dns_jitter=.2, dns_duration=120)
        planned = plan(validate(value, CAPS))
        env = phase_environment('18', dict(self.env, MRN_EXECUTION=json.dumps(planned), MRN_STARTED='0', MRNOBODY_BEACON_INTERVAL='99'), sleep=lambda n: None, clock=lambda: 0)
        self.assertEqual(env['MRNOBODY_DNS_INTERVAL'], '12')
        self.assertNotIn('MRNOBODY_BEACON_INTERVAL', env)
        env = phase_environment('18', dict(self.env, MRN_EXECUTION=json.dumps(planned), MRN_STARTED='0', MRNOBODY_DNS_COUNT='40'), sleep=lambda n: None, clock=lambda: 0)
        self.assertNotIn('MRNOBODY_DNS_COUNT', env)
        userdata = (ROOT/'MRNOBODY/mrnobody_userdata.yaml').read_text()
        for name in ('scripts/18-dns.sh', 'web/dns_actions.py'):
            self.assertIn('"'+name+'"', userdata)


class DNSEndpoints(API):
    def test_standalone_custom_full_and_scheduler(self):
        for platform in ('windows','linux'):
            params = definition('fixed', platform)['phases'][0]['parameters']
            spec = dict(type='phase', id='18', target_mode='fixed', parameters=params, profile={'mode':'normal'})
            self.assertEqual(web.planning.execution(spec)['id'], '18')
            web.campaign_process = None
            response = self.client.post('/api/executions/run', json=dict(execution=spec, credentials={'rdp_password':'RUNTIME_SECRET','ssh_password':'RUNTIME_SECRET'}))
            self.assertEqual(response.status_code, 200, response.get_json())
            for mode in ('auto','fixed'):
                response = self.client.post('/api/custom-scenarios', json=definition(mode, platform))
                self.assertEqual(response.status_code, 201, response.get_json())
            response = self.client.post('/api/schedules', json={'version':1,'execution':spec,'at':'2099-11-01T12:00:00Z','interval':86400,'enabled':False})
            self.assertEqual(response.status_code, 201, response.get_json())
            web.campaign_process = None; web.planning.scheduler.observe = None
            response = self.client.post('/api/schedules/'+response.get_json()['id']+'/run', json={'rdp_password':'RUNTIME_SECRET','ssh_password':'RUNTIME_SECRET'})
            self.assertEqual(response.status_code, 200, response.get_json())
            self.assertNotIn(b'RUNTIME_SECRET', web.planning.store.path.read_bytes())
        planned = web.planning.definition('full-incident', {'profile':{'mode':'slow'}})
        self.assertIn('18', [p['id'] for p in planned['phases']])


if __name__ == '__main__':
    unittest.main()
