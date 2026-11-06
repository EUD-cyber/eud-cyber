"""Offline P11 pair, worker, API, report and lifetime contracts. No lab traffic."""
import ast
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
import persistence_actions as p
import remote_actions as remote
from reports import build_report, read_metadata
from report_exports import export_html, export_pdf
from scenario_model import catalogue, validate, plan
from execution import phase_environment
CAPS = catalogue(PLATFORM / 'scripts', read_metadata)
TARGET = dict(platform='linux', target='192.168.1.20', port=22, protocol='ssh', username='ubuntu')
ENV = dict(MRNOBODY_PERSISTENCE_DNS='enabled', MRNOBODY_PERSISTENCE_RESOLVER='192.168.1.53',
           MRNOBODY_PERSISTENCE_DURATION='60', MRNOBODY_PERSISTENCE_INTERVAL='10')


class Configuration(unittest.TestCase):
    def test_defaults_platform_pairs_safe_scope_and_cleanup_without_dns_options(self):
        for platform, method in [('windows', 'task-service'), ('linux', 'cron-systemd')]:
            self.assertEqual(p.configuration({}, platform)[0], method)
            meta = p.metadata(ENV, platform)
            self.assertEqual(meta['dns_domain'], 'evilcorp.test')
            self.assertEqual(meta['network_detection'], 'not_assessed_requires_sensor_evidence')
            self.assertEqual(meta['mitre'], p.METHODS[method][1])
            self.assertNotIn('T1071.004', meta['mitre'])
            self.assertIn('MRN_P11_CLEANUP=complete', p.script({'MRNOBODY_ACTION':'cleanup'}, platform))
        for key, values in {
            'PERSISTENCE_DNS': ['yes', True],
            'PERSISTENCE_DOMAIN': ['evilcorp.com', 'evilcorp.test;id', 'x.test\nid', '-x.test', 'X.test', 'x..test', 'x' * 64 + '.test'],
            'PERSISTENCE_RESOLVER': ['', '8.8.8.8', '127.0.0.1', '::1', '192.168.1.0', '192.168.1.255', '192.168.1.53;id'],
            'PERSISTENCE_INTERVAL': ['0', '9', '3601', '1;id', 'NaN', True],
            'PERSISTENCE_DURATION': ['59', '14401', 'inf', '-1', True],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    p.configuration(dict(ENV, **{'MRNOBODY_' + key: value}), 'linux')
        with self.assertRaises(ValueError):
            p.configuration(dict(ENV, MRNOBODY_METHOD='cron'), 'linux')

    def test_profiles_and_environment_roundtrip(self):
        params = dict(platform='linux', method='cron-systemd', target=TARGET['target'], protocol='ssh',
                      persistence_dns='enabled', persistence_domain='evilcorp.test', persistence_resolver='192.168.1.53',
                      persistence_interval=10, persistence_duration=60)
        for mode in ('normal', 'slow', 'custom'):
            value = dict(version=1, name='P11 DNS fixture', target_mode='fixed', profile=dict(mode=mode),
                         phases=[dict(id='11', parameters=params)])
            value = plan(validate(value, CAPS))
            env = phase_environment('11', dict(MRN_EXECUTION=json.dumps(value), MRN_STARTED='0',
                                             MRNOBODY_PERSISTENCE_RESOLVER='192.168.99.99'), sleep=lambda _: None)
            self.assertEqual(env['MRNOBODY_PERSISTENCE_RESOLVER'], '192.168.1.53')
            self.assertEqual(p.configuration(env, 'linux')[0], 'cron-systemd')
        stale = phase_environment('11', dict(MRN_EXECUTION=json.dumps(dict(value, phases=[dict(id='11', parameters={})])),
                                           MRN_STARTED='0', MRNOBODY_PERSISTENCE_DNS='enabled'), sleep=lambda _:None)
        self.assertNotIn('MRNOBODY_PERSISTENCE_DNS', stale)

    def test_evidence_is_not_configuration_or_sensor_detection(self):
        for output in ('configured', 'MRN_P11=1,0,1900000000,1,1,1800000000000,0',
                       'MRN_P11=1,1,1900000000,1,2,1800000000000,0'):
            self.assertEqual(p.evidence(output, ENV, 'linux')['result'], 'failed')
        missing = p.evidence('MRN_P11=1,1,1900000000,1,0,1800000000000,-1', ENV, 'linux')
        self.assertEqual(missing['dns_verification'], 'not_observed')
        self.assertNotEqual(missing['warning'], 'none')
        ok = p.evidence('MRN_P11=1,1,1900000000,1,1,1800000000000,3', ENV, 'linux')
        self.assertEqual(ok['dns_verification'], 'matching_NOERROR_or_NXDOMAIN_response')
        self.assertNotIn('stdout_preview', ok)


@unittest.skipIf(os.name == 'nt', 'Linux setup uses fcntl')
class LinuxPair(unittest.TestCase):
    def test_create_rerun_deadline_cleanup_ownership_and_partial_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            directory = home / '.config/mrnobody/mrnobody-p11-telemetry'
            cron = ['0 0 * * * echo unrelated']
            state = {'active': False}
            def provider(argv, **kw):
                if argv[:2] == ['crontab', '-l']:
                    return SimpleNamespace(returncode=0, stdout='\n'.join(cron)+'\n', stderr='')
                if argv == ['crontab', '-']:
                    cron[:] = kw['input'].splitlines()
                    return SimpleNamespace(returncode=0)
                self.assertEqual(argv[:2], ['/usr/bin/systemctl', '--user'])
                if argv[2] == 'enable':
                    state['active'] = True
                    (directory/'status.txt').write_text('1,1,1800000000000,3')
                if argv[2] == 'disable':
                    state['active'] = False
                if argv[2] == 'is-active':
                    return SimpleNamespace(returncode=0 if state['active'] else 3, stdout='active\n' if state['active'] else 'inactive\n', stderr='')
                return SimpleNamespace(returncode=0, stdout='active\n', stderr='')
            def execute(action='create'):
                source = p.script(dict(ENV, MRNOBODY_ACTION=action), 'linux')
                setup = source.split("python3 - <<'MRN_P11_SETUP'\n", 1)[1].rsplit('\nMRN_P11_SETUP', 1)[0]
                with patch('pathlib.Path.home', return_value=home), patch('subprocess.run', side_effect=provider), contextlib.redirect_stdout(io.StringIO()) as output:
                    exec(compile(setup, '<P11 setup>', 'exec'), {})
                return output.getvalue()
            out = execute()
            self.assertEqual(p.evidence(out, ENV, 'linux')['result'], 'success')
            self.assertEqual(p.evidence(out, ENV, 'linux')['artifact_path'], str(directory))
            deadline = (directory/'config.txt').read_text()
            execute()
            self.assertEqual((directory/'config.txt').read_text(), deadline)
            self.assertEqual(len([c for c in cron if 'MrNobody' in c]), 1)
            self.assertTrue(state['active'])
            (directory/'owner.txt').write_text('unrelated')
            with self.assertRaises(SystemExit):
                execute('cleanup')
            (directory/'owner.txt').write_text(p.MARKER)
            execute('cleanup')
            execute('cleanup')
            self.assertFalse(directory.exists())
            self.assertFalse(state['active'])
            self.assertIn('0 0 * * * echo unrelated', cron)
            self.assertFalse(any('MrNobody' in c for c in cron))
            # Recover a partially installed owned directory and cron entry.
            directory.mkdir()
            (directory/'owner.txt').write_text(p.MARKER)
            cron.append('* * * * * true # ' + p.MARKER + ' mrnobody-p11-telemetry')
            execute('cleanup')
            self.assertFalse(directory.exists())

    def test_worker_packet_response_validation_expiry_and_unavailable_dns(self):
        for mode in ('nxdomain', 'unavailable', 'mismatch'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                now = [1800000000.]
                settings = 'enabled|evilcorp.test|192.168.1.53|10|60'
                (base/'config.txt').write_text(settings + '\n1800000060\n')
                question = p.question('evilcorp.test')
                self.assertEqual(struct.unpack('!H', question[2:4])[0], 0)  # no recursion
                sent = []
                class Client:
                    def __enter__(self): return self
                    def __exit__(self, *args): pass
                    def settimeout(self, value): assert value == 2
                    def connect(self, addr): assert addr == ('192.168.1.53', 53)
                    def send(self, q): self.q=q; sent.append(q)
                    def recv(self, count):
                        if mode == 'unavailable': raise OSError()
                        r = bytearray(self.q); r[2] = 128; r[3] = 3
                        if mode == 'mismatch': r[0] ^= 1
                        return bytes(r)
                source = p.LINUX_WORKER.replace('__SETTINGS__', settings).replace('__NAME__', 'mrnobody-p11-telemetry').replace('__PACKET__', base64.b64encode(question).decode())
                def sleep(seconds): now[0] += seconds
                with patch('socket.socket', return_value=Client()), patch('time.time', side_effect=lambda:now[0]), patch('time.monotonic', side_effect=lambda:now[0]), patch('time.sleep', side_effect=sleep):
                    exec(compile(source, '<P11 worker>', 'exec'), {'__file__':str(base/'worker.py')})
                attempts, responses, _, _ = (base/'status.txt').read_text().split(',')
                self.assertEqual(attempts, '6')
                self.assertEqual(responses, '6' if mode == 'nxdomain' else '0')
                self.assertEqual(len(sent), 6)
                self.assertTrue(all(q[2:] == question[2:] for q in sent))
                self.assertEqual(now[0], 1800000060)
                with patch('subprocess.run') as run, patch('time.time', return_value=1800000061), patch.object(sys, 'argv', ['worker.py','--maintain']):
                    with self.assertRaises(SystemExit):
                        exec(compile(source, '<expired maintenance>', 'exec'), {'__file__':str(base/'worker.py')})
                    run.assert_not_called()


class APIIntegration(unittest.TestCase):
    def test_full_incident_standalone_custom_scheduler_and_registry(self):
        # The shared API fixture replaces launch; no actual process or target.
        sys.path.insert(0, str(Path(__file__).parent))
        from planning import API
        import app as web
        fixture = API(methodName='runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        params = dict(platform='linux', method='cron-systemd', persistence_dns='enabled',
                      persistence_resolver='192.168.1.53', persistence_domain='evilcorp.test',
                      persistence_interval=60, persistence_duration=3600, artifact='api-dns')
        for mode in ('normal', 'slow'):
            spec = dict(type='campaign', id='full-incident', profile=dict(mode=mode), persistence=params)
            clean = web.planning.execution(spec)
            execution = web.planning.definition('full-incident', clean)
            phase = next(p for p in execution['phases'] if p['id']=='11')
            self.assertEqual(phase['parameters'], params)
            ids = [p['id'] for p in execution['phases']]
            self.assertLess(ids.index('03'), ids.index('11'))
            self.assertLess(ids.index('11'), ids.index('12'))
            result = fixture.client.post('/api/executions/run', json=dict(execution=spec, credentials=dict(ssh_password='LAB_ONLY', rdp_password='LAB_ONLY')))
            self.assertEqual(result.status_code, 200, result.json)
            web.campaign_process = None
            saved = fixture.client.post('/api/schedules', json=dict(version=1, execution=spec, interval=0, enabled=True, at='2099-01-01T00:00:00Z'))
            self.assertEqual(saved.status_code, 201, saved.json)
            self.assertEqual(saved.json['execution']['persistence'], params)
            self.assertEqual(fixture.client.post('/api/schedules/'+saved.json['id']+'/arm',
                json=dict(ssh_password='LAB_ONLY', rdp_password='LAB_ONLY')).status_code, 200)
        for platform, method, protocol in [('linux','cron-systemd','ssh'), ('windows','task-service','winrm-http')]:
            fixed = dict(params, platform=platform, method=method, protocol=protocol, target=TARGET['target'])
            phase = dict(type='phase',id='11',parameters=fixed)
            self.assertEqual(web.planning.execution(phase), dict(phase, profile={'mode':'normal','duration':0}))
            invalid = dict(fixed,persistence_domain='public.example')
            with self.assertRaises(ValueError):
                web.planning.execution(dict(phase,parameters=invalid))
        cap = web.planning.capabilities()['11']['fields']
        for key in params:
            self.assertIn(key, cap)
        self.assertIn('task-service', cap['method']['options'])
        self.assertIn('cron-systemd', cap['method']['options'])
        custom = dict(version=1,name='Pair integration',target_mode='auto',profile={'mode':'custom'},
                      phases=[{'id':'01'},{'id':'03'},{'id':'11','parameters':params,'timing':{'start_offset':10}}])
        self.assertEqual([p['id'] for p in plan(validate(custom,CAPS))['phases']], ['01','03','11'])
        for source in ('web/static/app.js', 'web/static/planning.js', 'web/templates/index.html'):
            text = (PLATFORM/source).read_text()
            for key in ('persistence_dns','persistence_resolver','persistence_duration'):
                self.assertIn(key, text)
        data = web.planning.store.path.read_bytes()
        self.assertNotIn(b'LAB_ONLY', data)


class TransportAndReports(unittest.TestCase):
    def test_transports_parse_only_evidence_and_cleanup(self):
        for platform in ('linux', 'windows'):
            target = dict(TARGET, platform=platform, protocol='ssh' if platform == 'linux' else 'winrm-http')
            for action in ('create', 'cleanup'):
                env = dict(ENV, MRNOBODY_PASSWORD='synthetic-only', MRNOBODY_ACTION=action)
                out = b'MRN_P11_CLEANUP=complete' if action == 'cleanup' else b'MRN_P11=1,1,1900000000,1,1,1800000000000,3'
                factory = Mock()
                factory.return_value.run_ps.return_value = SimpleNamespace(status_code=0,std_out=out,std_err=b'')
                framed = out + b'\nMRN_REMOTE_EXIT=0__MRN_END__\n'
                result = remote.perform('11', target, env, session_factory=factory,
                                        ssh=Mock(return_value=(0,(framed,len(framed)),(b'',0))))
                self.assertEqual(result['result'], 'success')
                self.assertEqual(result['cleanup_required'], 'false' if action == 'cleanup' else 'true')
            if platform == 'linux':
                self.assertEqual(remote.perform('11', target, ENV, ssh=Mock(return_value=(255,(b'',0),(b'',0))))['result'], 'failed')

    def test_ground_truth_investigation_html_pdf_and_mitre_pairs(self):
        from pypdf import PdfReader
        for platform in ('linux', 'windows'):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                (base/'scripts').mkdir()
                shutil.copy(PLATFORM/'scripts/11-persistence.sh', base/'scripts/11-persistence.sh')
                env = dict(ENV, NORDIC_BASE_DIR=tmp, NORDIC_INCIDENT_ID='MRN-p11-fixture',
                           MRNOBODY_RUN_MODE='standalone', MRNOBODY_PLATFORM=platform,
                           MRNOBODY_TARGET=TARGET['target'], MRNOBODY_PROTOCOL='ssh' if platform == 'linux' else 'winrm-http')
                response = dict(result='success', **{k:v for k,v in p.evidence('MRN_P11=1,1,1900000000,1,1,1800000000000,3', env, platform).items() if k!='result'})
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(remote.run('11', env, Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps(response).encode()))), 0)
                standalone = dict(incident_id=env['NORDIC_INCIDENT_ID'],scenario='standalone-phase',phase_id='11',status='complete',phases={'11':'complete'})
                report = build_report(base, env['NORDIC_INCIDENT_ID'], environ=env, standalone=standalone)
                phase = report['phases'][0]
                self.assertEqual([t['id'] for t in phase['mitre']['techniques']], p.METHODS[p.configuration(env,platform)[0]][1].split(','))
                self.assertNotIn('T1071.004', [t['id'] for t in report['mitre_summary']])
                for view in ('ground-truth', 'investigation'):
                    html = export_html(report, view)
                    pdf = ''.join(page.extract_text() for page in PdfReader(io.BytesIO(export_pdf(report, view))).pages)
                    for text in (html, pdf):
                        self.assertIn('evilcorp.test', text)
                        self.assertIn('192.168.1.53', text)
                        self.assertIn('dns_responses', text)
                self.assertTrue(phase['actions'])
                self.assertIn('Suricata', json.dumps(phase['analysis']))


if __name__ == '__main__':
    unittest.main()
