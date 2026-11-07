"""Offline contracts for the fixed synthetic P06 default; no remote connections."""
import base64
import os
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

BASE = Path(__file__).resolve().parents[2] / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE/'web'))
import app as web
from exfil_validation import validate
from execution import phase_environment
from p06_synthetic import create, fixture, linux_script, windows_script
from reports import read_metadata
from scenario_model import catalogue, plan, validate as scenario

IID = 'MRN-default-fixture'
DATA = dict(target='192.168.1.20', protocol='ssh', username='student', password='DO_NOT_RECORD')


class DefaultP06(unittest.TestCase):
    def test_no_staging_and_reject_custom_paths(self):
        self.assertEqual(validate(DATA, '/missing/staged-data.json')['source_kind'], 'synthetic-default')
        for changes in ({'file': '/etc/shadow'}, {'file': '/tmp/a-directory'}, {'file': '../x'},
                        {'staging_incident': IID}, {'username': '-oProxyCommand=bad'}, {'port': True},
                        {'file': []}, {'port': False}, {'username': '-option'}, {'target': '8.8.8.8'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate({**DATA, **changes}, '/missing')
        self.assertLess(len(fixture(IID)), 1024)
        self.assertIn(b'SIMULATED', fixture(IID))
        self.assertIn(b'never real company secrets', fixture(IID))

    def test_linux_preparation_and_failures(self):
        raw = fixture(IID)
        def run(args, **kw):
            self.assertNotIn(DATA['password'], args)
            self.assertEqual(kw['env']['SSHPASS'], DATA['password'])
            self.assertIn('mkdir --', kw['input'])
            self.assertIn('set -C', kw['input'])
            path = re.search(r"mkdir -- '([^']+)'", kw['input'])[1] + '/corporate-secret-data.txt'
            return Mock(returncode=0, stdout=f'P06_CREATED|{path}|{len(raw)}|{hashlib.sha256(raw).hexdigest()}\n')
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)/'exfiltration.json'
            result = create(DATA, IID, state, runner=run)
            self.assertEqual(result['result'], 'prepared')
            self.assertFalse(result['verified'])
            self.assertFalse(json.loads(state.read_text())['transfers'])
            for runner in (Mock(side_effect=TimeoutError(DATA['password'])),
                           Mock(return_value=Mock(returncode=1)),
                           Mock(return_value=Mock(returncode=0, stdout='P06_CREATED|/etc/shadow|3|bad\n'))):
                with self.assertRaises(ValueError) as error:
                    create(DATA, IID, state, runner=runner)
                self.assertNotIn(DATA['password'], str(error.exception))
                data = state.read_text()
                self.assertNotIn(DATA['password'], data)
                self.assertEqual(json.loads(data)['attempts'][0]['result'], 'preparation_failed')

    def test_windows_transports_and_evidence(self):
        raw = fixture(IID)
        def run_ps(script):
            folder = re.search(r"'mrnobody-p06-([^']+)'", script)[1]
            path = 'C:\\Users\\student\\AppData\\Local\\Temp\\mrnobody-p06-' + folder + '\\corporate-secret-data.txt'
            return Mock(status_code=0, std_out=f'P06_CREATED|{path}|{len(raw)}|{hashlib.sha256(raw).hexdigest()}\r\n'.encode())
        with tempfile.TemporaryDirectory() as tmp:
            for protocol in ('winrm', 'winrm-http', 'winrm-https'):
                factory = Mock(return_value=Mock(run_ps=Mock(side_effect=run_ps)))
                result = create({**DATA, 'protocol': protocol}, IID, Path(tmp)/'state.json', session_factory=factory)
                self.assertEqual(result['platform'], 'windows')
                self.assertEqual(result['source_size'], len(raw))
                endpoint = factory.call_args.args[0]
                self.assertIn('https://' if protocol == 'winrm-https' else 'http://', endpoint)
                self.assertIn(':5986/' if protocol == 'winrm-https' else ':5985/', endpoint)
            factory = Mock(return_value=Mock(run_ps=Mock(return_value=Mock(status_code=1))))
            with self.assertRaises(ValueError):
                create({**DATA, 'protocol': 'winrm-http'}, IID, Path(tmp)/'state.json', session_factory=factory)

    def test_api_default_dispatch_and_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attrs = dict(BASE_DIR=root, SCRIPT_DIR=BASE/'scripts', STATE_DIR=root/'state',
                         PHASE_RUNNER=BASE/'scripts/run-phase.sh', LOG_DIR=root/'logs',
                         CAMPAIGN_LOG=root/'logs/campaign.log', campaign_process=None)
            with patch.multiple(web, **attrs), patch.object(web, 'launch') as launch:
                launch.return_value.pid = 123
                for extra in ({}, {'profile': {'mode': 'normal', 'duration': 0}}, {'dry_run': True}):
                    reply = web.app.test_client().post('/api/phase/06/run', json={**DATA, **extra})
                    self.assertEqual(reply.status_code, 200, reply.json)
                    command = launch.call_args.args[1]
                    self.assertNotIn('--file', command)
                    self.assertNotIn(DATA['password'], command)
                    self.assertEqual(launch.call_args.kwargs['env']['MRNOBODY_STAGING_INCIDENT'], '')

    def test_scenario_default_and_p05_dependency_isolation(self):
        caps = catalogue(BASE/'scripts', read_metadata)
        def definition(ids):
            return dict(version=1, name='P06 default', description='Synthetic fixture', target_mode='fixed',
                        profile=dict(mode='normal', duration=0), phases=[dict(id=pid, parameters=dict(target=DATA['target'],
                        protocol='ssh', username='student'), timing={}) for pid in ids])
        config = plan(scenario(definition(['06']), caps))
        env = dict(MRN_EXECUTION=json.dumps(config), MRN_STARTED='0', NORDIC_INCIDENT_ID=IID,
                   NORDIC_SSH_PASSWORD=DATA['password'], MRNOBODY_STAGING_INCIDENT='MRN-stale')
        self.assertNotIn('MRNOBODY_FILE', phase_environment('06', env, sleep=lambda _: None))
        self.assertNotIn('MRNOBODY_STAGING_INCIDENT', phase_environment('06', env, sleep=lambda _: None))
        with self.assertRaisesRegex(ValueError, 'must precede'):
            scenario(definition(['06', '05']), caps)
        config = plan(scenario(definition(['05', '06']), caps))
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp)/'staged-data.json'
            env.update(MRN_EXECUTION=json.dumps(config), NORDIC_STAGING_STATE=str(staging))
            with self.assertRaises(OSError):
                phase_environment('06', env, sleep=lambda _: None)
            host = dict(ip=DATA['target'], staged=True, data_type='synthetic-training-data', file='/tmp/registered-p05')
            staging.write_text(json.dumps(dict(incident_id='MRN-other', hosts=[host])))
            with self.assertRaisesRegex(ValueError, 'incident ID mismatch'):
                phase_environment('06', env, sleep=lambda _: None)
            staging.write_text(json.dumps(dict(incident_id=IID, hosts=[host])))
            result = phase_environment('06', env, sleep=lambda _: None)
            self.assertEqual(result['MRNOBODY_FILE'], host['file'])
            self.assertEqual(result['MRNOBODY_STAGING_INCIDENT'], IID)
            self.assertEqual(result['MRNOBODY_REQUIRE_STAGING'], '1')

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell parser available on Windows CI')
    def test_windows_script_syntax_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp)/'p06.ps1'
            script.write_text(windows_script(IID, 'a'*32, fixture(IID)))
            parser = "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + str(script).replace("'", "''") + "',[ref]$t,[ref]$e);if($e.Count){$e;exit 1}"
            result = subprocess.run(['pwsh', '-NoProfile', '-EncodedCommand', base64.b64encode(parser.encode('utf-16le')).decode()], capture_output=True, text=True, env=dict(os.environ, XDG_CACHE_HOME=tmp, XDG_CONFIG_HOME=tmp, XDG_DATA_HOME=tmp))
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
