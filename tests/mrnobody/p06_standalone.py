"""P06 offline regressions: API, real dispatcher/report wrapper and loopback receiver.
Only sshpass is replaced. No connection to a target or VM is made.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
import app as module
from exfil_validation import validate
from execution import phase_environment

ORIGIN = 'MRN-20261106-120000-p05'
REMOTE = f'/tmp/.nordic-{ORIGIN}/nordic-data-{ORIGIN}.txt'
RAW = b'Nordic synthetic training fixture\n'
DIGEST = hashlib.sha256(RAW).hexdigest()
PAYLOAD = dict(target='192.168.1.20', protocol='ssh', username='student',
               password=' secret with spaces ', file=REMOTE, staging_incident=ORIGIN)


def staging(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(incident_id=ORIGIN, hosts=[dict(ip=PAYLOAD['target'],
        platform='linux', staged=True, data_type='synthetic-training-data', file=REMOTE,
        size=len(RAW), sha256=DIGEST)])))


class P06(unittest.TestCase):
    def test_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'staged-data.json'
            for value in (None, [], {}, {**PAYLOAD, 'protocol': 'rdp'}, {**PAYLOAD, 'port': '65536'},
                          {**PAYLOAD, 'target': '8.8.8.8'}, {**PAYLOAD, 'file': '/etc/shadow'}):
                with self.assertRaises(ValueError):
                    validate(value, path)
            with self.assertRaisesRegex(ValueError, 'Run P05 first'):
                validate(PAYLOAD, path)
            staging(path)
            self.assertEqual(validate(PAYLOAD, path)['sha256'], DIGEST)
            for field in PAYLOAD:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    validate({**PAYLOAD, field: ''}, path)
            for change in ({'staging_incident': 'MRN-other'}, {'target': '192.168.1.21'},
                           {'protocol': 'winrm-http'}, {'file': REMOTE+'-other'},
                           {'password': 'bad|delimiter'}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    validate({**PAYLOAD, **change}, path)
            windows = json.loads(path.read_text())
            windows['hosts'][0].update(platform='windows', file=rf'C:\NordicIncident\{ORIGIN}\staging\nordic-data-{ORIGIN}.txt')
            path.write_text(json.dumps(windows))
            for protocol in ('winrm', 'winrm-http', 'winrm-https'):
                self.assertEqual(validate({**PAYLOAD, 'protocol': protocol, 'file': windows['hosts'][0]['file']}, path)['platform'], 'windows')
            windows['hosts'][0]['sha256'] = ''
            path.write_text(json.dumps(windows))
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                validate({**PAYLOAD, 'protocol': 'winrm-http', 'file': windows['hosts'][0]['file']}, path)

    def test_api_payload_and_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=False):
            root = Path(tmp)
            os.environ.pop('NORDIC_STAGING_STATE', None)
            state = root / 'state/staged-data.json'
            staging(state)
            attrs = dict(BASE_DIR=root, SCRIPT_DIR=BASE/'scripts', STATE_DIR=root/'state',
                         PHASE_RUNNER=BASE/'scripts/run-phase.sh', LOG_DIR=root/'logs',
                         CAMPAIGN_LOG=root/'logs/campaign.log', campaign_process=None)
            with patch.multiple(module, **attrs), patch.object(module, 'launch') as launch:
                launch.return_value.pid = 123
                client = module.app.test_client()
                for payload in ([], {**PAYLOAD, 'password': ''}, {**PAYLOAD, 'file': '/etc/passwd'},
                                {**PAYLOAD, 'staging_incident': 'MRN-wrong'}):
                    self.assertEqual(client.post('/api/phase/06/run', json=payload).status_code, 400)
                state.unlink()
                self.assertEqual(client.post('/api/phase/06/run', json=PAYLOAD).status_code, 400)
                launch.assert_not_called()
                staging(state)
                ids = []
                for dry in (False, True):
                    reply = client.post('/api/phase/06/run', json={**PAYLOAD, 'dry_run': dry})
                    self.assertEqual(reply.status_code, 200, reply.json)
                    ids.append(reply.json['incident_id'])
                    args, kwargs = launch.call_args
                    cmd = args[1]
                    self.assertIn('06', cmd)
                    self.assertEqual(cmd[cmd.index('--file')+1], REMOTE)
                    self.assertEqual(cmd[cmd.index('--target')+1], PAYLOAD['target'])
                    self.assertEqual('--dry-run' in cmd, dry)
                    self.assertNotIn(PAYLOAD['password'], cmd)
                    self.assertEqual(kwargs['env']['MRNOBODY_PASSWORD'], PAYLOAD['password'])
                    self.assertEqual(kwargs['env']['MRNOBODY_STAGING_INCIDENT'], ORIGIN)
                self.assertEqual(len(set(ids)), 2)
                self.assertNotIn(ORIGIN, ids)
                self.assertNotIn(PAYLOAD['password'], module.CAMPAIGN_LOG.read_text())

    @unittest.skipUnless(shutil.which('bash') and sys.platform != 'win32', 'Linux dispatcher fixture')
    def test_real_dispatch_execution_and_report_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for folder in ('config', 'scripts', 'logs', 'state', 'uploads', 'bin'):
                (root/folder).mkdir()
            shutil.copytree(BASE/'web', root/'web', ignore=shutil.ignore_patterns('__pycache__'))
            for filename in ('run-phase.sh', '06-exfil.sh'):
                shutil.copy(BASE/'scripts'/filename, root/'scripts'/filename)
                (root/'scripts'/filename).chmod(0o755)
            (root/'config/defaults.conf').write_text(
                f'NORDIC_LOG_DIR="{root}/logs"\nNORDIC_STATE_DIR="{root}/state"\n'
                f'NORDIC_UPLOAD_DIR="{root}/uploads"\nNORDIC_COMPROMISED_STATE="{root}/state/compromised-hosts.json"\n'
                f'NORDIC_GROUND_TRUTH_LOG="{root}/logs/incident-ground-truth.log"\n'
                'NORDIC_DEFAULT_SSH_PASSWORD=""\nNORDIC_DEFAULT_RDP_PASSWORD=""\n')
            staging(root/'state/staged-data.json')
            # A remote-command double sends only the synthetic fixture to the real loopback receiver.
            fake = root/'bin/sshpass'
            fake.write_text('#!/usr/bin/env python3\n' +
                'import os, sys, urllib.request\n' +
                'if os.environ["FIXTURE_MODE"] == "failure": sys.exit(1)\n' +
                'raw = b"Nordic synthetic training fixture\\n" if os.environ["FIXTURE_MODE"] == "success" else b"wrong bytes"\n' +
                'req = urllib.request.Request("http://127.0.0.1:" + os.environ["NORDIC_EXFIL_PORT"] + "/upload", data=raw, headers={' +
                '"X-Nordic-Source":os.environ["MRNOBODY_TARGET"],"X-Nordic-Incident":os.environ["NORDIC_INCIDENT_ID"],"X-Nordic-Platform":"linux"})\n' +
                'print(urllib.request.urlopen(req, timeout=5).read().decode())\n')
            fake.chmod(0o755)
            env = dict(os.environ, NORDIC_BASE_DIR=str(root), MRNOBODY_PASSWORD=PAYLOAD['password'],
                       NORDIC_INCIDENT_IP='127.0.0.1', PATH=str(root/'bin')+os.pathsep+os.environ['PATH'])
            command = ['bash', str(root/'scripts/run-phase.sh'), '06', '--target', PAYLOAD['target'],
                       '--protocol', 'ssh', '--user', 'student', '--file', REMOTE, '--staging-incident', ORIGIN]
            for mode in ('success', 'failure', 'mismatch', 'missing'):
                with self.subTest(mode=mode):
                    with socket.socket() as sock:
                        sock.bind(('127.0.0.1', 0))
                        port = sock.getsockname()[1]
                    if mode == 'missing':
                        (root/'state/staged-data.json').unlink()
                    result = subprocess.run(command, env=dict(env, FIXTURE_MODE=mode, NORDIC_EXFIL_PORT=str(port)),
                                            text=True, capture_output=True, timeout=25)
                    self.assertEqual(result.returncode == 0, mode == 'success', result.stdout+result.stderr)
                    reports = sorted((root/'reports').glob('MRN-*.json'), key=lambda p:p.stat().st_mtime_ns)
                    self.assertTrue(reports)
                    report = json.loads(reports[-1].read_text())
                    self.assertEqual(report['report_type'], 'standalone_phase')
                    self.assertEqual(report['phase_id'], '06')
                    self.assertEqual(report['incident']['status'], 'complete' if mode == 'success' else 'failed')
                    if mode == 'success':
                        transfers = json.loads((root/'state/exfiltration.json').read_text())['transfers']
                        self.assertEqual(transfers[0]['bytes'], len(RAW))
                        self.assertEqual(transfers[0]['sha256'], DIGEST)
                    else:
                        self.assertNotIn('EXFIL_SUCCESS', result.stdout)
            self.assertNotIn(PAYLOAD['password'], (root/'logs/incident-ground-truth.log').read_text())


if __name__ == '__main__':
    unittest.main()
