"""Offline P09 standalone API and real worker preflight contracts. No lab traffic."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE/'web'))
import app as module
import windows_actions as actions

PAYLOAD = dict(target='192.168.1.20', username='student', password=' fixture secret ')
class P09(unittest.TestCase):
    def test_api_fixed_submission_validation_and_launch_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            attrs = dict(BASE_DIR=base, SCRIPT_DIR=BASE/'scripts', PHASE_RUNNER=BASE/'scripts/run-phase.sh',
                         LOG_DIR=base/'logs', CAMPAIGN_LOG=base/'logs/campaign.log', campaign_process=None)
            with patch.multiple(module, **attrs), patch.object(module, 'launch') as launch:
                launch.return_value.pid = 123
                client = module.app.test_client()
                for change in ({'target':''}, {'target':'8.8.8.8'}, {'username':''},
                               {'password':''}, {'timeout':301}, {'timeout':True}):
                    response = client.post('/api/phase/09/run', json={**PAYLOAD, **change})
                    self.assertEqual(response.status_code, 400, response.json)
                launch.assert_not_called()
                for data in (PAYLOAD, {**PAYLOAD, 'protocol':'ssh', 'port':22, 'dry_run':True}):
                    response = client.post('/api/phase/09/run', json=data)
                    self.assertEqual(response.status_code, 200, response.json)
                    args, kwargs = launch.call_args
                    command = args[1]
                    self.assertEqual(command[command.index('--protocol')+1], 'winrm-http')
                    self.assertEqual(command[command.index('--port')+1], '5985')
                    self.assertEqual(kwargs['env']['MRNOBODY_PASSWORD'], PAYLOAD['password'])
                    self.assertNotIn(PAYLOAD['password'], command)
                launch.side_effect = OSError(PAYLOAD['password'])
                response = client.post('/api/phase/09/run', json=PAYLOAD)
                self.assertEqual(response.status_code, 500)
                self.assertNotIn(PAYLOAD['password'], response.get_data(as_text=True))
                self.assertIn('launch failed', module.CAMPAIGN_LOG.read_text())
                self.assertNotIn(PAYLOAD['password'], module.CAMPAIGN_LOG.read_text())

    def test_worker_port_failure_is_actionable_and_never_authenticates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Fake import supplies a bounded TCP probe. run_ps must never be called.
            (root/'winrm.py').write_text("""
import socket
from types import SimpleNamespace
class WinRMError(Exception): pass
exceptions = SimpleNamespace(WinRMError=WinRMError)
def closed(address, timeout):
    assert address == ('192.168.1.20', 5985)
    assert timeout <= 5
    raise ConnectionRefusedError('PRIVATE_TRANSPORT_DETAIL')
socket.create_connection = closed
def Session(*args, **kwargs): raise AssertionError('Authentication before failed preflight')
""")
            env = dict(os.environ, PYTHONPATH=str(root), NORDIC_INCIDENT_ID='MRN-p09-fixture',
                       MRNOBODY_RUN_MODE='standalone', MRNOBODY_PASSWORD=PAYLOAD['password'],
                       MRN_WINDOWS_TARGET=json.dumps(dict(target=PAYLOAD['target'], protocol='winrm-http', port=5985, username='student')))
            worker = subprocess.run([sys.executable, str(BASE/'web/windows_actions.py'), '09', '--worker'],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(worker.returncode, 0, worker.stderr)
            result = json.loads(worker.stdout)
            self.assertEqual(result['warning'], 'winrm_http_port_unreachable')
            self.assertIn('5985', result['reason'])
            self.assertNotIn('PRIVATE_TRANSPORT_DETAIL', worker.stdout)
            self.assertNotIn(PAYLOAD['password'], worker.stdout)
            runtime = dict(env, NORDIC_BASE_DIR=str(root), MRNOBODY_TARGET=PAYLOAD['target'])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(actions.run('09', runtime, Mock(return_value=Mock(returncode=0, stdout=worker.stdout))), 1)
            log = (root/'logs/incident-ground-truth.log').read_text()
            for marker in ('PHASE_START', 'WINDOWS_ACTION_START', 'WINDOWS_PORT_CHECK', 'WINDOWS_ACTION_FAILED', 'PHASE_FAILED'):
                self.assertIn(marker, log)
            self.assertNotIn(PAYLOAD['password'], log)

if __name__ == '__main__':
    unittest.main()
