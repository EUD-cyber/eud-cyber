"""Offline P10 result, redaction, report and live-status regressions."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
import windows_actions as actions
from reports import build_report, run_phase
from report_exports import export_html, export_pdf
from execution import record, snapshot

SUCCESS = dict(result='success', exit_code=0, stdout_bytes=232, stderr_bytes=906,
               execution_status='success_with_warning', warning='nonfatal_stderr_output_omitted')
ERROR = dict(result='action_error', exit_code=1, stdout_bytes=0, stderr_bytes=0,
             execution_status='command_error', reason='Custom PowerShell command failed')
TRANSPORT = dict(result='failed', warning='transport_error_details_omitted')


class PowerShellErrors(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-p10',
                        MRNOBODY_RUN_MODE='standalone', MRNOBODY_TARGET='192.168.2.200',
                        MRNOBODY_PASSWORD='PRIVATE_CREDENTIAL', MRN_POWERSHELL_SECRET='$env:COMPUTERNAME')
        (self.base / 'scripts').mkdir()
        shutil.copy(PLATFORM / 'scripts/10-powershell.sh', self.base / 'scripts')

    def candidates(self, results):
        targets = [dict(target=f'192.168.2.{200+i}', protocol='winrm-http', port=5985, username='Administrator') for i in range(len(results))]
        children = [Mock(returncode=0, stdout=json.dumps(r)) for r in results]
        with patch.object(actions, 'targets', return_value=targets):
            code = actions.run('10', self.env, Mock(side_effect=children))
        return code, (self.base / 'logs/incident-ground-truth.log').read_text()

    def test_warning_stderr_and_transport_fallback(self):
        for results in ([SUCCESS], [TRANSPORT, SUCCESS], [SUCCESS, TRANSPORT]):
            code, log = self.candidates(results)
            self.assertEqual(code, 0)
            self.assertIn('PHASE_COMPLETE', log)
            self.assertNotIn('PHASE_FAILED', log)
            self.assertIn('stderr_bytes=906', log)

    def test_controlled_error_and_hard_failures(self):
        for results in ([ERROR], [TRANSPORT, ERROR], [SUCCESS, ERROR]):
            self.assertEqual(self.candidates(results)[0], 79)
        for results in ([TRANSPORT, TRANSPORT], [],
                        [SUCCESS, dict(result='failed', warning='worker_execution_failed')],
                        [dict(ERROR, exit_code=0)], [dict(result='skipped')]):
            self.assertEqual(self.candidates(results)[0], 1)
        self.assertEqual(actions.run('10', dict(self.env, MRNOBODY_TIMEOUT='bad')), 1)
        self.assertEqual(actions.run('10', dict(self.env, MRN_POWERSHELL_SECRET='')), 1)

    def test_worker_exit_semantics_and_safe_metadata(self):
        for code, stderr in ((0, b''), (0, b'PRIVATE_WARNING'), (1, b'PRIVATE_ERROR')):
            factory = Mock()
            factory.return_value.run_ps.return_value = Mock(status_code=code, std_out=b'MRNOBODY_P10_TEST_OK\nPRIVATE_CREDENTIAL', std_err=stderr)
            result = actions.perform('10', actions.targets(self.env)[0], self.env, factory)
            self.assertEqual(result['result'], 'success' if code == 0 else 'action_error')
            self.assertEqual(result['execution_status'], 'command_error' if code else 'success_with_warning' if stderr else 'success')
            self.assertEqual(result['exit_code'], code)
            self.assertEqual(result['stderr_bytes'], len(stderr))
            self.assertIn('MRNOBODY_P10_TEST_OK', result['stdout_preview'])
            for secret in ('PRIVATE_CREDENTIAL', '$env:COMPUTERNAME'):
                self.assertNotIn(secret, json.dumps(result))

    def test_preview_redaction_bounds_and_noise(self):
        from reports import p10_output_preview
        preview = p10_output_preview(b'MRNOBODY_P10_TEST_OK\nHOST01\nLAB\\Student\nPRIVATE_CREDENTIAL', self.env)
        self.assertIn('MRNOBODY_P10_TEST_OK', preview)
        self.assertIn('LAB\\Student', preview)
        self.assertNotIn('PRIVATE_CREDENTIAL', preview)
        self.assertEqual(len(p10_output_preview('benign output ' * 100)), 512)
        self.assertIn('withheld', p10_output_preview(b'A' * 65537))
        for secret in ('password=hiddenpass', '"api_key": "hiddenkey"', 'Bearer hiddenbearer',
                       'https://student:hiddenurl@example.test', 'token: hiddentoken',
                       '-----BEGIN PRIVATE KEY-----\nhiddenpem\n-----END PRIVATE KEY-----'):
            cleaned = p10_output_preview(secret)
            self.assertNotIn('hidden', cleaned)
        # Redact complete input before truncating even when a credential crosses the cap.
        self.assertNotIn('hidden', p10_output_preview('ok ' * 164 + 'password=' + 'hidden' * 30))
        xml = b'#< CLIXML\n<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress"><MS><S N="Activity">Preparing modules for first use.</S></MS></Obj><S S="warning">Useful warning_x000D__x000A_</S></Objs>'
        self.assertEqual(p10_output_preview(xml), 'Useful warning')
        self.assertEqual(p10_output_preview(xml.replace(b'<S S="warning">Useful warning_x000D__x000A_</S>', b'')), '')
        self.assertIn('CLIXML omitted', p10_output_preview(b'#< CLIXML\n<Objs>broken'))
        self.assertNotIn('Preparing modules', p10_output_preview('Preparing modules for first use.\nOK'))
        for command in ('Get-Content words.txt', 'Get-Secret value'):
            self.assertIn('withheld', p10_output_preview('unlabelled sensitive material', dict(self.env, MRN_POWERSHELL_SECRET=command)))

    def test_safe_previews_survive_worker_log_report_and_exports(self):
        factory = Mock()
        factory.return_value.run_ps.return_value = Mock(status_code=0,
            std_out=b'MRNOBODY_P10_TEST_OK\nHOST01\nLAB\\Student\nPRIVATE_CREDENTIAL\n<script>alert(1)</script>\nexit_code=999',
            std_err=b'Useful warning\npassword=hiddenpass')
        result = actions.perform('10', actions.targets(self.env)[0], self.env, factory)
        self.assertEqual(result['execution_status'], 'success_with_warning')
        code, log = self.candidates([result])
        self.assertEqual(code, 0)
        self.assertIn('PHASE_COMPLETE', log)
        self.assertEqual(len(log.splitlines()), 4)
        self.assertNotIn('PRIVATE_CREDENTIAL', log)
        self.assertNotIn('hiddenpass', log)
        state = dict(incident_id=self.env['NORDIC_INCIDENT_ID'], phase_id='10', phases={'10': 'complete'})
        report = build_report(self.base, state['incident_id'], code, self.env, standalone=state)
        phase = report['phases'][0]
        event = next(e for e in phase['events'] if e['event'] == 'WINDOWS_ACTION_SUCCESS')
        self.assertEqual(event['fields']['exit_code'], '0')
        self.assertEqual(event['fields']['stdout_preview'], result['stdout_preview'])
        self.assertIn('Safe stdout output preview', ' '.join(phase['action_evidence']))
        self.assertIn('Safe stderr output preview', ' '.join(phase['action_evidence']))
        from report_exports import report_document
        for view in ('investigation', 'ground-truth'):
            html = export_html(report, view)
            self.assertIn('MRNOBODY_P10_TEST_OK', html)
            self.assertIn('Safe stdout output preview', html)
            self.assertNotIn('<script>alert', html)
            self.assertNotIn('hiddenpass', html)
            self.assertNotIn('PRIVATE_CREDENTIAL', html)
            self.assertIn('MRNOBODY_P10_TEST_OK', str(report_document(report, view)))
            from io import BytesIO
            from pypdf import PdfReader
            pdf = export_pdf(report, view)
            extracted = '\n'.join(p.extract_text() for p in PdfReader(BytesIO(pdf)).pages)
            self.assertIn('MRNOBODY_P10_TEST_OK', extracted)
            self.assertIn('Safe stdout output preview', extracted)
            self.assertNotIn('hiddenpass', extracted)
            self.assertNotIn('PRIVATE_CREDENTIAL', extracted)

    def test_standalone_preserves_controlled_error_exit(self):
        with patch('reports.subprocess.Popen', return_value=Mock(wait=Mock(return_value=79))), patch('reports.save_report'), patch('reports.build_report', return_value={}) as build:
            self.assertEqual(run_phase(self.base, '10', Path('inert'), self.env), 79)
            state = build.call_args.kwargs['standalone']
            self.assertEqual(state['phases']['10'], 'skipped')
            self.assertEqual(state['status'], 'failed')

    def test_reports_both_views_and_live_status(self):
        for result, status, label in ((SUCCESS, 'complete', 'nonfatal stderr/warnings'), (ERROR, 'skipped', 'Custom PowerShell command failed'), (TRANSPORT, 'failed', 'transport/authentication')):
            (self.base / 'logs').mkdir(exist_ok=True)
            (self.base / 'logs/incident-ground-truth.log').write_text('')
            code, log = self.candidates([result])
            state = dict(incident_id=self.env['NORDIC_INCIDENT_ID'], phase_id='10', status='complete' if code == 0 else 'failed', phases={'10': status})
            report = build_report(self.base, state['incident_id'], code, self.env, standalone=state)
            phase = report['phases'][0]
            self.assertTrue(all(e['timestamp'] in ' '.join(phase['action_evidence']) for e in phase['events'] if e['event'] in {'WINDOWS_ACTION_SUCCESS', 'WINDOWS_ACTION_ERROR', 'WINDOWS_ACTION_FAILED'}))
            self.assertEqual(phase['status'], {'complete':'success', 'failed':'failure'}.get(status, status))
            for view in ('investigation', 'ground-truth'):
                html = export_html(report, view)
                for value in (label, '192.168.2.200', 'winrm-http', 'winrm_ntlm', 'custom_powershell_content_omitted'):
                    self.assertIn(value, html)
                if result != TRANSPORT:
                    self.assertIn('exit_code=', html)
                self.assertTrue(export_pdf(report, view).startswith(b'%PDF'))
            self.assertNotIn('PRIVATE_CREDENTIAL', json.dumps(report))
            env = dict(self.env, MRN_OVERVIEW=json.dumps(dict(type='campaign', id='full-incident', phases=[{'id':'10'}, {'id':'04'}])))
            record(self.base, env, 123)
            (self.base / 'state').mkdir(exist_ok=True)
            (self.base / 'state/campaign.json').write_text(json.dumps(dict(incident_id=state['incident_id'], status='running', phases={'10':status, '04':'running'})))
            live = snapshot(self.base, {}, Mock(poll=Mock(return_value=None)))
            self.assertEqual(live['timeline'][0]['status'], status)
            self.assertEqual(live['current_phase']['id'], '04')
            if result != TRANSPORT:
                self.assertEqual(live['timeline'][0]['action_result'], result['execution_status'])
                self.assertTrue(any(label in line for line in live['logs']))

    @unittest.skipUnless(shutil.which('pwsh') or shutil.which('powershell'), 'PowerShell unavailable')
    def test_real_powershell_parser_and_error_semantics(self):
        shell = shutil.which('pwsh') or shutil.which('powershell')
        for command, expected in (('$env:COMPUTERNAME', 0),
                                  ("Write-Warning 'warning'; Write-Information 'info'; Write-Output 'ok'", 0),
                                  ('Get-Item -NoSuchParameter value', 1),
                                  ('NoSuchMrNobodyCommand', 1),
                                  ('if (', 1),
                                  ("throw 'PRIVATE_ERROR'", 1),
                                  ("Write-Error 'PRIVATE_ERROR'", 1),
                                  ('exit 7', 7),
                                  ('exit 0', 0)):
            encoded = __import__('base64').b64encode(actions.custom_script(command).encode('utf-16-le')).decode()
            child = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], capture_output=True, timeout=30)
            self.assertEqual(child.returncode, expected, command)


if __name__ == '__main__':
    unittest.main()
