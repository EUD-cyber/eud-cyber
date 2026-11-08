"""Offline P09 prerequisite, reporting and live-status regressions."""
import json
from pathlib import Path
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

DC = dict(result='success', warning='none', account='already_enabled',
          group='already_member', domain='lab.example', dc='dc.lab.example', exit_code=0, domain_sid='S-1-5-21-123-456-789',
          account_sid='S-1-5-21-123-456-789-1001', group_sid='S-1-5-21-123-456-789-512',
          exists=True, enabled=True, member=True, owned=True, verified=True, stage='complete')
WORKGROUP = dict(result='skipped', warning='target_must_be_domain_controller',
                 account='not_attempted', group='not_attempted', domain='WORKGROUP', dc='unknown', exit_code=0, domain_sid='unknown', account_sid='none', group_sid='unknown',
                 exists=False, enabled=False, member=False, owned=False, verified=False, stage='dc')
TRANSPORT = dict(result='failed', warning='transport_error_details_omitted')


class Prerequisite(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-prerequisite',
                        MRNOBODY_RUN_MODE='standalone', MRNOBODY_TARGET='192.168.2.200',
                        MRNOBODY_PASSWORD='DO_NOT_PERSIST')

    def run_candidates(self, results):
        targets = [dict(target=f'192.168.2.{200+i}', protocol='winrm-http', port=5985, username='Administrator') for i in range(len(results))]
        children = [Mock(returncode=0, stdout=json.dumps(r)) for r in results]
        with patch.object(actions, 'targets', return_value=targets):
            code = actions.run('09', self.env, Mock(side_effect=children))
        return code, (self.base / 'logs/incident-ground-truth.log').read_text()

    def test_valid_dc_success(self):
        code, log = self.run_candidates([DC])
        self.assertEqual(code, 0)
        self.assertIn('PHASE_COMPLETE', log)
        self.assertIn('group=already_member', log)

    def test_workgroup_and_mixed_transport_are_skipped(self):
        for results in ([WORKGROUP], [TRANSPORT, WORKGROUP]):
            with self.subTest(results=results):
                code, log = self.run_candidates(results)
                self.assertEqual(code, 78)
                self.assertIn('PHASE_SKIPPED', log)
                self.assertNotIn('PHASE_FAILED', log)
                for evidence in ('domain=WORKGROUP', 'dc=unknown', 'account=not_attempted', 'group=not_attempted'):
                    self.assertIn(evidence, log)

    def test_every_transport_failure_is_failure(self):
        code, log = self.run_candidates([TRANSPORT, TRANSPORT])
        self.assertEqual(code, 1)
        self.assertIn('PHASE_FAILED', log)
        self.assertNotIn('PHASE_SKIPPED', log)

    def test_action_and_worker_errors_are_never_hidden(self):
        for error in (dict(DC, result='failed', warning='ad_action_failed_check_rights_module_and_dc_logs'),
                      dict(TRANSPORT, warning='invalid_ad_response'),
                      dict(TRANSPORT, warning='timeout_remote_action_may_still_be_running'),
                      dict(TRANSPORT, warning='worker_execution_failed')):
            with self.subTest(error=error):
                self.assertEqual(self.run_candidates([WORKGROUP, error])[0], 1)
        self.assertEqual(actions.run('09', dict(self.env, MRNOBODY_TIMEOUT='invalid')), 1)

    def test_authenticated_worker_response_and_nonzero_remote_exit(self):
        target = actions.targets(self.env)[0]
        for response_code in (0, 1):
            factory = Mock()
            factory.return_value.run_ps.return_value = Mock(status_code=response_code, std_out=json.dumps(WORKGROUP).encode(), std_err=b'')
            result = actions.perform('09', target, self.env, factory)
            self.assertEqual(result['result'], 'skipped' if response_code == 0 else 'failed')
        invalid = dict(WORKGROUP, group='added')
        factory.return_value.run_ps.return_value = Mock(status_code=0, std_out=json.dumps(invalid).encode(), std_err=b'')
        self.assertEqual(actions.perform('09', target, self.env, factory)['result'], 'failed')

    def test_reports_both_views_and_live_continuation(self):
        code, _ = self.run_candidates([TRANSPORT, WORKGROUP])
        (self.base / 'scripts').mkdir()
        (self.base / 'scripts/09-ad-privilege.sh').write_bytes((PLATFORM / 'scripts/09-ad-privilege.sh').read_bytes())
        state = dict(incident_id=self.env['NORDIC_INCIDENT_ID'], phase_id='09', status='complete', phases={'09': 'skipped'})
        report = build_report(self.base, state['incident_id'], code, self.env, standalone=state)
        phase = report['phases'][0]
        self.assertEqual((report['incident']['status'], phase['status']), ('complete', 'skipped'))
        self.assertIsNotNone(phase['ended'])
        for view in ('investigation', 'ground-truth'):
            html = export_html(report, view)
            for evidence in ('No Active Directory Domain Controller discovered', 'WORKGROUP', 'dc=unknown', 'account=not_attempted', 'group=not_attempted', '192.168.2.201'):
                self.assertIn(evidence, html)
            self.assertTrue(export_pdf(report, view).startswith(b'%PDF'))
        env = dict(self.env, MRN_OVERVIEW=json.dumps(dict(type='campaign', id='full-incident', phases=[{'id': '03'}, {'id': '09'}, {'id': '04'}])))
        record(self.base, env, 123)
        (self.base / 'state').mkdir()
        (self.base / 'state/campaign.json').write_text(json.dumps(dict(incident_id=state['incident_id'], status='running', phases={'03':'complete', '09':'skipped', '04':'running'})))
        live = snapshot(self.base, {}, Mock(poll=Mock(return_value=None)))
        self.assertEqual(live['timeline'][1]['status'], 'skipped')
        self.assertEqual(live['current_phase']['id'], '04')
        self.assertEqual(live['progress']['total'], 2)
        self.assertTrue(any('Phase Skipped' in line for line in live['logs']))

    def test_cli_handles_skip_without_changing_other_phase_codes(self):
        for pid, code, expected in [('09', 78, 0), ('09', 1, 1), ('10', 78, 0), ('13', 78, 0)]:
            with patch('reports.subprocess.Popen', return_value=Mock(wait=Mock(return_value=code))), patch('reports.save_report'), patch('reports.build_report', return_value={}) as build:
                self.assertEqual(run_phase(self.base, pid, Path('inert'), self.env), expected)
                self.assertEqual(build.call_args.kwargs['standalone']['phases'][pid], 'skipped' if code == 78 else 'failed')


if __name__ == '__main__':
    unittest.main()
