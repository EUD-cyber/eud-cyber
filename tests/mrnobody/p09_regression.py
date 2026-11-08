"""Offline P09 transport, timeout recovery and reporting contracts; no lab I/O."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent))
from ad_prerequisite import DC, WORKGROUP
import windows_actions as actions
from reports import build_report


def response(data):
    return Mock(status_code=0, std_out=json.dumps(data).encode(), std_err=b'#< CLIXML secret')


class P09Regression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2])
        self.addCleanup(self.temp.cleanup)
        self.env = dict(NORDIC_BASE_DIR=self.temp.name, NORDIC_INCIDENT_ID='MRN-p09-test',
            MRNOBODY_RUN_MODE='standalone', MRNOBODY_TARGET='192.168.2.200',
            MRNOBODY_PASSWORD='secret', MRNOBODY_TIMEOUT='60')
        self.target = actions.targets(self.env)[0]

    def perform(self, rows, env=None):
        factory = Mock()
        factory.return_value.run_ps.side_effect = [r if isinstance(r, Exception) else response(r) for r in rows]
        result = actions.perform('09', self.target, env or self.env, factory)
        self.assertNotIn('secret', json.dumps(result))
        self.assertTrue(all(c.kwargs['read_timeout_sec'] > c.kwargs['operation_timeout_sec'] for c in factory.call_args_list))
        return result, factory

    def test_first_run_and_partial_existing_only_missing_changes(self):
        for pre in (dict(DC, result='ready', exists=False, enabled=False, owned=False, member=False,
                        verified=False, account='missing', group='missing', account_sid='none'),
                    dict(DC, result='ready', enabled=False, member=False, verified=False, account='existing_disabled', group='missing'),
                    dict(DC, result='ready', member=False, verified=False, group='missing')):
            change = dict(DC, account='created_enabled' if not pre['exists'] else
                          'enabled_existing' if not pre['enabled'] else 'already_enabled', group='added')
            result, factory = self.perform([pre, change, DC])
            self.assertTrue(actions.ad_success(result))
            self.assertEqual((result['account'], result['group']), (change['account'], 'added'))
            self.assertEqual(factory.call_count, 3)
            scripts = [c.args[0] for c in factory.return_value.run_ps.call_args_list]
            self.assertIn("if ('read' -eq 'apply')", scripts[0])
            self.assertIn("if ('apply' -eq 'apply')", scripts[1])
            self.assertIn("if ('read' -eq 'apply')", scripts[2])

    def test_already_present_member_is_read_only(self):
        result, factory = self.perform([DC, DC])
        self.assertTrue(actions.ad_success(result))
        self.assertEqual(factory.call_count, 2)
        self.assertTrue(all("if ('read' -eq 'apply')" in c.args[0]
            for c in factory.return_value.run_ps.call_args_list))

    def test_timeout_after_success_independent_postcheck_no_replay(self):
        pre = dict(DC, result='ready', member=False, verified=False, group='missing')
        result, factory = self.perform([pre, TimeoutError('secret'), DC])
        self.assertTrue(actions.ad_success(result))
        self.assertEqual(result['recovery'], 'state_verified_after_uncertain_action')
        self.assertEqual(factory.call_count, 3)

    def test_partial_and_postcheck_unavailable(self):
        pre = dict(DC, result='ready', member=False, verified=False, group='missing')
        for post in (pre, TimeoutError('secret')):
            result, _ = self.perform([pre, TimeoutError('secret'), post])
            self.assertEqual(result['result'], 'partial')
            self.assertFalse(result['verified'])

    def test_connection_failure_and_non_dc_never_apply(self):
        for row, outcome in ((ConnectionError('secret'), 'failed'), (WORKGROUP, 'skipped')):
            result, factory = self.perform([row])
            self.assertEqual(result['result'], outcome)
            self.assertEqual(factory.call_count, 1)

    def test_known_creation_failure_and_confirmed_absence_is_failed(self):
        absent = dict(DC, result='ready', exists=False, enabled=False, owned=False, member=False,
                      verified=False, account='missing', group='missing', account_sid='none')
        failure = dict(absent, result='failed', stage='account_write',
                       warning='ad_action_failed_check_rights_module_and_dc_logs')
        result, _ = self.perform([absent, failure, absent])
        self.assertEqual(result['result'], 'failed')
        self.assertEqual(result['action_stage'], 'account_write')

    def test_ownership_conflict_and_identity_changes_fail_closed(self):
        conflict = dict(DC, result='failed', owned=False, verified=False, warning='account_ownership_conflict')
        result, factory = self.perform([conflict])
        self.assertEqual(result['warning'], 'account_ownership_conflict')
        self.assertEqual(factory.call_count, 1)
        for change in ({'account_sid': DC['domain_sid'] + '-1002'}, {'dc': 'other.lab.example'}):
            result, _ = self.perform([DC, dict(DC, **change)])
            self.assertFalse(actions.ad_success(result))

    def test_parent_timeout_verifies_without_replaying(self):
        invoke = Mock(side_effect=[subprocess.TimeoutExpired('worker', 230),
                                  Mock(returncode=0, stdout=json.dumps(DC))])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(actions.run('09', self.env, invoke), 0)
        first, second = invoke.call_args_list
        self.assertEqual(first.kwargs['timeout'], 230)
        self.assertEqual(second.kwargs['env']['MRN_P09_VERIFY_ONLY'], '1')
        self.assertEqual(second.kwargs['timeout'], 160)
        result, factory = self.perform([DC, DC], dict(self.env, MRN_P09_VERIFY_ONLY='1'))
        self.assertTrue(actions.ad_success(result))
        self.assertEqual(factory.call_count, 2)

    def test_manual_standalone_keeps_endpoint_and_credentials(self):
        explicit = dict(self.env, MRNOBODY_TARGET='10.20.30.40',
                        NORDIC_AD_DC_TARGET='192.168.2.200', MRNOBODY_PROTOCOL='winrm-https',
                        MRNOBODY_PORT='15986', MRNOBODY_USERNAME='LAB\\operator')
        row = actions.targets(explicit, '09')[0]
        self.assertEqual((row['target'], row['protocol'], row['port']), ('10.20.30.40', 'winrm-https', 15986))
        factory = Mock()
        factory.return_value.run_ps.return_value = response(DC)
        self.assertTrue(actions.ad_success(actions.perform('09', row, explicit, factory)))
        self.assertEqual(factory.call_args.args[0], 'https://10.20.30.40:15986/wsman')
        self.assertEqual(factory.call_args.kwargs['auth'], ('LAB\\operator', 'secret'))

    def test_invalid_schema_diagnostics_are_fixed_codes_without_remote_content(self):
        from p09_actions import parse, SchemaError
        cases = [(dict(DC, domain_sid={'Value': DC['domain_sid'], 'secret': 'secret'}), 'domain_sid', 'object'),
                 (dict(DC, group_sid=[DC['group_sid']]), 'group_sid', 'array'),
                 (dict(DC, owned='True secret'), 'owned', 'string'),
                 (dict(DC, result=['secret']), 'result', 'array'),
                 (dict(DC, dc=None), 'dc', 'null'),
                 (dict(DC, group_sid=DC['domain_sid'] + '-513'), 'domain_sid', 'null'),
                 ([DC], 'json', 'array')]
        for data, field, kind in cases:
            with self.subTest(field=field, kind=kind):
                with self.assertRaises(SchemaError) as caught:
                    parse(response(data))
                self.assertEqual(caught.exception.diagnostic['schema_field'], field)
                self.assertEqual(caught.exception.diagnostic['schema_type'], kind)
                result, factory = self.perform([data])
                self.assertEqual(result['warning'], 'invalid_ad_response')
                self.assertEqual(result['stage'], 'precheck')
                self.assertEqual(result['schema_field'], field)
                self.assertEqual(factory.call_count, 1)
        for row, field in ((Mock(status_code=1, std_out=b'secret', std_err=b'secret'), 'status_code'),
                           (Mock(status_code=0, std_out=b'secret', std_err=b'secret'), 'json'),
                           (Mock(status_code=0, std_out=b'x' * 8193, std_err=b''), 'stdout')):
            with self.assertRaises(SchemaError) as caught:
                parse(row)
            self.assertEqual(caught.exception.diagnostic['schema_field'], field)
            self.assertNotIn('secret', str(caught.exception))

    def test_unconfirmed_success_is_invalid_and_cannot_trigger_write(self):
        for changes in ({'verified': False}, {'member': False, 'verified': False, 'group': 'missing'},
                        {'exists': False, 'owned': False, 'enabled': False, 'member': False,
                         'verified': False, 'account_sid': 'none', 'account': 'missing', 'group': 'missing'}):
            result, factory = self.perform([dict(DC, **changes)])
            self.assertEqual(result['warning'], 'invalid_ad_response')
            self.assertEqual(factory.call_count, 1)

    def test_invalid_action_response_recovers_only_with_independent_confirmed_state(self):
        pre = dict(DC, result='ready', verified=False, member=False, group='missing')
        for after, outcome in ((DC, 'success'), (pre, 'partial')):
            result, factory = self.perform([pre, dict(DC, member='secret'), after])
            self.assertEqual(result['result'], outcome)
            self.assertEqual(result['schema_field'], 'member')
            self.assertEqual(factory.call_count, 3)

    def test_unverified_worker_success_rejected_and_partial_reported(self):
        for data, code in ((dict(DC, verified=False), 1),
                           (dict(DC, result='partial', verified=False), 80)):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(actions.run('09', self.env,
                    Mock(return_value=Mock(returncode=0, stdout=json.dumps(data)))), code)
        base = Path(self.temp.name)
        (base / 'scripts').mkdir()
        source = Path(actions.__file__).parents[1] / 'scripts/09-ad-privilege.sh'
        (base / 'scripts' / source.name).write_bytes(source.read_bytes())
        report = build_report(base, self.env['NORDIC_INCIDENT_ID'], 80, self.env,
            standalone=dict(incident_id=self.env['NORDIC_INCIDENT_ID'], phase_id='09', status='partial', phases={'09': 'partial'}))
        self.assertEqual(report['incident']['status'], 'partial')
        self.assertEqual(report['phases'][0]['action_result'], 'partial')


if __name__ == '__main__':
    unittest.main()
