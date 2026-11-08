"""Offline P01 -> WinRM -> writable DC selection; no sockets or AD writes."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent))
from ad_prerequisite import DC
import windows_actions as actions
from reports import build_report
from report_exports import export_html

ELIGIBLE = dict(result='eligible', warning='none', domain='lab.example',
                dc='dc.lab.example', probe='reachable', auth='authenticated')
NON_DC = dict(result='rejected', warning='target_must_be_domain_controller',
              domain='unknown', dc='unknown', probe='reachable', auth='authenticated')


class Discovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / 'state').mkdir()
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-discovery',
            MRNOBODY_RUN_MODE='campaign', NORDIC_RDP_USERNAME='LAB\\operator',
            NORDIC_RDP_PASSWORD='DO_NOT_LOG', MRNOBODY_TIMEOUT='60',
            # Deliberately stale non-WinRM endpoint from another phase.
            MRNOBODY_TARGET='192.168.1.120', MRNOBODY_PROTOCOL='ssh', MRNOBODY_PORT='22')
        self.inventory(['192.168.2.200', '192.168.1.120'])

    def write(self, filename, **fields):
        (self.base / 'state' / filename).write_text(json.dumps(
            dict(incident_id=self.env['NORDIC_INCIDENT_ID'], **fields)), encoding='utf-8')

    def inventory(self, addresses):
        self.write('networks.json', networks=[dict(network='192.168.1.0/24'), dict(network='192.168.2.0/24')])
        self.write('discovered-hosts.json', hosts=[dict(ip=ip, status='discovered',
            services={}, compromised=False) for ip in addresses])
        # Misleading P03 Windows/RDP classification must have no effect.
        self.write('compromised-hosts.json', hosts=[dict(ip='192.168.1.120',
            compromised=True, platform='windows', access='rdp', domain_controller=True)])

    def run_campaign(self, rows):
        invoke = Mock(side_effect=[r if isinstance(r, Exception) else
            Mock(returncode=0, stdout=json.dumps(r)) for r in rows])
        with contextlib.redirect_stdout(io.StringIO()):
            code = actions.run('09', self.env, invoke)
        log = (self.base / 'logs/incident-ground-truth.log').read_text()
        self.assertNotIn('DO_NOT_LOG', log)
        return code, log, invoke

    def test_p01_inventory_kali_filtered_dc_selected_no_p03_dependency(self):
        code, log, invoke = self.run_campaign([NON_DC, ELIGIBLE, DC])
        self.assertEqual(code, 0)
        calls = invoke.call_args_list
        self.assertEqual([json.loads(c.kwargs['env']['MRN_WINDOWS_TARGET'])['target']
                          for c in calls], ['192.168.1.120', '192.168.2.200', '192.168.2.200'])
        self.assertTrue(all(c.kwargs['env']['MRN_P09_DISCOVERY_ONLY'] == '1' for c in calls[:2]))
        self.assertNotIn('MRN_P09_DISCOVERY_ONLY', calls[2].kwargs['env'])
        self.assertIn('P09_DC_SELECTED target=192.168.2.200', log)
        self.assertIn('eligible=False warning=target_must_be_domain_controller', log)
        self.assertIn('PHASE_COMPLETE', log)

    def test_no_winrm_non_dc_credentials_denied_and_read_only_dc(self):
        for row in (dict(result='rejected', warning='winrm_port_unreachable', probe='unreachable', auth='not_attempted'),
                    NON_DC, dict(NON_DC, warning='credentials_denied', auth='denied'),
                    dict(NON_DC, warning='dc_identity_mismatch_or_read_only')):
            with self.subTest(reason=row['warning']):
                self.inventory(['192.168.2.200'])
                code, log, invoke = self.run_campaign([row])
                self.assertEqual(code, 78)
                self.assertEqual(invoke.call_count, 1)  # never dispatch apply worker
                self.assertIn('discovery_reason=' + row['warning'], log)
                self.assertNotIn('WINDOWS_ACTION_SUCCESS', log)

    def test_multiple_dcs_numeric_deterministic_single_action(self):
        for addresses in (['192.168.2.200', '192.168.2.20'], ['192.168.2.20', '192.168.2.200']):
            self.inventory(addresses)
            code, log, invoke = self.run_campaign([ELIGIBLE, DC])
            self.assertEqual(code, 0)
            self.assertEqual(invoke.call_count, 2)
            self.assertTrue(all(json.loads(c.kwargs['env']['MRN_WINDOWS_TARGET'])['target'] ==
                '192.168.2.20' for c in invoke.call_args_list))

    def test_scope_exclusions_stale_inventory_and_override(self):
        self.inventory(['192.168.2.200', '192.168.2.201', '10.1.1.1', '8.8.8.8', '172.20.0.2',
                        '192.168.2.0', '192.168.2.255'])
        env = dict(self.env, NORDIC_DISCOVERY_EXCLUDE_NETWORKS='192.168.2.201/32')
        self.assertEqual([t['target'] for t in actions.targets(env, '09')], ['192.168.2.200'])
        row = actions.targets(dict(env, NORDIC_AD_DC_TARGET='192.168.2.200'), '09')[0]
        self.assertEqual((row['port'], row['protocol'], row['username']), (5985, 'winrm-http', 'LAB\\operator'))
        for pin in ('192.168.2.201', '10.1.1.1', '8.8.8.8'):
            with self.assertRaises(actions.DiscoveryError):
                actions.targets(dict(env, NORDIC_AD_DC_TARGET=pin), '09')
        self.write('discovered-hosts.json', hosts=[], incident_id_unused='ignored')
        self.assertEqual(actions.targets(env, '09'), [])
        (self.base / 'state/discovered-hosts.json').write_text('{"incident_id":"MRN-stale","hosts":[]}')
        code, log, invoke = self.run_campaign([])
        self.assertEqual(code, 78)
        self.assertIn('p01_inventory_incident_mismatch', log)
        invoke.assert_not_called()

    def test_missing_inventory_limit_and_deadline_never_dispatch_writes(self):
        (self.base / 'state/networks.json').unlink()
        self.assertEqual(self.run_campaign([])[0], 78)
        self.inventory(['192.168.2.200', '192.168.2.201'])
        with self.assertRaises(actions.DiscoveryError):
            actions.targets(dict(self.env, NORDIC_MAX_DISCOVERED_HOSTS='1'), '09')
        with patch.object(actions.time, 'monotonic', side_effect=[0, 121]):
            code, log, invoke = self.run_campaign([])
        self.assertEqual(code, 78)
        self.assertIn('discovery_budget_exhausted', log)
        invoke.assert_not_called()
        code, log, invoke = self.run_campaign([subprocess.TimeoutExpired('worker', 12), ELIGIBLE, DC])
        self.assertEqual(code, 0)
        self.assertIn('candidate_probe_timeout', log)
        self.assertLessEqual(invoke.call_args_list[0].kwargs['timeout'], 12)

    def test_probe_read_only_auth_and_fixed_diagnostics(self):
        target = actions.targets(self.env, '09')[1]
        factory = Mock()
        factory.return_value.run_ps.return_value = Mock(status_code=0,
            std_out=json.dumps({k:v for k,v in ELIGIBLE.items() if k not in ('probe', 'auth')}).encode())
        connect = Mock()
        result = actions.probe_dc(target, self.env, factory, connect)
        self.assertEqual(result, ELIGIBLE)
        connect.assert_called_once_with(('192.168.2.200', 5985), timeout=2)
        self.assertEqual(factory.call_args.kwargs['auth'], ('LAB\\operator', 'DO_NOT_LOG'))
        command = factory.return_value.run_ps.call_args.args[0]
        self.assertIn('IsReadOnly', command)
        self.assertFalse(any(verb in command for verb in ('New-AD', 'Set-AD', 'Add-AD', 'Enable-AD')))
        denied = type('InvalidCredentialsError', (Exception,), {})
        factory.return_value.run_ps.side_effect = denied('DO_NOT_LOG')
        self.assertEqual(actions.probe_dc(target, self.env, factory, connect)['warning'], 'credentials_denied')
        factory.reset_mock()
        result = actions.probe_dc(target, self.env, factory, Mock(side_effect=OSError('DO_NOT_LOG')))
        self.assertEqual(result['warning'], 'winrm_port_unreachable')
        factory.assert_not_called()

    def test_invalid_probe_response_and_success_evidence_in_report(self):
        self.inventory(['192.168.2.200'])
        code, log, invoke = self.run_campaign([dict(ELIGIBLE, dc='DO_NOT_LOG\nFAKE=event')])
        self.assertEqual(code, 78)
        self.assertIn('candidate_probe_worker_failed', log)
        self.assertNotIn('FAKE', log)
        code, log, invoke = self.run_campaign([ELIGIBLE, DC])
        (self.base / 'scripts').mkdir()
        source = Path(actions.__file__).parents[1] / 'scripts/09-ad-privilege.sh'
        (self.base / 'scripts/09-ad-privilege.sh').write_bytes(source.read_bytes())
        report = build_report(self.base, self.env['NORDIC_INCIDENT_ID'], 0, self.env,
            standalone=dict(incident_id=self.env['NORDIC_INCIDENT_ID'], phase_id='09',
                status='complete', phases={'09':'complete'}))
        phase = report['phases'][0]
        self.assertTrue(any('P09_DC_SELECTED' in e for e in phase['action_evidence']))
        for view in ('investigation', 'ground-truth'):
            html = export_html(report, view)
            self.assertIn('P09_DC_SELECTED', html)
            self.assertNotIn('DO_NOT_LOG', html)


if __name__ == '__main__':
    unittest.main()
