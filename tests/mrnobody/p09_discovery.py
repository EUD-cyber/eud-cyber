"""Offline P01 -> WinRM -> writable DC selection; no sockets or AD writes."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import Mock, MagicMock, patch

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
        # Deliberately present P03 metadata; P09 must ignore it.
        self.write('compromised-hosts.json', hosts=[dict(ip=ip, compromised=True,
            platform='windows', access='winrm', access_methods={'winrm': dict(
                authenticated=True, port=5985, protocol='winrm-http',
                verification='read_only_windows_identity')}) for ip in addresses])

    def run_campaign(self, rows):
        invoke = Mock(side_effect=[r if isinstance(r, Exception) else
            Mock(returncode=0, stdout=json.dumps(r)) for r in rows])
        with contextlib.redirect_stdout(io.StringIO()):
            code = actions.run('09', self.env, invoke)
        log = (self.base / 'logs/incident-ground-truth.log').read_text()
        self.assertNotIn('DO_NOT_LOG', log)
        return code, log, invoke

    def test_p01_dc_with_p03_timeout_and_kali_false_positive(self):
        addresses = ['192.168.1.1', '192.168.1.20', '192.168.1.100',
                     '192.168.1.120', '192.168.1.150', '192.168.2.1',
                     '192.168.2.20', '192.168.2.21', '192.168.2.25', '192.168.2.200']
        self.inventory(addresses)
        discovered = json.loads((self.base / 'state/discovered-hosts.json').read_text())
        for host in discovered['hosts']:
            host.update(network='192.168.2.0/24' if host['ip'].startswith('192.168.2.') else
                        '192.168.1.0/24', interface='eth2' if host['ip'].startswith('192.168.2.') else 'eth0')
            if host['ip'] == '192.168.2.200':
                host['services']['winrm'] = dict(authenticated=False, reachable=False,
                    warning='candidate_probe_timeout', port=5985)
        self.write('discovered-hosts.json', hosts=discovered['hosts'])
        self.write('compromised-hosts.json', hosts=[
            dict(ip='192.168.2.200', platform='windows', access='rdp', compromised=True,
                 access_methods={'rdp': dict(authenticated=True), 'winrm': dict(
                     authenticated=False, warning='candidate_probe_timeout')}),
            dict(ip='192.168.1.120', platform='windows', access='rdp', compromised=True,
                 domain_controller=True, access_methods={'rdp': dict(authenticated=True)})])
        closed = dict(result='rejected', warning='winrm_port_unreachable',
                      probe='unreachable', auth='not_attempted')
        rows = [dict(NON_DC, warning='windows_identity_unverified') if ip == '192.168.1.120'
                else closed for ip in addresses[:-1]]
        code, log, invoke = self.run_campaign(rows + [ELIGIBLE, DC])
        self.assertEqual(code, 0)
        calls = invoke.call_args_list
        self.assertEqual([json.loads(c.kwargs['env']['MRN_WINDOWS_TARGET'])['target']
                          for c in calls], addresses + ['192.168.2.200'])
        self.assertTrue(all(c.kwargs['env']['MRN_P09_DISCOVERY_ONLY'] == '1' for c in calls[:-1]))
        self.assertNotIn('MRN_P09_DISCOVERY_ONLY', calls[-1].kwargs['env'])
        self.assertIn('P09_DC_SELECTED target=192.168.2.200', log)
        self.assertNotIn('P09_DC_SELECTED target=192.168.1.120', log)
        self.assertIn('source=p01_discovered_hosts', log)
        self.assertIn('warning=windows_identity_unverified', log)
        self.assertIn('PHASE_COMPLETE', log)

    def test_p03_missing_invalid_or_stale_never_gates_p01_candidates(self):
        path = self.base / 'state/compromised-hosts.json'
        for content in (None, 'not json', '{"incident_id":"MRN-old","hosts":[]}'):
            with self.subTest(content=content):
                if path.exists():
                    path.unlink()
                if content is not None:
                    path.write_text(content)
                self.assertEqual([t['target'] for t in actions.targets(self.env, '09')],
                                 ['192.168.1.120', '192.168.2.200'])
                code, log, invoke = self.run_campaign([NON_DC, ELIGIBLE, DC])
                self.assertEqual(code, 0)
                self.assertEqual(invoke.call_count, 3)

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
        self.assertIn('attempted=0', log)
        invoke.assert_not_called()
        code, log, invoke = self.run_campaign([subprocess.TimeoutExpired('worker', 12), ELIGIBLE, DC])
        self.assertEqual(code, 0)
        self.assertIn('candidate_probe_timeout', log)
        self.assertLessEqual(invoke.call_args_list[0].kwargs['timeout'], 12)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell syntax check')
    def test_discovery_powershell_parses_without_execution(self):
        child = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
            "$ErrorActionPreference='Stop'; [void][ScriptBlock]::Create([Console]::In.ReadToEnd())"],
            input=actions.DC_VERIFY, text=True, capture_output=True, timeout=20)
        self.assertEqual(child.returncode, 0, child.stderr)

    def test_probe_read_only_auth_and_fixed_diagnostics(self):
        target = actions.targets(self.env, '09')[1]
        factory = Mock()
        factory.return_value.run_ps.return_value = Mock(status_code=0,
            std_out=json.dumps({k:v for k,v in ELIGIBLE.items() if k not in ('probe', 'auth')}).encode())
        connect = MagicMock()
        result = actions.probe_dc(target, self.env, factory, connect)
        self.assertEqual(result, ELIGIBLE)
        connect.assert_called_once_with((target['target'], 5985), timeout=2)
        self.assertEqual(factory.call_args.kwargs['auth'], ('LAB\\operator', 'DO_NOT_LOG'))
        command = factory.return_value.run_ps.call_args.args[0]
        self.assertIn('IsReadOnly', command)
        self.assertIn('[PlatformID]::Win32NT', command)
        self.assertIn('$system.Name -ine $env:COMPUTERNAME', command)
        self.assertIn('$system.DomainRole -in @(4,5)', command)
        self.assertFalse(any(verb in command for verb in ('New-AD', 'Set-AD', 'Add-AD', 'Enable-AD')))
        denied = type('InvalidCredentialsError', (Exception,), {})
        factory.return_value.run_ps.side_effect = denied('DO_NOT_LOG')
        self.assertEqual(actions.probe_dc(target, self.env, factory, connect)['warning'], 'credentials_denied')

    def test_independent_tcp_probe_failure_never_authenticates(self):
        target = actions.targets(self.env, '09')[0]
        factory = Mock()
        connect = Mock(side_effect=TimeoutError('DO_NOT_LOG'))
        result = actions.probe_dc(target, self.env, factory, connect)
        self.assertEqual(result, dict(result='rejected', warning='winrm_port_unreachable',
                                     probe='unreachable', auth='not_attempted'))
        factory.assert_not_called()
        connect.assert_called_once_with((target['target'], 5985), timeout=2)

    def test_non_windows_read_only_response_never_eligible(self):
        factory = Mock()
        factory.return_value.run_ps.return_value = Mock(status_code=0,
            std_out=json.dumps(dict(NON_DC, warning='windows_identity_unverified')).encode())
        target = actions.targets(self.env, '09')[0]
        result = actions.probe_dc(target, self.env, factory, MagicMock())
        self.assertEqual(result['result'], 'rejected')
        self.assertEqual(result['warning'], 'windows_identity_unverified')

    def test_empty_p01_has_precise_reason_and_zero_workers(self):
        self.inventory([])
        code, log, invoke = self.run_campaign([])
        self.assertEqual(code, 78)
        self.assertIn('warning=no_p01_in_scope_candidates attempted=0', log)
        invoke.assert_not_called()

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
