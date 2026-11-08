"""Offline P03 WinRM service discovery, inventory merge and P09 handoff."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
import windows_actions as actions
from scenario_model import catalogue, validate
from reports import read_metadata

AUTH = dict(reachable=True, authenticated=True, auth='authenticated', warning='none',
            hostname='DC01', domain='lab.example')
CLOSED = dict(reachable=False, authenticated=False, auth='not_attempted', warning='winrm_port_unreachable')
DENIED = dict(reachable=True, authenticated=False, auth='denied', warning='credentials_denied')


class WinRMAccess(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / 'state').mkdir()
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-p03-winrm',
            MRNOBODY_RUN_MODE='campaign', NORDIC_RDP_USERNAME='Administrator',
            NORDIC_RDP_PASSWORD='WIN_SECRET', MRNOBODY_PASSWORD='SSH_SECRET')
        self.write('networks.json', networks=[dict(network='192.168.1.0/24'), dict(network='192.168.2.0/24')])
        self.write('discovered-hosts.json', hosts=[dict(ip='192.168.1.120', services={}),
            dict(ip='192.168.2.200', services={})])
        self.write('compromised-hosts.json', hosts=[dict(ip='192.168.1.120', platform='windows',
            access='rdp', primary_access='rdp', compromised=True, access_methods={
                'rdp': dict(authenticated=True, port=3389, user='Administrator')})])

    def write(self, filename, **fields):
        (self.base / 'state' / filename).write_text(json.dumps(dict(
            incident_id=self.env['NORDIC_INCIDENT_ID'], **fields)), encoding='utf-8')

    def read(self, filename):
        return json.loads((self.base / 'state' / filename).read_text())

    def run_access(self, rows, env=None):
        invoke = Mock(side_effect=[r if isinstance(r, Exception) else
            Mock(returncode=0, stdout=json.dumps(r)) for r in rows])
        with contextlib.redirect_stdout(io.StringIO()):
            code = actions.run_winrm_access(env or self.env, invoke)
        log = (self.base / 'logs/incident-ground-truth.log').read_text()
        self.assertNotIn('WIN_SECRET', log)
        self.assertNotIn('SSH_SECRET', log)
        return code, log, invoke

    def test_winrm_only_dc_and_rdp_kali_handoff(self):
        code, log, invoke = self.run_access([CLOSED, AUTH])
        self.assertEqual(code, 0)
        state = self.read('compromised-hosts.json')
        kali, dc = state['hosts']
        self.assertEqual(kali['access_methods']['rdp']['port'], 3389)
        self.assertNotIn('winrm', kali['access_methods'])
        self.assertEqual(dc['access'], 'winrm')
        self.assertEqual(dc['access_methods']['winrm']['protocol'], 'winrm-http')
        self.assertEqual(dc['access_methods']['winrm']['verification'], 'read_only_windows_identity')
        self.assertEqual([t['target'] for t in actions.targets(self.env, '09')], ['192.168.1.120', '192.168.2.200'])
        self.assertIn('ACCESS_SUCCESS target=192.168.2.200', log)
        for call in invoke.call_args_list:
            self.assertEqual(call.kwargs['env']['MRNOBODY_PASSWORD'], 'WIN_SECRET')
            self.assertNotIn('WIN_SECRET', str(call.args))
        inventory = self.read('discovered-hosts.json')
        self.assertFalse(inventory['hosts'][0]['services']['winrm']['reachable'])
        self.assertTrue(inventory['hosts'][1]['services']['winrm']['authenticated'])
        self.assertNotIn('WIN_SECRET', json.dumps(inventory) + json.dumps(state))

    def test_known_runtime_secrets_are_scrubbed_from_remote_identity_before_persistence(self):
        code, log, invoke = self.run_access([CLOSED, dict(AUTH, hostname='WIN_SECRET', domain='WIN_SECRET')])
        self.assertEqual(code, 0)
        state = self.read('compromised-hosts.json')
        inventory = self.read('discovered-hosts.json')
        self.assertNotIn('WIN_SECRET', json.dumps(state) + json.dumps(inventory))
        self.assertEqual(state['hosts'][1]['hostname'], 'redacted')

    def test_open_port_or_denied_credentials_never_establish_access(self):
        code, log, invoke = self.run_access([DENIED, dict(DENIED, auth='unconfirmed',
            warning='windows_identity_unverified')])
        self.assertEqual(code, 0)  # P03 records failed methods and continues.
        self.assertEqual([t['target'] for t in actions.targets(self.env, '09')], ['192.168.1.120', '192.168.2.200'])
        self.assertNotIn('ACCESS_SUCCESS', log)
        self.assertTrue(all(h['services']['winrm']['reachable'] for h in self.read('discovered-hosts.json')['hosts']))

    def test_success_merges_without_dropping_ssh_or_rdp_and_rerun_clears_stale_winrm(self):
        self.run_access([AUTH, AUTH])
        first = self.read('compromised-hosts.json')['hosts'][0]
        self.assertEqual(set(first['access_methods']), {'rdp', 'winrm'})
        self.assertEqual(first['primary_access'], 'rdp')
        self.run_access([DENIED, DENIED])
        hosts = self.read('compromised-hosts.json')['hosts']
        self.assertEqual(len(hosts), 1)  # WinRM-only stale success is removed.
        self.assertEqual(set(hosts[0]['access_methods']), {'rdp'})
        self.assertEqual([t['target'] for t in actions.targets(self.env, '09')], ['192.168.1.120', '192.168.2.200'])
        self.assertFalse(self.read('discovered-hosts.json')['hosts'][1]['compromised'])

    def test_scope_stale_inventory_and_optional_dc_pin_do_not_expand_probe_scope(self):
        env = dict(self.env, NORDIC_AD_DC_TARGET='192.168.2.200',
                   NORDIC_DISCOVERY_EXCLUDE_NETWORKS='192.168.1.0/24')
        code, log, invoke = self.run_access([AUTH], env)
        self.assertEqual(code, 0)
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(json.loads(invoke.call_args.kwargs['env']['MRN_WINDOWS_TARGET'])['target'], '192.168.2.200')
        (self.base / 'state/networks.json').write_text('{"incident_id":"MRN-old","networks":[]}')
        self.assertEqual(self.run_access([])[0], 1)

    def test_bound_timeouts_and_invalid_worker_evidence_are_not_success(self):
        code, log, invoke = self.run_access([subprocess.TimeoutExpired('worker', 12),
                                           dict(AUTH, hostname='WIN_SECRET\nFORGED=1')])
        self.assertEqual(code, 0)
        self.assertIn('candidate_probe_timeout', log)
        self.assertIn('candidate_probe_worker_failed', log)
        self.assertNotIn('FORGED', log)
        self.assertEqual([t['target'] for t in actions.targets(self.env, '09')], ['192.168.1.120', '192.168.2.200'])
        with patch.object(actions.time, 'monotonic', side_effect=[0, 121, 122]):
            code, log, invoke = self.run_access([])
        invoke.assert_not_called()
        self.assertIn('discovery_budget_exhausted', log)

    def test_read_only_windows_identity_not_merely_tcp_or_rdp(self):
        target = actions.discovered_winrm_targets(self.env)[1]
        factory, connect = Mock(), MagicMock()
        factory.return_value.run_ps.return_value = Mock(status_code=0, std_out=json.dumps(
            dict(result='authenticated', warning='none', hostname='DC01', domain='lab.example')).encode())
        result = actions.probe_winrm_access(target, self.env, factory, connect)
        self.assertTrue(result['authenticated'])
        self.assertEqual(factory.call_args.kwargs['auth'], ('Administrator', 'WIN_SECRET'))
        # The campaign parent normalizes runtime credentials before worker dispatch.
        connect.assert_called_once_with(('192.168.2.200', 5985), timeout=2)
        command = factory.return_value.run_ps.call_args.args[0]
        self.assertIn('Get-CimInstance', command)
        self.assertFalse(any(v in command for v in ('New-AD', 'Set-AD', 'Add-AD', 'Enable-AD')))
        denied = type('InvalidCredentialsError', (Exception,), {})
        factory.return_value.run_ps.side_effect = denied('WIN_SECRET')
        self.assertEqual(actions.probe_winrm_access(target, self.env, factory, connect)['warning'], 'credentials_denied')
        factory.reset_mock()
        self.assertFalse(actions.probe_winrm_access(target, self.env, factory,
            Mock(side_effect=OSError('WIN_SECRET')))['reachable'])
        factory.assert_not_called()

    def test_standalone_winrm_endpoint_and_protocol_metadata(self):
        env = dict(self.env, MRNOBODY_RUN_MODE='standalone', MRNOBODY_TARGET='10.20.30.40',
                   MRNOBODY_PROTOCOL='winrm-http', MRNOBODY_PORT='15985',
                   MRNOBODY_USERNAME='operator', MRNOBODY_PASSWORD='MANUAL_SECRET')
        code, log, invoke = self.run_access([AUTH], env)
        self.assertEqual(code, 0)
        target = json.loads(invoke.call_args.kwargs['env']['MRN_WINDOWS_TARGET'])
        self.assertEqual((target['target'], target['port'], target['username']), ('10.20.30.40', 15985, 'operator'))
        caps = catalogue(PLATFORM / 'scripts', read_metadata)
        self.assertIn('winrm-http', caps['03']['fields']['protocol']['options'])
        self.assertEqual(caps['09']['dependencies'], ['03'])
        self.assertIn('PHASE_COMPLETE', log)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell syntax check')
    def test_access_script_parses_without_execution(self):
        child = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
            "$ErrorActionPreference='Stop'; [void][ScriptBlock]::Create([Console]::In.ReadToEnd())"],
            input=actions.WINRM_ACCESS_CHECK, text=True, capture_output=True, timeout=20)
        self.assertEqual(child.returncode, 0, child.stderr)

    @unittest.skipIf(os.name == 'nt', 'Linux shell integration')
    def test_real_p03_campaign_shell_and_manual_winrm_with_inert_clients(self):
        for directory in ('scripts', 'web', 'config', 'venv/bin', 'fake', 'bin'):
            (self.base / directory).mkdir(parents=True, exist_ok=True)
        for source in (PLATFORM / 'web').glob('*.py'):
            shutil.copy(source, self.base / 'web' / source.name)
        script = self.base / 'scripts/03-access.sh'
        shutil.copy(PLATFORM / 'scripts/03-access.sh', script)
        config = (PLATFORM / 'config/defaults.conf').read_text().replace(
            'NORDIC_BASE_DIR="/opt/nordic-attack"', 'NORDIC_BASE_DIR="' + str(self.base) + '"')
        (self.base / 'config/defaults.conf').write_text(config)
        (self.base / 'venv/bin/python').symlink_to(sys.executable)
        # The shell sees SSH/RDP closed. The Python worker has inert TCP/WinRM.
        for name in ('ssh', 'sshpass', 'timeout'):
            tool = self.base / 'bin' / name
            tool.write_text('#!/bin/sh\nexit 1\n')
            tool.chmod(0o755)
        (self.base / 'fake/sitecustomize.py').write_text(
            'import socket\nfrom contextlib import nullcontext\nsocket.create_connection=lambda *a,**k:nullcontext()\n')
        (self.base / 'fake/winrm.py').write_text("""
import json
class Session:
    def __init__(self, endpoint, **kwargs): self.endpoint=endpoint
    def run_ps(self, command):
        class Response:
            status_code=0
            std_err=b''
            std_out=json.dumps(dict(result='authenticated', warning='none', hostname='DC01', domain='lab.example')).encode() if '192.168.2.200:' in self.endpoint else json.dumps(dict(result='rejected', warning='windows_identity_unverified')).encode()
        return Response()
""")
        env = dict(os.environ, **self.env, NORDIC_SSH_PASSWORD='SSH_SECRET',
                   PATH=str(self.base / 'bin') + os.pathsep + os.environ['PATH'],
                   PYTHONPATH=str(self.base / 'fake'))
        # P03's existing SSH/RDP merger starts with zero authenticated hosts.
        child = subprocess.run(['bash', str(script)], env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        state = self.read('compromised-hosts.json')
        self.assertEqual([h['ip'] for h in state['hosts']], ['192.168.2.200'])
        self.assertEqual([t['target'] for t in actions.targets(self.env, '09')], ['192.168.1.120', '192.168.2.200'])
        env.update(MRNOBODY_RUN_MODE='standalone', MRNOBODY_TARGET='192.168.2.200',
                   MRNOBODY_PROTOCOL='winrm-http', MRNOBODY_USERNAME='manual',
                   MRNOBODY_PASSWORD='MANUAL_SECRET')
        child = subprocess.run(['bash', str(script)], env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        self.assertNotIn('MANUAL_SECRET', child.stdout + child.stderr)


if __name__ == '__main__':
    unittest.main()
