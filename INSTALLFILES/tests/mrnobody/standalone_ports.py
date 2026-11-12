"""Offline Standalone port validation and submitted runner arguments."""
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import planning as fixtures
web, CAPS = fixtures.web, fixtures.CAPS


class StandalonePorts(unittest.TestCase):
    setUp = fixtures.API.setUp

    def test_all_supported_defaults_and_legacy_custom(self):
        defaults = dict(ssh=22, rdp=3389, winrm=5985, **{'winrm-http': 5985, 'winrm-https': 5986, 'http': 80, 'https': 443})
        for pid in ('04', '05', '06', '07', '08', '10', '11'):
            for protocol in CAPS[pid]['fields']['protocol']['options']:
                for mode in ('auto', None):
                    data = {'protocol': protocol}
                    if mode: data['port_mode'] = mode
                    web.standalone_port(pid, data)
                    self.assertEqual(data['port'], defaults[protocol])
                    self.assertNotIn('port_mode', data)
                for port in (1, 2222, 65535):
                    for mode in ('custom', None):
                        data = dict(protocol=protocol, port=str(port))
                        if mode: data['port_mode'] = mode
                        web.standalone_port(pid, data)
                        self.assertEqual(data['port'], port)

    def test_validation_before_launch_for_json_and_form(self):
        for form in (False, True):
            for dry_run in (False, True):
                for bad in ({'port': 0}, {'port': 65536}, {'port': -1}, {'port': 22.5},
                            {'port': True}, {'port': '1e3'}, {'port': ''}, {'port': None},
                            {'port': '１２'}, {'port_mode': 'bad'}, {'protocol': 'rdp'},
                            {'port_mode': 'auto', 'port': 22}):
                    data = dict(protocol='winrm-http', port_mode='custom', port=5985, dry_run=dry_run)
                    data.update(bad)
                    result = self.client.post('/api/phase/10/run', **({'data': data} if form else {'json': data}))
                    self.assertEqual(result.status_code, 400, (data, result.json))
        self.launch.assert_not_called()

    def test_dry_run_and_run_preserve_endpoint_and_runtime_command(self):
        for form in (False, True):
            for dry_run in (False, True):
                for protocol, mode, port in [('ssh', 'auto', 22), ('winrm-http', 'auto', 5985),
                                             ('winrm-https', 'auto', 5986), ('winrm-http', 'custom', 15985)]:
                    web.campaign_process = None
                    data = dict(target='192.168.2.200', protocol=protocol, port_mode=mode, port=str(port),
                                username='ubuntu' if protocol == 'ssh' else 'Administrator',
                                password='runtime-secret', powershell='Write-Output "WINRM_OK"', dry_run=str(dry_run))
                    if not form: data['profile'] = {'mode': 'normal'}
                    result = self.client.post('/api/phase/10/run', **({'data': data} if form else {'json': data}))
                    self.assertEqual(result.status_code, 200, result.json)
                    args = self.launch.call_args.args[1]
                    self.assertEqual(args[args.index('--port') + 1], str(port))
                    self.assertEqual(args[args.index('--protocol') + 1], protocol)
                    self.assertEqual(args[args.index('--user') + 1], data['username'])
                    self.assertEqual('--dry-run' in args, dry_run)
                    env = self.launch.call_args.kwargs['env']
                    self.assertEqual(env['MRNOBODY_PASSWORD'], 'runtime-secret')
                    self.assertEqual(env['MRN_POWERSHELL_SECRET'], 'Write-Output "WINRM_OK"')
                    self.assertNotIn('runtime-secret', str(args))
                    params = json.loads(env['MRN_EXECUTION'])['phases'][0]['parameters']
                    self.assertEqual(params['port'], port)
                    self.assertEqual(params['protocol'], protocol)
                    self.assertNotIn('port_mode', params)

    def test_excluded_phases_unchanged(self):
        for pid in ('01', '02', '03', '09'):
            data = dict(protocol='unchanged', port=1234)
            web.standalone_port(pid, data)
            self.assertEqual(data, dict(protocol='unchanged', port=1234))


if __name__ == '__main__':
    unittest.main()
