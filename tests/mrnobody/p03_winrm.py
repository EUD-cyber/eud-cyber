"""P03 access validation boundaries and staged WinRM timeouts; no lab I/O."""
import base64
import os
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch
from pipeline_fixtures import *


class Access(Fixture):
    def test_exact_open_port_handoff_and_independent_protocol_results(self):
        before = (self.base/'state/discovered-hosts.json').read_bytes()
        with patch.object(pipeline.shutil, 'which', return_value='xfreerdp'):
            code, log, invoke = self.access([
                Mock(returncode=0, stdout=b'NORDIC_ACCESS_OK\nLinux\nkali\n', stderr=b''),
                Mock(returncode=1, stdout=b'', stderr=b'STATUS_LOGON_FAILURE'), AUTH])
        # Supply real subprocess-like replies for SSH/RDP, JSON only for WinRM.
        self.assertEqual(code, 0)
        state = self.read('compromised-hosts.json')
        self.assertEqual([h['ip'] for h in state['hosts']], ['192.168.1.120','192.168.2.200'])
        self.assertEqual(set(state['hosts'][0]['access_methods']), {'ssh'})
        self.assertEqual(set(state['hosts'][1]['access_methods']), {'winrm'})
        self.assertEqual(state['results'][1]['warning'], 'credentials_denied')
        self.assertEqual(before, (self.base/'state/discovered-hosts.json').read_bytes())
        self.assertEqual([t['target'] for t in actions.targets(self.env,'09')], ['192.168.2.200'])
        self.assertIn('ACCESS_FAILED', log)
        self.assertEqual(invoke.call_count, 3)

    def test_closed_filtered_timeout_never_authenticate(self):
        for status in ('closed','filtered','timeout'):
            self.p01([('192.168.2.200',{22:status,3389:status,5985:status})])
            code, log, invoke = self.access([])
            invoke.assert_not_called()
            self.assertEqual(self.read('compromised-hosts.json')['hosts'], [])
            self.assertNotIn('ACCESS_SUCCESS', log)

    def test_missing_stale_incomplete_or_legacy_inventory_fails_closed(self):
        for changes in ({'incident_id':'MRN-old'}, {'complete':False}, {'schema_version':1}):
            data = self.read('discovered-hosts.json'); data.update(changes)
            pipeline.write(self.base/'state/discovered-hosts.json', data)
            code, _, invoke = self.access([])
            self.assertEqual(code, 1); invoke.assert_not_called()
            self.assertFalse(self.read('compromised-hosts.json')['complete'])
            self.setUp_inventory()

    def setUp_inventory(self):
        self.p01([('192.168.2.200',{5985:'open'})])

    def test_timeout_retry_is_bounded_and_never_promoted_to_success(self):
        self.setUp_inventory()
        code, log, invoke = self.access([subprocess.TimeoutExpired('worker',90), subprocess.TimeoutExpired('worker',90)])
        self.assertEqual(code, 0)
        self.assertEqual(invoke.call_count, 2)
        self.assertTrue(all(c.kwargs['timeout']==90 for c in invoke.call_args_list))
        state = self.read('compromised-hosts.json')
        self.assertFalse(state['results'][0]['authenticated'])
        self.assertEqual(len(state['results'][0]['attempts']), 2)
        self.assertEqual(state['hosts'], [])
        self.assertNotIn('ACCESS_SUCCESS',log)

    def test_timeout_then_verified_success_preserves_both_attempts(self):
        self.setUp_inventory()
        _, log, invoke = self.access([subprocess.TimeoutExpired('worker',90), AUTH])
        attempts = self.read('compromised-hosts.json')['results'][0]['attempts']
        self.assertEqual([a['authenticated'] for a in attempts], [False,True])
        self.assertIn('candidate_probe_timeout',log)
        self.assertIn('ACCESS_SUCCESS',log)

    def test_denied_credentials_are_not_retried_and_rerun_removes_old_success(self):
        self.setUp_inventory()
        self.access([AUTH])
        _, _, invoke = self.access([DENIED])
        self.assertEqual(invoke.call_count,1)
        self.assertEqual(actions.targets(self.env,'09'),[])

    def test_malformed_worker_and_fake_success_are_rejected(self):
        self.setUp_inventory()
        for response in ({}, dict(AUTH, authenticated=False), dict(AUTH, hostname='NEVER_PERSIST\nFORGED=1'),
                         dict(AUTH, warning='candidate_probe_timeout')):
            _, _, _ = self.access([response])
            self.assertEqual(self.read('compromised-hosts.json')['hosts'],[])

    def test_protocols_merge_without_inference(self):
        self.p01([('192.168.2.200',{22:'open',3389:'open',5985:'open'})])
        with patch.object(pipeline.shutil,'which',return_value='xfreerdp'):
            self.access([Mock(returncode=0,stdout=b'NORDIC_ACCESS_OK\nLinux\n',stderr=b''),
                         Mock(returncode=0,stdout=b'',stderr=b''),AUTH])
        self.assertEqual(set(self.read('compromised-hosts.json')['hosts'][0]['access_methods']),{'ssh','rdp','winrm'})

    def test_worker_records_timeout_stage_without_raw_details(self):
        self.setUp_inventory()
        def timeout(*args,**kwargs):
            Path(kwargs['env']['MRN_WINRM_PROGRESS']).write_text('identity_read')
            raise subprocess.TimeoutExpired('secret',90)
        with patch.object(pipeline,'winrm_auth', wraps=pipeline.winrm_auth):
            result = pipeline.winrm_auth(pipeline.open_targets(self.env,'winrm')[0],self.env,timeout)
        self.assertEqual(result['stage'],'identity_read')
        self.assertFalse(result['authenticated'])
        self.assertNotIn('secret',json.dumps(result))

    def test_ntlm_stages_no_tcp_probe_and_no_profile_startup(self):
        target = pipeline.open_targets(self.env,'winrm')[0]
        factory, connect = Mock(), Mock()
        protocol = factory.return_value.protocol
        protocol.get_command_output.return_value=(json.dumps(dict(result='authenticated',warning='none',hostname='DC01',domain='lab.example')).encode(),b'',0)
        result=actions.probe_winrm_access(target,self.env,factory,connect)
        self.assertTrue(result['authenticated']); connect.assert_not_called()
        protocol.open_shell.assert_called_once_with(noprofile=True)
        args=protocol.run_command.call_args.args[2]
        self.assertIn('-NoProfile',args); self.assertIn('-NonInteractive',args)
        command=base64.b64decode(args[-1]).decode('utf-16-le')
        self.assertNotIn('Get-CimInstance',command)
        self.assertFalse(any(v in command for v in ('New-AD','Add-AD','Set-AD')))
        self.assertEqual(factory.call_args.kwargs['transport'],'ntlm')
        self.assertEqual(factory.call_args.kwargs['operation_timeout_sec'],20)
        self.assertEqual(factory.call_args.kwargs['read_timeout_sec'],30)

    def test_transport_timeout_and_denial_classification(self):
        target=pipeline.open_targets(self.env,'winrm')[0]
        for error,warning in ((TimeoutError('SECRET'),'winrm_operation_timeout'),
                              (type('InvalidCredentialsError',(Exception,),{})('SECRET'),'credentials_denied')):
            factory=Mock(); factory.return_value.protocol.open_shell.side_effect=error
            result=actions.probe_winrm_access(target,self.env,factory)
            self.assertEqual(result['warning'],warning)
            self.assertEqual(result['stage'],'ntlm_shell'); self.assertFalse(result['authenticated'])

    def test_real_p03_dispatch_and_worker_use_only_inventory_endpoint(self):
        self.setUp_inventory()
        fake=self.base/'fake'; fake.mkdir()
        (fake/'winrm.py').write_text('''
import json, socket
def forbidden(*args,**kwargs): raise AssertionError('No TCP scan allowed in P03')
socket.create_connection=forbidden
class Protocol:
    def open_shell(self,**kwargs):
        assert kwargs=={'noprofile':True}
        return 'shell'
    def run_command(self,*args): return 'command'
    def get_command_output(self,*args):
        return json.dumps(dict(result='authenticated',warning='none',hostname='DC01',domain='lab.example')).encode(),b'',0
    def cleanup_command(self,*args): pass
    def close_shell(self,*args): pass
class Session:
    def __init__(self,endpoint,**kwargs):
        assert endpoint=='http://192.168.2.200:5985/wsman'
        assert kwargs['transport']=='ntlm'
        assert kwargs['auth']==('LAB\\\\operator','NEVER_PERSIST_WIN')
        self.protocol=Protocol()
''')
        runtime=dict(os.environ,**self.env,PYTHONPATH=str(fake))
        completed=subprocess.run([sys.executable,str(PLATFORM/'web/access_pipeline.py'),'03'],env=runtime,
                                 capture_output=True,text=True,timeout=15)
        self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
        self.assertEqual([t['target'] for t in actions.targets(self.env,'09')],['192.168.2.200'])
        self.assertNotIn('NEVER_PERSIST',completed.stdout)

    def test_ssh_rdp_timeout_protocol_error_and_missing_clients_are_not_success(self):
        for protocol in ('ssh','rdp'):
            target=dict(target='192.168.2.200',port=22 if protocol=='ssh' else 3389,protocol=protocol,username='student')
            with patch.object(pipeline.shutil,'which',return_value='xfreerdp'):
                for reply,warning in ((subprocess.TimeoutExpired('client',5),'authentication_timeout'),
                                      (OSError('SECRET'),'client_unavailable')):
                    result=pipeline.local_auth(target,self.env,Mock(side_effect=reply))
                    self.assertEqual(result['warning'],warning); self.assertFalse(result['authenticated'])

    def test_secret_like_remote_identity_is_redacted_in_persisted_state(self):
        self.setUp_inventory()
        self.access([dict(AUTH,hostname='NEVER_PERSIST_WIN')])
        self.assertNotIn('NEVER_PERSIST_WIN',(self.base/'state/compromised-hosts.json').read_text())

    def test_reachable_http_405_is_not_winrm_authentication(self):
        target=pipeline.open_targets(self.env,'winrm')[0]
        factory=Mock()
        factory.return_value.protocol.get_command_output.return_value=(b'HTTP 405',b'',405)
        result=actions.probe_winrm_access(target,self.env,factory)
        self.assertFalse(result['authenticated'])
        self.assertEqual(result['warning'],'invalid_winrm_response')

    def test_rdp_success_never_establishes_winrm(self):
        self.p01([('192.168.1.120',{3389:'open',5985:'open'})])
        with patch.object(pipeline.shutil,'which',return_value='xfreerdp'):
            self.access([Mock(returncode=0,stdout=b'',stderr=b''),DENIED])
        self.assertEqual(actions.targets(self.env,'09'),[])
        self.assertEqual(set(self.read('compromised-hosts.json')['hosts'][0]['access_methods']),{'rdp'})


if __name__=='__main__': unittest.main()
