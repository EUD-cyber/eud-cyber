"""P09 protocol and Windows PowerShell tests. AD is simulated; no lab I/O.

Run with pywinrm installed. PowerShell execution tests require Windows PS 5.1.
"""
import base64
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
sys.path.insert(0, str(ROOT / 'TESTFILES/ATTACKER-V2/web'))
import p09_actions as p09
import windows_actions as actions
from winrm import Response, Session

SID = 'S-1-5-21-123-456-789'
SECRET = 'PRIVATE_PASSWORD_!æ$()'
TARGET = dict(target='192.168.2.200', username='LAB\\operator', protocol='winrm-http', port=5985)
ENV = dict(MRNOBODY_PASSWORD=SECRET, MRNOBODY_RUN_MODE='standalone',
           MRNOBODY_TARGET=TARGET['target'], MRNOBODY_USERNAME=TARGET['username'])

# This prefix replaces every external cmdlet used by P09. Its state survives
# independent local processes, permitting real precheck/apply/postcheck execution.
HARNESS = r'''
$env:COMPUTERNAME='DC'
$script:path='__STATE__'
$script:s=Get-Content -LiteralPath $script:path -Raw | ConvertFrom-Json
function Save-State { $script:s | ConvertTo-Json | Set-Content -LiteralPath $script:path -Encoding UTF8 }
function Fail-At($stage) { if ($script:s.fail -eq $stage) { throw 'PRIVATE_REMOTE_DETAIL' } }
function Import-Module { param($Name,$ErrorAction) Fail-At 'module' }
function ConvertTo-SecureString { param([switch]$AsPlainText,[switch]$Force,$String)
    $expected=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('__EXPECTED__'))
    if ($String -cne $expected) { throw 'fixture_password_mismatch' }
    'secure-fixture'
}
function Get-CimInstance { param($ClassName,$ErrorAction)
    Fail-At 'cim'
    [pscustomobject]@{Domain='lab.example'; DomainRole=$script:s.role}
}
function Get-ADDomain { param($Server)
    Fail-At 'domain'
    [pscustomobject]@{DNSRoot='lab.example';DomainSID=[pscustomobject]@{Value='S-1-5-21-123-456-789'}}
}
function Get-ADDomainController { param($Identity,$Server)
    Fail-At 'controller'
    [pscustomobject]@{IsReadOnly=$script:s.readonly; Domain=$script:s.domain; Name='DC'; HostName='dc.lab.example'}
}
function Get-ADGroup { param($Identity,$Server)
    Fail-At 'group'
    if ($Identity -ne 'S-1-5-21-123-456-789-512') { throw 'wrong_rid' }
    [pscustomobject]@{SID=[pscustomobject]@{Value=$Identity};DistinguishedName='CN=Domain Admins,DC=lab,DC=example'}
}
function Get-ADUser { param($Filter,$Properties,$Server)
    Fail-At 'account'
    $script:s.reads++; Save-State
    if (-not $script:s.exists) { return }
    $groups=@(); if ($script:s.member) { $groups=@('CN=Domain Admins,DC=lab,DC=example') }
    $user=[pscustomobject]@{SamAccountName='mrnobody';Name='mrnobody';Description=$script:s.description;
        Enabled=$script:s.enabled; SID=[pscustomobject]@{Value=$script:s.sid};
        ObjectGUID='8e416876-5031-4383-943a-62047bdd8051'; MemberOf=$groups}
    $user
    if ($script:s.ambiguous) { $user }
}
function New-ADUser { param($Name,$SamAccountName,$AccountPassword,$Enabled,$Description,$Server,[switch]$PassThru)
    Fail-At 'create'
    $script:s.exists=$true; $script:s.enabled=$Enabled; $script:s.description=$Description
    $script:s.created++; Save-State
    Get-ADUser
}
function Set-ADAccountPassword { param($Identity,[switch]$Reset,$NewPassword,$Server)
    $script:s.reset++; Save-State
}
function Enable-ADAccount { param($Identity,$Server)
    $script:s.enabled=$true; $script:s.activated++; Save-State
}
function Add-ADGroupMember { param($Identity,$Members,$Server)
    Fail-At 'membership'
    $script:s.added++
    if (-not $script:s.ignore_write) { $script:s.member=$true }
    Save-State
}
'''


class LocalProtocol:
    """Real PowerShell process, fake WinRS transport; never opens a socket."""
    def __init__(self):
        self.calls = []
        self.closed = 0
        self.cleaned = 0

    def open_shell(self, **kwargs):
        assert kwargs == {'noprofile': True}
        return 'shell'

    def run_command(self, shell, command, arguments, **kwargs):
        assert shell == 'shell'
        assert kwargs == {'skip_cmd_shell': True}
        assert arguments[:4] == ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand']
        self.calls.append((command, arguments))
        return 'command'

    def get_command_output(self, shell, command):
        executable, arguments = self.calls[-1]
        proc = subprocess.run([executable, *arguments], capture_output=True, timeout=20)
        return proc.stdout, proc.stderr, proc.returncode

    def cleanup_command(self, *args):
        self.cleaned += 1

    def close_shell(self, *args):
        self.closed += 1


class ProtocolTests(unittest.TestCase):
    def test_genuine_winrm_zero_nonzero_and_invalid_response(self):
        failure = dict(protocol='p09_failure', stage='payload_parse', result='failed', warning='powershell_payload_failed')
        self.assertEqual(p09.parse(Response((json.dumps(failure).encode(), b'#< CLIXML PRIVATE', 0)))['stage'], 'payload_parse')
        for stdout in (b'', b'PRIVATE', json.dumps(failure).encode()):
            with self.assertRaises(p09.RemoteProcessError) as caught:
                p09.parse(Response((stdout, b'PRIVATE', 1)))
            self.assertEqual(caught.exception.diagnostic['exit_code'], 1)
            self.assertNotIn('PRIVATE', str(caught.exception.diagnostic))
        with self.assertRaises(p09.SchemaError):
            p09.parse(Response((b'not json', b'', 0)))
        with self.assertRaises(p09.SchemaError):
            p09.parse(Response((b'{}', b'', True)))

    def test_nonzero_precheck_is_process_failure_no_write(self):
        factory = Mock()
        factory.return_value.protocol.get_command_output.return_value = (b'PRIVATE', b'PRIVATE', 1)
        result = p09.perform(TARGET, ENV, factory, 60)
        self.assertEqual(result['warning'], 'remote_powershell_nonzero_exit')
        self.assertEqual(result['stage'], 'precheck')
        self.assertEqual(result['remote_stage'], 'process')
        self.assertEqual(result['exit_code'], 1)
        self.assertNotIn('schema_field', result)
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertEqual(factory.call_count, 1)
        factory.return_value.protocol.close_shell.assert_called_once()

    def test_timeout_cleanup_without_exception_text(self):
        factory = Mock()
        factory.return_value.protocol.get_command_output.side_effect = TimeoutError(SECRET)
        result = p09.perform(TARGET, ENV, factory, 60)
        self.assertFalse(result['verified'])
        self.assertNotIn(SECRET, json.dumps(result))
        factory.return_value.protocol.cleanup_command.assert_called_once()
        factory.return_value.protocol.close_shell.assert_called_once()

    def test_failed_payload_postcheck_preserves_stage_and_never_succeeds(self):
        from ad_prerequisite import DC
        failure = dict(protocol='p09_failure', stage='payload_parse',
                       result='failed', warning='powershell_payload_failed')
        factory = Mock()
        factory.return_value.protocol.get_command_output.side_effect = [
            (json.dumps(row).encode(), b'', 0) for row in (DC, failure)]
        result = p09.perform(TARGET, ENV, factory, 60)
        self.assertEqual(result['stage'], 'payload_parse')
        self.assertEqual(result['warning'], 'powershell_payload_failed')
        self.assertEqual(result['result'], 'failed')
        self.assertFalse(result['verified'])

    def test_nonzero_write_requires_independent_verified_postcheck(self):
        from ad_prerequisite import DC
        before = dict(DC, result='ready', member=False, verified=False, group='missing')
        for after, expected in ((DC, 'success'), (before, 'partial')):
            factory = Mock()
            factory.return_value.protocol.get_command_output.side_effect = [
                (json.dumps(before).encode(), b'', 0), (b'PRIVATE', b'PRIVATE', 1),
                (json.dumps(after).encode(), b'', 0)]
            result = p09.perform(TARGET, ENV, factory, 60)
            self.assertEqual(result['result'], expected)
            self.assertEqual(result['transport_diagnostic'], 'remote_powershell_nonzero_exit')
            self.assertNotIn('PRIVATE', json.dumps(result))
            self.assertEqual(factory.call_count, 3)
            if expected == 'success':
                self.assertEqual(result['recovery'], 'state_verified_after_uncertain_action')

    def test_command_boundary_and_oversize_payload_fails_closed(self):
        before = dict(domain_sid=SID, account_sid='none', dc='dc.lab.example')
        password = SECRET
        command = p09.script('apply', password, before)
        protocol = Mock()
        protocol.get_command_output.return_value = (b'{}', b'', 0)
        p09.run_powershell(Mock(protocol=protocol), command)
        call = protocol.run_command.call_args
        self.assertTrue(call.kwargs['skip_cmd_shell'])
        self.assertEqual(call.args[1], 'powershell.exe')
        self.assertLess(len(call.args[2][-1]) + 100, 30000)
        self.assertNotIn(password, str(call))
        with self.assertRaises(p09.PayloadError):
            p09.invocation(p09.script('apply', ''.join(chr(0x400+i) for i in range(4096)), before))


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Windows PowerShell 5.1 required')
class PowerShellTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'ad.json'
        self.state = dict(exists=True, enabled=True, member=True, readonly=False,
            domain='lab.example', role=5, description='MrNobody controlled lab account',
            sid=SID+'-1001', ambiguous=False, fail='', ignore_write=False,
            created=0, reset=0, activated=0, added=0, reads=0)
        self.protocols = []

    def factory(self, endpoint, **kwargs):
        self.assertEqual(endpoint, 'http://192.168.2.200:5985/wsman')
        self.assertEqual(kwargs['auth'], ('LAB\\operator', SECRET))
        session = Session.__new__(Session)
        session.protocol = LocalProtocol()
        self.protocols.append(session.protocol)
        return session

    def perform(self, **changes):
        self.protocols = []
        self.state.update(changes)
        self.path.write_text(json.dumps(self.state), encoding='utf-8')
        prefix = HARNESS.replace('__STATE__', str(self.path).replace("'", "''")).replace(
            '__EXPECTED__', base64.b64encode(SECRET.encode('utf-16-le')).decode())
        with patch.object(p09, 'AD_ACTION', prefix + p09.AD_ACTION):
            result = actions.perform('09', actions.targets(ENV, '09')[0], ENV, self.factory)
        self.state = json.loads(self.path.read_text(encoding='utf-8-sig'))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn('PRIVATE_REMOTE_DETAIL', json.dumps(result))
        for protocol in self.protocols:
            self.assertEqual((protocol.cleaned, protocol.closed), (1, 1))
        return result

    def test_existing_legacy_owned_account_and_group_no_writes(self):
        result = self.perform()
        self.assertTrue(p09.confirmed(result), result)
        self.assertEqual(result['verification'], 'independent_read_only')
        self.assertEqual(len(self.protocols), 2)
        self.assertEqual([self.state[k] for k in ('created','reset','activated','added')], [0,0,0,0])

    def test_empty_directory_create_then_independent_postcheck(self):
        result = self.perform(exists=False, enabled=False, member=False)
        self.assertTrue(p09.confirmed(result), result)
        self.assertEqual((result['account'], result['group']), ('created_enabled', 'added'))
        self.assertEqual((self.state['created'], self.state['added']), (1,1))
        self.assertEqual(len(self.protocols), 3)
        self.assertGreaterEqual(self.state['reads'], 5)

    def test_disabled_owned_account_with_group_already_present(self):
        result = self.perform(enabled=False)
        self.assertTrue(p09.confirmed(result), result)
        self.assertEqual((result['account'], result['group']), ('enabled_existing', 'already_member'))
        self.assertEqual([self.state[k] for k in ('created','reset','activated','added')], [0,1,1,0])

    def test_unowned_or_ambiguous_account_never_claimed(self):
        for changes in ({'description':'Unrelated account'}, {'sid':'S-1-5-21-9-8-7-1001'}, {'ambiguous':True}):
            with self.subTest(changes=changes):
                result = self.perform(**changes)
                self.assertFalse(result['verified'])
                self.assertEqual(len(self.protocols), 1)
                self.assertEqual(self.state['added'], 0)
                self.state.update(description='MrNobody controlled lab account', sid=SID+'-1001', ambiguous=False)

    def test_writable_dc_checks_and_structured_ad_failure_stages(self):
        for changes, stage in (({'readonly':True}, 'controller'), ({'domain':'other.example'}, 'controller'),
                ({'role':3}, 'cim'), *[({'fail':s},s) for s in ('cim','module','domain','controller','group','account')]):
            with self.subTest(changes=changes):
                result = self.perform(**changes)
                self.assertFalse(result['verified'])
                self.assertEqual(result['stage'], stage, result)
                self.assertEqual(len(self.protocols), 1)
                self.state.update(readonly=False, domain='lab.example', role=5, fail='')

    def test_missing_postcondition_is_not_success(self):
        result = self.perform(member=False, ignore_write=True)
        self.assertFalse(result['verified'])
        self.assertEqual(result['action_stage'], 'postread')
        self.assertEqual(result['result'], 'partial')

    def test_parse_error_and_unhandled_runtime_are_structured(self):
        for source, stage in (("if ( { PRIVATE", 'payload_parse'), ("throw 'PRIVATE'", 'payload_execute')):
            response = p09.run_powershell(self.factory('http://192.168.2.200:5985/wsman', auth=('LAB\\operator',SECRET)), source)
            self.assertEqual(response.status_code, 0)
            result = p09.parse(response)
            self.assertEqual(result['stage'], stage)
            self.assertEqual(result['result'], 'failed')
            self.assertNotIn('PRIVATE', json.dumps(result))

    def test_original_payload_exceeds_cmd_limit(self):
        command = 'powershell -encodedcommand ' + base64.b64encode(p09.script().encode('utf-16-le')).decode()
        self.assertGreater(len(command), 8191)
        proc = subprocess.run(['cmd.exe','/c',command], capture_output=True, timeout=10)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b'')


if __name__ == '__main__':
    unittest.main()
