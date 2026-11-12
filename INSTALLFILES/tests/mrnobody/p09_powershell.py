"""P09 protocol and Windows PowerShell tests. AD is simulated; no lab I/O.

Run with pywinrm installed. PowerShell execution tests require Windows PS 5.1.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
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
        assert kwargs == {'noprofile': True, 'idle_timeout': 'PT60S'}
        return 'shell'

    def run_command(self, shell, command, arguments, **kwargs):
        assert shell == 'shell'
        assert kwargs == {'console_mode_stdin': False, 'skip_cmd_shell': True}
        assert arguments[:4] == ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand']
        self.calls.append((command, arguments))
        self.frame = b''
        self.ended = False
        return 'command'

    def send_command_input(self, shell, command, chunk, end=False):
        assert not self.ended
        assert len(chunk) <= p09.INPUT_CHUNK_BYTES
        self.frame += chunk
        self.ended = end

    def get_command_output(self, shell, command):
        assert self.ended
        executable, arguments = self.calls[-1]
        proc = subprocess.run([executable, *arguments], input=self.frame, capture_output=True, timeout=20)
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
        factory.return_value.protocol.get_command_output.return_value = (b'', b'The command line is too long.\r\n', 1)
        result = p09.perform(TARGET, ENV, factory, 60)
        self.assertEqual(result['warning'], 'remote_powershell_nonzero_exit')
        self.assertEqual(result['stage'], 'precheck')
        self.assertEqual(result['remote_stage'], 'process')
        self.assertEqual(result['exit_code'], 1)
        self.assertEqual(result['stdout_bytes'], 0)
        self.assertEqual(result['stderr_bytes'], 31)
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
        self.assertLess(100 + len('powershell.exe ' + ' '.join(call.args[2])), 8000)
        self.assertNotIn(password, str(call))
        self.assertNotIn(base64.b64encode(password.encode('utf-16-le')).decode(), str(call))
        from p09_fixtures import decode_input
        sends = protocol.send_command_input.call_args_list
        self.assertEqual(decode_input(b''.join(c.args[2] for c in sends)), command)
        self.assertTrue(sends[-1].kwargs['end'])
        protocol.reset_mock()
        with self.assertRaises(p09.PayloadError):
            p09.run_powershell(Mock(protocol=protocol), 'x' * (p09.MAX_SCRIPT_BYTES + 1))
        protocol.open_shell.assert_not_called()

    def test_short_long_and_max_password_use_identical_short_command(self):
        from p09_fixtures import decode_input
        arguments = []
        before = dict(domain_sid=SID, account_sid='none', dc='dc.lab.example')
        for source in ('Write-Output "WINRM_OK"', '# ' + 'x' * 200000,
                p09.script('apply', ''.join(chr(0x400+i) for i in range(4096)), before)):
            protocol = Mock()
            protocol.get_command_output.return_value = (b'{}', b'', 0)
            p09.run_powershell(Mock(protocol=protocol), source)
            arguments.append(protocol.run_command.call_args.args[2])
            sends = protocol.send_command_input.call_args_list
            self.assertTrue(all(len(c.args[2]) <= 16384 for c in sends))
            self.assertTrue(all(not c.kwargs['end'] for c in sends[:-1]))
            self.assertTrue(sends[-1].kwargs['end'])
            self.assertEqual(decode_input(b''.join(c.args[2] for c in sends)), source)
        self.assertEqual(arguments[0], arguments[1])
        self.assertEqual(arguments[0], arguments[2])

    def test_send_failure_cleans_up_without_retry_or_secret_output(self):
        factory = Mock()
        protocol = factory.return_value.protocol
        protocol.send_command_input.side_effect = TimeoutError(SECRET)
        result = p09.perform(TARGET, ENV, factory, 60)
        self.assertEqual(result['result'], 'failed')
        self.assertNotIn(SECRET, json.dumps(result))
        protocol.send_command_input.assert_called_once()
        protocol.get_command_output.assert_not_called()
        protocol.cleanup_command.assert_called_once()
        protocol.close_shell.assert_called_once()

    def test_interrupted_apply_transfer_independently_verifies_without_replay(self):
        from ad_prerequisite import DC
        from p09_fixtures import p09_factory
        for after, expected in ((DC, 'success'),
                (dict(DC, result='ready', member=False, verified=False, group='missing'), 'partial')):
            factory = p09_factory()
            session = factory.return_value
            session.run_ps.side_effect = [Response((json.dumps(row).encode(), b'', 0))
                for row in (dict(DC, result='ready', member=False, verified=False, group='missing'), after)]
            original = session.protocol.send_command_input.side_effect
            count = 0
            def interrupt_apply(*args, **kwargs):
                nonlocal count
                count += 1
                if count == 2:
                    raise TimeoutError(SECRET)
                return original(*args, **kwargs)
            session.protocol.send_command_input.side_effect = interrupt_apply
            result = p09.perform(TARGET, ENV, factory, 60)
            self.assertEqual(result['result'], expected)
            self.assertEqual(factory.call_count, 3)
            self.assertEqual(session.protocol.run_command.call_count, 3)
            self.assertEqual(session.protocol.cleanup_command.call_count, 3)
            self.assertNotIn(SECRET, json.dumps(result))

    def test_ntlm_message_encryption_required(self):
        factory = Mock()
        factory.return_value.protocol.get_command_output.return_value = (b'', b'', 1)
        p09.perform(TARGET, ENV, factory, 60)
        self.assertEqual(factory.call_args.kwargs['message_encryption'], 'always')

    def test_real_pywinrm_stdin_envelope_is_bounded_and_preserves_bytes(self):
        protocol = Session('http://fixture.invalid:5985/wsman', auth=('fixture', 'fixture'),
            transport='ntlm', message_encryption='always').protocol
        with patch.object(protocol, 'send_message', return_value=b'') as send:
            chunk = b'x' * p09.INPUT_CHUNK_BYTES
            protocol.send_command_input('shell', 'command', chunk, end=True)
        xml = send.call_args.args[0]
        self.assertLess(len(xml.encode()), 153600)
        stream = ET.fromstring(xml).find('.//{http://schemas.microsoft.com/wbem/wsman/1/windows/shell}Stream')
        self.assertEqual(stream.attrib['Name'], 'stdin')
        self.assertEqual(stream.attrib['End'], 'true')
        self.assertEqual(base64.b64decode(stream.text), chunk)
        reply = b'<Envelope><Selector Name="ShellId">shell</Selector></Envelope>'
        with patch.object(protocol, 'send_message', return_value=reply) as send:
            protocol.open_shell(noprofile=True, idle_timeout='PT60S')
        root = ET.fromstring(send.call_args.args[0])
        self.assertEqual(root.find('.//{http://schemas.microsoft.com/wbem/wsman/1/windows/shell}IdleTimeOut').text, 'PT60S')


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

    def test_short_long_unicode_and_maximum_input_execute_in_memory(self):
        prefix = 'Write-Output "WINRM_OK"\n#'
        for source in ('Write-Output "WINRM_OK"',
                '# ' + 'ø' * 100000 + '\nWrite-Output "WINRM_OK"',
                prefix + 'x' * (p09.MAX_SCRIPT_BYTES - len(prefix))):
            protocol = LocalProtocol()
            response = p09.run_powershell(Mock(protocol=protocol), source)
            self.assertEqual(response.status_code, 0)
            self.assertEqual(response.std_out.strip(), b'WINRM_OK')
            self.assertEqual((protocol.cleaned, protocol.closed), (1, 1))

    def test_bad_framing_integrity_and_encoding_never_execute(self):
        source = b'Write-Output "MUST_NOT_EXECUTE"'
        def frame(raw):
            payload = base64.b64encode(raw)
            return f'{len(payload):07d}:{hashlib.sha256(raw).hexdigest()}\n'.encode() + payload
        valid = frame(source)
        invalid = [b'', valid[:72], valid[:-1], valid + b'x',
            valid[:8] + b'0'*64 + valid[72:], b'9999999:' + valid[8:],
            b'0000003:' + valid[8:], valid[:73] + b'!' * (len(valid)-73), frame(b'\xff')]
        executable = ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
            base64.b64encode(p09.invocation().encode('utf-16-le')).decode()]
        for data in invalid:
            with self.subTest(size=len(data)):
                proc = subprocess.run(executable, input=data, capture_output=True, timeout=10)
                result = p09.parse(Response((proc.stdout, proc.stderr, proc.returncode)))
                self.assertEqual(result['stage'], 'payload_decode')
                self.assertEqual(result['result'], 'failed')
                self.assertNotIn(b'MUST_NOT_EXECUTE', proc.stdout + proc.stderr)

    def test_complete_frame_waits_for_eof_before_execution(self):
        protocol = LocalProtocol()
        p09.run_powershell(Mock(protocol=protocol), 'Write-Output "WINRM_OK"')
        executable, arguments = protocol.calls[0]
        proc = subprocess.Popen([executable, *arguments], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            proc.stdin.write(protocol.frame)
            proc.stdin.flush()
            with self.assertRaises(subprocess.TimeoutExpired):
                proc.wait(timeout=1)
            stdout, stderr = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 0, stderr)
            self.assertEqual(stdout.strip(), b'WINRM_OK')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def test_original_payload_exceeds_cmd_limit(self):
        command = 'powershell -encodedcommand ' + base64.b64encode(p09.script().encode('utf-16-le')).decode()
        self.assertGreater(len(command), 8191)
        proc = subprocess.run(['cmd.exe','/c',command], capture_output=True, timeout=10)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b'')

    def test_fixed_loader_also_fits_real_cmd_limit_with_large_stdin(self):
        protocol = LocalProtocol()
        source = '# ' + 'x' * 100000 + '\nWrite-Output "WINRM_OK"'
        p09.run_powershell(Mock(protocol=protocol), source)
        executable, arguments = protocol.calls[0]
        command = executable + ' ' + ' '.join(arguments)
        self.assertLess(len(command), 8191)
        proc = subprocess.run(['cmd.exe', '/c', command], input=protocol.frame,
            capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), b'WINRM_OK')


if __name__ == '__main__':
    unittest.main()
