"""Offline P11 WinRS contracts; no network, SCM or real scheduled tasks."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'TESTFILES/ATTACKER-V2/web'))
import persistence_actions as p
import remote_actions as remote
from p09_actions import MAX_COMMAND_CHARS, INPUT_CHUNK_BYTES, MAX_SCRIPT_BYTES, invocation
from windows_actions import custom_script

TARGET = dict(target='192.168.2.200', platform='windows', protocol='winrm-http',
              port=5985, username='Administrator')
ENV = dict(MRNOBODY_PASSWORD='RUNTIME_CREDENTIAL', MRNOBODY_METHOD='service', MRNOBODY_RUN_MODE='standalone')


def factory(output=b'MrNobody P11 verified\n', code=0, stderr=b''):
    value = Mock()
    protocol = value.return_value.protocol
    protocol.open_shell.return_value = 'shell'
    protocol.run_command.return_value = 'command'
    protocol.get_command_output.return_value = output, stderr, code
    return value


class WindowsTransport(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Runs the real Windows loader with harmless input only')
    def test_real_loader_long_input_integrity_and_safe_error_output(self):
        loader = base64.b64encode(invocation().encode('utf-16-le')).decode()
        argv = ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', loader]
        source = ("#" + 'x' * 40000 + "\nWrite-Output 'MrNobody P11 verified'").encode()
        payload = base64.b64encode(source)
        header = f'{len(payload):07d}:{hashlib.sha256(source).hexdigest()}\n'.encode()
        for frame, expected in [(header + payload, b'MrNobody P11 verified'),
                                (header + payload[:-4], b'payload_decode'),
                                (header + payload + b'x', b'payload_decode'),
                                (header.replace(hashlib.sha256(source).hexdigest().encode(), b'0'*64) + payload, b'payload_decode')]:
            response = subprocess.run(argv, input=frame, capture_output=True, timeout=20)
            self.assertEqual(response.returncode, 0, response.stderr)
            self.assertIn(expected, response.stdout)
        source = p.windows_diagnostic_script("$p11Stage='compile'; throw 'RUNTIME_CREDENTIAL'").encode()
        payload = base64.b64encode(source)
        frame = f'{len(payload):07d}:{hashlib.sha256(source).hexdigest()}\n'.encode() + payload
        response = subprocess.run(argv, input=frame, capture_output=True, timeout=20)
        self.assertEqual(response.returncode, 1)
        self.assertEqual(response.stdout.strip(), b'MRN_P11_ERROR=compile,persistence_action_failed')
        self.assertNotIn(b'RUNTIME_CREDENTIAL', response.stdout + response.stderr)

    def test_long_scripts_use_fixed_command_and_integrity_checked_stdin(self):
        lengths = set()
        for method in ('service', 'task-service'):
            env = dict(ENV, MRNOBODY_METHOD=method)
            source = p.script(env, 'windows')
            old_chars = len(base64.b64encode(custom_script(source).encode('utf-16-le'))) if len(source) <= 16384 else 0
            if method == 'service':
                self.assertGreater(old_chars, 8191)
            else:
                self.assertGreater(old_chars, 32767)
            # A fixed benign comment also exercises multi-chunk staging.
            source += '\n#' + ('x' * 40000)
            f = factory(b'MRN_P11=1,1,1900000000,0,0,0,-1\n' if method == 'task-service' else b'MrNobody P11 verified\n')
            with patch.object(p, 'script', return_value=source):
                result = remote.perform('11', TARGET, env, session_factory=f)
            self.assertEqual(result['result'], 'success', result)
            proto = f.return_value.protocol
            args = proto.run_command.call_args
            self.assertTrue(args.kwargs['skip_cmd_shell'])
            self.assertFalse(args.kwargs['console_mode_stdin'])
            command_length = 100 + len(args.args[1] + ' ' + ' '.join(args.args[2]))
            self.assertLessEqual(command_length, MAX_COMMAND_CHARS)
            lengths.add(command_length)
            self.assertNotIn('MrNobodyLabService', ' '.join(args.args[2]))
            sends = proto.send_command_input.call_args_list
            self.assertGreater(len(sends), 1)
            self.assertTrue(all(len(c.args[2]) <= INPUT_CHUNK_BYTES for c in sends))
            self.assertEqual([c.kwargs['end'] for c in sends], [False] * (len(sends)-1) + [True])
            header, payload = b''.join(c.args[2] for c in sends).split(b'\n', 1)
            length, digest = header.decode().split(':')
            decoded = base64.b64decode(payload)
            self.assertEqual(int(length), len(payload))
            self.assertEqual(digest, hashlib.sha256(decoded).hexdigest())
            self.assertEqual(decoded.decode(), p.windows_diagnostic_script(source))
            self.assertNotIn(b'RUNTIME_CREDENTIAL', decoded)
            f.return_value.run_ps.assert_not_called()
            proto.cleanup_command.assert_called_once_with('shell', 'command')
            proto.close_shell.assert_called_once_with('shell')
            self.assertEqual(f.call_args.kwargs['message_encryption'], 'always')
        self.assertEqual(len(lengths), 1)

    def test_create_and_cleanup_evidence_for_both_methods(self):
        for method in ('service', 'task-service'):
            for action in ('create', 'cleanup'):
                output = b'MrNobody P11 verified\n' if method == 'service' else b'MRN_P11_CLEANUP=complete\n' if action == 'cleanup' else b'MRN_P11=1,1,1900000000,0,0,0,-1\n'
                result = remote.perform('11', TARGET, dict(ENV, MRNOBODY_METHOD=method, MRNOBODY_ACTION=action), session_factory=factory(output))
                self.assertEqual(result['result'], 'success', result)
                self.assertEqual(result['cleanup_required'], 'false' if action == 'cleanup' else 'true')

    def test_no_replay_on_launch_send_receive_timeout_or_error(self):
        for name, stage in [('open_shell','winrm_shell'), ('run_command','process_launch'),
                            ('send_command_input','payload_send'), ('get_command_output','process_receive')]:
            for error in (TimeoutError('RUNTIME_CREDENTIAL'), RuntimeError('RUNTIME_CREDENTIAL')):
                f = factory()
                proto = f.return_value.protocol
                getattr(proto, name).side_effect = error
                result = remote.perform('11', TARGET, ENV, session_factory=f)
                self.assertEqual(result['result'], 'failed')
                self.assertEqual(result['stage'], stage)
                # Keep the existing runner's candidate fallback classification.
                self.assertEqual(result['warning'], 'timeout_remote_action_may_still_be_running' if isinstance(error, TimeoutError) else 'transport_error_details_omitted')
                self.assertEqual(result['cleanup_required'], 'true')
                self.assertNotIn('RUNTIME_CREDENTIAL', json.dumps(result))
                self.assertEqual(getattr(proto, name).call_count, 1)
                if name != 'open_shell': proto.close_shell.assert_called_once()
                if name in {'send_command_input','get_command_output'}: proto.cleanup_command.assert_called_once()

    def test_diagnostics_are_allowlisted_and_require_verified_evidence(self):
        cases = [(b'MRN_P11_ERROR=compile,persistence_action_failed\n',1,'compile','persistence_action_failed'),
                 (b'MRN_P11_ERROR=ownership,artifact_ownership_conflict\n',1,'ownership','artifact_ownership_conflict'),
                 (b'The command line is too long.\r\n',1,'process','remote_powershell_nonzero_exit'),
                 (b'RUNTIME_CREDENTIAL',0,'verify','invalid_persistence_evidence'),
                 (b'MRN_P11_ERROR=RUNTIME_CREDENTIAL,evil\n',1,'process','remote_powershell_nonzero_exit'),
                 (b'{"protocol":"p09_failure","stage":"payload_parse"}',0,'payload_parse','powershell_payload_failed')]
        for output, code, stage, warning in cases:
            result = p.perform_windows(TARGET, ENV, factory(output, code, b'RUNTIME_CREDENTIAL'))
            self.assertEqual((result['stage'], result['warning']), (stage, warning))
            self.assertEqual(result['result'], 'failed')
            self.assertNotIn('RUNTIME_CREDENTIAL', json.dumps(result))
        self.assertEqual(len(b'The command line is too long.\r\n'), 31)

    def test_payload_bound_and_cleanup_failure_does_not_hide_result(self):
        f = factory()
        with patch.object(p, 'script', return_value='#' * (MAX_SCRIPT_BYTES + 1)):
            result = p.perform_windows(TARGET, ENV, f)
        self.assertEqual(result['warning'], 'powershell_payload_too_large')
        f.return_value.protocol.open_shell.assert_not_called()
        f = factory()
        f.return_value.protocol.cleanup_command.side_effect = RuntimeError('RUNTIME_CREDENTIAL')
        f.return_value.protocol.close_shell.side_effect = RuntimeError('RUNTIME_CREDENTIAL')
        self.assertEqual(p.perform_windows(TARGET, ENV, f)['result'], 'success')

    def test_scheduled_task_and_p10_keep_existing_transport(self):
        for pid, env in [('11', dict(ENV, MRNOBODY_METHOD='scheduled-task')),
                         ('10', dict(ENV, MRN_POWERSHELL_SECRET='Write-Output 1'))]:
            f = factory()
            f.return_value.run_ps.return_value = SimpleNamespace(status_code=0, std_out=b'MrNobody P11 verified\n', std_err=b'')
            self.assertEqual(remote.perform(pid, TARGET, env, session_factory=f)['result'], 'success')
            f.return_value.run_ps.assert_called_once()
            f.return_value.protocol.open_shell.assert_not_called()


if __name__ == '__main__':
    unittest.main()
