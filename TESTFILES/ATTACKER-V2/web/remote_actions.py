"""P10/P11 transport selection and candidate fallback, shared across all runners."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import persistence_actions as persistence
import native_actions as native
import lab_actions as lab
import dns_actions as dns
import exercise_actions as exercise
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
    if pid in {'16', '17'}:
        config = exercise.configuration(pid, env)
        source = exercise.script(pid, platform, env)
        if platform == 'windows':
            return windows_command('10', target, dict(env, MRN_POWERSHELL_SECRET=source), session_factory,
                evidence_parser=lambda output: exercise.evidence(pid, output, config, platform))
        code, stdout, stderr = ssh(target, source, env, limit)
        if code or b'\nMRN_REMOTE_EXIT=' not in stdout[0] or not stdout[0].rstrip().endswith(b'__MRN_END__'):
            return dict(result='failed', warning='transport_error_details_omitted', cleanup_required='true')
        raw, trailer = stdout[0].rsplit(b'\nMRN_REMOTE_EXIT=', 1)
        action_code = int(trailer.split(b'__MRN_END__')[0])
        if action_code:
            return dict(result='skipped' if action_code == 78 else 'failed', warning='target_dependency_unsupported' if action_code == 78 else 'action_or_restore_failed', cleanup_required='true')
        return exercise.evidence(pid, raw.decode('ascii', errors='replace'), config, platform)
    if pid in {'12', '14', '18'}:
        action = dns if pid == '18' else lab
        config = action.configuration(pid, env)
        source = action.script(pid, platform, env)
        if platform == 'windows':
            return windows_command('10', target, dict(env, MRN_POWERSHELL_SECRET=source), session_factory,
                                   evidence_parser=lambda output: action.evidence(pid, output, config))
        else:
            code, stdout, stderr = ssh(target, source, env, limit)
            if code or b'\nMRN_REMOTE_EXIT=' not in stdout[0] or not stdout[0].rstrip().endswith(b'__MRN_END__'):
                return dict(result='failed', warning='transport_error_details_omitted')
            raw, trailer = stdout[0].rsplit(b'\nMRN_REMOTE_EXIT=', 1)
            action_code = int(trailer.split(b'__MRN_END__')[0])
            if action_code:
                return dict(result='skipped' if action_code == 78 else 'failed', warning='target_dependency_unsupported' if action_code == 78 else 'lab_action_failed_output_omitted')
            output = raw.decode('ascii', errors='replace')
        return action.evidence(pid, output, config)
    if pid == '13':
        result = windows_command('10', target, dict(env, MRN_POWERSHELL_SECRET=native.script(env)), session_factory)
        result['command'] = native.metadata(env)['behavior']
        preview = result.get('stdout_preview', '')
        artifact = re.search(r'(?m)^artifact_path=([^\r\n]{1,260})$', preview)
        if artifact:
            result['artifact_path'] = artifact[1]
        job = re.search(r'(?m)^job_name: (MrNobody-P13-[a-f0-9]{24})$', preview)
        if job:
            result['job_name'] = job[1]
        result['cleanup'] = 'complete' if 'cleanup=complete' in preview else 'required_or_unverified'
        result['cleanup_required'] = 'false' if result['cleanup'] == 'complete' and result.get('result') == 'success' else 'true'
        return result
    if pid == '10' and platform == 'windows':
        return windows_command('10', target, env, session_factory)
    source = runtime_command(env.get('MRN_POWERSHELL_SECRET', '')) if pid == '10' else persistence.script(env, platform)
    if pid == '11' and persistence.configuration(env, platform)[0] in persistence.PAIRED:
        if platform == 'windows':
            return windows_command('10', target, dict(env, MRN_POWERSHELL_SECRET=source), session_factory,
                                   evidence_parser=lambda output: persistence.evidence(output, env, platform))
        code, stdout, stderr = ssh(target, source, env, limit)
        marker = b'\nMRN_REMOTE_EXIT='
        if code or marker not in stdout[0] or not stdout[0].rstrip().endswith(b'__MRN_END__'):
            return dict(result='failed', warning='transport_error_details_omitted', cleanup_required='true')
        raw, trailer = stdout[0].rsplit(marker, 1)
        try:
            action_code = int(trailer.split(b'__MRN_END__')[0])
        except ValueError:
            return dict(result='failed', warning='invalid_worker_response', cleanup_required='true')
        if action_code:
            return dict(result='skipped' if action_code == 78 else 'failed', exit_code=action_code,
                        warning='target_method_unsupported' if action_code == 78 else 'persistence_action_failed_check_target_logs',
                        cleanup_required='true')
        return persistence.evidence(raw.decode('ascii', errors='replace'), env, platform)
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
    result = dict(result='success' if action_code == 0 else 'skipped' if pid in {'11', '13'} and action_code == 78 else 'action_error' if pid == '10' else 'failed',
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


def command_inputs(env):
    explicit = any(k in env for k in ('MRN_POWERSHELL_WINDOWS_SECRET', 'MRN_BASH_SECRET'))
    if explicit:
        values = {'windows': env.get('MRN_POWERSHELL_WINDOWS_SECRET', ''), 'linux': env.get('MRN_BASH_SECRET', '')}
        return {p: runtime_command(v.strip()) for p, v in values.items() if isinstance(v, str) and v.strip()}
    value = env.get('MRN_POWERSHELL_SECRET', '')
    if not value.strip():
        return {}
    value = runtime_command(value)
    # Legacy Auto semantics: try the same command on the first compatible host.
    platform = 'linux' if env.get('MRNOBODY_PROTOCOL') == 'ssh' or env.get('MRNOBODY_PLATFORM') == 'linux' else 'windows' if env.get('MRNOBODY_PROTOCOL') or env.get('MRNOBODY_PLATFORM') == 'windows' else None
    return {platform: value} if platform else {'windows': value, 'linux': value}


def command_environment(data, env, full=False):
    """Runtime-only inputs; explicitly blank values never inherit old commands."""
    explicit = full or any(k in data for k in ('powershell_windows', 'bash'))
    if explicit:
        for field, key in (('powershell_windows', 'MRN_POWERSHELL_WINDOWS_SECRET'), ('bash', 'MRN_BASH_SECRET')):
            value = data.get(field, data.get('powershell', '') if field == 'powershell_windows' else '')
            if not isinstance(value, str):
                raise ValueError('Remote commands must be text')
            env[key] = runtime_command(value.strip()) if value.strip() else ''
        env.pop('MRN_POWERSHELL_SECRET', None)
    else:
        for key in ('MRN_POWERSHELL_WINDOWS_SECRET', 'MRN_BASH_SECRET'):
            env.pop(key, None)
        env['MRN_POWERSHELL_SECRET'] = runtime_command(data.get('powershell') or env.get('MRN_POWERSHELL_SECRET', ''))
    return env


def run(pid, env, invoke=subprocess.run):
    if pid not in {'10', '11', '12', '13', '14', '16', '17', '18'} or not INCIDENT_ID.fullmatch(env.get('NORDIC_INCIDENT_ID', '')):
        raise ValueError('Invalid phase/incident')
    base = Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack'))
    emit(base, env, pid, 'PHASE_START', phase=pid)
    outcomes = []
    candidates, completed, dual = [], set(), False
    try:
        limit = timeout_value(env.get('MRNOBODY_TIMEOUT') or 60)
        if pid in {'16', '17'}:
            exercise.configuration(pid, env)
        if pid == '18':
            dns.configuration(pid, env)
            env = dict(env, MRNOBODY_TIMEOUT='300')
            limit = 300
        if pid in {'12', '14'}:
            lab.configuration(pid, env)
            if pid == '14':
                env = dict(env, MRNOBODY_TIMEOUT='300')
                limit = 300
        if pid == '10':
            commands = command_inputs(env)
            if not commands:
                emit(base, env, pid, 'PHASE_SKIPPED', phase=pid, reason='NOT_CONFIGURED')
                return 78
        if pid == '13':
            native.metadata(env)
            env = dict(env, MRNOBODY_PLATFORM='windows')
        if pid == '11':
            method = env.get('MRNOBODY_METHOD') or 'auto'
            persistence.configuration(env, persistence.METHODS.get(method, ('linux',))[0])
        candidates = targets(env if pid == '11' else {k: v for k, v in env.items() if k != 'MRNOBODY_METHOD'})
        dual = pid == '10' and any(k in env for k in ('MRN_POWERSHELL_WINDOWS_SECRET', 'MRN_BASH_SECRET'))
        configured = set(commands) if pid == '10' else None
        completed = set()
        if configured is not None:
            candidates = [t for t in candidates if t['platform'] in configured]
        for target in candidates:
            if target['platform'] in completed:
                continue
            fields = dict(platform=target['platform'], target=target['target'], username=target['username'], protocol=target['protocol'],
                          method='ssh' if target['platform'] == 'linux' else 'winrm_ntlm',
                          interpreter='bash' if target['platform'] == 'linux' else 'powershell')
            if pid == '18':
                fields.update(dns.configuration(pid, env))
                fields.update(source=target['target'], destination=fields['dns_endpoint'], sample_queries=','.join(dns.queries(fields)[:3]))
            elif pid in {'12', '14'}:
                fields.update(lab.configuration(pid, env))
                if pid == '14':
                    destination = lab.endpoint(target, fields['transport'], fields['uri_profile'])
                    env = dict(env, MRN_BEACON_ENDPOINT=destination)
                    fields['destination'] = destination
                    fields['source'] = target['target']
            elif pid in {'16', '17'}:
                fields.update(exercise.configuration(pid, env))
                if pid == '17' and target['platform'] == 'windows': fields['mitre'] = 'T1005,T1560.002'
            elif pid == '13':
                fields.update(native.metadata(env))
            elif pid == '11':
                fields.update(persistence.metadata(env, target['platform']))
            else:
                fields['mitre'] = 'T1059.004' if target['platform'] == 'linux' else 'T1059.001'
            prefix = 'DNS_ACTION' if pid == '18' else 'EVASION_ACTION' if pid == '16' else 'COLLECTION_ACTION' if pid == '17' else 'CREDENTIAL_ACTION' if pid == '12' else 'BEACON_ACTION' if pid == '14' else 'WINDOWS_ACTION' if pid == '10' and target['platform'] == 'windows' else 'REMOTE_ACTION' if pid == '10' else 'NATIVE_ACTION' if pid == '13' else 'PERSISTENCE_ACTION'
            emit(base, env, pid, prefix + '_START', **fields)
            if pid == '17':
                # A failed rerun must never leave a stale archive advertised to P06.
                from collection_state import update
                update(dict(env, MRNOBODY_ACTION='cleanup'), target, {})
            try:
                child = invoke([sys.executable, str(Path(__file__).resolve()), pid, '--worker'],
                               env=dict(env, MRN_REMOTE_TARGET=json.dumps(target), **({'MRN_POWERSHELL_SECRET': commands[target['platform']]} if pid == '10' else {})),
                               capture_output=True, timeout=limit + 15, check=False)
                result = json.loads(child.stdout) if child.returncode == 0 else {}
                if not isinstance(result, dict) or result.get('result') not in ({'success', 'partial', 'action_error', 'skipped', 'failed'} if pid == '18' else {'success', 'action_error', 'skipped', 'failed'}):
                    raise ValueError('Invalid worker response')
            except subprocess.TimeoutExpired:
                result = dict(result='failed', warning='timeout_remote_action_may_still_be_running')
            except (OSError, ValueError):
                result = dict(result='failed', warning='worker_execution_failed')
            if pid == '17' and result.get('result') == 'success':
                from collection_state import update
                update(env, target, result)
            outcome = result.pop('result')
            if outcome == 'action_error' and (pid not in {'10', '13'} or type(result.get('exit_code')) is not int or result['exit_code'] == 0):
                outcome = 'failed'
            if outcome == 'skipped' and pid not in {'11', '12', '14', '16', '17', '18'}:
                outcome = 'failed'
            if pid in {'11', '13'} and outcome != 'success':
                fields['cleanup_required'] = 'true'
            if pid == '12' and outcome != 'success':
                fields.update(cleanup='required_or_unverified', cleanup_required='true')
            emit(base, env, pid, prefix + '_' + {'partial': 'PARTIAL', 'success': 'SUCCESS', 'action_error': 'ERROR', 'skipped': 'SKIPPED', 'failed': 'FAILED'}[outcome], **{**fields, **result})
            outcomes.append('transport' if result.get('warning') == 'transport_error_details_omitted' else outcome)
            if outcome in {'success', 'partial', 'action_error'} or outcome == 'failed' and outcomes[-1] != 'transport':
                completed.add(target['platform'])
                if pid != '10' or not dual:
                    break
        if configured is not None:
            available = {t['platform'] for t in candidates}
            for platform in sorted(configured - available if dual else set()):
                emit(base, env, pid, 'REMOTE_ACTION_SKIPPED', platform=platform, warning='no_compatible_access_targets')
                outcomes.append('skipped')
        if not candidates and configured is not None and not dual:
            outcomes.append('failed')
            emit(base, env, pid, 'REMOTE_ACTION_FAILED', warning='no_compatible_access_targets')
        if not candidates and configured is None:
            outcomes.append('skipped' if pid in {'12', '14', '16', '17', '18'} or pid in {'11', '13'} and env.get('MRNOBODY_RUN_MODE') == 'campaign' else 'failed')
            emit(base, env, pid, 'REMOTE_ACTION_SKIPPED' if outcomes[-1] == 'skipped' else 'REMOTE_ACTION_FAILED', warning='no_compatible_access_targets')
    except Exception:
        outcomes.append('failed')
        emit(base, env, pid, 'REMOTE_ACTION_FAILED', warning='invalid_or_missing_runtime_configuration')
    # A failed candidate followed by successful fallback is not a failure.
    unresolved_transport = ({t['platform'] for t in candidates} - completed if candidates else set()) if dual or not completed else set()
    if pid == '18' and 'partial' in outcomes:
        emit(base, env, pid, 'PHASE_PARTIAL', phase=pid, execution_status='partial', warning='partial_dns_success')
        return 80
    if 'success' in outcomes and 'failed' not in outcomes and not unresolved_transport:
        if any(x in outcomes for x in ('action_error', 'skipped')):
            emit(base, env, pid, 'REMOTE_ACTION_PARTIAL', execution_status='success_with_warning', warning='some_configured_actions_did_not_complete')
        emit(base, env, pid, 'PHASE_COMPLETE', phase=pid)
        return 0
    if 'action_error' in outcomes and 'failed' not in outcomes and not unresolved_transport:
        emit(base, env, pid, 'PHASE_SKIPPED', phase=pid, execution_status='command_error', reason='Native_tool_behavior_failed' if pid == '13' else 'Custom_remote_command_failed')
        return 79
    if outcomes and set(outcomes) == {'skipped'}:
        emit(base, env, pid, 'PHASE_SKIPPED', phase=pid, reason='No_compatible_target_or_supported_method')
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
