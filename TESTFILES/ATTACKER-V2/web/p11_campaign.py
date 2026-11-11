"""Consent-based P11 campaign: completed P03 access is the target allowlist.

No discovery, credential guessing, operator payloads or network activity. Remote
activity has a fixed deadline; artifacts remain visible until explicit cleanup.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

LINUX = ('cron', 'systemd', 'process', 'cron-systemd-process')
WINDOWS = ('scheduled-task', 'service', 'task-service')


def bounded(env):
    # Reserved campaign names also select the bounded implementation on standalone
    # cleanup, so the instructor can stop one method without replaying a campaign.
    return env.get('MRNOBODY_RUN_MODE') == 'campaign' or bool(re.fullmatch(
        r'fc-[a-f0-9]{8}-(?:cron|systemd|process|cron-systemd-process|scheduled-task|service|task-service)',
        env.get('MRNOBODY_ARTIFACT', '')))


def suffix(incident, method):
    return 'fc-' + hashlib.sha256(incident.encode()).hexdigest()[:8] + '-' + method


def targets(env):
    from scenario_model import private
    path = Path(env.get('NORDIC_COMPROMISED_STATE', '/opt/nordic-attack/state/compromised-hosts.json'))
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    if (data.get('producer') != 'P03' or data.get('schema_version') != 2
            or data.get('complete') is not True or data.get('run_mode') not in {'campaign', 'standalone'}
            or data.get('incident_id') != env['NORDIC_INCIDENT_ID']):
        raise ValueError('Completed same-incident P03 evidence required')
    result = {}
    for host in data.get('hosts', []):
        if not isinstance(host, dict) or not isinstance(host.get('access_methods'), dict):
            continue
        if host.get('authenticated') is not True or host.get('compromised') is not True:
            continue
        platform = host.get('platform')
        kind = 'ssh' if platform == 'linux' else 'winrm' if platform == 'windows' else None
        access = host.get('access_methods', {}).get(kind, {})
        if not isinstance(access, dict):
            continue
        protocols = {'ssh'} if kind == 'ssh' else {'winrm-http', 'winrm-https'}
        verification = 'ssh_session_marker' if kind == 'ssh' else 'read_only_windows_identity'
        user = access.get('user', '')
        # Passwords stay runtime-only. A changed account is not verified by P03.
        runtime_user = env.get('NORDIC_SSH_USERNAME' if kind == 'ssh' else 'NORDIC_RDP_USERNAME')
        password = env.get('NORDIC_SSH_PASSWORD' if kind == 'ssh' else 'NORDIC_RDP_PASSWORD')
        if (kind is None or access.get('authenticated') is not True
                or access.get('protocol') not in protocols or access.get('verification') != verification
                or not isinstance(user, str) or not re.fullmatch(r'[A-Za-z0-9_.@\\-]{1,128}', user)
                or user != runtime_user or not password
                or type(access.get('port')) is not int or not 1 <= access['port'] <= 65535):
            continue
        try:
            address = private(host.get('ip'))
        except (ValueError, TypeError):
            continue
        target = dict(target=address, platform=platform, protocol=access['protocol'],
                      port=access['port'], username=user)
        result[(address, platform)] = target
    return list(result.values())


def run(env, invoke):
    from windows_actions import emit, timeout_value
    import persistence_actions as p
    base = Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack'))
    outcomes = []
    try:
        limit = timeout_value(env.get('MRNOBODY_TIMEOUT') or 60)
        action = env.get('MRNOBODY_ACTION') or 'create'
        if action not in {'create', 'cleanup'}:
            raise ValueError('Campaign supports create or cleanup')
        candidates = targets(env)
        for target in candidates:
            for method in LINUX if target['platform'] == 'linux' else WINDOWS:
                runtime = dict(env, MRNOBODY_METHOD=method, MRNOBODY_ACTION=action,
                    MRNOBODY_ARTIFACT=suffix(env['NORDIC_INCIDENT_ID'], method),
                    MRNOBODY_PERSISTENCE_DNS='disabled', MRNOBODY_PERSISTENCE_CPU='low',
                    MRNOBODY_PERSISTENCE_DURATION='300', MRN_REMOTE_TARGET=json.dumps(target))
                fields = dict(target, method=method, action_attempted=action, activity_duration=300,
                    target_verification='p03_ssh_session_marker' if target['platform'] == 'linux' else 'p03_read_only_windows_identity',
                    activity_deadline_utc_epoch='unverified_until_target_receipt',
                    cleanup_policy='manual_artifacts_automatic_activity_stop',
                    detection='not_assessed_requires_sensor_evidence')
                try:
                    fields.update(p.metadata(runtime, target['platform']))
                    emit(base, env, '11', 'PERSISTENCE_ACTION_START', **fields)
                    child = invoke([sys.executable, str(Path(__file__).with_name('remote_actions.py')), '11', '--worker'],
                                   env=runtime, capture_output=True, timeout=limit + 15, check=False)
                    receipt = json.loads(child.stdout) if child.returncode == 0 else {}
                    if not isinstance(receipt, dict) or receipt.get('result') not in {'success', 'skipped', 'failed', 'partial'}:
                        raise ValueError('Invalid receipt')
                except subprocess.TimeoutExpired:
                    receipt = dict(result='failed', warning='timeout_remote_action_may_still_be_running', cleanup_required='true')
                except Exception:
                    # Never serialize exception text: transport errors can contain credentials.
                    receipt = dict(result='failed', warning='worker_execution_failed', cleanup_required='true')
                outcome = receipt.pop('result')
                outcomes.append(outcome)
                if outcome == 'skipped' and receipt.get('verification_scope') == 'prewrite_collision_only':
                    receipt['action_attempted'] = 'not_attempted'
                    receipt['reason_label'] = 'SKIPPED – Artifact already exists'
                    emit(base, env, '11', 'P11_ARTIFACT_EXISTS', **{**fields, **receipt})
                if outcome in {'failed', 'partial'}:
                    receipt['cleanup_required'] = 'true'
                emit(base, env, '11', 'PERSISTENCE_ACTION_' + outcome.upper(), **{**fields, **receipt})
    except Exception:
        outcomes.append('failed')
        emit(base, env, '11', 'PERSISTENCE_ACTION_FAILED', warning='invalid_or_missing_p03_campaign_configuration')
    if not outcomes or set(outcomes) == {'skipped'}:
        event, code = 'PHASE_SKIPPED', 78
    elif set(outcomes) == {'success'}:
        event, code = 'PHASE_COMPLETE', 0
    elif 'success' in outcomes or 'partial' in outcomes:
        event, code = 'PHASE_PARTIAL', 80
    else:
        event, code = 'PHASE_FAILED', 1
    emit(base, env, '11', event, phase='11', attempted=len(outcomes),
         reason='no_p03_verified_targets' if not outcomes else 'per_method_outcomes',
         success=outcomes.count('success'), skipped=outcomes.count('skipped'), failed=outcomes.count('failed'),
         partial=outcomes.count('partial'))
    return code


def script(env, platform, method, action, name):
    """Bound the legacy single cron/task/service actions in campaign only."""
    import persistence_actions as p
    c = p.activity_configuration(env, method, action)
    if method == 'service':
        settings = '|'.join(['disabled', c['dns_domain'], 'none', str(c['query_interval']), str(c['activity_duration'])])
        return p.windows_pair(name, action, settings, '', service_only=True, capture_pid=True)
    if method == 'scheduled-task':
        # Reuse the ownership-checked cleanup; creation is one fixed echo action,
        # with an explicit EndBoundary and execution time limit.
        source = p._script(dict(env, MRNOBODY_RUN_MODE='standalone', MRNOBODY_ARTIFACT='telemetry'), platform)
        source = source.replace('mrnobody-p11-telemetry', name)
        if action == 'create':
            source = source.replace("$t = New-ScheduledTaskTrigger -Daily -At '12:00'",
                "$deadline = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + " + str(c['activity_duration']) + "\n"
                "$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)\n"
                "$t.EndBoundary = [DateTimeOffset]::FromUnixTimeSeconds($deadline).LocalDateTime.ToString('s')\n"
                "$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 10)")
            source = source.replace('-Description $marker -Action $a -Trigger $t', '-Description $marker -Action $a -Trigger $t -Settings $settings')
            source = source.replace("Write-Output 'MrNobody P11 verified'", """$verified = Get-ScheduledTask -TaskName $name -TaskPath '\\' -ErrorAction Stop
if (@($verified.Triggers).Count -ne 1 -or @($verified.Triggers)[0].EndBoundary -ne $t.EndBoundary -or $verified.Actions.Arguments -ne '/c echo MrNobody controlled lab P11') { throw 'create_verification_failed' }
Write-Output 'MrNobody P11 verified'""")
            source += "\nWrite-Output ('MRN_P11_DEADLINE=' + $deadline)\n"
        return source
    if method == 'cron':
        source = p._script(dict(env, MRNOBODY_RUN_MODE='standalone', MRNOBODY_ARTIFACT='telemetry'), platform)
        source = source.replace('mrnobody-p11-telemetry', name)
        if action == 'create':
            # A fixed absolute deadline in the crontab is visible and cannot be
            # extended by cron. The expired entry is inert until manual cleanup.
            deadline = "$(($(date +%s) + " + str(c['activity_duration']) + "))"
            source = source.replace("{ test -z", 'deadline=' + deadline + '\n{ test -z', 1)
            source = source.replace("printf '*/5 * * * * logger", "printf '* * * * * test \"$(date +\\%%s)\" -lt %s && logger")
            source = source.replace('"$marker"; } | crontab -', '"$deadline" "$marker"; } | crontab -')
            source += '\nprintf "MRN_P11_DEADLINE=%s\\n" "$deadline"\n'
        return source
    return None


def legacy_evidence(output, env, platform):
    import persistence_actions as p
    method, action, _ = p.configuration(env, platform)
    if method == 'service':
        result = p.evidence(output, dict(env, MRNOBODY_METHOD='task-service'), platform)
        result['trigger_configured'] = 'false'
        return result
    if action == 'cleanup':
        verified = output.strip() == 'MrNobody P11 verified'
        return dict(result='success' if verified else 'failed',
                    cleanup='complete' if verified else 'unverified', cleanup_required='false' if verified else 'true')
    match = re.fullmatch(r'MrNobody P11 verified\s+MRN_P11_DEADLINE=([0-9]{10})\s*', output)
    return dict(result='success' if match else 'failed',
                activity_deadline_utc_epoch=int(match[1]) if match else 'unverified',
                trigger_configured='true' if match else 'unverified', cleanup_required='true',
                verification_scope='target_configuration_not_sensor_detection')
