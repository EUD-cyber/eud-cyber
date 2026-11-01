"""Opt-in Windows lab actions using the existing pywinrm/NTLM transport.

Only fixed-format evidence leaves the worker. Arbitrary PowerShell and its output
are runtime-only, including errors: output byte counts are safe to retain.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

from reports import INCIDENT_ID, redact_environment
from scenario_model import private


# Resolve Domain Admins by RID so localized lab domains work too. Run directly on
# the DC: this avoids a hidden second-hop authentication or out-of-scope AD write.
# New accounts remain disabled; never reset an existing account's password/state.
AD_ACTION = r'''
$ErrorActionPreference = 'Stop'
$r = @{domain='unknown'; dc='unknown'; account='not_attempted'; group='not_attempted'; result='failed'; warning='none'}
try {
    $system = Get-CimInstance Win32_ComputerSystem
    $r.domain = $system.Domain
    if ($system.DomainRole -lt 4) {
        $r.warning = 'target_must_be_domain_controller'
        throw 'not_dc'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $d = Get-ADDomain -Server localhost
    $r.domain = $d.DNSRoot
    $r.dc = $env:COMPUTERNAME + '.' + $d.DNSRoot
    $g = Get-ADGroup -Identity ($d.DomainSID.Value + '-512') -Server localhost
    $u = Get-ADUser -Filter "SamAccountName -eq 'mrnobody'" -Server localhost
    if ($null -eq $u) {
        New-ADUser -Name 'mrnobody' -SamAccountName 'mrnobody' -Enabled $false -Description 'MrNobody controlled lab account' -Server localhost
        $r.account = 'created_disabled'
        $u = Get-ADUser -Identity 'mrnobody' -Server localhost
    } else { $r.account = 'already_exists_unchanged' }
    $member = @(Get-ADGroupMember -Identity $g -Server localhost | Where-Object {$_.SID -eq $u.SID})
    if ($member.Count -gt 0) { $r.group = 'already_member' }
    else {
        Add-ADGroupMember -Identity $g -Members $u -Server localhost
        $r.group = 'added'
    }
    $verify = @(Get-ADGroupMember -Identity $g -Server localhost | Where-Object {$_.SID -eq $u.SID})
    if ($verify.Count -eq 0) { throw 'verification_failed' }
    $r.result = 'success'
} catch {
    if ($r.warning -eq 'none') { $r.warning = 'ad_action_failed_check_rights_module_and_dc_logs' }
}
$r | ConvertTo-Json -Compress
'''


def runtime_command(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 16384 or '\x00' in value:
        raise ValueError('P10 requires a runtime PowerShell command of 1–16384 characters')
    return value


def timeout_value(value):
    if isinstance(value, bool) or not str(value).isdigit() or not 5 <= int(value) <= 300:
        raise ValueError('Windows action timeout must be 5–300 seconds')
    return int(value)


def targets(env):
    protocol = env.get('MRNOBODY_PROTOCOL') or 'winrm-http'
    if protocol not in {'winrm', 'winrm-http', 'winrm-https'}:
        raise ValueError('Windows actions require WinRM')
    port = env.get('MRNOBODY_PORT') or ('5986' if protocol == 'winrm-https' else '5985')
    if not str(port).isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid WinRM port')
    if env.get('MRNOBODY_RUN_MODE') == 'standalone':
        hosts = [{'ip': env.get('MRNOBODY_TARGET'), 'rdp_username': env.get('MRNOBODY_USERNAME') or 'Administrator'}]
    else:
        path = Path(env.get('NORDIC_COMPROMISED_STATE', '/opt/nordic-attack/state/compromised-hosts.json'))
        if not path.exists():
            return []
        data = json.loads(path.read_text())
        if data.get('incident_id') != env.get('NORDIC_INCIDENT_ID'):
            raise ValueError('Windows access inventory belongs to another incident')
        hosts = [h for h in data.get('hosts', []) if h.get('compromised') and
                 (h.get('platform') == 'windows' or h.get('access') in {'rdp', 'winrm'})]
    result = []
    for host in hosts:
        # Never consume credentials from persisted inventories.
        result.append({'target': private(host.get('ip')), 'protocol': protocol, 'port': int(port),
                       'username': host.get('rdp_username') or host.get('rdp_user') or 'Administrator'})
    if not result and env.get('MRNOBODY_RUN_MODE') == 'campaign':
        return []
    if not result:
        raise ValueError('No Windows access targets; P03 must establish Windows access first')
    return result


def perform(pid, target, env, session_factory=None):
    if session_factory is None:
        import winrm
        session_factory = winrm.Session
    password = env.get('MRNOBODY_PASSWORD') or env.get('NORDIC_RDP_PASSWORD')
    if not password:
        return {'result': 'failed', 'warning': 'missing_runtime_windows_credentials'}
    limit = timeout_value(env.get('MRNOBODY_TIMEOUT') or '60')
    scheme = 'https' if target['protocol'] == 'winrm-https' else 'http'
    # Same NTLM transport/certificate policy as existing Windows phases.
    session = session_factory(f"{scheme}://{private(target['target'])}:{target['port']}/wsman",
                              auth=(target['username'], password), transport='ntlm',
                              server_cert_validation='ignore', operation_timeout_sec=limit,
                              read_timeout_sec=limit + 10)
    command = AD_ACTION if pid == '09' else runtime_command(env.get('MRN_POWERSHELL_SECRET', ''))
    response = session.run_ps(command)
    stdout, stderr = response.std_out, response.std_err
    result = {'result': 'success' if response.status_code == 0 else 'failed',
              'exit_code': int(response.status_code), 'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
              'command': 'ad_account_and_domain_admins' if pid == '09' else 'custom_powershell_content_omitted',
              'warning': 'output_omitted_may_contain_secrets' if pid == '10' else 'none'}
    if pid == '09':
        try:
            data = json.loads(stdout.decode('utf-8-sig')) if len(stdout) <= 8192 else {}
            if not isinstance(data, dict) or data.get('result') not in {'success', 'failed'}:
                raise ValueError('invalid response')
            result['result'] = data['result'] if response.status_code == 0 else 'failed'
            for key, allowed in {'account': {'not_attempted', 'created_disabled', 'already_exists_unchanged'},
                                 'group': {'not_attempted', 'added', 'already_member'},
                                 'warning': {'none', 'target_must_be_domain_controller', 'ad_action_failed_check_rights_module_and_dc_logs'}}.items():
                result[key] = data.get(key) if data.get(key) in allowed else 'unknown'
            for key in ('domain', 'dc'):
                val = data.get(key, '')
                result[key] = val if isinstance(val, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', val) else 'unknown'
        except (ValueError, UnicodeError):
            result.update(result='failed', warning='invalid_ad_response')
    return redact_environment(result, env)


def emit(base, env, pid, event, **fields):
    stamp = datetime.now(timezone.utc).isoformat()
    iid = env['NORDIC_INCIDENT_ID']
    safe = redact_environment(fields, env)
    line = f'{stamp} INCIDENT={iid} PHASE={pid} {event} ' + ' '.join(f'{k}={v}' for k, v in safe.items()) + '\n'
    log = Path(env.get('NORDIC_GROUND_TRUTH_LOG', base / 'logs/incident-ground-truth.log'))
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('a', encoding='utf-8') as handle:
        handle.write(line)
    print(line.rstrip(), flush=True)


def run(pid, env, invoke=subprocess.run):
    base = Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack'))
    if pid not in {'09', '10'} or not INCIDENT_ID.fullmatch(env.get('NORDIC_INCIDENT_ID', '')):
        raise ValueError('Invalid phase/incident')
    emit(base, env, pid, 'PHASE_START', phase=pid, method='winrm_ntlm')
    success = True
    try:
        limit = timeout_value(env.get('MRNOBODY_TIMEOUT') or '60')
        if pid == '10':
            runtime_command(env.get('MRN_POWERSHELL_SECRET', ''))
        selected_targets = targets(env)
        if not selected_targets:
            emit(base, env, pid, 'WINDOWS_ACTION_SKIPPED', warning='no_windows_rdp_access_targets', method='winrm_ntlm')
        for target in selected_targets:
            emit(base, env, pid, 'WINDOWS_ACTION_START', target=target['target'], protocol=target['protocol'], method='winrm_ntlm')
            child_env = dict(env, MRN_WINDOWS_TARGET=json.dumps(target))
            try:
                child = invoke([sys.executable, str(Path(__file__).resolve()), pid, '--worker'],
                               env=child_env, capture_output=True, timeout=limit, check=False)
                result = json.loads(child.stdout) if child.returncode == 0 else {'result': 'failed', 'warning': 'transport_error_details_omitted'}
            except subprocess.TimeoutExpired:
                result = {'result': 'failed', 'warning': 'timeout_remote_action_may_still_be_running'}
            except (ValueError, OSError):
                result = {'result': 'failed', 'warning': 'transport_error_details_omitted'}
            ok = result.pop('result', 'failed') == 'success'
            success &= ok
            emit(base, env, pid, 'WINDOWS_ACTION_SUCCESS' if ok else 'WINDOWS_ACTION_FAILED',
                 target=target['target'], protocol=target['protocol'], method='winrm_ntlm', **result)
    except (ValueError, OSError, KeyError, TypeError):
        success = False
        emit(base, env, pid, 'WINDOWS_ACTION_FAILED', warning='invalid_or_missing_runtime_configuration')
    emit(base, env, pid, 'PHASE_COMPLETE' if success else 'PHASE_FAILED', phase=pid)
    return 0 if success else 1


if __name__ == '__main__':
    phase = sys.argv[1]
    if '--worker' in sys.argv:
        try:
            print(json.dumps(perform(phase, json.loads(os.environ['MRN_WINDOWS_TARGET']), os.environ)))
        except Exception:
            # Transport exceptions may echo auth/command content. Never emit them.
            print(json.dumps({'result': 'failed', 'warning': 'transport_error_details_omitted'}))
    else:
        raise SystemExit(run(phase, os.environ))
