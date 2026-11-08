"""Opt-in Windows lab actions using the existing pywinrm/NTLM transport.

Raw PowerShell and output stay runtime-only. P10 retains bounded, scrubbed previews.
"""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import socket
import ipaddress
import time
import sys
from datetime import datetime, timezone

from reports import INCIDENT_ID, redact_environment, p10_output_preview
from scenario_model import private


from p09_actions import AD_ACTION, STATES as AD_ENABLED_STATES, confirmed as ad_success
from p09_actions import perform as perform_ad


def runtime_command(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 16384 or '\x00' in value:
        raise ValueError('P10 requires a runtime remote command of 1–16384 characters')
    return value


def custom_script(value):
    """Parse operator input inside try/catch, keeping syntax errors off the wire.

    Base64 is only quoting for the remote script, never a persisted representation.
    Error records fail the action; warning/information streams do not.
    """
    encoded = base64.b64encode(runtime_command(value).encode('utf-16-le')).decode('ascii')
    return r"""
$ErrorActionPreference = 'Stop'
$global:LASTEXITCODE = 0
try {
    $source = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('__SOURCE__'))
    $action = [ScriptBlock]::Create($source)
    & $action
    $succeeded = $?
    if (-not $succeeded) { exit 1 }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    exit 0
} catch {
    # No exception/command/output text leaves this handler.
    exit 1
}
""".replace('__SOURCE__', encoded)


def timeout_value(value):
    if isinstance(value, bool) or not str(value).isdigit() or not 5 <= int(value) <= 300:
        raise ValueError('Windows action timeout must be 5–300 seconds')
    return int(value)


def targets(env, pid=None):
    if pid == '09' and env.get('MRNOBODY_RUN_MODE') == 'campaign':
        return campaign_dc_candidates(env)
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


class DiscoveryError(ValueError):
    """Fixed diagnostic codes; never include inventory contents."""
    pass


def discovered_winrm_targets(env, honor_override=True):
    from access_pipeline import open_targets
    return open_targets(env, 'winrm')


def campaign_dc_candidates(env):
    """Consume ONLY completed same-incident P03 authenticated WinRM evidence."""
    from access_pipeline import read, path, ContractError
    try:
        data = read(path(env, 'NORDIC_COMPROMISED_STATE', 'compromised-hosts.json'), env.get('NORDIC_INCIDENT_ID'))
        if (data.get('producer') != 'P03' or data.get('schema_version') != 2 or data.get('complete') is not True
                or data.get('run_mode') != 'campaign' or not re.fullmatch(r'[a-f0-9]{32}', data.get('source_inventory_id', ''))):
            raise ContractError('p03_access_inventory_incomplete_or_legacy')
        candidates = []
        for host in data['hosts']:
            method = host.get('access_methods', {}).get('winrm', {})
            if method.get('authenticated') is not True:
                continue
            if (method.get('protocol') != 'winrm-http' or type(method.get('port')) is not int
                    or not 1 <= method['port'] <= 65535 or method.get('verification') != 'read_only_windows_identity'):
                continue
            candidates.append(dict(target=private(host['ip']), protocol=method['protocol'], port=method['port'],
                username=env.get('NORDIC_RDP_USERNAME') or 'Administrator'))
        candidates = sorted({t['target']: t for t in candidates}.values(), key=lambda t: ipaddress.IPv4Address(t['target']))
        maximum = max(1, min(4096, int(env.get('NORDIC_MAX_DISCOVERED_HOSTS', '254'))))
        if len(candidates) > maximum:
            raise ContractError('p03_access_inventory_limit_exceeded')
        override = env.get('NORDIC_AD_DC_TARGET')
        if override:
            candidates = [t for t in candidates if t['target'] == private(override)]
        return candidates
    except (ContractError, ValueError, TypeError, KeyError, AttributeError):
        raise DiscoveryError('no_authenticated_winrm_targets') from None


DC_VERIFY = r"""
$ErrorActionPreference='Stop'
$r=@{result='rejected'; warning='windows_identity_unverified'; domain='unknown'; dc='unknown'}
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'not_windows' }
    $system=Get-CimInstance Win32_ComputerSystem
    if (-not $system.Name -or $system.Name -ine $env:COMPUTERNAME -or
        $system.DomainRole -notin @(0,1,2,3,4,5)) { throw 'identity_unverified' }
    $r.warning='target_must_be_domain_controller'
    if ($system.DomainRole -in @(4,5)) {
        $r.warning='dc_verification_failed'
        Import-Module ActiveDirectory -ErrorAction Stop
        $d=Get-ADDomain -Server localhost
        $c=Get-ADDomainController -Identity $env:COMPUTERNAME -Server localhost
        if ($c.IsReadOnly -eq $false -and $c.Domain -ieq $d.DNSRoot -and
            $system.Domain -ieq $d.DNSRoot -and $c.Name -ieq $env:COMPUTERNAME) {
            $r.result='eligible'; $r.warning='none'
            $r.domain=[string]$d.DNSRoot; $r.dc=[string]$c.HostName
        } else { $r.warning='dc_identity_mismatch_or_read_only' }
    }
} catch { if ($r.warning -ne 'windows_identity_unverified') { $r.warning='dc_verification_failed' } }
$r | ConvertTo-Json -Compress
"""


def probe_dc(target, env, session_factory=None, connect=None):
    """Read-only role validation on a P03-authenticated endpoint; no port scan."""
    address = private(target['target'])
    if target['protocol'] != 'winrm-http' or type(target['port']) is not int or not 1 <= target['port'] <= 65535:
        raise ValueError('Invalid P03 WinRM endpoint')
    password = env.get('MRNOBODY_PASSWORD') or env.get('NORDIC_RDP_PASSWORD')
    if not password:
        return dict(result='rejected', warning='missing_runtime_windows_credentials', probe='reachable', auth='not_attempted')
    try:
        if session_factory is None:
            import winrm
            session_factory = winrm.Session
        session = session_factory(f"http://{target['target']}:{target['port']}/wsman",
            auth=(target['username'], password), transport='ntlm', server_cert_validation='ignore',
            operation_timeout_sec=20, read_timeout_sec=30)
        response = session.run_ps(DC_VERIFY)
        if response.status_code != 0 or not isinstance(response.std_out, bytes) or len(response.std_out) > 2048:
            raise ValueError()
        data = json.loads(response.std_out.decode('utf-8-sig'))
        if not isinstance(data, dict) or data.get('result') not in {'eligible', 'rejected'} or data.get('warning') not in {
                'none', 'windows_identity_unverified', 'target_must_be_domain_controller', 'dc_verification_failed', 'dc_identity_mismatch_or_read_only'}:
            raise ValueError()
        for key in ('domain', 'dc'):
            if not isinstance(data.get(key), str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}', data[key]):
                raise ValueError()
        if data['result'] == 'eligible' and (data['warning'] != 'none' or 'unknown' in (data['domain'], data['dc'])):
            raise ValueError()
        return dict(data, probe='reachable', auth='authenticated')
    except Exception as error:
        # Inspect types/status only, never exception text (which can contain secrets).
        denied = type(error).__name__ in {'InvalidCredentialsError', 'AuthenticationError'}
        status = getattr(getattr(error, 'response', None), 'status_code', None)
        denied = denied or status in (401, 403)
        return dict(result='rejected', probe='reachable', auth='denied' if denied else 'unconfirmed',
                    warning='credentials_denied' if denied else 'invalid_dc_response' if isinstance(error, (ValueError, TypeError, UnicodeError)) else 'winrm_transport_or_auth_failed')


def select_campaign_dc(candidates, env, base, invoke):
    deadline = time.monotonic() + 120
    reasons = []
    attempted = 0
    emit(base, env, '09', 'P09_DISCOVERY_START', candidates=len(candidates),
         source='p03_authenticated_winrm', budget_seconds=120, selection='lowest_numeric_verified_writable_dc')
    for target in candidates:
        remaining = deadline - time.monotonic()
        if remaining < 1:
            reasons.append('discovery_budget_exhausted')
            break
        emit(base, env, '09', 'P09_CANDIDATE', target=target['target'], source='p03_authenticated_winrm', port=target['port'])
        attempted += 1
        try:
            child = invoke([sys.executable, str(Path(__file__).resolve()), '09', '--worker'],
                env=dict(env, MRN_WINDOWS_TARGET=json.dumps(target), MRN_P09_DISCOVERY_ONLY='1'),
                capture_output=True, timeout=min(90, remaining), check=False)
            result = json.loads(child.stdout) if child.returncode == 0 else {}
            allowed = {'none', 'winrm_port_unreachable', 'missing_runtime_windows_credentials',
                'windows_identity_unverified', 'target_must_be_domain_controller', 'dc_verification_failed', 'dc_identity_mismatch_or_read_only',
                'credentials_denied', 'invalid_dc_response', 'winrm_transport_or_auth_failed'}
            if not isinstance(result, dict) or result.get('warning') not in allowed or result.get('result') not in {'eligible', 'rejected'}:
                raise ValueError()
            # Never copy arbitrary worker fields into Ground Truth.
            details = {k: result[k] for k in ('probe', 'auth') if result.get(k) in
                       {'reachable', 'unreachable', 'not_attempted', 'authenticated', 'denied', 'unconfirmed'}}
            eligible = result['result'] == 'eligible' and result['warning'] == 'none' and details.get('auth') == 'authenticated' and details.get('probe') == 'reachable'
            for key in ('domain', 'dc'):
                if eligible:
                    value = result.get(key)
                    if not isinstance(value, str) or value == 'unknown' or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}', value):
                        raise ValueError()
                    details[key] = value
            reason = result['warning']
        except subprocess.TimeoutExpired:
            eligible, reason, details = False, 'candidate_probe_timeout', {}
        except (ValueError, TypeError, OSError):
            eligible, reason, details = False, 'candidate_probe_worker_failed', {}
        emit(base, env, '09', 'P09_DC_VERIFICATION', target=target['target'], port=target['port'],
             eligible=eligible, warning=reason, **details)
        if eligible:
            emit(base, env, '09', 'P09_DC_SELECTED', target=target['target'],
                 selection='lowest_numeric_verified_writable_dc', **details)
            return [target], None
        reasons.append(reason)
    reason = 'no_authenticated_winrm_targets' if not candidates else 'no_writable_dc_verified'
    emit(base, env, '09', 'P09_DISCOVERY_EXHAUSTED', warning=reason, attempted=attempted)
    return [], reason


WINRM_ACCESS_CHECK = r"""
$ErrorActionPreference='Stop'
$r=@{result='rejected'; warning='windows_identity_unverified'; hostname='unknown'; domain='unknown'}
try {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and $env:COMPUTERNAME) {
        $r.result='authenticated'; $r.warning='none'; $r.hostname=[string]$env:COMPUTERNAME
        if ($env:USERDNSDOMAIN) { $r.domain=[string]$env:USERDNSDOMAIN }
    }
} catch {}
$r | ConvertTo-Json -Compress
"""

WINRM_ACCESS_WARNINGS = {'none', 'winrm_port_unreachable', 'missing_runtime_windows_credentials',
    'credentials_denied', 'windows_identity_unverified', 'invalid_winrm_response',
    'winrm_transport_or_auth_failed', 'missing_pywinrm_or_ntlm_dependencies',
    'candidate_probe_timeout', 'candidate_probe_worker_failed', 'discovery_budget_exhausted', 'winrm_operation_timeout'}


def access_evidence(data):
    """Project an untrusted worker response into a fixed, non-secret schema."""
    if not isinstance(data, dict) or data.get('warning') not in WINRM_ACCESS_WARNINGS:
        raise ValueError('Invalid WinRM access evidence')
    if type(data.get('reachable')) is not bool or type(data.get('authenticated')) is not bool:
        raise ValueError('Invalid WinRM access evidence')
    if data.get('auth') not in {'not_attempted', 'authenticated', 'denied', 'unconfirmed'}:
        raise ValueError('Invalid WinRM access evidence')
    safe = {key: data[key] for key in ('reachable', 'authenticated', 'auth', 'warning')}
    if data.get('stage') in {'ntlm_shell', 'powershell_start', 'identity_read', 'cleanup', 'complete'}:
        safe['stage'] = data['stage']
    if safe['authenticated']:
        if not safe['reachable'] or safe['auth'] != 'authenticated' or safe['warning'] != 'none':
            raise ValueError('Inconsistent WinRM access evidence')
        for key in ('hostname', 'domain'):
            value = data.get(key)
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}', value):
                raise ValueError('Invalid Windows identity')
            safe[key] = value
        if safe['hostname'] == 'unknown':
            raise ValueError('Missing Windows identity')
        safe['verification'] = 'read_only_windows_identity'
    elif safe['warning'] == 'none' or safe['auth'] == 'authenticated':
        raise ValueError('Inconsistent WinRM access evidence')
    return safe


def probe_winrm_access(target, env, session_factory=None, connect=None):
    """P03: TCP discovery and a fixed read-only Windows identity query."""
    address = private(target['target'])
    port = target['port']
    if target['protocol'] != 'winrm-http' or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid WinRM endpoint')
    # P01 already proved the port open; TCP/HTTP GET is not authentication.
    rejected = dict(reachable=True, authenticated=False, auth='not_attempted', warning='winrm_port_unreachable')
    stage = 'ntlm_shell'
    def progress(value):
        nonlocal stage
        stage = value
        if env.get('MRN_WINRM_PROGRESS'):
            Path(env['MRN_WINRM_PROGRESS']).write_text(value, encoding='ascii')
    password = (env.get('NORDIC_RDP_PASSWORD') if env.get('MRNOBODY_RUN_MODE') == 'campaign' else
                env.get('MRNOBODY_PASSWORD') or env.get('NORDIC_RDP_PASSWORD'))
    if not password:
        return dict(rejected, warning='missing_runtime_windows_credentials')
    try:
        if session_factory is None:
            import winrm
            session_factory = winrm.Session
        from access_pipeline import bounded
        operation = bounded(env, 'NORDIC_WINRM_OPERATION_TIMEOUT', 20, 1, 120)
        read_limit = bounded(env, 'NORDIC_WINRM_READ_TIMEOUT', 30, 2, 180)
        if read_limit <= operation:
            raise ValueError('Invalid WinRM timeouts')
        session = session_factory(f"http://{address}:{port}/wsman",
            auth=(target['username'], password), transport='ntlm', server_cert_validation='ignore',
            operation_timeout_sec=operation, read_timeout_sec=read_limit)
        progress('ntlm_shell')
        shell = session.protocol.open_shell(noprofile=True)
        progress('powershell_start')
        encoded = base64.b64encode(WINRM_ACCESS_CHECK.encode('utf-16-le')).decode('ascii')
        command = session.protocol.run_command(shell, 'powershell.exe',
            ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded])
        progress('identity_read')
        stdout, stderr, code = session.protocol.get_command_output(shell, command)
        response = type('IdentityResponse', (), dict(status_code=code, std_out=stdout))()
        progress('cleanup')
        session.protocol.cleanup_command(shell, command)
        session.protocol.close_shell(shell)
        progress('complete')
        if response.status_code != 0 or not isinstance(response.std_out, bytes) or len(response.std_out) > 2048:
            raise ValueError()
        data = json.loads(response.std_out.decode('utf-8-sig'))
        if not isinstance(data, dict):
            raise ValueError()
        if data.get('result') == 'rejected' and data.get('warning') == 'windows_identity_unverified':
            return dict(rejected, auth='unconfirmed', warning='windows_identity_unverified')
        if data.get('result') != 'authenticated' or data.get('warning') != 'none':
            raise ValueError()
        return access_evidence(dict(data, reachable=True, authenticated=True, auth='authenticated', stage='complete'))
    except Exception as error:
        denied = type(error).__name__ in {'InvalidCredentialsError', 'AuthenticationError'}
        denied = denied or getattr(getattr(error, 'response', None), 'status_code', None) in (401, 403)
        timed_out = isinstance(error, TimeoutError) or type(error).__name__ in {'ReadTimeout', 'ConnectTimeout', 'Timeout', 'WinRMOperationTimeoutError'}
        warning = ('winrm_operation_timeout' if timed_out else 'missing_pywinrm_or_ntlm_dependencies' if isinstance(error, ImportError) else
                   'credentials_denied' if denied else 'invalid_winrm_response'
                   if isinstance(error, (ValueError, TypeError, UnicodeError)) else 'winrm_transport_or_auth_failed')
        return dict(rejected, auth='denied' if denied else 'unconfirmed', warning=warning, stage=stage)


def run_winrm_access(env, invoke=subprocess.run):
    from access_pipeline import run_access
    return run_access(env, invoke)


def perform(pid, target, env, session_factory=None, evidence_parser=None):
    if session_factory is None:
        import winrm
        session_factory = winrm.Session
    if pid == '09':
        private(target['target'])
        return redact_environment(dict(perform_ad(target, env, session_factory,
            timeout_value(env.get('MRNOBODY_TIMEOUT') or '60'), env.get('MRN_P09_VERIFY_ONLY') == '1'),
            command='ad_account_and_domain_admins'), env)
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
    command = custom_script(env.get('MRN_POWERSHELL_SECRET', ''))
    response = session.run_ps(command)
    stdout, stderr = response.std_out, response.std_err
    if evidence_parser is not None:
        # Fixed lab protocols are parsed into an allowlisted result, never a P10
        # free-text preview. The P10 sensitive-command suppression stays intact.
        if response.status_code != 0 or len(stdout) > 8192:
            return dict(result='failed', warning='lab_action_failed_output_omitted')
        return evidence_parser(stdout.decode('utf-8-sig', errors='replace'))
    result = {'result': 'success' if response.status_code == 0 else 'failed',
              'exit_code': int(response.status_code), 'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
              'command': 'ad_account_and_domain_admins' if pid == '09' else 'custom_powershell_content_omitted',
              'warning': 'output_omitted_may_contain_secrets' if pid == '10' else 'none'}
    if pid == '10':
        result['result'] = 'success' if response.status_code == 0 else 'action_error'
        result['execution_status'] = ('success_with_warning' if stderr else 'success') if response.status_code == 0 else 'command_error'
        result['warning'] = 'nonfatal_stderr_output_omitted' if stderr and response.status_code == 0 else result['warning']
        result['output'] = 'omitted_may_contain_secrets'
        for stream, data in (('stdout', stdout), ('stderr', stderr)):
            result[stream + '_preview'] = p10_output_preview(data, env)
        if response.status_code != 0:
            result['reason'] = 'Custom PowerShell command failed'
    return redact_environment(result, env)


def emit(base, env, pid, event, **fields):
    stamp = datetime.now(timezone.utc).isoformat()
    iid = env['NORDIC_INCIDENT_ID']
    safe = redact_environment(fields, env)
    if pid == '11':
        # Escape before serializing so target paths cannot forge log fields or
        # physical lines. Historical unquoted P11 logs remain readable.
        safe = {key: json.dumps(value, ensure_ascii=True).replace(' ', r'\u0020').replace('=', r'\u003d')
                if isinstance(value, str) else value for key, value in safe.items()}
    if pid in {'10'}:
        # JSON quoting keeps multiline output and forged key=value/event text
        # inside one field on one physical log line. Scrub BEFORE encoding.
        for key in ('stdout_preview', 'stderr_preview'):
            if key in safe:
                safe[key] = json.dumps(p10_output_preview(safe[key], env), ensure_ascii=True).replace(' ', r'\u0020').replace('=', r'\u003d')
    line = f'{stamp} INCIDENT={iid} PHASE={pid} {event} ' + ' '.join(f'{k}={v}' for k, v in safe.items()) + '\n'
    log = Path(env.get('NORDIC_GROUND_TRUTH_LOG', base / 'logs/incident-ground-truth.log'))
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('a', encoding='utf-8') as handle:
        handle.write(line)
    print(line.rstrip(), flush=True)


def emit_p03_evidence(base, env):
    from access_pipeline import read, path, ContractError
    try:
        data = read(path(env, 'NORDIC_COMPROMISED_STATE', 'compromised-hosts.json'), env.get('NORDIC_INCIDENT_ID'))
        for result in data.get('results', []):
            # Only fixed diagnostic codes from P03; never serialize arbitrary inventory text.
            if result.get('access') == 'winrm' and result.get('warning') in WINRM_ACCESS_WARNINGS:
                emit(base, env, '09', 'P03_WINRM_EVIDENCE', target=private(result['target']),
                     authenticated=result.get('authenticated') is True, warning=result['warning'])
        emit(base, env, '09', 'P03_ACCESS_STATE', complete=data.get('complete') is True,
             reason='Review_P03_WinRM_attempts_credentials_listener_and_timeouts')
    except (ContractError, ValueError, TypeError, KeyError, AttributeError):
        emit(base, env, '09', 'P03_ACCESS_STATE', warning='p03_inventory_missing_invalid_or_other_incident',
             reason='Rerun_P01_then_P03_with_runtime_Windows_credentials')


def run(pid, env, invoke=subprocess.run):
    if pid == '09' and env.get('MRNOBODY_RUN_MODE') == 'campaign':
        env = dict(env, MRNOBODY_PASSWORD=env.get('NORDIC_RDP_PASSWORD') or env.get('MRNOBODY_PASSWORD', ''))
    base = Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack'))
    if pid not in {'09', '10'} or not INCIDENT_ID.fullmatch(env.get('NORDIC_INCIDENT_ID', '')):
        raise ValueError('Invalid phase/incident')
    emit(base, env, pid, 'PHASE_START', phase=pid, method='winrm_ntlm')
    outcomes = []
    skip_reason = None
    try:
        limit = timeout_value(env.get('MRNOBODY_TIMEOUT') or '60')
        if pid == '10':
            runtime_command(env.get('MRN_POWERSHELL_SECRET', ''))
        if pid == '09' and env.get('MRNOBODY_RUN_MODE') == 'campaign':
            emit_p03_evidence(base, env)
        selected_targets = targets(env, pid)
        discovery_reason = None
        if pid == '09' and env.get('MRNOBODY_RUN_MODE') == 'campaign':
            selected_targets, discovery_reason = select_campaign_dc(selected_targets, env, base, invoke)
            skip_reason = discovery_reason
        if not selected_targets:
            emit(base, env, pid, 'WINDOWS_ACTION_SKIPPED' if pid == '09' else 'WINDOWS_ACTION_FAILED',
                 warning=discovery_reason or 'no_authenticated_winrm_targets' if pid == '09' else 'no_windows_rdp_access_targets', method='winrm_ntlm')
            outcomes.append('skipped' if pid == '09' else 'failed')
        for target in selected_targets:
            emit(base, env, pid, 'WINDOWS_ACTION_START', target=target['target'], protocol=target['protocol'], method='winrm_ntlm')
            if pid == '09' and env.get('MRNOBODY_RUN_MODE') == 'standalone':
                emit(base, env, pid, 'WINDOWS_PORT_CHECK', target=target['target'], port=target['port'],
                     reason='Checking configured WinRM TCP reachability before authentication')
            child_env = dict(env, MRN_WINDOWS_TARGET=json.dumps(target))
            try:
                child = invoke([sys.executable, str(Path(__file__).resolve()), pid, '--worker'],
                               env=child_env, capture_output=True, timeout=(3 * (limit + 10) + 20 if pid == '09' else limit), check=False)
                result = json.loads(child.stdout) if child.returncode == 0 else {'result': 'failed', 'warning': 'worker_execution_failed'}
                if not isinstance(result, dict) or result.get('result') not in {'success', 'failed', 'skipped', 'action_error', 'partial'}:
                    raise ValueError('Invalid worker response')
                if pid == '09' and result['result'] == 'success' and not ad_success(result):
                    raise ValueError('Invalid AD success response')
            except subprocess.TimeoutExpired:
                if pid == '09':
                    # A killed worker does not cancel an AD command. Never replay
                    # the write; recover using a bounded read-only worker.
                    try:
                        recovery = invoke([sys.executable, str(Path(__file__).resolve()), pid, '--worker'],
                            env=dict(child_env, MRN_P09_VERIFY_ONLY='1'), capture_output=True,
                            timeout=2 * (limit + 10) + 20, check=False)
                        result = json.loads(recovery.stdout) if recovery.returncode == 0 else {}
                        if not isinstance(result, dict) or result.get('result') != 'success' or not ad_success(result):
                            result = dict(result='partial', warning='timeout_postconditions_not_confirmed', verified=False)
                    except (subprocess.TimeoutExpired, OSError, ValueError):
                        result = dict(result='partial', warning='timeout_postcheck_unavailable_state_unknown', verified=False)
                else:
                    result = {'result': 'failed', 'warning': 'timeout_remote_action_may_still_be_running'}
            except OSError:
                result = {'result': 'failed', 'warning': 'worker_execution_failed'}
            except ValueError:
                result = {'result': 'failed', 'warning': 'invalid_worker_response'}
            outcome = result.pop('result', 'failed')
            if pid == '10':
                result.setdefault('command', 'custom_powershell_content_omitted')
                result.setdefault('execution_status', 'transport_auth_error' if result.get('warning') == 'transport_error_details_omitted' else 'infrastructure_error' if outcome == 'failed' else outcome)
            # Only P09 prerequisites and P10 command errors have controlled exits.
            if outcome == 'action_error' and (pid != '10' or not isinstance(result.get('exit_code'), int) or result['exit_code'] == 0):
                outcome = 'failed'
            if outcome == 'skipped' and pid != '09':
                outcome = 'failed'
            outcomes.append('transport' if outcome == 'failed' and result.get('warning') == 'transport_error_details_omitted' else outcome)
            if outcome == 'skipped':
                result['reason'] = 'Target is not an Active Directory Domain Controller; privileged AD action not attempted'
            emit(base, env, pid, {'success': 'WINDOWS_ACTION_SUCCESS', 'skipped': 'WINDOWS_ACTION_SKIPPED', 'action_error': 'WINDOWS_ACTION_ERROR', 'partial': 'WINDOWS_ACTION_PARTIAL'}.get(outcome, 'WINDOWS_ACTION_FAILED'),
                 target=target['target'], protocol=target['protocol'], method='winrm_ntlm', **result)
    except DiscoveryError as error:
        skip_reason = str(error)
        emit(base, env, pid, 'WINDOWS_ACTION_SKIPPED', warning=str(error), account='not_attempted', group='not_attempted')
        outcomes.append('skipped')
    except Exception:
        outcomes.append('failed')
        emit(base, env, pid, 'WINDOWS_ACTION_FAILED', warning='invalid_or_missing_runtime_configuration')
    # A reachable non-DC establishes the missing prerequisite even if other
    # candidates had transport failures. Never suppress an action/config error.
    if pid == '09' and 'skipped' in outcomes and not any(x in outcomes for x in ('success', 'failed', 'partial')):
        emit(base, env, pid, 'PHASE_SKIPPED', phase=pid, reason='No Active Directory Domain Controller discovered',
             discovery_reason=skip_reason or 'no_writable_dc_verified',
             account='not_attempted', group='not_attempted')
        return 78  # Internal prerequisite exit; campaign/CLI wrappers handle explicitly.
    if pid == '10':
        # Transport/auth failures are candidate failures. A later reachable target
        # establishes the action result; internal/configuration failures stay fatal.
        hard_failure = 'failed' in outcomes or not any(x in {'success', 'action_error'} for x in outcomes)
        if not hard_failure and 'action_error' in outcomes:
            emit(base, env, pid, 'PHASE_SKIPPED', phase=pid, execution_status='command_error',
                 reason='Custom PowerShell command failed')
            return 79  # Campaign handles this; standalone retains a nonzero exit.
        success = not hard_failure and 'success' in outcomes
    else:
        # Candidate transport/auth failures cannot poison a verified DC success.
        # AD action, timeout, worker and configuration errors remain hard failures.
        success = 'success' in outcomes and not any(x in outcomes for x in ('failed', 'partial'))
        if 'partial' in outcomes and 'failed' not in outcomes:
            emit(base, env, pid, 'PHASE_PARTIAL', phase=pid, verified=False)
            return 80
    emit(base, env, pid, 'PHASE_COMPLETE' if success else 'PHASE_FAILED', phase=pid)
    return 0 if success else 1


if __name__ == '__main__':
    phase = sys.argv[1]
    if phase == '03':
        if '--worker' in sys.argv:
            try:
                result = probe_winrm_access(json.loads(os.environ['MRN_WINDOWS_TARGET']), os.environ)
            except Exception:
                result = dict(reachable=False, authenticated=False, auth='unconfirmed', warning='candidate_probe_worker_failed')
            print(json.dumps(result))
        else:
            raise SystemExit(run_winrm_access(os.environ))
    elif '--worker' in sys.argv:
        try:
            import winrm
            from requests.exceptions import RequestException
        except ImportError:
            print(json.dumps({'result': 'failed', 'warning': 'missing_pywinrm_or_ntlm_dependencies'}))
            raise SystemExit(0)
        try:
            target = json.loads(os.environ['MRN_WINDOWS_TARGET'])
            if phase == '09' and os.environ.get('MRN_P09_DISCOVERY_ONLY') == '1':
                print(json.dumps(probe_dc(target, os.environ)))
                raise SystemExit(0)
            if phase == '09' and os.environ.get('MRNOBODY_RUN_MODE') == 'standalone':
                try:
                    with socket.create_connection((private(target['target']), target['port']),
                                                  timeout=min(timeout_value(os.environ.get('MRNOBODY_TIMEOUT') or '60'), 5)):
                        pass
                except OSError:
                    print(json.dumps(dict(result='failed', warning='winrm_http_port_unreachable',
                        reason=f"TCP {target['port']} unavailable; check target address, WinRM listener, routing and firewall")))
                    raise SystemExit(0)
            print(json.dumps(perform(phase, target, os.environ)))
        except (ImportError, ValueError, KeyError, TypeError):
            print(json.dumps({'result': 'failed', 'warning': 'invalid_or_missing_runtime_configuration'}))
        except (winrm.exceptions.WinRMError, RequestException):
            # Transport/auth exceptions may echo credentials or command content.
            print(json.dumps({'result': 'failed', 'warning': 'transport_error_details_omitted'}))
        except Exception:
            print(json.dumps({'result': 'failed', 'warning': 'worker_execution_failed'}))
    else:
        raise SystemExit(run(phase, os.environ))
