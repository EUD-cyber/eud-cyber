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


def campaign_dc_candidates(env):
    """Use incident-matched P01 inventories, never P03 platform/access claims."""
    base = Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack'))
    def inventory(key, filename, field):
        path = Path(env.get(key) or base / 'state' / filename)
        if not path.exists():
            raise DiscoveryError('p01_inventory_missing')
        if path.stat().st_size > 1048576:
            raise DiscoveryError('p01_inventory_oversized')
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (ValueError, UnicodeError):
            raise DiscoveryError('p01_inventory_invalid') from None
        if not isinstance(data, dict) or data.get('incident_id') != env.get('NORDIC_INCIDENT_ID'):
            raise DiscoveryError('p01_inventory_incident_mismatch')
        rows = data.get(field)
        if not isinstance(rows, list) or len(rows) > 4096:
            raise DiscoveryError('p01_inventory_invalid')
        return rows
    networks = inventory('NORDIC_NETWORK_STATE', 'networks.json', 'networks')
    hosts = inventory('NORDIC_DISCOVERED_STATE', 'discovered-hosts.json', 'hosts')
    try:
        scope = [ipaddress.IPv4Network(n['network']) for n in networks]
        excluded = [ipaddress.IPv4Network(n.strip()) for n in
                    env.get('NORDIC_DISCOVERY_EXCLUDE_NETWORKS', '172.20.0.0/24').split(',') if n.strip()]
        minimum = max(16, int(env.get('NORDIC_DISCOVERY_MIN_PREFIX', '16')))
        if not scope or any(n.prefixlen < minimum or private(str(n.network_address)) is None for n in scope):
            raise ValueError()
        addresses = set()
        for host in hosts:
            if not isinstance(host, dict):
                raise ValueError()
            try:
                address = ipaddress.IPv4Address(private(host.get('ip')))
            except ValueError:
                continue
            if any(address in n and address not in (n.network_address, n.broadcast_address) for n in scope) and not any(address in n for n in excluded):
                addresses.add(address)
        override = env.get('NORDIC_AD_DC_TARGET')
        if override:
            pinned = ipaddress.IPv4Address(private(override))
            if pinned not in addresses:
                raise DiscoveryError('explicit_dc_outside_p01_scope')
            addresses = {pinned}
        maximum = max(1, min(254, int(env.get('NORDIC_MAX_DISCOVERED_HOSTS', '254'))))
    except DiscoveryError:
        raise
    except (ValueError, TypeError, KeyError):
        raise DiscoveryError('p01_scope_invalid') from None
    if len(addresses) > maximum:
        raise DiscoveryError('p01_candidate_limit_exceeded')
    return [dict(target=str(address), protocol='winrm-http', port=5985,
                 username=env.get('MRNOBODY_USERNAME') or env.get('NORDIC_RDP_USERNAME') or 'Administrator')
            for address in sorted(addresses)]


DC_VERIFY = r"""
$ErrorActionPreference='Stop'
$r=@{result='rejected'; warning='target_must_be_domain_controller'; domain='unknown'; dc='unknown'}
try {
    $system=Get-CimInstance Win32_ComputerSystem
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
} catch { $r.warning='dc_verification_failed' }
$r | ConvertTo-Json -Compress
"""


def probe_dc(target, env, session_factory=None, connect=None):
    """One bounded TCP probe and one authenticated, strictly read-only role check."""
    private(target['target'])
    connect = connect or socket.create_connection
    try:
        with connect((target['target'], 5985), timeout=2):
            pass
    except OSError:
        return dict(result='rejected', warning='winrm_port_unreachable', probe='unreachable', auth='not_attempted')
    password = env.get('MRNOBODY_PASSWORD') or env.get('NORDIC_RDP_PASSWORD')
    if not password:
        return dict(result='rejected', warning='missing_runtime_windows_credentials', probe='reachable', auth='not_attempted')
    try:
        if session_factory is None:
            import winrm
            session_factory = winrm.Session
        session = session_factory(f"http://{target['target']}:5985/wsman",
            auth=(target['username'], password), transport='ntlm', server_cert_validation='ignore',
            operation_timeout_sec=5, read_timeout_sec=8)
        response = session.run_ps(DC_VERIFY)
        if response.status_code != 0 or not isinstance(response.std_out, bytes) or len(response.std_out) > 2048:
            raise ValueError()
        data = json.loads(response.std_out.decode('utf-8-sig'))
        if not isinstance(data, dict) or data.get('result') not in {'eligible', 'rejected'} or data.get('warning') not in {
                'none', 'target_must_be_domain_controller', 'dc_verification_failed', 'dc_identity_mismatch_or_read_only'}:
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
    emit(base, env, '09', 'P09_DISCOVERY_START', candidates=len(candidates),
         port=5985, budget_seconds=120, selection='lowest_numeric_verified_writable_dc')
    for target in candidates:
        remaining = deadline - time.monotonic()
        if remaining < 1:
            reasons.append('discovery_budget_exhausted')
            break
        emit(base, env, '09', 'P09_CANDIDATE', target=target['target'], source='p01', port=5985)
        try:
            child = invoke([sys.executable, str(Path(__file__).resolve()), '09', '--worker'],
                env=dict(env, MRN_WINDOWS_TARGET=json.dumps(target), MRN_P09_DISCOVERY_ONLY='1'),
                capture_output=True, timeout=min(12, remaining), check=False)
            result = json.loads(child.stdout) if child.returncode == 0 else {}
            allowed = {'none', 'winrm_port_unreachable', 'missing_runtime_windows_credentials',
                'target_must_be_domain_controller', 'dc_verification_failed', 'dc_identity_mismatch_or_read_only',
                'credentials_denied', 'invalid_dc_response', 'winrm_transport_or_auth_failed'}
            if not isinstance(result, dict) or result.get('warning') not in allowed or result.get('result') not in {'eligible', 'rejected'}:
                raise ValueError()
            # Never copy arbitrary worker fields into Ground Truth.
            details = {k: result[k] for k in ('probe', 'auth') if result.get(k) in
                       {'reachable', 'unreachable', 'not_attempted', 'authenticated', 'denied', 'unconfirmed'}}
            eligible = result['result'] == 'eligible' and result['warning'] == 'none' and details.get('auth') == 'authenticated'
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
        emit(base, env, '09', 'P09_DC_VERIFICATION', target=target['target'], port=5985,
             eligible=eligible, warning=reason, **details)
        if eligible:
            emit(base, env, '09', 'P09_DC_SELECTED', target=target['target'],
                 selection='lowest_numeric_verified_writable_dc', **details)
            return [target], None
        reasons.append(reason)
    reason = ('no_p01_discovered_hosts' if not candidates else
              reasons[0] if reasons and len(set(reasons)) == 1 else
              'discovery_budget_exhausted' if 'discovery_budget_exhausted' in reasons else 'no_verified_writable_dc')
    emit(base, env, '09', 'P09_DISCOVERY_EXHAUSTED', warning=reason, attempted=len(reasons))
    return [], reason


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


def run(pid, env, invoke=subprocess.run):
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
        selected_targets = targets(env, pid)
        discovery_reason = None
        if pid == '09' and env.get('MRNOBODY_RUN_MODE') == 'campaign':
            selected_targets, discovery_reason = select_campaign_dc(selected_targets, env, base, invoke)
            skip_reason = discovery_reason
        if not selected_targets:
            emit(base, env, pid, 'WINDOWS_ACTION_SKIPPED' if pid == '09' else 'WINDOWS_ACTION_FAILED',
                 warning=discovery_reason or 'no_verified_writable_dc' if pid == '09' else 'no_windows_rdp_access_targets', method='winrm_ntlm')
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
             discovery_reason=skip_reason or 'no_verified_writable_dc',
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
    if '--worker' in sys.argv:
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
