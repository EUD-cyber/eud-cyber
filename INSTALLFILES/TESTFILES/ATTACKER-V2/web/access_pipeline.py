"""P01 produces TCP facts, P03 validates access; P09 consumes P03 only.

Stdlib-only inventory production; remote clients are loaded only during P03.
No passwords, raw remote output or exception messages are persisted.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from scenario_model import private


class ContractError(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def bounded(env, key, default, low, high):
    value = env.get(key, str(default))
    if not str(value).isdigit() or not low <= int(value) <= high:
        raise ContractError('invalid_pipeline_configuration')
    return int(value)


def path(env, key, name):
    return Path(env.get(key) or Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack')) / 'state' / name)


def read(pathname, iid):
    try:
        if pathname.stat().st_size > 4 * 1048576:
            raise ContractError('inventory_oversized')
        data = json.loads(pathname.read_text(encoding='utf-8'))
        if not iid or not isinstance(data, dict) or data.get('incident_id') != iid:
            raise ContractError('inventory_incident_mismatch')
        if not isinstance(data.get('hosts'), list) or len(data['hosts']) > 4096:
            raise ContractError('inventory_invalid')
        return data
    except (OSError, ValueError, UnicodeError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError('inventory_missing_or_invalid') from None


def write(pathname, data):
    pathname.parent.mkdir(parents=True, exist_ok=True)
    temporary = pathname.with_name(pathname.name + '.pipeline.tmp')
    temporary.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    temporary.replace(pathname)


def service_ports(env):
    return dict(ssh=bounded(env, 'NORDIC_SSH_PORT', env.get('NORDIC_DEFAULT_SSH_PORT', 22), 1, 65535),
                rdp=bounded(env, 'NORDIC_RDP_PORT', env.get('NORDIC_DEFAULT_RDP_PORT', 3389), 1, 65535),
                winrm=bounded(env, 'NORDIC_WINRM_PORT', env.get('NORDIC_DEFAULT_WINRM_HTTP_PORT', 5985), 1, 65535))


def scan_ports(env):
    # Mandatory current services plus bounded explicit future inventory ports.
    values = set(service_ports(env).values())
    text = env.get('NORDIC_DISCOVERY_TCP_PORTS', env.get('NORDIC_DEFAULT_WEB_PORTS', '80,443,3010,8080,8443'))
    for item in text.split(','):
        if not item.strip().isdigit() or not 1 <= int(item) <= 65535:
            raise ContractError('invalid_discovery_ports')
        values.add(int(item))
    if len(values) > 64:
        raise ContractError('too_many_discovery_ports')
    return sorted(values)


def scoped_hosts(env, data):
    """P01/P03 scope validation. P09 intentionally never calls this."""
    try:
        networks = json.loads(path(env, 'NORDIC_NETWORK_STATE', 'networks.json').read_text())
        if networks.get('incident_id') != env['NORDIC_INCIDENT_ID']:
            raise ContractError('p01_network_incident_mismatch')
        scope = [ipaddress.IPv4Network(n['network']) for n in networks['networks']]
        excluded = [ipaddress.IPv4Network(n.strip()) for n in env.get('NORDIC_DISCOVERY_EXCLUDE_NETWORKS', '172.20.0.0/24').split(',') if n.strip()]
        minimum = bounded(env, 'NORDIC_DISCOVERY_MIN_PREFIX', 16, 16, 32)
        if not scope or any(n.prefixlen < minimum or private(str(n.network_address)) is None for n in scope):
            raise ValueError()
        found = {}
        for host in data['hosts']:
            address = ipaddress.IPv4Address(private(host['ip']))
            if any(address in n and address not in (n.network_address, n.broadcast_address) for n in scope) and not any(address in n for n in excluded):
                if str(address) in found:
                    raise ContractError('duplicate_inventory_host')
                found[str(address)] = host
        if len(found) > bounded(env, 'NORDIC_MAX_DISCOVERED_HOSTS', 254, 1, 4096):
            raise ContractError('p01_candidate_limit_exceeded')
        return sorted(found.values(), key=lambda h: ipaddress.IPv4Address(h['ip']))
    except (OSError, ValueError, TypeError, KeyError):
        raise ContractError('p01_scope_invalid') from None


def tcp_facts(address, ports, env, invoke=subprocess.run):
    started = now()
    limit = bounded(env, 'NORDIC_DISCOVERY_PORT_TIMEOUT', 20, 2, 120)
    status, records = 'scan_failed', {}
    try:
        child = invoke(['nmap', '-n', '-Pn', '-sT', '--reason', '--max-retries', '1',
                        '--host-timeout', str(limit) + 's', '-p', ','.join(map(str, ports)),
                        '-oX', '-', address], capture_output=True, timeout=limit + 3, check=False)
        if child.returncode == 0:
            root = ET.fromstring(child.stdout)
            for host in root.findall('host'):
                if not any(a.get('addr') == address for a in host.findall('address')):
                    continue
                for port in host.findall('ports/port'):
                    state = port.find('state')
                    if port.get('protocol') == 'tcp' and state is not None:
                        number = int(port.get('portid'))
                        outcome = state.get('state')
                        if number in ports and outcome in {'open', 'closed', 'filtered'}:
                            reason = state.get('reason', 'nmap_state')
                            records[number] = (outcome, reason if re.fullmatch(r'[a-z0-9_-]{1,64}', reason) else 'nmap_state')
                # nmap may compress all uninteresting ports into extraports.
                extra = host.findall('ports/extraports')
                missing = [p for p in ports if p not in records]
                if len(extra) == 1 and int(extra[0].get('count', '0')) == len(missing) and extra[0].get('state') in {'closed', 'filtered'}:
                    records.update({p: (extra[0].get('state'), 'nmap_extraports') for p in missing})
            status = 'host_scan_timeout_or_missing_result'
    except subprocess.TimeoutExpired:
        status = 'port_scan_timeout'
    except (OSError, ValueError, ET.ParseError):
        pass
    finished = now()
    return {str(p): dict(transport='tcp', port=p, state=records.get(p, ('timeout', status))[0],
                         started=started, observed=finished,
                         evidence=dict(tool='nmap_tcp_connect', reason=records.get(p, ('timeout', status))[1])) for p in ports}


def produce(env, invoke=subprocess.run):
    destination = path(env, 'NORDIC_DISCOVERED_STATE', 'discovered-hosts.json')
    data = read(destination, env['NORDIC_INCIDENT_ID'])
    ports = scan_ports(env)
    hosts = scoped_hosts(env, data)
    # Publish a new incomplete generation first; interrupted runs fail closed.
    data.update(schema_version=2, producer='P01', inventory_id=uuid.uuid4().hex,
                complete=False, configured_tcp_ports=ports, hosts=hosts, count=len(hosts))
    for host in hosts:
        host['tcp_ports'] = {}
    write(destination, data)
    for host in hosts:
        host['tcp_ports'] = tcp_facts(host['ip'], ports, env, invoke)
        from windows_actions import emit
        for fact in host['tcp_ports'].values():
            emit(Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack')), env, '01', 'PORT_OBSERVATION',
                 target=host['ip'], port=fact['port'], state=fact['state'],
                 observed=fact['observed'], evidence=fact['evidence']['reason'], authenticated=False)
    data.update(complete=True, generated=now())
    write(destination, data)
    return data


def inventory(env):
    data = read(path(env, 'NORDIC_DISCOVERED_STATE', 'discovered-hosts.json'), env['NORDIC_INCIDENT_ID'])
    if data.get('schema_version') != 2 or data.get('producer') != 'P01' or data.get('complete') is not True or not re.fullmatch(r'[a-f0-9]{32}', data.get('inventory_id', '')):
        raise ContractError('p01_port_inventory_required_rerun_p01')
    hosts = scoped_hosts(env, data)
    for host in hosts:
        if not isinstance(host.get('tcp_ports'), dict):
            raise ContractError('p01_port_inventory_invalid')
        for number, fact in host['tcp_ports'].items():
            if (not number.isdigit() or not isinstance(fact, dict) or type(fact.get('port')) is not int
                    or fact['port'] != int(number) or not 1 <= fact['port'] <= 65535
                    or fact.get('transport') != 'tcp' or fact.get('state') not in {'open', 'closed', 'filtered', 'timeout'}
                    or not isinstance(fact.get('observed'), str) or not isinstance(fact.get('evidence'), dict)):
                raise ContractError('p01_port_inventory_invalid')
    return data, hosts


def open_targets(env, protocol):
    _, hosts = inventory(env)
    port = service_ports(env)[protocol]
    return [dict(target=h['ip'], protocol='winrm-http' if protocol == 'winrm' else protocol, port=port,
                 username=env.get('NORDIC_SSH_USERNAME', env.get('NORDIC_DEFAULT_SSH_USER', 'ubuntu')) if protocol == 'ssh' else
                 env.get('NORDIC_RDP_USERNAME', env.get('NORDIC_DEFAULT_RDP_USER', 'Administrator')))
            for h in hosts if h['tcp_ports'].get(str(port), {}).get('state') == 'open']


def local_auth(target, env, invoke=subprocess.run):
    protocol = target['protocol']
    limit = bounded(env, 'NORDIC_' + protocol.upper() + '_TIMEOUT', 5, 1, 300)
    password = env.get('MRNOBODY_PASSWORD') if env.get('MRNOBODY_RUN_MODE') == 'standalone' else env.get('NORDIC_' + protocol.upper() + '_PASSWORD')
    failed = dict(authenticated=False, warning='missing_runtime_credentials', auth='not_attempted')
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@\\-]{0,127}', target['username']):
        raise ContractError('invalid_access_username')
    if not password:
        return failed
    if protocol == 'ssh':
        command = ['sshpass', '-e', 'ssh', '-p', str(target['port']), '-o', 'StrictHostKeyChecking=no',
                   '-o', 'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=' + str(limit),
                   '-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
                   '-o', 'NumberOfPasswordPrompts=1', target['username'] + '@' + target['target'],
                   'printf "NORDIC_ACCESS_OK\\n"; uname -s; hostname']
        runtime = dict(env, SSHPASS=password)
    else:
        client = shutil.which('xfreerdp3') or shutil.which('xfreerdp')
        if not client:
            return dict(failed, warning='client_unavailable')
        command = [client, '/v:' + target['target'] + ':' + str(target['port']), '/u:' + target['username'],
                   '/p:' + password, '/auth-only', '/cert:ignore', '/log-level:ERROR']
        runtime = env
    try:
        child = invoke(command, env=runtime, capture_output=True, timeout=limit, check=False)
        output = child.stdout.decode('utf-8', errors='replace') if isinstance(child.stdout, bytes) else child.stdout
        errors = child.stderr.decode('utf-8', errors='replace') if isinstance(child.stderr, bytes) else child.stderr
        text = (output or '') + (errors or '')
        if child.returncode == 0 and (protocol != 'ssh' or 'NORDIC_ACCESS_OK' in output.splitlines()) and not re.search(r'ERRCONNECT_LOGON_FAILURE|STATUS_LOGON_FAILURE|authentication failure|logon failure', text, re.I):
            platform = 'unknown'
            if protocol == 'rdp':
                platform = 'windows'
            elif re.search(r'Linux|Darwin|FreeBSD|OpenBSD|NetBSD', output):
                platform = 'linux'
            elif re.search(r'Windows|Microsoft', output, re.I):
                platform = 'windows'
            return dict(authenticated=True, auth='authenticated', warning='none', platform=platform,
                        verification='ssh_session_marker' if protocol == 'ssh' else 'rdp_auth_only')
        denied = child.returncode == 5 if protocol == 'ssh' else bool(re.search(r'LOGON_FAILURE|authentication failure|logon failure', text, re.I))
        return dict(failed, auth='denied' if denied else 'unconfirmed', warning='credentials_denied' if denied else 'protocol_error')
    except subprocess.TimeoutExpired:
        return dict(failed, auth='unconfirmed', warning='authentication_timeout')
    except OSError:
        return dict(failed, warning='client_unavailable')


def winrm_auth(target, env, invoke=subprocess.run):
    import windows_actions as actions
    attempts = []
    limit = bounded(env, 'NORDIC_WINRM_WORKER_TIMEOUT', 90, 15, 300)
    retries = bounded(env, 'NORDIC_WINRM_RETRIES', 1, 0, 2)
    for attempt in range(retries + 1):
        started = now()
        with tempfile.TemporaryDirectory(prefix='mrn-winrm-') as temporary:
            progress = Path(temporary) / 'stage'
            try:
                child = invoke([sys.executable, str(Path(actions.__file__).resolve()), '03', '--worker'],
                               env=dict(env, MRN_WINDOWS_TARGET=json.dumps(target), MRN_WINRM_PROGRESS=str(progress)),
                               capture_output=True, timeout=limit, check=False)
                if child.returncode != 0:
                    raise ValueError()
                evidence = actions.access_evidence(json.loads(child.stdout))
            except subprocess.TimeoutExpired:
                stage = progress.read_text() if progress.exists() else 'worker'
                if stage not in {'ntlm_shell', 'powershell_start', 'identity_read', 'cleanup'}:
                    stage = 'worker'
                evidence = dict(authenticated=False, reachable=True, auth='unconfirmed', warning='candidate_probe_timeout', stage=stage)
            except (OSError, ValueError, TypeError):
                evidence = dict(authenticated=False, reachable=True, auth='unconfirmed', warning='candidate_probe_worker_failed', stage='worker')
        attempts.append(dict(attempt=attempt + 1, started=started, finished=now(),
                             warning=evidence['warning'], stage=evidence.get('stage', 'identity'),
                             authenticated=evidence['authenticated']))
        if evidence['warning'] not in {'candidate_probe_timeout', 'winrm_transport_or_auth_failed', 'winrm_operation_timeout'}:
            break
    return dict(evidence, attempts=attempts, verification='read_only_windows_identity' if evidence['authenticated'] else 'none')


def run_access(env, invoke=subprocess.run):
    import windows_actions as actions
    if not actions.INCIDENT_ID.fullmatch(env.get('NORDIC_INCIDENT_ID', '')):
        raise ContractError('invalid_incident_id')
    base = Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack'))
    destination = path(env, 'NORDIC_COMPROMISED_STATE', 'compromised-hosts.json')
    state = dict(schema_version=2, producer='P03', incident_id=env['NORDIC_INCIDENT_ID'],
                 run_mode=env.get('MRNOBODY_RUN_MODE', 'campaign'),
                 complete=False, hosts=[], results=[], count=0, generated=now())
    # A failed rerun cannot leave prior successful access eligible for P09.
    write(destination, state)
    actions.emit(base, env, '03', 'PHASE_START', phase='03', method='p01_inventory_validation')
    try:
        direct = env.get('MRNOBODY_RUN_MODE') == 'standalone'
        if direct:
            protocol = env['MRNOBODY_PROTOCOL']
            kind = 'winrm' if protocol == 'winrm-http' else protocol
            if kind not in {'ssh', 'rdp', 'winrm'}:
                raise ContractError('unsupported_access_protocol')
            candidates = {kind: [dict(target=private(env['MRNOBODY_TARGET']), protocol=protocol,
                                     port=int(env.get('MRNOBODY_PORT') or service_ports(env)[kind]),
                                     username=env.get('MRNOBODY_USERNAME') or 'Administrator')]}
        else:
            data, _ = inventory(env)
            state['source_inventory_id'] = data['inventory_id']
            candidates = {kind: open_targets(env, kind) for kind in ('ssh', 'rdp', 'winrm')}
        state['candidate_counts'] = {kind: len(targets) for kind, targets in candidates.items()}
        for kind, count in state['candidate_counts'].items():
            actions.emit(base, env, '03', 'P01_PORT_GATE', protocol=kind, open_candidates=count,
                         source='p01_tcp_inventory' if not direct else 'manual_endpoint')
        merged = {}
        for kind, targets in candidates.items():
            runtime = dict(env)
            if kind == 'winrm' and not direct:
                runtime.update(MRNOBODY_PASSWORD=env.get('NORDIC_RDP_PASSWORD', ''),
                               MRNOBODY_USERNAME=env.get('NORDIC_RDP_USERNAME', 'Administrator'))
            for target in targets:
                evidence = winrm_auth(target, runtime, invoke) if kind == 'winrm' else local_auth(target, runtime, invoke)
                record = dict(target=target['target'], protocol=target['protocol'], access=kind,
                              port=target['port'], observed=now(), **evidence)
                state['results'].append(record)
                actions.emit(base, env, '03', 'ACCESS_SUCCESS' if evidence['authenticated'] else 'ACCESS_FAILED',
                             ip=target['target'], **{k: v for k, v in record.items() if k != 'attempts'})
                for attempt in evidence.get('attempts', []):
                    actions.emit(base, env, '03', 'WINRM_AUTH_ATTEMPT', target=target['target'], **attempt)
                if not evidence['authenticated']:
                    continue
                host = merged.setdefault(target['target'], dict(ip=target['target'], authenticated=True,
                    compromised=True, platform='unknown', access=kind, primary_access=kind, access_methods={}))
                method = dict(authenticated=True, port=target['port'], protocol=target['protocol'],
                              user=target['username'], observed=record['observed'], verification=evidence['verification'])
                host['access_methods'][kind] = method
                host[kind + '_port'] = target['port']
                host[kind + '_username'] = target['username']
                if kind in {'rdp', 'winrm'}:
                    host.update(platform='windows', access=kind, primary_access=kind, os='Windows')
                elif host['platform'] == 'unknown':
                    host['platform'] = evidence.get('platform', 'unknown')
        state.update(complete=True, hosts=sorted(merged.values(), key=lambda h: ipaddress.IPv4Address(h['ip'])),
                     count=len(merged), generated=now())
        write(destination, actions.redact_environment(state, env))
        success = not direct or bool(merged)
        actions.emit(base, env, '03', 'PHASE_COMPLETE' if success else 'PHASE_FAILED', phase='03',
                     authenticated=len(merged), checked=len(state['results']))
        return 0 if success else 1
    except (ContractError, ValueError, KeyError, TypeError, OSError):
        actions.emit(base, env, '03', 'PHASE_FAILED', warning='p01_inventory_or_access_configuration_invalid_rerun_p01')
        return 1


if __name__ == '__main__':
    if sys.argv[1] == '01':
        produce(os.environ)
    elif sys.argv[1] == '03':
        raise SystemExit(run_access(os.environ))
