"""Versioned, secret-free scenario definitions and execution plans.

Metadata advertises inputs; adapters below describe the inputs the current scripts
actually consume. An unknown capability fails closed until an adapter is added.
"""
import copy
import ipaddress
import json
import math
import re
from pathlib import Path

VERSION = 1
SECRET_FIELDS = {'password', 'wordlist', 'wordlist_contents', 'ssh_password', 'rdp_password', 'powershell_windows', 'bash', 'powershell'}
FIELDS = {
    'transport': {'type': 'choice', 'label': 'Beacon transport', 'options': ['http', 'https']},
    'beacon_interval': {'type': 'seconds', 'label': 'Beacon interval', 'default': 5},
    'beacon_jitter': {'type': 'fraction', 'label': 'Beacon jitter (%)', 'default': 0},
    'beacon_count': {'type': 'number', 'label': 'Number of beacons (1-20)', 'default': 5},
    'uri_profile': {'type': 'choice', 'label': 'Benign URI profile', 'options': ['heartbeat', 'status']},
    'behavior': {'type': 'choice', 'label': 'Native tool behavior', 'options': ['encoded-powershell', 'certutil-decode', 'bits-job']},
    'target': {'type': 'ipv4', 'label': 'Target IPv4'},
    'source': {'type': 'ipv4', 'label': 'Source IPv4'},
    'subnet': {'type': 'networks', 'label': 'Private subnets (comma separated)'},
    'port': {'type': 'port', 'label': 'Port'},
    'protocol': {'type': 'choice', 'label': 'Protocol'},
    'username': {'type': 'text', 'label': 'Username'},
    'timeout': {'type': 'timeout', 'label': 'Action timeout (seconds, 5–300)'},
    'platform': {'type': 'choice', 'label': 'Execution platform', 'options': ['auto', 'windows', 'linux']},
    'method': {'type': 'choice', 'label': 'Persistence method', 'options': ['auto', 'scheduled-task', 'service', 'cron', 'systemd']},
    'action': {'type': 'choice', 'label': 'Persistence action', 'options': ['create', 'cleanup']},
    'artifact': {'type': 'text', 'label': 'Artifact suffix (default: telemetry)'},
    'file': {'type': 'path', 'label': 'Synthetic staged file (@staged = current target staging output)'},
}
PROTOCOLS = {'02': ['http', 'https'], '03': ['ssh', 'rdp'],
             '04': ['ssh', 'winrm', 'winrm-http', 'winrm-https'],
             '05': ['ssh', 'winrm', 'winrm-http', 'winrm-https'],
             '06': ['ssh', 'winrm', 'winrm-http', 'winrm-https'],
             '07': ['ssh', 'winrm', 'winrm-http', 'winrm-https'],
             '08': ['ssh', 'rdp'], '09': ['winrm-http', 'winrm-https'], '10': ['ssh', 'winrm-http', 'winrm-https'], '11': ['ssh', 'winrm-http', 'winrm-https'], '12': ['ssh', 'winrm-http', 'winrm-https'], '14': ['ssh', 'winrm-http', 'winrm-https'], '13': ['winrm-http', 'winrm-https']}
TIMING = {'start_offset': 'Start offset (seconds)', 'duration': 'Target duration (seconds)',
          'delay_min': 'Minimum action delay (seconds)', 'delay_max': 'Maximum action delay (seconds)',
          'jitter': 'Jitter fraction (0–1)'}
PRIVATE = [ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
DEPENDENCIES = {'02': ['01'], '03': ['01'], '04': ['03'], '05': ['03'],
                '06': ['03', '05'], '07': ['03'], '08': ['01', '03'], '09': ['03'], '10': ['03'], '11': ['03'], '12': ['03'], '14': ['03'], '13': ['03']}


def required_fields(pid):
    required = {'subnet'} if pid == '01' else {'target'}
    if pid in {'03', '08', '09', '10', '11', '12', '13', '14'}:
        required.add('protocol')
    if pid == '06':
        required.add('file')
    if pid == '04':
        required.add('source')
    return required


def keys(value, allowed, label):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ValueError(f'Unsupported {label} fields')


def text(value, maximum=160):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid text value')
    return value.strip()


def private(value, network=False):
    try:
        item = ipaddress.ip_network(value, strict=False) if network else ipaddress.ip_network(str(value) + '/32')
    except ValueError:
        raise ValueError('A private IPv4 address/network is required') from None
    if item.version != 4 or not any(item.subnet_of(n) for n in PRIVATE):
        raise ValueError('Only RFC1918 lab targets are supported')
    if network and item.prefixlen < 24:
        raise ValueError('Use lab networks of /24 or smaller')
    return str(item) if network else str(item.network_address)


def catalogue(script_dir, read_metadata):
    result = {}
    for script in sorted(Path(script_dir).glob('[0-9][0-9]-*.sh')):
        meta = read_metadata(script)
        pid = meta.get('ATTACK_ID', '')
        if not re.fullmatch(r'\d{2}', pid):
            continue
        supported = meta.get('ATTACK_PARAMETERS', '').split(',')
        fields = {key: copy.deepcopy(FIELDS[key]) for key in supported if key in FIELDS}
        if pid == '12':
            fields['method'] = {'type': 'choice', 'label': 'Synthetic credential action', 'options': ['metadata', 'read-test-file']}
        if pid == '08':
            fields.pop('file', None)  # Wordlist is an execution-time secret input.
        if 'protocol' in fields:
            fields['protocol']['options'] = PROTOCOLS.get(pid, [])
        result[pid] = {'id': pid, 'name': meta.get('ATTACK_NAME', script.stem),
                       'dependencies': DEPENDENCIES.get(pid, []),
                       'required_fields': sorted(required_fields(pid)),
                       'script': script.name, 'fields': fields, 'auto': 'auto' in supported,
                       'credentials': 'password' in supported,
                       'wordlist': pid == '08',
                       'runtime_powershell': pid == '10',
                       'timing': list(TIMING) if pid in {'01', '02'} else ['start_offset'],
                       'standalone': meta.get('ATTACK_STANDALONE', '').lower() == 'true'}
    return result


def profile(value):
    keys(value, ['mode', 'duration'], 'profile')
    if value.get('mode', 'normal') not in {'normal', 'slow', 'custom'}:
        raise ValueError('Unknown execution profile')
    mode = value.get('mode', 'normal')
    duration = value.get('duration', 14400 if mode == 'slow' else 0)
    if type(duration) not in (int, float) or not math.isfinite(duration) or not 0 <= duration <= 86400:
        raise ValueError('Duration must be between 0 and 86400 seconds')
    if mode == 'slow' and duration < 60:
        raise ValueError('Slow duration must be at least 60 seconds')
    if mode == 'normal' and duration:
        raise ValueError('Normal profile does not take a duration')
    return {'mode': mode, 'duration': duration}


def validate(value, capabilities):
    keys(value, ['version', 'id', 'name', 'description', 'target_mode', 'phases', 'profile'], 'scenario')
    if value.get('version') != VERSION:
        raise ValueError('Unsupported scenario version')
    result = copy.deepcopy(value)
    result['name'] = text(value.get('name'))
    description = value.get('description', '')
    result['description'] = text(description, 2000) if description else ''
    if 'id' in value and not re.fullmatch(r'custom-[a-f0-9]{32}', value['id']):
        raise ValueError('Invalid custom scenario ID')
    mode = value.get('target_mode')
    if mode not in {'auto', 'fixed'}:
        raise ValueError('Choose Auto Discovery or Fixed Targets')
    result['profile'] = profile(value.get('profile', {}))
    phases = value.get('phases')
    if not isinstance(phases, list) or not 1 <= len(phases) <= 32:
        raise ValueError('Select between 1 and 32 phases')
    seen = set()
    enabled = []
    for phase in phases:
        keys(phase, ['id', 'enabled', 'parameters', 'timing'], 'phase')
        pid = phase.get('id')
        if pid not in capabilities or pid in seen:
            raise ValueError('Unknown or duplicate phase')
        seen.add(pid)
        cap = capabilities[pid]
        if type(phase.get('enabled', True)) is not bool:
            raise ValueError('Enabled must be boolean')
        params = phase.setdefault('parameters', {})
        allowed = set(cap['fields'])
        if mode == 'auto' and pid not in {'10', '11', '12', '13', '14'}:
            allowed -= {'target', 'source', 'subnet', 'protocol', 'port', 'username', 'file'}
        keys(params, allowed, 'phase parameter')
        for key, val in list(params.items()):
            if key in {'source', 'target'}:
                params[key] = private(val)
            elif key == 'subnet':
                params[key] = ','.join(private(x.strip(), True) for x in str(val).split(','))
            elif key == 'port':
                if isinstance(val, bool) or not str(val).isdigit() or not 1 <= int(val) <= 65535:
                    raise ValueError('Invalid port')
                params[key] = int(val)
            elif key == 'timeout':
                if isinstance(val, bool) or not str(val).isdigit() or not 5 <= int(val) <= 300:
                    raise ValueError('Windows action timeout must be 5–300 seconds')
                params[key] = int(val)
            elif key in {'platform', 'method', 'action', 'protocol', 'behavior', 'transport', 'uri_profile'}:
                if val not in cap['fields'][key]['options']:
                    raise ValueError('Unsupported choice')
            elif key in {'beacon_interval', 'beacon_jitter', 'beacon_count'}:
                from lab_actions import number
                limits = {'beacon_interval': (1, 60, False), 'beacon_jitter': (0, .5, False), 'beacon_count': (1, 20, True)}
                params[key] = number(val, *limits[key])
            elif key == 'artifact':
                if not isinstance(val, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', val):
                    raise ValueError('Artifact suffix must be 1–32 lowercase letters/digits/hyphens')
            elif key == 'file':
                # The existing exfil phase accepts a synthetic file. Do not turn
                # the builder into a way to transfer arbitrary remote files.
                if val != '@staged' and not re.fullmatch(r'(?:/tmp/\.nordic-(?:MRN|H3)-[A-Za-z0-9_-]+/nordic-data-(?:MRN|H3)-[A-Za-z0-9_-]+\.txt|C:\\NordicIncident\\(?:MRN|H3)-[A-Za-z0-9_-]+\\staging\\nordic-data-(?:MRN|H3)-[A-Za-z0-9_-]+\.txt)', str(val)):
                    raise ValueError('Only synthetic staging paths are supported')
            else:
                if not re.fullmatch(r'[A-Za-z0-9_.@\\-]{1,128}', str(val)):
                    raise ValueError('Invalid username')
        if pid in {'10', '11', '12', '13', '14'}:
            platform = params.get('platform', 'auto')
            protocol = params.get('protocol')
            effective = 'linux' if protocol == 'ssh' else 'windows' if protocol else platform
            if platform != 'auto' and effective != platform:
                raise ValueError('Platform/protocol mismatch')
            method = params.get('method', 'auto')
            if pid == '11' and method != 'auto':
                from persistence_actions import METHODS
                if effective != 'auto' and METHODS[method][0] != effective:
                    raise ValueError('Persistence method/platform mismatch')
        if pid in {'12', '14'}:
            from lab_actions import configuration
            configuration(pid, {'MRNOBODY_' + k.upper(): str(v) for k, v in params.items()})
        timing = phase.setdefault('timing', {})
        keys(timing, cap['timing'], 'timing')
        if result['profile']['mode'] != 'custom' and timing:
            raise ValueError('Phase timing requires Custom Timing')
        for key, val in timing.items():
            if type(val) not in (int, float) or not math.isfinite(val) or not 0 <= val <= (1 if key == 'jitter' else 86400):
                raise ValueError('Invalid timing value')
        if timing.get('delay_max', timing.get('delay_min', 0)) < timing.get('delay_min', 0):
            raise ValueError('Maximum delay must be >= minimum delay')
        if phase.get('enabled', True):
            enabled.append(pid)
            if mode == 'fixed':
                required = required_fields(pid)
                if not required <= set(params):
                    raise ValueError(f'Phase {pid} needs: {", ".join(sorted(required))}')
    if not enabled:
        raise ValueError('Enable at least one phase')
    # Fresh campaigns clear shared inventories; reject impossible dependencies.
    if mode == 'auto':
        prior = set()
        for pid in enabled:
            needed = set(DEPENDENCIES.get(pid, []))
            if not needed <= prior:
                raise ValueError(f'Phase {pid} requires earlier phases: {", ".join(sorted(needed))}')
            prior.add(pid)
    return result


def plan(definition):
    result = copy.deepcopy(definition)
    phases = [p for p in result['phases'] if p.get('enabled', True)]
    if result['profile']['mode'] == 'slow':
        duration = result['profile']['duration']
        # Pacing is implemented inside discovery and web actions. Remaining
        # phases get an absolute offset, rather than accumulating phase sleeps.
        weights = {'01': .40, '02': .25, '03': .08, '08': .05, '04': .06, '05': .06, '06': .05, '07': .05}
        total = sum(weights.get(p['id'], .05) for p in phases)
        offset = 0
        for p in phases:
            slot = duration * weights.get(p['id'], .05) / total
            p['timing'] = {'start_offset': offset}
            if p['id'] in {'01', '02'}:
                p['timing'].update(duration=slot, jitter=.1)
            offset += slot
    result['phases'] = phases
    return result


def needs_password(definition, windows=False):
    if definition is None:
        return True  # Preserve the existing Full Incident form contract.
    for p in definition['phases']:
        if p['id'] not in {'03', '04', '05', '06', '07', '09', '10', '11', '12', '13', '14'}:
            continue
        if definition['target_mode'] == 'auto':
            return True
        protocol = p.get('parameters', {}).get('protocol', 'winrm-http' if p['id'] in {'09', '10', '11', '12', '13', '14'} else 'ssh')
        if protocol.startswith(('rdp', 'winrm')) == windows:
            return True
    return False
