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
# The existing `version` field is the canonical scenario schema version.
MAX_SCENARIO_BYTES = 128 * 1024
SECRET_FIELDS = {'password', 'wordlist', 'wordlist_contents', 'ssh_password', 'rdp_password', 'powershell_windows', 'bash', 'powershell'}
FIELDS = {
    'dns_behavior': {'type': 'choice', 'label': 'DNS behavior', 'options': ['standard', 'low-and-slow', 'encoded-marker']},
    'dns_endpoint': {'type': 'ipv4', 'label': 'Private lab DNS endpoint (UDP 53)'},
    'dns_domain': {'type': 'text', 'label': 'Lab domain (.test/.internal/.localhost)', 'default': 'mrnobody.test'},
    'dns_pattern': {'type': 'text', 'label': 'Query label pattern', 'default': 'mrn-{seq}'},
    'dns_interval': {'type': 'seconds', 'label': 'DNS interval (default standard 5s / slow 60s)'},
    'dns_jitter': {'type': 'fraction', 'label': 'DNS jitter (%)', 'default': 0},
    'dns_count': {'type': 'number', 'label': 'DNS query count (1-40)', 'default': 3},
    'dns_duration': {'type': 'seconds', 'label': 'DNS duration ceiling (max 4 minutes)', 'default': 240},
    'web_profile': {'type': 'choice', 'label': 'Web behavior', 'options': ['sqli', 'traversal']},
    'web_path': {'type': 'text', 'label': 'Lab application base path', 'default': '/mrn-lab'},
    'dataset': {'type': 'choice', 'label': 'Synthetic dataset', 'options': ['finance', 'engineering']},
    'archive_name': {'type': 'text', 'label': 'Archive suffix', 'default': 'collection'},
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
    'method': {'type': 'choice', 'label': 'Persistence method', 'options': ['auto', 'task-service', 'cron-systemd', 'scheduled-task', 'service', 'cron', 'systemd']},
    'persistence_dns': {'type': 'choice', 'label': 'P11 periodic DNS activity', 'options': ['disabled', 'enabled'], 'default': 'disabled'},
    'persistence_domain': {'type': 'text', 'label': 'P11 reserved test domain (.test)', 'default': 'evilcorp.test'},
    'persistence_resolver': {'type': 'ipv4', 'label': 'P11 internal non-forwarding lab DNS resolver'},
    'persistence_interval': {'type': 'seconds', 'label': 'P11 DNS interval (10–3600 seconds)', 'default': 60},
    'persistence_duration': {'type': 'seconds', 'label': 'P11 activity lifetime (60–14400 seconds; manual artifact cleanup)', 'default': 3600},
    'action': {'type': 'choice', 'label': 'Persistence action', 'options': ['create', 'cleanup']},
    'artifact': {'type': 'text', 'label': 'Artifact suffix (default: telemetry)'},
    'file': {'type': 'path', 'label': 'Synthetic staged file (@staged = current target staging output)'},
}
PROTOCOLS = {'02': ['http', 'https'], '03': ['ssh', 'rdp'],
             '04': ['ssh', 'winrm', 'winrm-http', 'winrm-https'],
             '05': ['ssh', 'winrm', 'winrm-http', 'winrm-https'],
             '06': ['ssh', 'winrm', 'winrm-http', 'winrm-https'],
             '07': ['ssh', 'winrm', 'winrm-http', 'winrm-https'],
             '08': ['ssh', 'rdp'], '09': ['winrm-http', 'winrm-https'], '10': ['ssh', 'winrm-http', 'winrm-https'], '11': ['ssh', 'winrm-http', 'winrm-https'], '12': ['ssh', 'winrm-http', 'winrm-https'], '14': ['ssh', 'winrm-http', 'winrm-https'], '13': ['winrm-http', 'winrm-https'], '15': ['http', 'https'], '16': ['ssh', 'winrm-http', 'winrm-https'], '17': ['ssh', 'winrm-http', 'winrm-https'], '18': ['ssh', 'winrm-http', 'winrm-https']}
TIMING = {'start_offset': 'Start offset (seconds)', 'duration': 'Target duration (seconds)',
          'delay_min': 'Minimum action delay (seconds)', 'delay_max': 'Maximum action delay (seconds)',
          'jitter': 'Jitter fraction (0–1)'}
PRIVATE = [ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
DEPENDENCIES = {'02': ['01'], '03': ['01'], '04': ['03'], '05': ['03'],
                '06': ['03', '05'], '07': ['03'], '08': ['01', '03'], '09': ['03'], '10': ['03'], '11': ['03'], '12': ['03'], '14': ['03'], '13': ['03'], '15': ['02'], '16': ['03'], '17': ['03'], '18': ['03']}


def required_fields(pid):
    required = {'subnet'} if pid == '01' else {'target'}
    if pid in {'03', '08', '09', '10', '11', '12', '13', '14', '16', '17', '18'}:
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
        if pid in {'16', '17'}:
            fields['action'] = {'type': 'choice', 'label': 'Exercise action', 'options': ['run', 'cleanup']}
        if pid == '16':
            fields['behavior'] = {'type': 'choice', 'label': 'Reversible synthetic behavior', 'options': ['config-toggle', 'log-rename']}
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


def technique_metadata(meta, capability, full_incident_ids=()):
    """Add presentation metadata without changing execution or historical reports.

    Script comments own educational text. Planning adapters own dependencies and
    configuration; installed scenario metadata owns Full Incident membership.
    Missing metadata stays explicitly unknown, including for future scripts.
    """
    split = lambda value: [x.strip() for x in re.split(r'[,|]', value) if x.strip()]
    pid = meta.get('ATTACK_ID', '')
    modes = []
    if capability.get('standalone'):
        modes.append('Standalone')
    if capability:
        modes.append('Custom Scenario')
    if pid in full_incident_ids:
        modes.append('Full Incident')
    if capability.get('standalone'):
        modes.append('Scheduler')
    ids = split(meta.get('MITRE_TECHNIQUES', ''))
    names = meta.get('MITRE_TECHNIQUE_NAMES', '').split('|')
    return {
        'description': meta.get('ATTACK_DESCRIPTION', ''),
        'teaching_purpose': meta.get('ATTACK_TEACHING_PURPOSE', ''),
        'detection_focus': split(meta.get('ATTACK_DETECTION_FOCUS', '')),
        'platforms': split(meta.get('ATTACK_PLATFORMS', '')),
        'supported_modes': modes,
        'prerequisites': meta.get('ATTACK_PREREQUISITES', ''),
        'dependencies': capability.get('dependencies', []),
        'required_fields': capability.get('required_fields', []),
        'configuration': capability.get('fields', {}),
        'target_type': meta.get('ATTACK_TARGET_TYPE', ''),
        'cleanup': meta.get('ATTACK_CLEANUP', ''),
        'readiness': meta.get('ATTACK_STATUS', 'Installed'),
        'tactics': split(meta.get('MITRE_TACTIC', '')),
        'technique_details': [
            {'id': tid, 'name': names[i].strip() if i < len(names) else '',
             'url': 'https://attack.mitre.org/techniques/' + tid.replace('.', '/') + '/'}
            for i, tid in enumerate(ids) if re.fullmatch(r'T\d{4}(?:\.\d{3})?', tid)
        ],
    }


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


def secret_free(value, depth=0):
    """Reject secrets, never strip them or echo their values in an error/log."""
    if depth > 16:
        raise ValueError('Scenario JSON is nested too deeply')
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in SECRET_FIELDS or re.search(
                    r'password|passwd|credential|secret|token|private.?key|wordlist|^commands?$|^shell$|^cron$', key, re.I):
                raise ValueError('Scenario definitions cannot contain secrets, wordlists or runtime commands')
            secret_free(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            secret_free(item, depth + 1)
    elif isinstance(value, str):
        try:
            value.encode('utf-8')
        except UnicodeError:
            raise ValueError('Scenario text must contain valid UTF-8 characters') from None
        if re.search(
                r'-----BEGIN .*PRIVATE KEY-----|\bBearer\s+\S+|\b(?:password|passwd|token|secret)\s*[:=]\s*\S+|[a-z]+://[^\s/:]+:[^\s/@]+@|\bgh[pousr]_[A-Za-z0-9]{20,}|\bAKIA[A-Z0-9]{16}\b', value, re.I):
            raise ValueError('Remove embedded credentials or private keys from scenario text')


def parse_scenario(raw):
    """Strict, bounded JSON. Duplicate keys and non-finite numbers fail closed."""
    if len(raw) > MAX_SCENARIO_BYTES:
        raise ValueError('Scenario JSON exceeds the 128 KiB limit')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Scenario JSON contains duplicate fields')
            result[key] = value
        return result

    def constant(_):
        raise ValueError('Scenario JSON must contain finite numbers')

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        raise ValueError('Malformed scenario JSON; upload a UTF-8 JSON object') from None
    if not isinstance(value, dict):
        raise ValueError('Scenario JSON must be an object')
    secret_free(value)
    return value


def migrate_scenario(value):
    """Only the legacy unversioned/v0 form of this model is supported.

    There is no inferred technique mapping, reordering or removal. Materialize
    the old model defaults deterministically and require an explicit review.
    """
    value = copy.deepcopy(value)
    version = value.get('version', 0)
    if type(version) is not int or version not in (0, VERSION):
        raise ValueError(f'Incompatible scenario version; this installation supports version {VERSION} and legacy version 0')
    notes = []
    if version == 0:
        value['version'] = VERSION
        value.setdefault('description', '')
        value.setdefault('profile', {'mode': 'normal', 'duration': 0})
        value['needs_review'] = True
        notes.append('Legacy version 0 migrated to version 1 using current defaults. Review targets, technique order and timing before acknowledging.')
    return value, notes


def import_scenario(raw, capabilities):
    value, notes = migrate_scenario(parse_scenario(raw))
    # Validate the whole document before creating any persistent state.
    value = validate(value, capabilities, template=True)
    readiness = scenario_readiness(value, capabilities)
    return value, notes, readiness


def scenario_readiness(value, capabilities):
    if value.get('needs_review'):
        return 'Needs review'
    try:
        validate(value, capabilities)
    except ValueError:
        return 'Needs configuration'
    return 'Compatible · Ready'


def export_scenario(value, capabilities):
    secret_free(value)
    value = validate(value, capabilities, template=True)
    raw = (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
    if len(raw) > MAX_SCENARIO_BYTES:
        raise ValueError('Scenario JSON exceeds the 128 KiB limit')
    safe_name = re.sub(r'[^a-z0-9]+', '-', value['name'].lower()).strip('-')[:80] or 'custom'
    return raw, f'mrnobody-scenario-{safe_name}-v{VERSION}.json'


def validate(value, capabilities, *, template=False):
    keys(value, ['version', 'id', 'name', 'description', 'target_mode', 'phases', 'profile', 'preset', 'teaching_objective', 'needs_review'], 'scenario')
    if type(value.get('version')) is not int or value.get('version') != VERSION:
        raise ValueError('Unsupported scenario version')
    if type(value.get('needs_review', False)) is not bool:
        raise ValueError('Needs review must be boolean')
    if value.get('needs_review') and not template:
        raise ValueError('Needs review: inspect and acknowledge the migrated scenario before running or scheduling')
    result = copy.deepcopy(value)
    value = result  # Normalization must never mutate the caller's definition.
    if 'preset' in value:
        origin = value['preset']
        keys(origin, ['id', 'version', 'name'], 'preset origin')
        if str(origin.get('id', '')).removeprefix('preset-') not in PRESETS or origin.get('version') != VERSION:
            raise ValueError('Unknown preset origin or version')
        result['preset']['name'] = PRESETS[origin['id'].removeprefix('preset-')][0]
    if 'teaching_objective' in value:
        result['teaching_objective'] = text(value['teaching_objective'], 2000)
    result['name'] = text(value.get('name'))
    description = value.get('description', '')
    result['description'] = text(description, 2000) if description else ''
    if 'id' in value and (not isinstance(value['id'], str) or not re.fullmatch(r'custom-[a-f0-9]{32}', value['id'])):
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
        if not isinstance(pid, str) or pid not in capabilities:
            label = 'P' + pid if isinstance(pid, str) and re.fullmatch(r'\d{2}', pid) else 'invalid ID'
            raise ValueError(f'Unknown or deferred Attack Technique {label}; resolve it before importing. No techniques were removed.')
        if pid in seen:
            raise ValueError(f'Duplicate Attack Technique P{pid}')
        seen.add(pid)
        cap = capabilities[pid]
        if type(phase.get('enabled', True)) is not bool:
            raise ValueError('Enabled must be boolean')
        params = phase.setdefault('parameters', {})
        allowed = set(cap['fields'])
        if mode == 'auto' and pid not in {'10', '11', '12', '13', '14', '15', '16', '17', '18'}:
            allowed -= {'target', 'source', 'subnet', 'protocol', 'port', 'username', 'file'}
        keys(params, allowed, 'phase parameter')
        for key, val in list(params.items()):
            if key.startswith('persistence_'):
                pass  # Validated together below using the remote-action contract.
            elif key == 'dns_endpoint':
                params[key] = private(val)
            elif key.startswith('dns_'):
                pass  # Full cross-field validation below, shared with CLI.
            elif key in {'source', 'target'}:
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
            elif key in {'platform', 'method', 'action', 'protocol', 'behavior', 'transport', 'uri_profile', 'web_profile', 'dataset'}:
                if val not in cap['fields'][key]['options']:
                    raise ValueError('Unsupported choice')
            elif key in {'beacon_interval', 'beacon_jitter', 'beacon_count'}:
                from lab_actions import number
                limits = {'beacon_interval': (1, 60, False), 'beacon_jitter': (0, .5, False), 'beacon_count': (1, 20, True)}
                params[key] = number(val, *limits[key])
            elif key == 'web_path':
                from web_profiles import configuration
                configuration({'MRNOBODY_WEB_PATH': val})
            elif key in {'artifact', 'archive_name'}:
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
        if pid in {'10', '11', '12', '13', '14', '16', '17', '18'}:
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
        if pid == '11':
            from persistence_actions import configuration
            configuration({'MRNOBODY_' + k.upper(): str(v) for k, v in params.items()},
                          effective if effective != 'auto' else METHODS[method][0] if method != 'auto' else 'linux')
        if pid == '18':
            from dns_actions import configuration
            configuration(pid, {'MRNOBODY_' + k.upper(): str(v) for k, v in params.items()})
        if pid in {'16', '17'}:
            from exercise_actions import configuration
            configuration(pid, {'MRNOBODY_' + k.upper(): str(v) for k, v in params.items()})
        if pid == '15':
            from web_profiles import configuration
            configuration({'MRNOBODY_' + k.upper(): str(v) for k, v in params.items()})
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
            if mode == 'fixed' and not template:
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
    positions = {pid: i for i, pid in enumerate(enabled)}
    for first, later in [('14', '18'), ('18', '16'), ('18', '04'), ('18', '17'), ('18', '05'), ('18', '06'), ('18', '07'), ('02', '15'), ('15', '03'), ('10', '16'), ('11', '16'), ('12', '16'), ('13', '16'), ('14', '16'), ('16', '17'), ('17', '05'), ('17', '06'), ('17', '07'), ('16', '05'), ('16', '06'), ('16', '07')]:
        if first in positions and later in positions and positions[first] > positions[later]:
            raise ValueError(f'Phase {first} must precede {later}')
    if not template:
        missing = preset_requirements(result)
        if missing:
            raise ValueError('Needs configuration: ' + '; '.join(missing))
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
        if p['id'] not in {'03', '04', '05', '06', '07', '09', '10', '11', '12', '13', '14', '16', '17', '18'}:
            continue
        if definition['target_mode'] == 'auto':
            return True
        protocol = p.get('parameters', {}).get('protocol', 'winrm-http' if p['id'] in {'09', '10', '11', '12', '13', '14', '16', '17', '18'} else 'ssh')
        if protocol.startswith(('rdp', 'winrm')) == windows:
            return True
    return False

# These are scenario-model definitions, not an independent runner. Ordering is
# deliberate; catalogue validation below rejects registry/dependency drift.
PRESETS = {
    'recon-only': ('Recon Only', 'Discover private lab hosts and identify web services.',
                   'Distinguish host discovery from service identification without authenticated activity.',
                   '01 02'),
    'credential-attack': ('Credential Attack', 'Validate supplied lab credentials, then inspect synthetic credential telemetry.',
                          'Correlate successful authentication with a bounded synthetic credential action. No password guessing is enabled.',
                          '01 03 12'),
    'windows-domain-compromise': ('Windows Domain Compromise', 'Exercise explicit Windows/DC targets and reversible host persistence.',
                                 'Correlate AD account/group changes, host persistence, synthetic credential access and native-tool telemetry. AD changes require separate lab rollback.',
                                 '01 03 09 11 12 13'),
    'c2-detection': ('C2 Detection Exercise', 'Observe bounded HTTP and DNS marker check-ins after authenticated access.',
                      'Compare HTTP beacon and reserved-zone DNS detections using a private non-forwarding lab resolver.',
                      '01 03 14 18'),
    'web-attack': ('Web Attack', 'Discover web services and exercise the fingerprinted MrNobody Web Lab.',
                   'Correlate dedicated synthetic SQL injection requests with application and web telemetry; this does not grant host access.',
                   '01 02 15'),
    'collection-exfiltration': ('Collection + Exfiltration', 'Archive synthetic exercise data, stage it and transfer the staged output.',
                                'Follow marker-verified collection artifacts through shared staging state into transfer evidence.',
                                '01 03 17 05 06'),
    'ransomware-style': ('Ransomware-style Incident', 'Exercise a synthetic access-to-impact incident with bounded marker beacons.',
                         'Investigate persistence, synthetic collection, staging, transfer and impact artifacts without encrypting existing files.',
                         '01 03 11 12 14 16 17 05 06 07'),
    'slow-intrusion': ('Slow Intrusion', 'Spread a representative synthetic incident across a four-hour target window.',
                       'Correlate sparse discovery and post-authentication events using the engine Slow Campaign offsets. Target duration is best effort.',
                       '01 02 03 11 12 14 16 04 17 05 06 07'),
    'full-attack-incident': ('Full ATT&CK-style Incident', 'A broad coherent lab incident from discovery through synthetic impact.',
                            'Investigate web, authenticated host, persistence, synthetic credential, C2, evasion, collection, transfer and impact evidence. Web activity is a separate branch, not a host exploit.',
                            '01 02 15 03 11 12 14 18 16 04 17 05 06 07'),
}


def preset_requirements(value):
    """Non-secret configuration only. Runtime credentials retain their own flow.

    Origin survives cloning so configuration requirements cannot disappear just
    by saving a template as a custom scenario. Removed techniques need no input.
    """
    if not value.get('preset'):
        return []
    missing = []
    for p in value.get('phases', []):
        if not p.get('enabled', True):
            continue
        params = p.get('parameters', {})
        pid = p['id']
        if value['target_mode'] == 'fixed':
            missing.extend(f'P{pid}: {key}' for key in sorted(required_fields(pid)) if not params.get(key))
        if pid == '09' and value['target_mode'] != 'fixed':
            missing.append('P09: use Fixed Targets and select a lab DC with AD management rights')
        if pid == '18' and not params.get('dns_endpoint'):
            missing.append('P18: private non-forwarding lab DNS endpoint')
        if pid == '15' and not params.get('target'):
            missing.append('P15: fingerprinted MrNobody Web Lab target (edit base path/profile for your app)')
    return missing


def preset_definition(sid, capabilities):
    key = sid.removeprefix('preset-')
    if sid != 'preset-' + key or key not in PRESETS:
        return None
    name, description, objective, flow = PRESETS[key]
    windows = key == 'windows-domain-compromise'
    defaults = {
        '11': {'method': 'task-service' if windows else 'auto', 'action': 'create', 'artifact': 'telemetry'},
        '12': {'method': 'metadata'},
        '13': {'behavior': 'encoded-powershell'},
        '14': {'transport': 'http', 'beacon_interval': 5, 'beacon_jitter': .1, 'beacon_count': 5, 'uri_profile': 'heartbeat'},
        '15': {'web_profile': 'sqli', 'web_path': '/mrn-lab'},
        '16': {'behavior': 'config-toggle', 'action': 'run'},
        '17': {'dataset': 'finance', 'archive_name': 'collection', 'action': 'run'},
        '18': {'dns_behavior': 'standard', 'dns_domain': 'mrnobody.test', 'dns_pattern': 'mrn-{seq}', 'dns_interval': 5, 'dns_jitter': .1, 'dns_count': 5, 'dns_duration': 60},
    }
    phases = []
    for pid in flow.split():
        params = copy.deepcopy(defaults.get(pid, {}))
        if windows and pid != '01':
            params['protocol'] = 'rdp' if pid == '03' else 'winrm-http'
            if 'platform' in capabilities[pid]['fields']:
                params['platform'] = 'windows'
        phases.append({'id': pid, 'enabled': True, 'parameters': params, 'timing': {}})
    value = {'version': VERSION, 'name': name, 'description': description, 'target_mode': 'fixed' if windows else 'auto',
             'profile': {'mode': 'slow', 'duration': 14400} if key == 'slow-intrusion' else {'mode': 'normal', 'duration': 0},
             'phases': phases, 'teaching_objective': objective, 'preset': {'id': sid, 'version': VERSION}}
    return validate(value, capabilities, template=True)


def preset_cards(capabilities):
    cards = []
    for key, (_, _, objective, _) in PRESETS.items():
        sid = 'preset-' + key
        try:
            value = preset_definition(sid, capabilities)
        except (ValueError, KeyError):
            # Partial/older installations must not advertise executable presets.
            continue
        required = preset_requirements(value)
        cards.append({'id': sid, 'name': value['name'], 'description': value['description'],
                      'teaching_objective': objective, 'version': VERSION, 'preset': True, 'read_only': True,
                      'phases': [p['id'] for p in value['phases']], 'target_mode': value['target_mode'],
                      'profile': value['profile'], 'required_inputs': required, 'runnable': not required,
                      'readiness': 'Needs configuration' if required else 'Ready · runtime credentials where required',
                      'duration_seconds': value['profile']['duration'] or None,
                      'estimated_seconds': 60 if key == 'c2-detection' else None})
    return cards
