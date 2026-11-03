"""Offline P19 teaching fixture. Never contacts a target or grants access.

This is deliberately outside the distributed MrNobody runtime. Outcomes describe
provided synthetic observations, not verified vulnerabilities or real access.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from types import MappingProxyType


PRIVATE = tuple(IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    service: str
    port: int
    protocol: str
    fingerprint: str
    proof: str
    validation_action: str = 'Compare an in-memory synthetic marker'
    cleanup: str = 'None: no target contact, files, or access changes'
    mitre: tuple = ()

    def __post_init__(self):
        if not self.id or not self.name or not self.service:
            raise ValueError('Profile identity and service are required')
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError('Invalid profile port')
        if self.protocol not in ('http', 'https') or not self.fingerprint or not self.proof:
            raise ValueError('Invalid fixture contract')
        if self.mitre:
            raise ValueError('Offline fixture must not claim observed ATT&CK activity')


def registry(profiles):
    result = {}
    for item in profiles:
        if not isinstance(item, Profile) or item.id in result:
            raise ValueError('Invalid or duplicate profile')
        result[item.id] = item
    return MappingProxyType(result)


PROFILES = registry((Profile(
    'offline-marker-v1', 'Offline benign proof exercise',
    'synthetic CyberLab HTTP fixture', 8080, 'http',
    'mrnobody-offline-fixture-v1', 'benign-proof-v1',
),))


def private_target(value):
    try:
        address = IPv4Address(value)
    except (ValueError, TypeError):
        raise ValueError('A literal RFC1918 IPv4 target is required') from None
    if not any(address in network for network in PRIVATE):
        raise ValueError('Only RFC1918 targets are permitted')
    return str(address)


def validate_config(config):
    if not isinstance(config, dict) or set(config) - {'profile', 'mode', 'target'}:
        raise ValueError('Unsupported configuration fields')
    pid = config.get('profile', 'offline-marker-v1')
    if not isinstance(pid, str) or pid not in PROFILES:
        raise ValueError('Unknown profile')
    mode = config.get('mode', 'auto')
    if mode not in ('auto', 'fixed'):
        raise ValueError('Mode must be auto or fixed')
    if mode == 'auto' and 'target' in config:
        raise ValueError('Auto uses supplied discovery observations')
    target = private_target(config.get('target')) if mode == 'fixed' else None
    return {'profile': pid, 'mode': mode, 'target': target}


def now():
    return datetime.now(timezone.utc).isoformat()


def evaluate(config, observations):
    """Evaluate up to 64 synthetic observations with allowlisted evidence only.

    No callbacks, commands, URLs, credentials, network clients, state paths, or
    executable provider hooks are accepted. Input strings never enter evidence.
    A matching fixture with bad proof fails unless a later candidate succeeds.
    """
    cfg = validate_config(config)
    if not isinstance(observations, list) or len(observations) > 64:
        raise ValueError('Supply at most 64 synthetic observations')
    profile = PROFILES[cfg['profile']]
    started = now()
    candidates = []
    for entry in observations:
        if not isinstance(entry, dict):
            raise ValueError('Invalid observation')
        target = private_target(entry.get('target'))
        if cfg['mode'] == 'fixed' and target != cfg['target']:
            continue
        candidates.append((target, entry))
    attempts = []
    for target, entry in candidates:
        matched = (entry.get('fingerprint') == profile.fingerprint
                   and type(entry.get('port')) is int
                   and entry['port'] == profile.port
                   and entry.get('protocol') == profile.protocol)
        proved = matched and entry.get('proof') == profile.proof
        outcome = 'SUCCESS' if proved else 'FAILURE' if matched else 'NOT_APPLICABLE'
        attempts.append({
            'target': target, 'service': profile.service, 'port': profile.port,
            'protocol': profile.protocol, 'fingerprint_match': matched,
            'validation_action': profile.validation_action,
            'proof_verified': proved, 'outcome': outcome, 'timestamp': now(),
            'evidence_preview': 'Synthetic marker accepted' if proved else 'No verified synthetic proof',
        })
        if proved:
            break
    outcomes = {a['outcome'] for a in attempts}
    outcome = ('SUCCESS' if 'SUCCESS' in outcomes else
               'FAILURE' if 'FAILURE' in outcomes else 'NOT_APPLICABLE')
    return {
        'schema_version': 1, 'phase': 'P19', 'simulation': True,
        'profile': profile.id, 'outcome': outcome,
        'started_at': started, 'completed_at': now(), 'attempts': attempts,
        'access': {'verified_real_access': False, 'compromise_state_changed': False},
        'mitre': [], 'cleanup': profile.cleanup,
        'warnings': ['Offline synthetic evidence only; no vulnerability or real access validated'],
    }
