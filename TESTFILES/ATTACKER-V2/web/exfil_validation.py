"""Validate explicit standalone reuse of synthetic staging evidence (no remote I/O)."""
import json
import os
from pathlib import Path
import re
import sys

from scenario_model import private

IID = re.compile(r'(?:MRN|H3)-[A-Za-z0-9_-]{1,100}')


def validate(data, staging_path):
    if not isinstance(data, dict):
        raise ValueError('P06 request must be a JSON object')
    for key in ('target', 'protocol', 'username', 'password'):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError('P06 requires ' + key)
        if any(ch in value for ch in ('|', '\r', '\n', '\0')):
            raise ValueError('Invalid P06 ' + key)
    target = private(data['target'])
    protocol = data['protocol']
    if protocol not in {'ssh', 'winrm', 'winrm-http', 'winrm-https'}:
        raise ValueError('P06 protocol must be ssh, winrm-http or winrm-https')
    if isinstance(data.get('port'), bool):
        raise ValueError('P06 port must be 1–65535')
    port = str(data.get('port') or {'ssh': 22, 'winrm': 5985, 'winrm-http': 5985, 'winrm-https': 5986}[protocol])
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('P06 port must be 1–65535')
    if data['username'].startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.@\\-]{1,128}', data['username']):
        raise ValueError('Invalid P06 username')
    for key in ('file', 'staging_incident'):
        value = data.get(key, '')
        if not isinstance(value, str) or any(ch in value for ch in ('|', '\r', '\n', '\0')):
            raise ValueError('Invalid P06 ' + key)
    if not data.get('file') and not data.get('staging_incident'):
        return {'source_kind': 'synthetic-default', 'synthetic': True, 'platform': 'linux' if protocol == 'ssh' else 'windows'}
    if not data.get('file') or not data.get('staging_incident'):
        raise ValueError('P06 staged reuse requires both remote file and staging incident ID')
    origin = data['staging_incident']
    if not IID.fullmatch(origin):
        raise ValueError('Invalid staging incident ID')
    try:
        state = json.loads(Path(staging_path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise ValueError('P06 needs readable staged-data.json. Run P05 first and copy its incident ID and remote file path.') from None
    if not isinstance(state, dict) or state.get('incident_id') != origin:
        raise ValueError('Staging incident ID mismatch. Select the incident recorded in staged-data.json; no previous state is selected automatically.')
    platform = 'linux' if protocol == 'ssh' else 'windows'
    hosts = state.get('hosts', [])
    if not isinstance(hosts, list):
        raise ValueError('Invalid staged-data.json hosts')
    matches = [h for h in hosts if isinstance(h, dict) and h.get('ip') == target
               and h.get('file') == data['file'] and h.get('platform') == platform
               and h.get('staged') is True and h.get('data_type') == 'synthetic-training-data']
    if len(matches) != 1:
        raise ValueError('No unique synthetic P05/P17 artifact matches target, protocol and remote file in this staging incident')
    host = matches[0]
    if type(host.get('size')) is not int or host['size'] <= 0 or not re.fullmatch(r'[a-fA-F0-9]{64}', str(host.get('sha256', ''))):
        raise ValueError('Staging artifact requires a positive size and SHA256 evidence; run P05 again')
    return host


def received(path, size, sha256):
    import hashlib
    source = Path(path)
    if source.stat().st_size != int(size):
        return False
    digest = hashlib.sha256()
    with source.open('rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest() == sha256.lower()


if __name__ == '__main__':
    try:
        if len(sys.argv) == 4 and sys.argv[1] == '--received':
            # Size and digest are one argument so receiver validation has no shell parsing.
            size, digest = sys.argv[3].split('|')
            raise SystemExit(0 if received(sys.argv[2], size, digest) else 1)
        data = {key: os.environ.get('MRNOBODY_' + key.upper(), '') for key in
                ('target', 'protocol', 'port', 'username', 'password', 'file')}
        data['staging_incident'] = os.environ.get('MRNOBODY_STAGING_INCIDENT') or os.environ.get('NORDIC_INCIDENT_ID', '')
        host = validate(data, sys.argv[1])
        print(str(host['size']) + '|' + host['sha256'])
    except (OSError, ValueError) as exc:
        print('[ERROR] ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
