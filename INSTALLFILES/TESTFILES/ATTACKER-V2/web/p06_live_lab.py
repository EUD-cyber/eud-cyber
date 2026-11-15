"""One explicit outbound transfer of the verified, fixed P06 training fixture."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from p06_synthetic import fixture

MAX_FILE = 4096


def validate_selection(data):
    live = data.get('live_lab', False)
    if type(live) is not bool:
        raise ValueError('Live Lab must be an explicit boolean selection')
    if live:
        if data.get('file') or data.get('staging_incident'):
            raise ValueError('Live Lab accepts only the generated P06 test file')
        from agent_client import load_agent_config, FatalAgentError
        try:
            load_agent_config()
        except (FatalAgentError, OSError, ValueError):
            raise ValueError('Live Lab requires a configured, paired Slave Agent') from None
    return live


def validate_payload(data):
    fields = {'agent_id', 'protocol_version', 'campaign_id', 'phase', 'synthetic', 'size', 'sha256', 'content'}
    if (not isinstance(data, dict) or set(data) != fields or data['phase'] != 'P06'
            or not isinstance(data['campaign_id'], str)
            or data['synthetic'] is not True or type(data['protocol_version']) is not int
            or data['protocol_version'] != 1 or type(data['size']) is not int
            or not 0 < data['size'] <= MAX_FILE or not isinstance(data['content'], str)
            or len(data['content']) > 4*((MAX_FILE+2)//3)):
        raise ValueError('Invalid P06 Live Lab payload')
    raw = base64.b64decode(data['content'], validate=True)
    if (len(raw) != data['size'] or hashlib.sha256(raw).hexdigest() != data['sha256']
            or raw != fixture(data['campaign_id'])):
        raise ValueError('P06 content, size or SHA-256 mismatch')
    return raw


def read_verified(state_path, upload_dir, incident):
    """No caller-selected source: derive the artifact name from P06 evidence."""
    expected = fixture(incident)
    state = json.loads(Path(state_path).read_text(encoding='utf-8'))
    transfers = state.get('transfers', [])
    if state.get('incident_id') != incident or len(transfers) != 1:
        raise ValueError('One current P06 transfer required')
    entry = transfers[0]
    if (entry.get('source_kind') != 'synthetic-default' or entry.get('synthetic') is not True
            or entry.get('verified') is not True or entry.get('successful') is not True):
        raise ValueError('Verified generated P06 fixture required')
    from scenario_model import private
    private(entry.get('source'))
    if entry.get('platform') not in {'linux', 'windows'}:
        raise ValueError('Invalid P06 platform')
    directory = Path(upload_dir)
    path = directory / f"{incident}-{entry['platform']}-{entry['source']}.bin"
    if directory.is_symlink() or path.is_symlink():
        raise ValueError('P06 symlink rejected')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            raise ValueError('Invalid P06 artifact size/type')
        raw = handle.read(MAX_FILE+1)
    if raw != expected or entry.get('sha256') != hashlib.sha256(raw).hexdigest():
        raise ValueError('P06 artifact changed')
    return raw


def send(state_path, upload_dir, incident, sender=None):
    from agent_client import AgentTransport, load_agent_config
    raw = read_verified(state_path, upload_dir, incident)
    sender = sender or AgentTransport(load_agent_config())
    result = sender.post('p06-file', p06=dict(campaign_id=incident, phase='P06', synthetic=True,
                         size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                         content=base64.b64encode(raw).decode('ascii')))
    state = json.loads(Path(state_path).read_text(encoding='utf-8'))
    state['live_lab'] = dict(result, master_url=sender.config.master_url)
    Path(state_path).write_text(json.dumps(state, indent=2), encoding='utf-8')
    return result


if __name__ == '__main__':
    try:
        result = send(sys.argv[1], sys.argv[2], os.environ['NORDIC_INCIDENT_ID'])
        print('P06 Live Lab: Master verified receipt ' + str(result['event_id']))
    except Exception:
        # Credentials, local paths and remote response bodies must never reach logs.
        print('[ERROR] P06 Live Lab receipt unavailable; check Agent identity, Master and Receiver.', file=sys.stderr)
        raise SystemExit(1)
