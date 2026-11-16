"""One explicit outbound transfer of the verified, fixed P06 training fixture."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import signal
import subprocess
import threading
import time

from p06_synthetic import fixture

MAX_FILE = 4096


def campaign_selection(data, definition, scenario_id):
    live = data.get('p06_live_lab', False)
    if type(live) is not bool:
        raise ValueError('P06 campaign Live Lab requires an explicit boolean')
    if not live:
        return False
    if scenario_id != 'full-incident' or not isinstance(definition, dict):
        raise ValueError('P06 campaign Live Lab is supported only by Full Incident')
    phases = {p['id']: p for p in definition.get('phases', []) if p.get('enabled', True)}
    if '03' not in phases or '06' not in phases or list(phases).index('03') > list(phases).index('06'):
        raise ValueError('P06 Live Lab requires enabled P03 before P06')
    if any(phases['06'].get('parameters', {}).get(key) or data.get(key)
           for key in ('file', 'staging_incident')):
        raise ValueError('P06 Live Lab accepts only one generated fixture, not staged/custom files')
    validate_selection({'live_lab': True})
    return True


def campaign_environment(env):
    """Reuse the fixed-file standalone pipeline on one verified same-incident P03 host."""
    if env.get('MRNOBODY_P06_CAMPAIGN_LIVE_LAB') != '1':
        raise ValueError('Explicit campaign P06 Live Lab required')
    from p11_campaign import targets  # Shared strict P03 identity/access evidence verifier; no remote action.
    candidates = targets(env)
    selected = env.get('MRNOBODY_TARGET')
    if selected:
        candidates = [target for target in candidates if target['target'] == selected]
    if not candidates:
        raise ValueError('No verified same-incident P03 access for P06 Live Lab')
    target = sorted(candidates, key=lambda item: (item['target'], item['platform']))[0]
    result = dict(env)
    for key in ('MRNOBODY_STAGING_INCIDENT', 'MRNOBODY_REQUIRE_STAGING', 'MRNOBODY_FILE'):
        result.pop(key, None)
    result.update(MRNOBODY_RUN_MODE='standalone', MRNOBODY_P06_LIVE_LAB='1',
                  NORDIC_INCIDENT_IP='',  # Route-selected Slave receiver; never confuse it with the Master hint.
                  MRNOBODY_TARGET=target['target'], MRNOBODY_PROTOCOL=target['protocol'],
                  MRNOBODY_PORT=str(target['port']), MRNOBODY_USERNAME=target['username'],
                  MRNOBODY_PASSWORD=env['NORDIC_SSH_PASSWORD' if target['platform'] == 'linux' else 'NORDIC_RDP_PASSWORD'])
    from windows_actions import emit
    emit(Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack')), env, '06',
         'P06_CAMPAIGN_LIVE_SOURCE', source=target['target'], platform=target['platform'],
         protocol=target['protocol'], source_kind='synthetic-default', origin='verified_P03', count=1)
    return result


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


def bounded_receipt(payload, config, stop=None, timeout=10):
    """Disposable child bounds DNS/TLS/response reading; no retries after uncertain ACK."""
    stop = stop if stop is not None else threading.Event()
    if stop.is_set():
        raise ValueError('P06 Master transfer stopped')
    deadline = time.monotonic() + timeout
    with subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--once'],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
        child.stdin.write(json.dumps(payload).encode())
        child.stdin.close()
        while child.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or stop.wait(min(.1, max(0, remaining))):
                child.kill(); child.wait()
                raise ValueError('P06 Master transfer stopped or exceeded deadline')
        if child.returncode or stop.is_set():
            raise ValueError('P06 Master receipt unavailable')
        raw = child.stdout.read(4097)
        if len(raw) > 4096:
            raise ValueError('Invalid P06 worker response')
        result = json.loads(raw)
        if (not isinstance(result, dict) or set(result) != {'ack', 'master_url', 'agent_id'}
                or result['master_url'] != config.master_url or result['agent_id'] != config.agent_id):
            raise ValueError('P06 Agent identity changed during transfer')
        ack = result['ack']
        if (not isinstance(ack, dict) or ack.get('verified') is not True
                or any(ack.get(key) != value for key, value in dict(agent_id=config.agent_id,
                    campaign_id=payload.get('campaign_id'), phase='P06', size=payload.get('size'),
                    sha256=payload.get('sha256')).items())):
            raise ValueError('P06 worker receipt mismatch')
        return ack


def send(state_path, upload_dir, incident, sender=None, stop=None):
    from agent_client import AgentTransport, load_agent_config
    raw = read_verified(state_path, upload_dir, incident)
    payload = dict(campaign_id=incident, phase='P06', synthetic=True,
                         size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                         content=base64.b64encode(raw).decode('ascii'))
    config = sender.config if sender is not None else load_agent_config()
    result = sender.post('p06-file', p06=payload) if sender is not None else bounded_receipt(payload, config, stop)
    state = json.loads(Path(state_path).read_text(encoding='utf-8'))
    state['live_lab'] = dict(result, master_url=config.master_url)
    Path(state_path).write_text(json.dumps(state, indent=2), encoding='utf-8')
    return result


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--once']:
            from agent_client import AgentTransport, load_agent_config
            raw = sys.stdin.buffer.read(8193)
            if len(raw) > 8192:
                raise ValueError('Invalid fixed P06 payload')
            config = load_agent_config()
            ack = AgentTransport(config).post('p06-file', p06=json.loads(raw))
            print(json.dumps(dict(ack=ack, master_url=config.master_url, agent_id=config.agent_id)))
        else:
            stop = threading.Event()
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: stop.set())
            result = send(sys.argv[1], sys.argv[2], os.environ['NORDIC_INCIDENT_ID'], stop=stop)
            print('P06 Live Lab: Master verified receipt ' + str(result['event_id']))
    except Exception:
        # Credentials, local paths and remote response bodies must never reach logs.
        print('[ERROR] P06 Live Lab receipt unavailable; check Agent identity, Master and Receiver.', file=sys.stderr)
        raise SystemExit(1)
