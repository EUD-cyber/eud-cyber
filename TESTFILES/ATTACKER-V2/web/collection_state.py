"""P17 writes the existing staged-data schema; P05 retains these host entries."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile

from exercise_actions import configuration, paths
from scenario_model import private


def retained(data, iid):
    return [h for h in data.get('hosts', []) if data.get('incident_id') == iid
            and h.get('producer_phase') == '17' and h.get('staged')
            and h.get('data_type') == 'synthetic-training-data']


def update(env, target, result):
    config = configuration('17', env)
    _, expected = paths(config, target['platform'])
    path = Path(env.get('NORDIC_STAGING_STATE', Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack')) / 'state/staged-data.json'))
    data = json.loads(path.read_text()) if path.exists() else {}
    hosts = data.get('hosts', []) if data.get('incident_id') == config['incident'] else []
    ip = private(target['target'])
    hosts = [h for h in hosts if not (h.get('ip') == ip and (config['action'] != 'cleanup' or h.get('file') == expected))]
    if config['action'] != 'cleanup':
        if result.get('file') != expected or type(result.get('size')) is not int or not 0 < result['size'] < 1000000 or not re.fullmatch('[a-f0-9]{64}', result.get('sha256', '')):
            raise ValueError('Invalid synthetic archive evidence')
        host = dict(ip=ip, platform=target['platform'], access='ssh' if target['platform'] == 'linux' else 'winrm',
                    staged=True, file=expected, size=result['size'], sha256=result['sha256'],
                    data_type='synthetic-training-data', producer_phase='17', dataset=config['dataset'],
                    files_count=result['files_count'], collection_incident=config['incident'])
        host.update({'ssh_port': target['port'], 'ssh_username': target['username']} if target['platform'] == 'linux'
                    else {'winrm_port': target['port'], 'rdp_username': target['username']})
        hosts.append(host)
    data = dict(incident_id=config['incident'], generated=datetime.now(timezone.utc).isoformat(), count=len(hosts), hosts=hosts)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False, encoding='utf-8') as out:
        json.dump(data, out, indent=2)
        tmp = out.name
    os.replace(tmp, path)


if __name__ == '__main__':
    import sys
    path, iid, ip = sys.argv[1:]
    data = json.loads(Path(path).read_text()) if Path(path).exists() else {}
    raise SystemExit(0 if any(h.get('ip') == ip for h in retained(data, iid)) else 1)
