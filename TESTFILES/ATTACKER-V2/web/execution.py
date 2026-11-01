"""Adapters for the existing campaign/phase runners; never constructs shell code."""
import argparse
import json
import os
import random
import subprocess
import time
from pathlib import Path


def phase_environment(pid, environ=None, sleep=time.sleep, clock=time.time):
    env = dict(os.environ if environ is None else environ)
    config = json.loads(env['MRN_EXECUTION'])
    phase = next(p for p in config['phases'] if p['id'] == pid)
    timing = phase.get('timing', {})
    offset = timing.get('start_offset', 0)
    sleep(max(0, float(env['MRN_STARTED']) + offset - clock()))
    for key in ('SOURCE', 'TARGET', 'SUBNET', 'PORT', 'PROTOCOL', 'USERNAME', 'FILE', 'AUTO'):
        env.pop('MRNOBODY_' + key, None)
    env['MRNOBODY_RUN_MODE'] = 'campaign' if config['target_mode'] == 'auto' else 'standalone'
    for key, value in phase.get('parameters', {}).items():
        env['MRNOBODY_' + key.upper()] = str(value)
    if env.get('MRNOBODY_FILE') == '@staged':
        staging = Path(env.get('NORDIC_STAGING_STATE', Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack')) / 'state/staged-data.json'))
        data = json.loads(staging.read_text())
        host = next((h for h in data.get('hosts', []) if h.get('ip') == env.get('MRNOBODY_TARGET') and h.get('staged') and h.get('data_type') == 'synthetic-training-data'), None)
        if host is None:
            raise ValueError('No synthetic staging output exists for this target')
        env['MRNOBODY_FILE'] = host['file']
    if pid == '01':
        env['MRNOBODY_AUTO'] = '1' if config['target_mode'] == 'auto' else '0'
    protocol = env.get('MRNOBODY_PROTOCOL', 'ssh')
    env['MRNOBODY_PASSWORD'] = env.get('NORDIC_RDP_PASSWORD' if protocol.startswith(('winrm', 'rdp')) else 'NORDIC_SSH_PASSWORD', '')
    env['MRN_TIMING'] = json.dumps(timing)
    env['MRN_PHASE_STARTED'] = str(clock())
    return env


def pace(index, count, timing, started, sleep=time.sleep, clock=time.time, uniform=random.uniform):
    """Space actions across a minimum duration; delays are lower bounds too.

    Work takes time itself, so target duration is best effort, never a timeout.
    The final action starts at duration*(count-1)/count.
    """
    duration = timing.get('duration', 0)
    slot = duration / max(1, count)
    due = started + slot * index
    if index:
        due += uniform(-1, 1) * timing.get('jitter', 0) * slot
    delay = uniform(timing.get('delay_min', 0), timing.get('delay_max', timing.get('delay_min', 0)))
    jitter = timing.get('jitter', 0)
    delay *= uniform(1 - jitter, 1 + jitter)
    sleep(max(0, due - clock(), delay if index else 0))


def discovery(networks, environ=None):
    """Paced -sn probes, retaining the phase's filtered network list and nmap output."""
    import ipaddress
    env = os.environ if environ is None else environ
    timing = json.loads(env.get('MRN_TIMING', '{}'))
    hosts = []
    for line in Path(networks).read_text().splitlines():
        network = line.split('|', 1)[0]
        hosts.extend(str(ip) for ip in ipaddress.ip_network(network).hosts())
    started = float(env.get('MRN_PHASE_STARTED', time.time()))
    for index, host in enumerate(hosts):
        pace(index, len(hosts), timing, started)
        # No shell, no arbitrary flags; each nmap operation remains bounded.
        try:
            subprocess.run(['nmap', '-sn', '-n', host, '-oG', '-'], timeout=20, check=False)
        except subprocess.TimeoutExpired:
            print('[WARN] Discovery probe timed out', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase')
    parser.add_argument('--script')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--discovery')
    parser.add_argument('--pace', nargs=2, type=int)
    args = parser.parse_args()
    if args.list:
        for p in json.loads(os.environ['MRN_EXECUTION'])['phases']:
            print(p['id'])
    elif args.discovery:
        discovery(args.discovery)
    elif args.pace:
        pace(*args.pace, json.loads(os.environ.get('MRN_TIMING', '{}')), float(os.environ['MRN_PHASE_STARTED']))
    else:
        env = phase_environment(args.phase)
        # exec preserves process-group cancellation and the existing EXIT report.
        os.execve(args.script, [args.script], env)


if __name__ == '__main__':
    main()
