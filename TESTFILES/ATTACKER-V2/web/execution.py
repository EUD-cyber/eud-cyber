"""Adapters for the existing campaign/phase runners; never constructs shell code."""
import math
import re
import tempfile
from datetime import datetime, timezone
from functools import lru_cache
from reports import INCIDENT_ID, load_report, redact_environment

import argparse
import json
import os
import random
import subprocess
import time
from pathlib import Path


def read(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def number(value):
    return value if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 86400 else None


def instant(value):
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError, AttributeError):
        return None


def project(value):
    """Allowlist even when reading historical or hand-edited runtime files."""
    profile = value.get('profile') if isinstance(value.get('profile'), dict) else {}
    return {'type': value.get('type') if value.get('type') in {'campaign', 'custom', 'phase'} else 'campaign',
            'id': str(value.get('id', ''))[:160], 'name': str(value.get('name', ''))[:160],
            'profile': {'mode': profile.get('mode') if profile.get('mode') in {'normal', 'slow', 'custom'} else 'normal',
                        'duration': number(profile.get('duration'))},
            'phases': [{'id': p['id'], 'timing': {k: n for k in ('start_offset', 'duration')
                        if (n := number((p.get('timing') or {}).get(k))) is not None}}
                       for p in value.get('phases', []) if isinstance(p, dict)
                       and re.fullmatch(r'\d{2,4}', str(p.get('id', ''))) and p.get('enabled', True)],
            'trigger': 'scheduler' if value.get('trigger') == 'scheduler' else 'manual',
            'schedule_id': value.get('schedule_id') if re.fullmatch(r'schedule-[a-zA-Z0-9-]+', str(value.get('schedule_id', ''))) else None}


def record(base, env, pid):
    """Called under the existing launch lock after Popen succeeds."""
    value = project(json.loads(env['MRN_OVERVIEW']))
    value.update(incident_id=env['NORDIC_INCIDENT_ID'], started=datetime.now(timezone.utc).isoformat(),
                 pid=pid, process_start=process_identity(pid))
    directory = Path(base) / 'runtime'
    directory.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.overview-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(value, handle)
        os.replace(temporary, directory / 'execution-overview.json')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def process_identity(pid):
    """Linux process start ticks prevent PID reuse; reading never takes runner locks."""
    try:
        if type(pid) is not int or pid < 1:
            return None
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return fields[19] if fields[0] not in {'Z', 'X'} else None
    except (OSError, IndexError):
        return None


@lru_cache(maxsize=4)
def final_report(directory, iid, modified, size):
    # Immutable Reports V2 files need not be reparsed on every dashboard poll.
    return load_report(Path(directory), iid, enrich=False)


def report_for(base, iid):
    path = base / 'reports' / (iid + '.json')
    info = path.stat()
    return final_report(str(base / 'reports'), iid, info.st_mtime_ns, info.st_size)


def snapshot(base, capabilities, process=None, now=None):
    base = Path(base)
    now = time.time() if now is None else now
    launch = read(base / 'runtime/execution-overview.json')
    state = read(base / 'state/campaign.json')
    # CLI campaigns write campaign.json themselves. Prefer a newer campaign to
    # an old GUI launch record; never combine two incidents' phase states.
    if state.get('incident_id') != launch.get('incident_id') and (instant(state.get('started')) or 0) > (instant(launch.get('started')) or 0):
        execution = state.get('execution') or {}
        launch = dict(execution, incident_id=state.get('incident_id'), started=state.get('started'),
                      id=state.get('scenario'), name=state.get('scenario_name') or state.get('campaign'),
                      type='custom' if str(state.get('scenario', '')).startswith('custom-') else 'campaign')
    if not launch:
        # Idle after an update or a CLI standalone run: retain a report shortcut.
        paths = sorted((base / 'reports').glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
        for path in paths:
            try:
                last = report_for(base, path.stem)
                old = last['incident']
                execution = last.get('execution') or {}
                launch = dict(execution, incident_id=old['id'], started=old.get('started'),
                              id=old.get('scenario'), name=old.get('scenario_name'),
                              type='phase' if last.get('report_type') == 'standalone_phase' else 'campaign',
                              phases=execution.get('phases') or [{'id': p['id']} for p in last.get('phases', []) if p.get('status') != 'skipped' or last.get('report_type') == 'standalone_phase'])
                break
            except (OSError, ValueError, KeyError, TypeError):
                continue
    iid = launch.get('incident_id')
    if not isinstance(iid, str) or not INCIDENT_ID.fullmatch(iid):
        return {'version': 1, 'active': False, 'status': 'idle', 'execution': None}
    meta = project(launch)
    state = state if state.get('incident_id') == iid else {}
    try:
        report = report_for(base, iid)
    except (OSError, ValueError, TypeError, AttributeError):
        report = {}
    incident = report.get('incident', {})
    code = process.poll() if process is not None else None
    identity = process_identity(launch.get('pid'))
    active = not report and (process is not None and code is None or identity is not None and identity == launch.get('process_start'))
    status = 'running' if active else incident.get('status') or ('complete' if state.get('status') == 'complete' or code == 0 else 'failed' if code not in {None, -9, -15, 130, 137, 143} else 'interrupted')
    if status not in {'running', 'complete', 'failed', 'interrupted'}:
        status = 'interrupted'
    phases = meta['phases']
    if not phases:
        phases = [{'id': pid, 'timing': {}} for pid, s in state.get('phases', {}).items() if s != 'disabled']
    reported = {p['id']: p for p in report.get('phases', [])}
    timeline = []
    for p in phases:
        pid = p['id']
        raw = reported.get(pid, {}).get('status') if report else state.get('phases', {}).get(pid, 'running' if meta['type'] == 'phase' and active else 'pending')
        phase_status = {'success': 'complete', 'failure': 'failed', 'disabled': 'skipped', 'not_run': 'pending'}.get(raw, raw)
        if phase_status == 'running' and not active:
            phase_status = 'failed' if status == 'failed' else 'interrupted'
        if phase_status not in {'complete', 'running', 'pending', 'skipped', 'failed', 'interrupted'}:
            phase_status = 'pending'
        timeline.append({'id': pid, 'name': capabilities.get(pid, {}).get('name', 'Phase ' + pid),
                         'status': phase_status, **p['timing']})
    current = next((p for p in timeline if p['status'] == 'running'), None)
    next_phase = next((p for p in timeline if p['status'] == 'pending'), None) if active else None
    completed = sum(p['status'] == 'complete' for p in timeline)
    # Skipped phases do not inflate executable-phase progress.
    total = sum(p['status'] != 'skipped' for p in timeline)
    started = instant(launch.get('started'))
    ended = instant(incident.get('ended') or state.get('completed') or state.get('updated'))
    elapsed = max(0, (now if active else ended or started or now) - (started or now))
    span = max([meta['profile']['duration'] or 0] + [(p.get('start_offset') or 0) + (p.get('duration') or 0) for p in timeline])
    # Only fixed-format lifecycle lines are exposed. Raw stdout, command lines,
    # usernames, target parameters and wordlist contents never enter this API.
    logs = []
    try:
        with (base / 'logs/incident-ground-truth.log').open('rb') as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - 16384))
            tail = handle.read().decode('utf-8', errors='replace')
        for line in tail.splitlines():
            if f'INCIDENT={iid} ' not in line:
                continue
            match = re.search(r'\b(PHASE_START|PHASE_COMPLETE|PHASE_FAILED|PHASE_SKIPPED|CAMPAIGN_START|CAMPAIGN_COMPLETE)\b', line)
            if match:
                phase = re.search(r'\bphase=(\d{2,4})\b', line)
                logs.append(match[1].replace('_', ' ').title() + (' · P' + phase[1] if phase else ''))
    except OSError:
        pass
    return redact_environment({'version': 1, 'active': bool(active), 'status': status, 'incident_id': iid,
            'execution': meta, 'started': launch.get('started'), 'elapsed_seconds': round(elapsed),
            'planned_seconds': span or None, 'timing_best_effort': True, 'timeline': timeline,
            'current_phase': current, 'next_phase': next_phase,
            'progress': {'complete': completed, 'total': total, 'percent': round(100 * completed / total) if total else 0, 'basis': 'phase states'},
            'report_id': iid if report else None, 'logs': logs[-6:]}, os.environ)


def phase_environment(pid, environ=None, sleep=time.sleep, clock=time.time):
    env = dict(os.environ if environ is None else environ)
    config = json.loads(env['MRN_EXECUTION'])
    phase = next(p for p in config['phases'] if p['id'] == pid)
    timing = phase.get('timing', {})
    offset = timing.get('start_offset', 0)
    sleep(max(0, float(env['MRN_STARTED']) + offset - clock()))
    for key in ('SOURCE', 'TARGET', 'SUBNET', 'PORT', 'PROTOCOL', 'USERNAME', 'FILE', 'AUTO', 'TIMEOUT'):
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
    protocol = env.get('MRNOBODY_PROTOCOL') or ('winrm-http' if pid in {'09', '10'} else 'ssh')
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
