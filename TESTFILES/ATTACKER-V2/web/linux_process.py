"""Bounded visible Linux lab processes. Never installs a restart mechanism.

This module is also the fixed remote worker payload; no operator code is run.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shlex
import socket
import struct
import subprocess
import sys
import time

CPU = {'idle': 0., 'low': .02, 'medium': .10}
ALLOWED = {'owner.txt', 'config.txt', 'worker.py', 'pid.json', 'status.json', 'status.tmp'}
MARKER = 'MrNobody controlled lab P11 process v1'


def atomic(path, value):
    temporary = path.with_name('status.tmp')
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def identity(pid):
    """PID plus kernel start ticks prevents PID reuse; inspect exact argv and UID."""
    root = Path('/proc') / str(pid)
    try:
        stat = (root / 'stat').read_text()
        fields = stat.rsplit(')', 1)[1].split()
        if fields[0] == 'Z':
            return None
        return dict(pid=pid, uid=root.stat().st_uid, start_ticks=fields[19],
                    command=(root / 'cmdline').read_bytes().split(b'\0')[:-1])
    except (FileNotFoundError, ProcessLookupError):
        return None


def owned_process(record, worker, token):
    current = identity(record['pid'])
    if current is None:
        return None
    expected = [b'/usr/bin/python3', str(worker).encode(), b'--worker', token.encode()]
    if (current['uid'] != os.getuid() or current['start_ticks'] != record['start_ticks']
            or current['command'] != expected or record['uid'] != os.getuid()):
        raise SystemExit('process_identity_conflict')
    return current


def worker_main(token):
    base = Path(__file__).resolve().parent
    config = json.loads((base / 'config.txt').read_text())
    if config['token'] != token:
        raise SystemExit(1)
    import ipaddress
    if (config['cpu'] not in CPU or config['duration'] not in {300, 900, 1800, 3600}
            or type(config['dns']) is not bool or not 10 <= config['interval'] <= 3600):
        raise SystemExit(1)
    if config['dns']:
        address = ipaddress.ip_address(config['resolver'])
        if (address.version != 4 or not any(address in ipaddress.ip_network(net) for net in
                ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
                or str(address).split('.')[-1] in {'0', '255'}):
            raise SystemExit(1)
    # Visible in top/htop; ps args retains the full artifact path and token.
    import ctypes
    ctypes.CDLL(None).prctl(15, b'mrn-p11-worker', 0, 0, 0)
    stop = [False]
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__(0, True))
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
    start = time.monotonic()
    end = start + max(0, min(config['duration'], config['deadline'] - time.time()))
    next_query = start
    state = dict(pid=os.getpid(), uid=os.getuid(), started_utc_epoch=time.time(),
                 dns_attempts=0, dns_responses=0, last_dns_rcode=-1,
                 last_query_utc_epoch_ms=0, cpu_seconds=0., state='running')
    def publish():
        state['cpu_seconds'] = time.process_time()
        atomic(base / 'status.json', state)
    publish()
    while not stop[0] and time.monotonic() < end and time.time() < config['deadline']:
        frame = time.monotonic()
        if config['dns'] and frame >= next_query and state['dns_attempts'] < 360:
            state['dns_attempts'] += 1
            state['last_query_utc_epoch_ms'] = int(time.time()*1000)
            state['last_dns_rcode'] = -1
            # Fixed A IN question, RD=0, no variable labels, payload or fallback.
            q = os.urandom(2) + struct.pack('!5H', 0, 1, 0, 0, 0) + b'\x08evilcorp\x04test\0\0\1\0\1'
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(min(1., max(.001, end-time.monotonic())))
                    client.connect((config['resolver'], 53))
                    client.send(q)
                    r = client.recv(4096)
                    if (len(r) >= len(q) and r[:2] == q[:2] and r[2] & 128
                            and not r[2] & 120 and r[4:6] == b'\0\1'
                            and r[12:len(q)] == q[12:] and r[3] & 15 in (0, 3)):
                        state['dns_responses'] += 1
                        state['last_dns_rcode'] = r[3] & 15
            except OSError:
                pass
            next_query = time.monotonic() + config['interval']
        # One thread; at most 20/100ms CPU time per 1-second frame.
        budget = CPU[config['cpu']]
        cpu_start = time.process_time()
        while (not stop[0] and time.process_time()-cpu_start < budget
               and time.monotonic() < end and time.time() < config['deadline']):
            hashlib.sha256(b'MrNobody bounded lab activity').digest()
        publish()
        remaining = min(frame + 1., end)-time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    state['state'] = 'stopped' if stop[0] else 'expired'
    publish()


def manager(name, action, options, source):
    import fcntl
    import secrets
    stage = 'ownership'
    try:
        root = Path.home() / '.config/mrnobody'
        base = root / name
        for entry in (root, base, *root.parents):
            if entry.is_symlink() or (entry.exists() and entry.stat().st_uid not in {0, os.getuid()}):
                raise SystemExit('artifact_ownership_conflict')
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        lockpath = root / 'p11-cron.lock'
        if lockpath.is_symlink() or (lockpath.exists() and lockpath.stat().st_uid != os.getuid()):
            raise SystemExit('artifact_ownership_conflict')
        with lockpath.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if base.exists():
                if not (base / 'owner.txt').is_file():
                    raise SystemExit('artifact_ownership_conflict')
                if base.stat().st_uid != os.getuid() or (base / 'owner.txt').read_text() != MARKER:
                    raise SystemExit('artifact_ownership_conflict')
                for child in base.iterdir():
                    if (child.is_symlink() or not child.is_file() or child.name not in ALLOWED
                            or child.stat().st_uid != os.getuid()):
                        raise SystemExit('artifact_ownership_conflict')
            configpath = base / 'config.txt'
            pidpath = base / 'pid.json'
            worker = base / 'worker.py'
            config = json.loads(configpath.read_text()) if configpath.exists() else None
            record = json.loads(pidpath.read_text()) if pidpath.exists() else None
            if config and not record:
                # Recover the small spawn/receipt window after an interrupted create.
                matches = []
                expected = [b'/usr/bin/python3', str(worker).encode(), b'--worker', config['token'].encode()]
                for entry in Path('/proc').iterdir():
                    try:
                        eligible = entry.name.isdigit() and entry.stat().st_uid == os.getuid()
                    except FileNotFoundError:
                        continue
                    if not eligible:
                        continue
                    candidate = identity(int(entry.name))
                    if candidate and candidate['command'] == expected:
                        matches.append({k: candidate[k] for k in ('pid', 'uid', 'start_ticks')})
                if len(matches) > 1:
                    raise SystemExit('process_identity_conflict')
                if matches:
                    record = matches[0]
                    pidpath.write_text(json.dumps(record))
            current = owned_process(record, worker, config['token']) if record and config else None
            if record and not config:
                raise SystemExit('process_identity_conflict')
            stage = action
            if action == 'cleanup':
                if current:
                    # Pin process identity in the kernel: never signal a reused PID.
                    fd = os.pidfd_open(record['pid'])
                    try:
                        if owned_process(record, worker, config['token']):
                            signal.pidfd_send_signal(fd, signal.SIGTERM)
                            for _ in range(30):
                                if identity(record['pid']) is None:
                                    break
                                time.sleep(.1)
                            if identity(record['pid']) is not None:
                                raise SystemExit('process_stop_failed')
                    finally:
                        os.close(fd)
                if base.exists():
                    for child in base.iterdir():
                        child.unlink()
                    base.rmdir()
                print('MRN_P11_CLEANUP=complete')
                return
            if action == 'create':
                stage = 'configuration'
                if config:
                    if config['options'] != options:
                        raise SystemExit('configuration_changed_cleanup_before_reconfigure')
                    if config['deadline'] <= time.time():
                        raise SystemExit('exercise_expired_cleanup_before_recreate')
                else:
                    if base.exists():
                        raise SystemExit('configuration_missing')
                    base.mkdir(mode=0o700)
                    (base / 'owner.txt').write_text(MARKER)
                    config = dict(options, options=options, token=secrets.token_hex(16),
                                  deadline=int(time.time())+options['duration'])
                    configpath.write_text(json.dumps(config))
                # Do not silently respawn a stopped process. Reruns preserve identity/deadline.
                if not current and record:
                    raise SystemExit('process_start_failed')
                if not current:
                    stage = 'create'
                    worker.write_text(source)
                    process = subprocess.Popen(['/usr/bin/python3', str(worker), '--worker', config['token']],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        start_new_session=True, close_fds=True)
                    for _ in range(30):
                        current = identity(process.pid)
                        if current and current['command'] == [b'/usr/bin/python3', str(worker).encode(), b'--worker', config['token'].encode()]:
                            break
                        time.sleep(.1)
                    if not current:
                        raise SystemExit('process_start_failed')
                    record = dict(pid=current['pid'], uid=current['uid'], start_ticks=current['start_ticks'])
                    pidpath.write_text(json.dumps(record))
            if not config or not record:
                raise SystemExit('configuration_missing')
            stage = 'verify' if action == 'create' else 'inspect'
            statuspath = base / 'status.json'
            for _ in range(30 if action == 'create' else 1):
                if statuspath.exists():
                    break
                time.sleep(.1)
            if not statuspath.exists():
                raise SystemExit('worker_status_missing')
            status = json.loads(statuspath.read_text())
            current = owned_process(record, worker, config['token'])
            if action == 'create' and not current:
                raise SystemExit('process_start_failed')
            status.update(record, running=bool(current), deadline=config['deadline'],
                          command=shlex.join(['/usr/bin/python3', str(worker), '--worker', config['token']]),
                          owner=__import__('pwd').getpwuid(os.getuid()).pw_name,
                          artifact_path=str(base), cpu_level=config['cpu'], persistence=False,
                          dns_domain='evilcorp.test' if config['dns'] else 'none',
                          dns_resolver=config['resolver'] if config['dns'] else 'none',
                          query_interval=config['interval'], activity_duration=config['duration'])
            print('MRN_P11_PROCESS=' + base64.b64encode(json.dumps(status).encode()).decode())
    except SystemExit as error:
        from_error = str(error.code)
        print('MRN_P11_ERROR=%s,%s' % (stage, from_error))
        raise SystemExit(1)
    except Exception:
        print('MRN_P11_ERROR=%s,action_failed' % stage)
        raise SystemExit(1)


def render(name, action, configuration, cpu):
    options = dict(dns=configuration['persistence_dns'] == 'enabled',
                   resolver=configuration['dns_resolver'], interval=configuration['query_interval'],
                   duration=configuration['activity_duration'], cpu=cpu)
    source = Path(__file__).read_text()
    # Source is fixed repository content, options validated by persistence_actions.
    invocation = "\nmanager(" + repr(name) + ", " + repr(action) + ", " + repr(options) + ", " + repr(source) + ")\n"
    return "set -eu\numask 077\npython3 - <<'MRN_P11_PROCESS'\n" + source + invocation + "\nMRN_P11_PROCESS\n"


def evidence(output, action):
    failure = dict(result='failed', warning='invalid_process_evidence', cleanup_required='true')
    if action == 'cleanup':
        return dict(result='success', cleanup_required='false', process_running='false') if output.strip() == 'MRN_P11_CLEANUP=complete' else failure
    rows = re.findall(r'(?m)^MRN_P11_PROCESS=([A-Za-z0-9+/=]{1,7000})\r?$', output)
    if len(rows) != 1:
        return failure
    try:
        data = json.loads(base64.b64decode(rows[0], validate=True))
        required = {'pid', 'uid', 'start_ticks', 'owner', 'command', 'started_utc_epoch',
                    'deadline', 'running', 'dns_attempts', 'dns_responses', 'last_query_utc_epoch_ms',
                    'last_dns_rcode', 'cpu_level', 'cpu_seconds', 'state', 'persistence', 'artifact_path',
                    'dns_domain', 'dns_resolver', 'query_interval', 'activity_duration'}
        if set(data) != required or data['persistence'] is not False:
            return failure
        if (type(data['pid']) is not int or data['pid'] < 1 or type(data['running']) is not bool
                or not 0 <= data['dns_responses'] <= data['dns_attempts'] <= 360
                or data['cpu_level'] not in CPU or data['last_dns_rcode'] not in {-1, 0, 3}
                or any(ord(c) < 32 for k in ('command', 'owner', 'artifact_path') for c in data[k])):
            return failure
        return dict(data, process_pid=data.pop('pid'), result='success', process_running=str(data.pop('running')).lower(),
                    cleanup_required='true', verification_scope='target_process_and_counters_not_sensor_detection',
                    dns_verification='matching_NOERROR_or_NXDOMAIN_response' if data['dns_responses'] else 'not_observed')
    except (ValueError, TypeError, KeyError):
        return failure


if __name__ == '__main__' and len(sys.argv) == 3 and sys.argv[1] == '--worker':
    worker_main(sys.argv[2])
