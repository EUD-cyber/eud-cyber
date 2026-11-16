"""Bounded, opt-in Slave-to-Master training beacons. No commands or tasking."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

FIELDS = {'agent_id', 'protocol_version', 'campaign_id', 'phase', 'synthetic',
          'timestamp', 'sequence', 'marker'}
MARKER = 'MRN-EXERCISE-ONLY'


def settings(data):
    live = data.get('p11_live_lab', False)
    if type(live) is not bool:
        raise ValueError('P11 Live Lab requires an explicit boolean selection')
    if not live:
        return None
    if data.get('action', 'create') != 'create' or data.get('target_mode', 'fixed') != 'fixed':
        raise ValueError('P11 Live Lab starts only with Create; use Stop before Cleanup')
    result = {}
    for key, default, lower, upper in (('beacon_interval', 30, 10, 300),
                                      ('beacon_duration', 180, 60, 1800),
                                      ('beacon_count', 6, 1, 60)):
        value = data.get(key, default)
        if isinstance(value, bool) or not re.fullmatch(r'[0-9]{1,4}', str(value)) or not lower <= int(value) <= upper:
            raise ValueError(f'{key} must be {lower}–{upper}')
        result[key] = int(value)
    if result['beacon_interval'] > result['beacon_duration']:
        raise ValueError('Beacon interval must fit the duration')
    return result


def validate_payload(data):
    if (not isinstance(data, dict) or set(data) != FIELDS
            or data['phase'] != 'P11' or data['synthetic'] is not True
            or type(data['protocol_version']) is not int or data['protocol_version'] != 1
            or type(data['sequence']) is not int or not 1 <= data['sequence'] <= 60
            or data['marker'] != MARKER
            or not isinstance(data['campaign_id'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,100}', data['campaign_id'])
            or not isinstance(data['timestamp'], str)
            or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?\+00:00', data['timestamp'])):
        raise ValueError('Invalid P11 synthetic beacon')
    datetime.fromisoformat(data['timestamp'])
    from master_registry import validate_id
    validate_id(data['agent_id'])
    return data


def campaign_selection(data, definition, phase_ids):
    """Runtime-only opt-in; never save live traffic in a scenario or schedule."""
    if data.get('live_lab'):
        raise ValueError('Use explicit p06_live_lab/p11_live_lab campaign selections')
    options = settings(data)
    if options is None:
        return None
    phases = (definition or {}).get('phases', [{'id': pid} for pid in phase_ids])
    enabled = {p['id']: p for p in phases if p.get('enabled', True)}
    if '11' not in enabled or '03' not in enabled:
        raise ValueError('Campaign Live Lab requires enabled P03 and P11 phases')
    if list(enabled).index('03') > list(enabled).index('11'):
        raise ValueError('Campaign Live Lab requires P03 before P11')
    if enabled['11'].get('parameters', {}).get('action', 'create') != 'create':
        raise ValueError('Campaign Live Lab requires P11 Create; stop before Cleanup')
    from agent_client import load_agent_config, FatalAgentError
    try:
        load_agent_config()
    except (FatalAgentError, OSError, ValueError):
        raise ValueError('Live Lab requires a configured, paired Slave Agent') from None
    return dict(p11_live_lab=True, **options)


def bounded_post(payload, timeout, stop):
    """A disposable child bounds DNS, TLS and response reading as well as connect."""
    from agent_client import RetryableAgentError, FatalAgentError
    with subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--once'],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
        child.stdin.write(json.dumps(payload).encode())
        child.stdin.close()
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if stop.wait(min(.1, max(0, deadline - time.monotonic()))) or time.monotonic() >= deadline:
                child.kill()
                child.wait()
                raise RetryableAgentError('Beacon interrupted or timed out')
        if child.returncode:
            raise (RetryableAgentError if child.returncode == 1 else FatalAgentError)('Beacon unavailable')
        return json.loads(child.stdout.read(4097))


def run_loop(config, campaign, options, *, post=bounded_post, stop=None,
             clock=time.monotonic, stamp=None, record=lambda event, **fields: None):
    from agent_client import RetryableAgentError, FatalAgentError
    stop = stop if stop is not None else threading.Event()
    stamp = stamp or (lambda: datetime.now(timezone.utc).isoformat())
    start = clock()
    attempts = acknowledged = 0
    reason = 'count_limit'
    record('P11_BEACON_START', agent_id=config.agent_id, origin='slave_agent', **options)
    while attempts < options['beacon_count']:
        remaining = options['beacon_duration'] - (clock() - start)
        if stop.is_set() or remaining <= 0:
            reason = 'stopped' if stop.is_set() else 'duration_limit'
            break
        attempts += 1
        payload = dict(campaign_id=campaign, phase='P11', synthetic=True,
                       timestamp=stamp(), sequence=attempts, marker=MARKER)
        try:
            ack = post(payload, min(10, remaining), stop)
            acknowledged += 1
            record('P11_BEACON_ACK', agent_id=config.agent_id, sequence=attempts,
                   event_id=ack['event_id'], received_at=ack['received_at'], verified=True)
        except RetryableAgentError:
            record('P11_BEACON_RETRY', sequence=attempts, reason='network_or_master_unavailable')
        except FatalAgentError:
            reason = 'fatal_protocol_auth_or_tls_error'
            break
        if attempts < options['beacon_count']:
            # Start-to-start cadence, no catch-up burst and no immediate replay.
            wait = min(options['beacon_interval'], max(0, options['beacon_duration'] - (clock() - start)))
            wait = min(wait, max(0, start + attempts * options['beacon_interval'] - clock()))
            if stop.wait(wait):
                reason = 'stopped'
                break
    if stop.is_set():
        reason = 'stopped'
    record('P11_BEACON_STOP', attempts=attempts, acknowledged=acknowledged,
           failed=attempts-acknowledged, reason=reason)
    return 0 if acknowledged and reason != 'stopped' and not reason.startswith('fatal') else 1


def run(env):
    from agent_client import load_agent_config
    from windows_actions import emit
    options = settings(json.loads(env['MRNOBODY_P11_LIVE_CONFIG']))
    if (options is None or env.get('MRNOBODY_RUN_MODE') not in {'standalone', 'campaign'}
            or env.get('MRNOBODY_ACTION', '') not in {'', 'create'}):
        raise ValueError('Explicit Create Live Lab required')
    config = load_agent_config()
    stop = threading.Event()
    previous = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        return run_loop(config, env['NORDIC_INCIDENT_ID'], options, stop=stop,
            record=lambda event, **fields: emit(Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack')),
                                                env, '11', event, **fields))
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    # Internal worker accepts a fixed schema and only the configured Master URL.
    from agent_client import AgentTransport, load_agent_config, RetryableAgentError
    try:
        payload = json.loads(sys.stdin.buffer.read(4097))
        result = AgentTransport(load_agent_config()).post('p11-beacon', p11=payload)
        print(json.dumps(result))
    except RetryableAgentError:
        raise SystemExit(1)
    except Exception:
        raise SystemExit(2)
