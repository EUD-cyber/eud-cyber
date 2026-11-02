"""Bounded P15 profile registry and fingerprinted lab-only HTTP validation."""
import http.client
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlencode

from scenario_model import private
from windows_actions import emit

PROFILES = {
    'sqli': dict(name='Synthetic SQL injection', app='MrNobody Web Lab v1', method='GET',
                 endpoint='/search', query={'q': "' OR '1'='1"}, verification='MRN_SYNTHETIC_SQLI',
                 mitre='T1190', cleanup='none_read_only', establishes_access=False),
    'traversal': dict(name='Synthetic path traversal', app='MrNobody Web Lab v1', method='GET',
                      endpoint='/file', query={'name': '../synthetic-marker.txt'}, verification='MRN_SYNTHETIC_TRAVERSAL',
                      mitre='T1190,T1005', cleanup='none_read_only', establishes_access=False),
}


def configuration(env):
    profile = env.get('MRNOBODY_WEB_PROFILE') or 'sqli'
    path = env.get('MRNOBODY_WEB_PATH') or '/mrn-lab'
    if profile not in PROFILES or not re.fullmatch(r'/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', path) or len(path) > 120:
        raise ValueError('Choose a supported profile and simple absolute lab base path')
    return profile, path


def targets(env):
    if env.get('MRNOBODY_RUN_MODE') == 'standalone':
        rows = [dict(host=env.get('MRNOBODY_TARGET'), port=env.get('MRNOBODY_PORT') or 8088,
                     protocol=env.get('MRNOBODY_PROTOCOL') or 'http')]
    else:
        path = Path(env.get('NORDIC_WEB_STATE', Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack')) / 'state/web-targets.json'))
        if not path.exists(): return []
        data = json.loads(path.read_text())
        if data.get('incident_id') != env['NORDIC_INCIDENT_ID']: raise ValueError('Stale web inventory')
        rows = data.get('targets', [])
    result = []
    for row in rows[:64]:
        host = private(row.get('host') or row.get('ip'))
        protocol = row.get('protocol', 'http')
        port = row.get('port', 80)
        if protocol not in {'http', 'https'} or not str(port).isdigit() or not 1 <= int(port) <= 65535: continue
        if env.get('MRNOBODY_TARGET') and host != env['MRNOBODY_TARGET']: continue
        result.append(dict(target=host, port=int(port), protocol=protocol))
    return result


def request(target, path):
    # Numeric private IP only, no DNS, proxies, redirects, cookies or auth.
    host = private(target['target'])
    cls = http.client.HTTPSConnection if target['protocol'] == 'https' else http.client.HTTPConnection
    conn = cls(host, target['port'], timeout=3, **({'context': ssl.create_default_context()} if target['protocol'] == 'https' else {}))
    try:
        conn.request('GET', path, headers={'User-Agent': 'MrNobody-P15-lab', 'Connection': 'close'})
        response = conn.getresponse()
        body = response.read(4097)
        if len(body) > 4096: return response.status, None
        try: return response.status, json.loads(body)
        except (ValueError, UnicodeError): return response.status, None
    finally: conn.close()


def perform(target, env, send=request):
    profile, path = configuration(env)
    spec = PROFILES[profile]
    fields = dict(profile=profile, app=spec['app'], path=path, request_method='GET',
                  request_summary=spec['endpoint'], mitre=spec['mitre'], host_compromise_changed='false',
                  cleanup=spec['cleanup'])
    try: status, body = send(target, path + '/fingerprint')
    except (OSError, http.client.HTTPException):
        return dict(result='skipped', fingerprint='unavailable', warning='no_matching_lab_endpoint', **fields)
    if status != 200 or body != {'app': 'MrNobody Web Lab v1', 'synthetic': True}:
        return dict(result='skipped', fingerprint='mismatch', warning='NOT_APPLICABLE', **fields)
    fields['fingerprint'] = 'matched'
    try: status, body = send(target, path + spec['endpoint'] + '?' + urlencode(spec['query']))
    except (OSError, http.client.HTTPException):
        return dict(result='failed', warning='validation_request_failed_details_omitted', **fields)
    success = status == 200 and body == {'evidence': spec['verification'], 'synthetic': True}
    return dict(result='success' if success else 'failed', response_status=status,
                evidence_preview=spec['verification'] if success else 'response_content_omitted',
                warning='none' if success else 'validation_not_verified', **fields)


def run(env, send=request):
    base = Path(env.get('NORDIC_BASE_DIR', '/opt/nordic-attack'))
    emit(base, env, '15', 'PHASE_START', phase='15')
    outcomes = []
    try:
        configuration(env)
        for target in targets(env):
            emit(base, env, '15', 'WEB_ACTION_START', **target)
            result = perform(target, env, send)
            outcome = result.pop('result')
            outcomes.append(outcome)
            emit(base, env, '15', 'WEB_ACTION_' + {'success': 'SUCCESS', 'skipped': 'SKIPPED', 'failed': 'FAILED'}[outcome], **target, **result)
            if outcome == 'success': break
    except (OSError, ValueError, KeyError, TypeError):
        outcomes.append('failed')
        emit(base, env, '15', 'WEB_ACTION_FAILED', warning='invalid_runtime_configuration')
    status = 'PHASE_FAILED' if 'failed' in outcomes else 'PHASE_COMPLETE' if 'success' in outcomes else 'PHASE_SKIPPED'
    emit(base, env, '15', status, phase='15')
    return 1 if status == 'PHASE_FAILED' else 0 if status == 'PHASE_COMPLETE' else 78


if __name__ == '__main__':
    import os
    raise SystemExit(run(os.environ))
