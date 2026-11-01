"""Planning API integrated with the existing Flask phase/scenario endpoints."""
import json
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path

from flask import jsonify, request
from reports import read_metadata
from scenario_model import catalogue, keys, plan, profile, validate
from scheduler import Scheduler, Store, timestamp


class BusyError(RuntimeError):
    pass


def launch(base, *args, **kwargs):
    """Keep one advisory lock inherited by the runner for its entire lifetime.

    A service restart cannot lose the lock while an old child is still alive.
    CLI runners use the same lock unless this inherited descriptor is present.
    """
    import fcntl
    directory = Path(base) / 'runtime'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle = (directory / 'execution.lock').open('a')
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BusyError('An execution is already running') from None
        env = dict(kwargs.pop('env', os.environ))
        env['MRN_LOCK_FD'] = str(handle.fileno())
        kwargs['pass_fds'] = (handle.fileno(),)
        process = subprocess.Popen(*args, env=env, **kwargs)
        if env.get('MRN_OVERVIEW'):
            from execution import record
            try:
                record(base, env, process.pid)
            except (OSError, ValueError, TypeError):
                # Display metadata failure must never orphan or stop a valid run.
                pass
        return process
    finally:
        handle.close()


class Planning:
    def __init__(self, module):
        self.m = module
        self._store = None
        self._scheduler = None

    @property
    def store(self):
        directory = self.m.BASE_DIR / 'data' / 'planning'
        if self._store is None or self._store.directory != directory:
            self._store = Store(directory)
            self._scheduler = Scheduler(self._store, self.dispatch, self.log, observe=lambda: self.m.campaign_process)
        return self._store

    @property
    def scheduler(self):
        self.store
        return self._scheduler

    def capabilities(self):
        return catalogue(self.m.SCRIPT_DIR, read_metadata)

    def custom(self, sid):
        return next((s for s in self.store.scenarios() if s['id'] == sid), None)

    def log(self, sid, status):
        self.m.LOG_DIR.mkdir(parents=True, exist_ok=True)
        with self.m.CAMPAIGN_LOG.open('a', encoding='utf-8') as handle:
            # Only internal IDs and fixed status messages; never input payloads.
            handle.write(f'[SCHEDULER] {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())} {sid} {status}\n')

    def execution(self, spec):
        keys(spec, ['type', 'id', 'profile', 'parameters', 'timing', 'target_mode'], 'execution')
        if spec.get('type') not in {'phase', 'campaign', 'custom'}:
            raise ValueError('Unknown execution type')
        if not isinstance(spec.get('id'), str):
            raise ValueError('Execution ID is required')
        p = profile(spec.get('profile', {}))
        spec = dict(spec)
        if 'profile' in spec or spec['type'] == 'phase':
            spec['profile'] = p
        if spec['type'] == 'phase':
            mode = spec.get('target_mode', 'fixed')
            definition = {'version': 1, 'name': 'Standalone', 'target_mode': mode, 'profile': p,
                          'phases': [{'id': spec['id'], 'parameters': spec.get('parameters', {}), 'timing': spec.get('timing', {})}]}
            # Standalone auto consumers intentionally use existing inventory.
            caps = self.capabilities()
            if not caps.get(spec['id'], {}).get('standalone'):
                raise ValueError('This phase does not support standalone execution')
            if mode == 'auto' and spec['id'] != '01':
                raise ValueError('Standalone phases require fixed targets')
            validate(definition, caps)
        elif spec['type'] == 'custom':
            definition = self.custom(spec['id'])
            if definition is None:
                raise ValueError('Custom scenario not found')
            if set(spec) & {'parameters', 'timing', 'target_mode'}:
                raise ValueError('Edit custom scenario phase configuration in the builder')
            if 'profile' in spec:
                validate(dict(definition, profile=p), self.capabilities())
        else:
            scenario = self.m.find_scenario(spec['id'])
            if scenario is None or self.custom(spec['id']):
                raise ValueError('Built-in scenario not found')
            if set(spec) & {'parameters', 'timing', 'target_mode'}:
                raise ValueError('Built-in campaigns do not accept phase overrides')
            if p['mode'] != 'normal' and spec['id'] != 'full-incident':
                raise ValueError('This campaign has no structured timing adapter')
            if p['mode'] == 'custom':
                raise ValueError('Use the Scenario Builder to configure phase timing for a campaign')
        return spec

    def definition(self, sid, data):
        definition = self.custom(sid)
        if definition is None and 'profile' in data:
            scenario = self.m.find_scenario(sid)
            if sid != 'full-incident':
                raise ValueError('This campaign has no structured timing adapter')
            ids = scenario['metadata'].get('SCENARIO_PHASES', '').split(',')
            definition = {'version': 1, 'name': scenario['metadata'].get('SCENARIO_NAME', sid),
                          'description': '', 'target_mode': 'auto', 'profile': data['profile'],
                          'phases': [{'id': p, 'enabled': p != '08' or str(data.get('wordlist_enabled', '0')).lower() in {'1', 'true'}, 'parameters': {}, 'timing': {}} for p in ids if p]}
        if definition is None:
            return None
        definition = dict(definition)
        if 'profile' in data:
            definition['profile'] = profile(data['profile'])
        definition = validate(definition, self.capabilities())
        return plan(dict(definition, id=sid))

    def dispatch(self, execution, credentials):
        execution = self.execution(execution)  # Revalidate at dispatch; capabilities may change.
        credentials = dict(credentials)
        keys(credentials, ['ssh_password', 'rdp_password', 'password', 'powershell'], 'credential')
        if credentials.get('powershell'):
            from windows_actions import runtime_command
            runtime_command(credentials['powershell'])
        if execution['type'] == 'phase':
            data = dict(execution.get('parameters', {}), profile=execution.get('profile', {'mode': 'normal'}),
                        timing=execution.get('timing', {}), target_mode=execution.get('target_mode', 'fixed'))
            protocol = data.get('protocol', 'winrm-http' if execution['id'] in {'09', '10'} else 'ssh')
            data['password'] = credentials.get('password') or credentials.get('rdp_password' if protocol.startswith(('rdp', 'winrm')) else 'ssh_password') or os.environ.get('NORDIC_RDP_PASSWORD' if protocol.startswith(('rdp', 'winrm')) else 'NORDIC_SSH_PASSWORD', '')
            cap = self.capabilities()[execution['id']]
            if cap.get('wordlist') and not os.environ.get('NORDIC_WORDLIST_FILE'):
                return 'needs credentials: supply service wordlist input'
            if cap['credentials'] and not data['password']:
                return 'needs credentials: supply execution-time credentials'
            url = f'/api/phase/{execution["id"]}/run'
            call = lambda: self.m.api_run_phase(execution['id'])
        else:
            data = {k: credentials.get(k) or os.environ.get('NORDIC_' + k.upper(), '') for k in ('ssh_password', 'rdp_password')}
            if 'profile' in execution:
                data['profile'] = execution['profile']
            definition = self.custom(execution['id'])
            if definition and any(p['id'] == '08' and p.get('enabled', True) for p in definition['phases']):
                data['wordlist_enabled'] = '1'
                data['wordlist_users'] = os.environ.get('NORDIC_WORDLIST_USERS', 'ubuntu,Administrator')
            url = f'/api/scenario/{execution["id"]}/start'
            call = lambda: self.m.api_start(execution['id'])
        if credentials.get('powershell'):
            data['powershell'] = credentials['powershell']
        with self.m.app.test_request_context(url, method='POST', json=data):
            response = call()
        if isinstance(response, tuple):
            _, code = response
        else:
            code = response.status_code
        return 'started' if code < 300 else 'skipped: execution already running' if code == 409 else 'needs credentials or invalid execution configuration' if code == 400 else 'failed: runner rejected execution'

    def start(self):
        self.scheduler.start()


def install(module):
    service = Planning(module)
    app = module.app

    def guarded(fn):
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (ValueError, TypeError, KeyError) as exc:
                return jsonify({'status': 'error', 'message': str(exc)}), 400
        wrapper.__name__ = fn.__name__
        return wrapper

    @app.route('/api/planning/capabilities')
    def planning_capabilities():
        return jsonify({'version': 1, 'phases': list(service.capabilities().values())})

    @app.route('/api/custom-scenarios', methods=['GET', 'POST'])
    @guarded
    def custom_scenarios():
        if request.method == 'GET':
            return jsonify({'scenarios': service.store.scenarios()})
        definition = validate(request.get_json(), service.capabilities())
        definition.pop('id', None)
        return jsonify(service.store.save_scenario(definition)), 201

    @app.route('/api/custom-scenarios/<sid>', methods=['PUT', 'DELETE'])
    @guarded
    def custom_scenario(sid):
        if service.custom(sid) is None:
            raise ValueError('Custom scenario not found; built-ins are protected')
        if request.method == 'DELETE':
            service.store.delete_scenario(sid)
            return jsonify({'status': 'deleted'})
        definition = validate(dict(request.get_json(), id=sid), service.capabilities())
        return jsonify(service.store.save_scenario(definition))

    @app.route('/api/executions/run', methods=['POST'])
    @guarded
    def execute_now():
        data = request.get_json()
        keys(data, ['execution', 'credentials'], 'run')
        execution = service.execution(data['execution'])
        status = service.dispatch(execution, data.get('credentials', {}))
        return jsonify({'status': status}), 200 if status == 'started' else 409 if status.startswith('skipped:') else 400

    @app.route('/api/schedules', methods=['GET', 'POST'])
    @app.route('/api/schedules/<sid>', methods=['PUT', 'DELETE'])
    @guarded
    def schedules(sid=None):
        if request.method == 'GET':
            rows = service.store.schedules()
            for row in rows:
                row['credentials_ready'] = row['id'] in service.scheduler.credentials or bool(os.environ.get('NORDIC_SSH_PASSWORD') or os.environ.get('NORDIC_RDP_PASSWORD'))
            return jsonify({'schedules': rows})
        if sid and not any(s['id'] == sid for s in service.store.schedules()):
            raise ValueError('Schedule not found')
        if request.method == 'DELETE':
            service.store.update(sid, delete=True)
            service.scheduler.credentials.pop(sid, None)
            return jsonify({'status': 'deleted'})
        value = request.get_json()
        keys(value, ['version', 'execution', 'at', 'interval', 'enabled'], 'schedule')
        if value.get('version') != 1:
            raise ValueError('Unsupported schedule version')
        value['execution'] = service.execution(value['execution'])
        timestamp(value['at'])
        interval = value.get('interval', 0)
        if type(interval) is not int or interval != 0 and not 60 <= interval <= 31536000:
            raise ValueError('Recurrence must be 60–31536000 seconds, or zero for Run Once')
        if type(value.get('enabled', True)) is not bool:
            raise ValueError('Enabled must be boolean')
        result = service.store.save_schedule(value, sid)
        # Editing invalidates any in-memory secret lease for the old execution.
        service.scheduler.credentials.pop(result, None)
        return jsonify({'id': result}), 200 if sid else 201

    @app.route('/api/schedules/<sid>/<action>', methods=['POST'])
    @guarded
    def schedule_action(sid, action):
        definition = next((s for s in service.store.schedules() if s['id'] == sid), None)
        if definition is None:
            raise ValueError('Schedule not found')
        if action in {'enable', 'disable'}:
            service.store.update(sid, enabled=action == 'enable')
            return jsonify({'status': action})
        data = request.get_json(silent=True) or {}
        keys(data, ['ssh_password', 'rdp_password', 'password', 'powershell'], 'credential')
        if not all(isinstance(v, str) and len(v) <= (16384 if k == 'powershell' else 4096) for k, v in data.items()):
            raise ValueError('Invalid credential input')
        if 'powershell' in data and data['powershell']:
            from windows_actions import runtime_command
            runtime_command(data['powershell'])
        if action == 'arm':
            service.scheduler.credentials[sid] = data
            return jsonify({'status': 'credentials held until service restart or schedule edit/delete'})
        if action == 'run':
            status = service.scheduler.run(sid, definition, data)
            return jsonify({'status': status}), 200 if status == 'started' else 409 if status.startswith('skipped:') else 400
        raise ValueError('Unsupported schedule action')

    return service
