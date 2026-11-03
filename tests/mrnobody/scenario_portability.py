"""Offline portability contracts. All execution is mocked; no VM is contacted."""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from scenario_presets import API as Fixture, CAPS, configured, web, BASE
from scenario_model import (VERSION, MAX_SCENARIO_BYTES, import_scenario,
                            export_scenario, migrate_scenario, validate)
from execution import project
from reports import build_report


def definition():
    return {'version': VERSION, 'name': 'Portable Lab', 'description': 'Teaching exercise',
            'teaching_objective': 'Correlate discovery and service telemetry',
            'target_mode': 'auto', 'profile': {'mode': 'normal', 'duration': 0},
            'phases': [{'id': p, 'enabled': True, 'parameters': {}, 'timing': {}}
                       for p in ['01', '02']]}


class Portability(unittest.TestCase):
    setUp = Fixture.setUp

    def upload(self, value):
        return self.client.post('/api/custom-scenarios/import', data=json.dumps(value), content_type='application/json')

    def test_export_import_round_trip_and_identity(self):
        original = self.client.post('/api/custom-scenarios', json=definition()).json
        response = self.client.get(f'/api/custom-scenarios/{original["id"]}/export')
        self.assertEqual(response.status_code, 200)
        self.assertIn('mrnobody-scenario-portable-lab-v1.json', response.headers['Content-Disposition'])
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.json, original)
        result = self.upload(response.json)
        self.assertEqual(result.status_code, 201, result.json)
        imported = result.json['scenario']
        self.assertNotEqual(imported['id'], original['id'])
        self.assertEqual({k:v for k,v in imported.items() if k != 'id'}, {k:v for k,v in original.items() if k != 'id'})
        self.assertEqual(result.json['readiness'], 'Compatible · Ready')
        self.assertEqual(len(web.planning.store.scenarios()), 2)
        self.assertEqual(web.planning.store.schedules(), [])
        self.launch.assert_not_called()

    def test_slow_custom_timing_and_disabled_round_trip(self):
        for mode in ('slow', 'custom'):
            value = definition(); value['profile'] = {'mode': mode, 'duration': 7200}
            value['phases'].append({'id': '03', 'enabled': False, 'parameters': {}, 'timing': {}})
            if mode == 'custom':
                value['phases'][0]['timing'] = {'start_offset': 30, 'duration': 300, 'delay_min': 2, 'delay_max': 5, 'jitter': .2}
            expected = validate(value, CAPS)
            raw, _ = export_scenario(expected, CAPS)
            actual, notes, _ = import_scenario(raw, CAPS)
            self.assertEqual(actual, expected); self.assertEqual(notes, [])

    def test_p10_dual_platform_configuration_and_no_commands(self):
        for platform, protocol in [('linux', 'ssh'), ('windows', 'winrm-https'), ('auto', None)]:
            value = definition(); value['target_mode'] = 'fixed'
            params = {'target': '192.168.1.20', 'platform': platform, 'timeout': 120}
            if protocol: params['protocol'] = protocol
            else: params['protocol'] = 'ssh'
            value['phases'] = [{'id': '10', 'parameters': params, 'timing': {}}]
            raw, _ = export_scenario(value, CAPS)
            actual, _, _ = import_scenario(raw, CAPS)
            self.assertEqual(actual['phases'][0]['parameters'], params)
            for field in ('bash', 'powershell_windows', 'powershell'):
                dirty = copy.deepcopy(value); dirty['phases'][0]['parameters'][field] = 'runtime only'
                self.assertEqual(self.upload(dirty).status_code, 400)

    def test_duplicate_preset_and_custom(self):
        preset = configured('preset-recon-only')
        saved = self.client.post('/api/custom-scenarios', json=preset).json
        self.assertTrue(saved['id'].startswith('custom-'))
        duplicate = copy.deepcopy(saved); duplicate['name'] += ' (copy)'
        clone = self.client.post('/api/custom-scenarios', json=duplicate).json
        self.assertNotEqual(clone['id'], saved['id']); self.assertNotEqual(clone['name'], saved['name'])
        self.assertEqual(self.client.get('/api/scenario-presets/preset-recon-only').json, preset)
        self.assertEqual(self.client.get('/api/custom-scenarios/preset-recon-only/export').status_code, 400)
        self.assertEqual(self.client.put('/api/custom-scenarios/preset-recon-only', json=preset).status_code, 400)

    def test_legacy_migration_is_deterministic_and_requires_review(self):
        for version in (None, 0):
            value = definition(); value.pop('version'); value.pop('profile')
            if version is not None: value['version'] = version
            before = copy.deepcopy(value)
            self.assertEqual(migrate_scenario(value), migrate_scenario(value))
            self.assertEqual(value, before)
            result = self.upload(value); self.assertEqual(result.status_code, 201, result.json)
            saved = result.json['scenario']; sid = saved['id']
            self.assertEqual(saved['version'], VERSION); self.assertTrue(saved['needs_review'])
            self.assertEqual(result.json['readiness'], 'Needs review'); self.assertTrue(result.json['notes'])
            run = {'execution': {'type': 'custom', 'id': sid}}
            self.assertEqual(self.client.post('/api/executions/run', json=run).status_code, 400)
            self.assertEqual(self.client.post('/api/scenario/' + sid + '/start', json={}).status_code, 400)
            schedule = {'version': 1, 'execution': run['execution'], 'at': '2099-01-01T12:00:00Z'}
            self.assertEqual(self.client.post('/api/schedules', json=schedule).status_code, 400)
            bypass = dict(saved, needs_review=False)
            self.assertTrue(self.client.put('/api/custom-scenarios/' + sid, json=bypass).json['needs_review'])
            self.assertEqual(self.client.post('/api/custom-scenarios/' + sid + '/review', json={}).status_code, 400)
            self.assertEqual(self.client.post('/api/custom-scenarios/' + sid + '/review', json={'acknowledged': True}).status_code, 200)
        self.assertEqual(web.planning.store.schedules(), [])
        self.launch.assert_not_called()

    def test_incompatible_and_invalid_imports_are_atomic(self):
        invalid = []
        for version in (2, -1, '1', True, 1.0):
            invalid.append(dict(definition(), version=version))
        for missing in ('name', 'phases', 'target_mode'):
            value = definition(); del value[missing]; invalid.append(value)
        for pid in ('19', '99', 'P19'):
            value = definition(); value['phases'].append({'id': pid, 'enabled': False})
            result = self.upload(value); self.assertEqual(result.status_code, 400)
            self.assertIn('Unknown or deferred Attack Technique', result.json['message'])
        value = definition(); value['phases'].reverse(); invalid.append(value)
        value = definition(); value['phases'].append({'id': '01'}); invalid.append(value)
        for target in ('8.8.8.8', '127.0.0.1', '169.254.1.1', '::1'):
            value = definition(); value['target_mode'] = 'fixed'; value['phases'] = [{'id': '02', 'parameters': {'target': target}}]; invalid.append(value)
        value = definition(); value['profile'] = {'mode': 'slow', 'duration': 10}; invalid.append(value)
        value = definition(); value['phases'][0]['timing'] = {'start_offset': 5}; invalid.append(value)
        value = definition(); value['schedule'] = {'enabled': True}; invalid.append(value)
        value = definition(); value['execution'] = {'run': True}; invalid.append(value)
        for value in invalid:
            self.assertEqual(self.upload(value).status_code, 400, value)
        self.assertEqual(web.planning.store.scenarios(), []); self.assertEqual(web.planning.store.schedules(), [])
        self.launch.assert_not_called()

    def test_malformed_duplicate_keys_depth_and_oversized_json(self):
        for raw in (b'{bad', b'[]', b'null', b'\xff', b'{"version":1,"version":1}', b'{"x":NaN}', b'{"x":Infinity}', b'[' * 2000):
            result = self.client.post('/api/custom-scenarios/import', data=raw, content_type='application/json')
            self.assertEqual(result.status_code, 400, raw[:50])
        value = definition(); value['description'] = {'x': {}}
        current = value['description']['x']
        for _ in range(20): current['x'] = {}; current = current['x']
        self.assertEqual(self.upload(value).status_code, 400)
        result = self.client.post('/api/custom-scenarios/import', data=b' ' * (MAX_SCENARIO_BYTES + 1), content_type='application/json')
        self.assertEqual(result.status_code, 413)
        self.assertEqual(web.planning.store.scenarios(), [])

    def test_secrets_and_commands_rejected_without_echo_or_export(self):
        for key in ('password', 'ssh_password', 'rdp_password', 'credentials', 'access_token', 'private_key', 'wordlist', 'wordlist_path', 'command', 'shell', 'cron'):
            value = definition(); value['phases'][0]['parameters'][key] = 'SENSITIVE_VALUE'
            result = self.upload(value); self.assertEqual(result.status_code, 400)
            self.assertNotIn('SENSITIVE_VALUE', result.get_data(as_text=True))
            with self.assertRaises(ValueError): export_scenario(value, CAPS)
        for secret in ('-----BEGIN RSA PRIVATE KEY-----', 'password=SENSITIVE_VALUE', 'Bearer SENSITIVE_VALUE', 'https://user:pass@example.test'):
            result = self.upload(dict(definition(), description=secret)); self.assertEqual(result.status_code, 400)
        self.assertEqual(web.planning.store.scenarios(), [])

    def test_import_incomplete_configuration_stays_non_executable(self):
        value = configured('preset-windows-domain-compromise'); value['phases'][1]['parameters'].pop('target')
        result = self.upload(value); self.assertEqual(result.status_code, 201, result.json)
        self.assertEqual(result.json['readiness'], 'Needs configuration')
        sid = result.json['scenario']['id']
        self.assertEqual(self.client.post('/api/scenario/' + sid + '/start', json={}).status_code, 400)
        self.launch.assert_not_called()

    def test_report_metadata_after_imported_execution(self):
        saved = self.upload(definition()).json['scenario']; sid = saved['id']
        result = self.client.post('/api/executions/run', json={'execution': {'type': 'custom', 'id': sid}})
        self.assertEqual(result.status_code, 200, result.json)
        execution = json.loads(self.launch.call_args.kwargs['env']['MRN_EXECUTION'])
        self.assertEqual((execution['id'], execution['name'], execution['version']), (sid, saved['name'], VERSION))
        self.assertEqual(project(execution)['version'], VERSION)
        (self.base/'state').mkdir(exist_ok=True)
        campaign = {'incident_id': 'MRN-import-test', 'scenario': sid, 'scenario_name': saved['name'],
                    'execution': execution, 'status': 'complete', 'phases': {'01': 'complete', '02': 'complete'}}
        (self.base/'state/campaign.json').write_text(json.dumps(campaign), encoding='utf8')
        report = build_report(self.base, 'MRN-import-test', environ={'MRN_EXECUTION': json.dumps(execution)})
        self.assertEqual(report['execution']['id'], sid)
        self.assertEqual(report['execution']['name'], saved['name'])
        self.assertEqual(report['execution']['version'], VERSION)


if __name__ == '__main__': unittest.main()
