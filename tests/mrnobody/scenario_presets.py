"""Preset contracts against the installed registry; runners are always mocked."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
import app as web
from scenario_model import (PRESETS, SECRET_FIELDS, catalogue, plan, preset_cards,
                            preset_definition, preset_requirements, validate)
from reports import build_report, read_metadata
from execution import project
from report_exports import report_document
CAPS = catalogue(BASE / 'scripts', read_metadata)


def configured(sid):
    value = preset_definition(sid, CAPS)
    for p in value['phases']:
        if value['target_mode'] == 'fixed':
            p['parameters'].update({'subnet': '192.168.1.0/24'} if p['id'] == '01' else {'target': '192.168.1.20'})
        if p['id'] == '18': p['parameters']['dns_endpoint'] = '192.168.1.53'
        if p['id'] == '15': p['parameters'].update(target='192.168.1.30', port=8088, protocol='http')
    return value


class Presets(unittest.TestCase):
    def test_all_registry_dependencies_schema_and_secrets(self):
        self.assertEqual(len(PRESETS), 9)
        for card in preset_cards(CAPS):
            with self.subTest(card=card['id']):
                template = preset_definition(card['id'], CAPS)
                self.assertEqual(validate(template, CAPS, template=True), template)
                self.assertEqual(validate(configured(card['id']), CAPS)['version'], 1)
                prior = set()
                for p in template['phases']:
                    self.assertTrue(set(CAPS[p['id']]['dependencies']) <= prior)
                    prior.add(p['id'])
                    self.assertFalse(set(p['parameters']) & SECRET_FIELDS)
                    self.assertNotIn('19', prior)
                self.assertEqual(card['phases'], [p['id'] for p in template['phases']])
                self.assertEqual(card['runnable'], not preset_requirements(template))
                self.assertTrue(template['teaching_objective'])

    def test_excluded_technique_not_referenced(self):
        marker = 'p' + '19'
        for path in [BASE/'web/scenario_model.py', BASE/'web/static/planning.js', ROOT/'docs/mrnobody-scenario-presets.md']:
            self.assertNotIn(marker, path.read_text(encoding='utf8').lower())
        self.assertFalse(any('19' in c['phases'] for c in preset_cards(CAPS)))

    def test_readiness_and_drift_fail_closed(self):
        for key in ('web-attack', 'c2-detection', 'windows-domain-compromise', 'full-attack-incident'):
            value = preset_definition('preset-' + key, CAPS)
            self.assertTrue(preset_requirements(value))
            with self.assertRaises(ValueError): validate(value, CAPS)
        windows = configured('preset-windows-domain-compromise'); windows['target_mode'] = 'auto'
        self.assertTrue(any('Fixed Targets' in x for x in preset_requirements(windows)))
        caps = copy.deepcopy(CAPS); del caps['17']
        with self.assertRaises(ValueError): preset_definition('preset-collection-exfiltration', caps)
        value = configured('preset-full-attack-incident'); value['phases'].reverse()
        with self.assertRaises(ValueError): validate(value, CAPS)
        self.assertIsNone(preset_definition('unknown', CAPS))

    def test_timing_and_coherent_flows(self):
        slow = plan(validate(configured('preset-slow-intrusion'), CAPS))
        self.assertEqual(slow['profile'], {'mode': 'slow', 'duration': 14400})
        offsets = [p['timing']['start_offset'] for p in slow['phases']]
        self.assertEqual(offsets, sorted(offsets)); self.assertGreater(offsets[-1], 13000)
        c2 = configured('preset-c2-detection')
        self.assertEqual([p['id'] for p in c2['phases']], ['01', '03', '14', '18'])
        self.assertEqual(c2['phases'][-1]['parameters']['dns_duration'], 60)
        self.assertEqual(c2['phases'][-2]['parameters']['beacon_count'], 5)
        for sid in ('collection-exfiltration', 'ransomware-style', 'full-attack-incident'):
            ids = [p['id'] for p in configured('preset-' + sid)['phases']]
            self.assertLess(ids.index('03'), ids.index('17'))
            self.assertLess(ids.index('17'), ids.index('05'))
            self.assertLess(ids.index('05'), ids.index('06'))
            if '07' in ids: self.assertLess(ids.index('06'), ids.index('07'))
        windows = configured('preset-windows-domain-compromise')
        self.assertEqual(windows['target_mode'], 'fixed')
        self.assertEqual([p['id'] for p in windows['phases']], ['01','03','09','11','12','13'])
        self.assertTrue(all(p['parameters']['protocol'] == 'winrm-http' for p in windows['phases'][2:]))


class API(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.addCleanup(patch.stopall)
        for key, value in {'BASE_DIR': self.base, 'STATE_DIR': self.base/'state', 'LOG_DIR': self.base/'logs',
                           'CAMPAIGN_LOG': self.base/'logs/campaign.log', 'SCENARIO_DIR': BASE/'scenarios',
                           'SCRIPT_DIR': BASE/'scripts', 'CONFIG_FILE': BASE/'config/defaults.conf',
                           'campaign_process': None}.items(): patch.object(web, key, value).start()
        patch.object(web, 'determine_incident_ip', return_value='192.168.1.254').start()
        self.launch = patch.object(web, 'launch', return_value=Mock(pid=123, poll=lambda: None)).start()
        self.client = web.app.test_client()

    def test_duplicate_edit_run_schedule_and_origin(self):
        cards = self.client.get('/api/scenarios').json['scenarios']
        self.assertEqual(sum(bool(c.get('preset')) for c in cards), 9)
        for key in PRESETS:
            sid = 'preset-' + key
            with self.subTest(sid=sid):
                self.assertEqual(self.client.get('/api/scenario-presets/' + sid).status_code, 200)
                self.assertEqual(self.client.put('/api/custom-scenarios/' + sid, json={}).status_code, 400)
                saved = self.client.post('/api/custom-scenarios', json=configured(sid))
                self.assertEqual(saved.status_code, 201, saved.json)
                value = saved.json; self.assertTrue(value['id'].startswith('custom-'))
                self.assertEqual(value['preset']['id'], sid)
                duplicate = self.client.post('/api/custom-scenarios', json=value).json
                self.assertNotEqual(duplicate['id'], value['id'])
                value['name'] += ' edited'
                self.assertEqual(self.client.put('/api/custom-scenarios/' + value['id'], json=value).status_code, 200)
                web.campaign_process = None
                response = self.client.post('/api/executions/run', json={'execution': {'type': 'custom', 'id': value['id']}, 'credentials': {'ssh_password': 'RUNTIME_ONLY', 'rdp_password': 'RUNTIME_ONLY'}})
                self.assertEqual(response.status_code, 200, response.json)
                env = self.launch.call_args.kwargs['env']; execution = json.loads(env['MRN_EXECUTION'])
                self.assertEqual(execution['preset']['id'], sid)
                self.assertNotIn('RUNTIME_ONLY', env['MRN_EXECUTION'])
                self.assertEqual(project(execution)['preset'], execution['preset'])
                self.assertEqual(project(execution)['version'], 1)
                scheduled = self.client.post('/api/schedules', json={'version': 1, 'execution': {'type':'custom','id':value['id']}, 'at':'2099-01-01T12:00:00Z', 'interval':0})
                self.assertEqual(scheduled.status_code, 201, scheduled.json)
                self.assertNotIn(b'RUNTIME_ONLY', web.planning.store.path.read_bytes())
                self.assertEqual(self.client.get('/api/scenario-presets/' + sid).json['name'], PRESETS[key][0])

    def test_unconfigured_save_and_direct_run_rejected(self):
        for key in ('web-attack', 'windows-domain-compromise', 'c2-detection', 'full-attack-incident'):
            sid = 'preset-' + key
            value = self.client.get('/api/scenario-presets/' + sid).json
            self.assertEqual(self.client.post('/api/custom-scenarios', json=value).status_code, 400)
            self.assertEqual(self.client.post('/api/scenario/' + sid + '/start', json={}).status_code, 400)
        self.launch.assert_not_called()
        result = self.client.post('/api/scenario/preset-recon-only/start', json={})
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(json.loads(self.launch.call_args.kwargs['env']['MRN_EXECUTION'])['phases'][0]['id'], '01')

    def test_report_metadata_exports_and_executed_summary(self):
        execution = plan(validate(configured('preset-full-attack-incident'), CAPS))
        execution['id'] = 'custom-' + 'a'*32
        iid = 'MRN-preset-test'
        (self.base/'state').mkdir(); (self.base/'scripts').mkdir()
        for script in (BASE/'scripts').glob('[0-9][0-9]-*.sh'):
            (self.base/'scripts'/script.name).write_bytes(script.read_bytes())
        campaign = {'incident_id':iid, 'scenario':execution['id'], 'scenario_name':execution['name'], 'execution':execution,
                    'status':'complete', 'phases':{p['id']: 'complete' if p['id'] in {'01','03'} else 'disabled' for p in execution['phases']}}
        (self.base/'state/campaign.json').write_text(json.dumps(campaign), encoding='utf8')
        report = build_report(self.base, iid, environ={'MRN_EXECUTION':json.dumps(execution)})
        self.assertEqual(report['execution'], execution)
        self.assertEqual([p['id'] for p in report['phases']][:len(execution['phases'])], [p['id'] for p in execution['phases']])
        self.assertTrue(all(set(t['phases']) <= {'01','03'} for t in report['mitre_summary']))
        for view in ('investigation','ground-truth'):
            rendered = str(report_document(report, view))
            self.assertIn('preset-full-attack-incident', rendered)
            self.assertIn('Scenario version: 1', rendered)
            self.assertIn('Ordered Attack Technique flow:', rendered)


if __name__ == '__main__': unittest.main()
