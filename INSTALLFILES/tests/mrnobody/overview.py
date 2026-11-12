"""Execution projection fixtures only: no real phase payloads or network activity."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'TESTFILES/ATTACKER-V2/web'))
import app as web
from execution import project, record, snapshot
from scheduler import Scheduler, Store, current_schedule

IID = 'MRN-20261101-120000-test'
CAPS = {'01': {'name': 'Discovery'}, '03': {'name': 'Access'}, '07': {'name': 'Impact'}}


class Overview(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.meta = {'incident_id': IID, 'started': '2026-11-01T12:00:00+00:00',
                     'type': 'campaign', 'id': 'full-incident', 'name': 'Full Incident',
                     'profile': {'mode': 'normal', 'duration': 0}, 'phases': [{'id': '01'}, {'id': '03'}]}
        self.running = Mock(poll=Mock(return_value=None))

    def write(self, path, value):
        target = self.base / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value), encoding='utf-8')

    def state(self, **changes):
        self.write('runtime/execution-overview.json', self.meta)
        self.write('state/campaign.json', dict(incident_id=IID, status='running',
                   started='2026-11-01T12:00:01+00:00', phases={'01': 'complete', '03': 'running', '07': 'disabled'}, **changes))

    def test_idle_endpoint_is_read_only_and_rejects_writes(self):
        with patch.object(web, 'BASE_DIR', self.base), patch.object(web, 'campaign_process', None), patch.object(web.planning, 'capabilities', return_value=CAPS):
            before = list(self.base.rglob('*'))
            response = web.app.test_client().get('/api/execution-status')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['status'], 'idle')
            self.assertEqual(list(self.base.rglob('*')), before)
            self.assertEqual(web.app.test_client().post('/api/execution-status').status_code, 405)

    def test_selected_phase_progress_and_next(self):
        self.state()
        value = snapshot(self.base, CAPS, self.running)
        self.assertTrue(value['active'])
        self.assertEqual(value['current_phase']['id'], '03')
        self.assertEqual(value['progress'], {'complete': 1, 'total': 2, 'percent': 50, 'basis': 'phase states'})
        self.assertEqual([p['id'] for p in value['timeline']], ['01', '03'])
        self.meta['phases'].append({'id': '07'})
        self.write('runtime/execution-overview.json', self.meta)
        self.write('state/campaign.json', {'incident_id': IID, 'phases': {'01': 'running', '03': 'pending', '07': 'pending'}})
        self.assertEqual(snapshot(self.base, CAPS, self.running)['next_phase']['id'], '03')

    def test_profiles_scheduler_and_no_foreign_state(self):
        for mode in ('slow', 'custom'):
            self.meta.update(type='custom', id='custom-test', name='<script>scenario</script>',
                             trigger='scheduler', schedule_id='schedule-test',
                             profile={'mode': mode, 'duration': 3600},
                             phases=[{'id': '03', 'timing': {'start_offset': 600, 'duration': 120}}])
            self.write('runtime/execution-overview.json', self.meta)
            self.write('state/campaign.json', {'incident_id': 'MRN-other', 'phases': {'03': 'complete'}})
            value = snapshot(self.base, CAPS, self.running)
            self.assertEqual(value['execution']['profile']['mode'], mode)
            self.assertEqual(value['execution']['schedule_id'], 'schedule-test')
            self.assertEqual(value['planned_seconds'], 3600)
            self.assertEqual(value['timeline'][0]['start_offset'], 600)
            self.assertEqual(value['progress']['percent'], 0)

    def test_standalone_and_restart_liveness(self):
        self.meta.update(type='phase', id='03', phases=[{'id': '03'}], pid=1234, process_start='ticks')
        self.write('runtime/execution-overview.json', self.meta)
        self.assertEqual(snapshot(self.base, CAPS, self.running)['current_phase']['id'], '03')
        with patch('execution.process_identity', return_value='ticks'):
            self.assertTrue(snapshot(self.base, CAPS)['active'])
        with patch('execution.process_identity', return_value='other'):
            self.assertEqual(snapshot(self.base, CAPS)['status'], 'interrupted')

    def test_terminal_report_wins_and_retains_summary(self):
        self.state()
        for status in ('complete', 'failed', 'interrupted'):
            self.write('reports/' + IID + '.json', {'schema_version': 1,
                       'incident': {'id': IID, 'status': status, 'ended': '2026-11-01T12:10:00+00:00'},
                       'phases': [{'id': '01', 'status': 'success'}, {'id': '03', 'status': {'complete': 'success', 'failed': 'failure', 'interrupted': 'interrupted'}[status]}]})
            value = snapshot(self.base, CAPS, self.running)
            self.assertFalse(value['active'])
            self.assertEqual(value['status'], status)
            self.assertEqual(value['report_id'], IID)
            self.assertEqual(value['elapsed_seconds'], 600)
        (self.base / 'runtime/execution-overview.json').unlink()
        (self.base / 'state/campaign.json').unlink()
        self.assertEqual(snapshot(self.base, CAPS)['report_id'], IID)

    def test_exit_without_report_is_useful(self):
        self.state()
        for code, status in ((1, 'failed'), (143, 'interrupted'), (0, 'complete')):
            value = snapshot(self.base, CAPS, Mock(poll=Mock(return_value=code)))
            self.assertEqual(value['status'], status)
            self.assertFalse(value['active'])

    def test_secrets_commands_and_wordlists_never_enter_projection(self):
        self.meta.update(password='DO_NOT_SHOW', parameters={'password': 'DO_NOT_SHOW'}, wordlist='DO_NOT_SHOW',
                         phases=[{'id': '03', 'parameters': {'password': 'DO_NOT_SHOW'}, 'timing': {'duration': float('nan')}}])
        self.write('runtime/execution-overview.json', self.meta)
        log = self.base / 'logs/incident-ground-truth.log'
        log.parent.mkdir()
        log.write_text(f'2026-11-01 INCIDENT={IID} CAMPAIGN PHASE_START phase=03 password=DO_NOT_SHOW command=evil\n'
                       f'2026-11-01 INCIDENT=MRN-other CAMPAIGN PHASE_COMPLETE phase=01\n'
                       f'2026-11-01 INCIDENT={IID} RAW DO_NOT_SHOW\n')
        value = snapshot(self.base, CAPS, self.running)
        self.assertEqual(value['logs'], ['Phase Start · P03'])
        self.assertNotIn('DO_NOT_SHOW', json.dumps(value))
        self.assertNotIn('parameters', json.dumps(value))
        record(self.base, {'MRN_OVERVIEW': json.dumps(self.meta), 'NORDIC_INCIDENT_ID': IID}, 1234)
        self.assertNotIn('DO_NOT_SHOW', (self.base / 'runtime/execution-overview.json').read_text())

    def test_schedule_context_is_scoped_and_never_persisted_as_secret(self):
        store = Store(self.base / 'planning')
        sid = store.save_schedule({'version': 1, 'execution': {'type': 'campaign', 'id': 'full-incident'}, 'at': '2030-01-01T00:00:00+00:00'})
        seen = []
        scheduler = Scheduler(store, lambda execution, credentials: seen.append(current_schedule.get()) or 'started', lambda *args: None)
        scheduler.run(sid, store.schedules()[0])
        self.assertEqual(seen, [sid])
        self.assertIsNone(current_schedule.get())


if __name__ == '__main__':
    unittest.main()
