"""Offline retirement, credential denial, retention and browser authority boundaries."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

from flask import Flask

WEB = Path(__file__).resolve().parents[2] / 'TESTFILES/ATTACKER-V2/web'
sys.path.insert(0, str(WEB))
from master_registry import Registry, Conflict, Unauthorized, OFFLINE_AFTER
from master_jobs import Jobs
from master_api import install_master_api
from master_admin import install_admin_auth, PREFIX


class RemovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = 1000
        self.store = Jobs(Path(self.tmp.name) / 'registry.sqlite3', clock=lambda: self.now)
        self.token = self.store.issue('old-agent')
        self.store.register('old-agent', self.token, 'OldSlave')
        self.other = self.store.issue('other-agent')
        self.store.register('other-agent', self.other, 'OtherSlave')

    def offline(self):
        self.now += OFFLINE_AFTER + 1

    def remove(self):
        return self.store.remove('old-agent', 'old-agent')

    def rows(self, table):
        with self.store._db() as db:
            return [tuple(row) for row in db.execute('SELECT * FROM ' + table)]

    def test_only_exact_confirmation_of_offline_registered_identity(self):
        for confirmation in (None, '', 'other-agent', 'old-agent ', ['old-agent']):
            with self.assertRaises(ValueError):
                self.store.remove('old-agent', confirmation)
        with self.assertRaises(Conflict):
            self.remove()
        self.now += OFFLINE_AFTER
        with self.assertRaises(Conflict):
            self.remove()
        self.store.issue('pending')
        self.offline()
        with self.assertRaises(Conflict):
            self.store.remove('pending', 'pending')
        with self.assertRaises(ValueError):
            self.store.remove('missing', 'missing')
        self.store.revoke('other-agent')
        with self.assertRaises(Conflict):
            self.store.remove('other-agent', 'other-agent')
        self.assertTrue(self.remove()['removed'])

    def test_all_active_job_states_block_without_mutating_any_jobs(self):
        job = self.store.enqueue('old-agent', 'request-1')
        self.offline()
        for state in ('queued', 'delivered', 'running', 'future_unknown_state'):
            with self.store._db(write=True) as db:
                db.execute('UPDATE execution_jobs SET status=?, deadline=0', (state,))
            before = self.rows('execution_jobs')
            with self.assertRaises(Conflict):
                self.remove()
            self.assertEqual(self.rows('execution_jobs'), before)
        with self.store._db(write=True) as db:
            db.execute("UPDATE execution_jobs SET status='stopped'")
        self.remove()
        self.assertEqual(self.rows('execution_jobs')[0][0], job['job_id'])

    def test_history_and_other_agent_are_unchanged_and_reports_remain_readable(self):
        job = self.store.enqueue('old-agent', 'finished-job')
        with self.store._db(write=True) as db:
            db.execute("UPDATE execution_jobs SET status='succeeded'")
        event = dict(protocol_version=1, agent_id='old-agent', campaign_id='MRN-history',
                     event_type='beacon', timestamp='2026-11-28T12:00:00Z', bytes=1, synthetic=True)
        self.store.receive_event(event, self.token, p11=1)
        self.store.receive_event(dict(event, event_type='exfil'), self.token, p06=b'synthetic-history')
        inventory = [dict(id='MRN-history', status='complete', report_type='campaign',
                          phase_id=None, started=None, completed=None)]
        self.store.sync_reports('old-agent', self.token, inventory)
        # Store a known snapshot without depending on unrelated report sanitization.
        with self.store._db(write=True) as db:
            self.store._report_table(db)
            db.execute('INSERT INTO report_content VALUES(?,?,?,?,?)',
                       ('old-agent', 'MRN-history', '{}', '{"incident":{"id":"MRN-history"}}', 'digest'))
        self.offline()
        self.store.heartbeat('other-agent', self.other)
        self.store.enqueue('other-agent', 'other-active-job')
        tables = ('execution_jobs', 'receiver_events', 'p11_receipts', 'p06_receipts', 'report_inventory', 'report_content')
        before = {table: self.rows(table) for table in tables}
        other = next(row for row in self.rows('agents') if row[0] == 'other-agent')
        first = self.remove()
        for table in tables:
            self.assertEqual(self.rows(table), before[table])
        self.assertEqual(next(row for row in self.rows('agents') if row[0] == 'other-agent'), other)
        self.assertEqual([a['agent_id'] for a in self.store.list_agents()], ['other-agent'])
        archived = next(a for a in self.store.list_agents(include_removed=True) if a['status'] == 'removed')
        self.assertEqual(archived['name'], 'OldSlave')
        self.assertEqual(archived['removal']['actor'], 'master-operator')
        self.assertEqual(archived['available_reports'], ['MRN-history'])
        self.assertEqual(self.store.read_report('old-agent', 'MRN-history')['sha256'], 'digest')
        self.assertEqual(len(self.store.list_receiver_events(agent_id='old-agent')['events']), 2)
        self.assertEqual(self.rows('execution_jobs')[0][0], job['job_id'])
        restarted = Registry(self.store.path, clock=lambda: self.now)
        self.assertEqual(restarted.remove('old-agent', 'old-agent'), first)
        self.assertEqual(len(self.rows('agent_removals')), 1)
        self.assertEqual(restarted.list_agents(), self.store.list_agents())
        self.assertNotIn('token_hash', json.dumps(archived))

    def test_credentials_cannot_return_or_reenroll_in_lab_mode(self):
        self.offline()
        self.remove()
        for operation in (
            lambda: self.store.heartbeat('old-agent', self.token),
            lambda: self.store.register('old-agent', self.token, 'OldSlave'),
            lambda: self.store.register('old-agent', self.token, 'OldSlave', enroll=True),
            lambda: self.store.register('old-agent', 'z'*43, 'OldSlave', enroll=True),
            lambda: self.store.sync_reports('old-agent', self.token, []),
            lambda: self.store.transfer_report('old-agent', self.token),
            lambda: self.store.exchange('old-agent', self.token, None),
            lambda: self.store.receive_event(dict(protocol_version=1, agent_id='old-agent', campaign_id='MRN-old',
                event_type='beacon', timestamp='2026-11-28T12:00:00Z', bytes=0, synthetic=True), self.token),
        ):
            with self.assertRaises(Unauthorized):
                operation()
        with self.assertRaises(Conflict):
            self.store.issue('old-agent')
        with self.assertRaises(Conflict):
            self.store.enqueue('old-agent', 'new-job')
        self.assertEqual(next(row for row in self.rows('agents') if row[0] == 'old-agent')[1], '')
        self.store.heartbeat('other-agent', self.other)

    def test_transaction_rolls_back_audit_and_revocation_together(self):
        self.offline()
        with self.store._db(write=True) as db:
            db.execute("""CREATE TRIGGER refuse_removal BEFORE UPDATE ON agents
                          BEGIN SELECT RAISE(ABORT, 'fixture failure'); END""")
        before = self.rows('agents')
        with self.assertRaises(sqlite3.Error):
            self.remove()
        self.assertEqual(self.rows('agents'), before)
        with self.store._db() as db:
            self.assertEqual(self.store._removed(db), {})

    def test_heartbeat_race_cannot_resurrect_a_removed_agent(self):
        self.offline()
        results = []
        barrier = threading.Barrier(2)
        def run(operation):
            barrier.wait()
            try:
                operation()
                results.append('ok')
            except (Conflict, Unauthorized) as error:
                results.append(type(error).__name__)
        threads = [threading.Thread(target=run, args=(operation,)) for operation in
                   (self.remove, lambda: self.store.heartbeat('old-agent', self.token))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(results.count('ok'), 1)
        self.assertEqual(len(results), 2)
        if 'Unauthorized' in results:
            self.assertEqual([a['agent_id'] for a in self.store.list_agents()], ['other-agent'])
        else:
            self.assertEqual(self.store.list_agents()[0]['status'], 'online')


class RemovalAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Registry(Path(self.tmp.name) / 'registry.sqlite3', clock=lambda: 1000)
        self.token = self.store.issue('old-agent')
        self.store.register('old-agent', self.token, 'OldSlave')
        self.secret = 'a'*43
        self.config = types.SimpleNamespace(role='master', config_status='loaded', lab_http=True, lab_mode=False)
        self.loader = patch('master_admin.load_credential', return_value=dict(version=1,
            origin='https://master.lab', sha256=hashlib.sha256(self.secret.encode()).hexdigest()))
        self.loader.start()
        self.addCleanup(self.loader.stop)
        self.app = Flask(__name__)
        install_master_api(self.app, lambda: self.config, registry_path=self.store.path)
        install_admin_auth(self.app, lambda: self.config, registry_path=self.store.path)
        self.client = self.app.test_client()
        self.url = PREFIX + '/agents/old-agent/remove'

    def login(self):
        return self.client.post(PREFIX + '/session', base_url='https://master.lab',
            headers={'Origin': 'https://master.lab'}, json={'credential': self.secret}).json['csrf']

    def remove(self, csrf='', body=None, origin='https://master.lab'):
        return self.client.post(self.url, base_url='https://master.lab',
            headers={'Origin': origin, 'X-CSRF-Token': csrf},
            json={'confirm_agent_id': 'old-agent'} if body is None else body)

    def test_protected_operator_auth_and_csrf_unchanged(self):
        self.assertEqual(self.remove().status_code, 401)
        result = self.client.post(self.url, base_url='https://master.lab',
            headers={'Authorization': 'Bearer '+self.token}, json={'confirm_agent_id': 'old-agent'})
        self.assertEqual(result.status_code, 401)
        csrf = self.login()
        self.assertEqual(self.remove().status_code, 403)
        self.assertEqual(self.remove(csrf, origin='https://evil.lab').status_code, 403)
        self.assertEqual(self.remove(csrf, {'confirm_agent_id': 'other'}).status_code, 400)
        self.assertEqual(self.remove(csrf, {'confirm_agent_id': 'old-agent', 'actor': 'root'}).status_code, 400)
        response = self.remove(csrf)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.remove(csrf).json, response.json)
        archive = self.client.get(PREFIX+'/removed-agents', base_url='https://master.lab')
        self.assertEqual(archive.json['agents'][0]['status'], 'removed')
        self.assertNotIn('token_hash', archive.get_data(as_text=True))
        self.assertEqual(self.client.get('/api/master/agents', base_url='https://master.lab').json['agents'], [])
        for suffix in ('heartbeat', 'register', 'job-poll', 'reports', 'report-transfer'):
            body = dict(agent_id='old-agent', protocol_version=1)
            if suffix == 'register': body['name'] = 'OldSlave'
            if suffix == 'reports': body['reports'] = []
            if suffix == 'job-poll': body['report'] = None
            if suffix == 'report-transfer': body.update(report_id=None, content=None)
            result = self.client.post('/api/master/agents/'+suffix, base_url='https://master.lab',
                headers={'Authorization': 'Bearer '+self.token}, json=body)
            self.assertEqual(result.status_code, 401, (suffix, result.json))

    def test_strict_payload_and_roles(self):
        csrf = self.login()
        for raw in ('[]', '{', '{"confirm_agent_id":"old-agent","confirm_agent_id":"old-agent"}', 'x'*1025):
            result = self.client.post(self.url, base_url='https://master.lab', data=raw,
                content_type='application/json', headers={'Origin':'https://master.lab', 'X-CSRF-Token':csrf})
            self.assertEqual(result.status_code, 400)
        self.assertEqual(self.client.post(self.url+'?extra=1', base_url='https://master.lab',
            json={'confirm_agent_id':'old-agent'}, headers={'Origin':'https://master.lab','X-CSRF-Token':csrf}).status_code, 400)
        for role in ('agent', 'standalone'):
            self.config.role = role
            self.assertEqual(self.remove(csrf).status_code, 404)
        self.config.role = 'master'
        self.config.config_status = 'invalid'
        self.assertEqual(self.remove(csrf).status_code, 503)
        self.assertEqual(len(self.store.list_agents()), 1)

    def test_server_rechecks_online_and_jobs(self):
        csrf = self.login()
        current = Registry(self.store.path)
        current.heartbeat('old-agent', self.token)
        self.assertEqual(self.remove(csrf).status_code, 409)
        jobs = Jobs(self.store.path)
        jobs.enqueue('old-agent', 'active')
        with self.store._db(write=True) as db:
            db.execute('UPDATE agents SET last_seen_at=1000')
        self.assertEqual(self.remove(csrf).status_code, 409)
        self.assertEqual(len(self.store.list_agents()), 1)

    def test_explicit_lab_mode_keeps_its_existing_csrf_boundary(self):
        self.config.lab_mode = True
        session = self.client.get(PREFIX+'/session', base_url='http://master.lab')
        csrf = session.json['csrf']
        def call(headers):
            return self.client.post(self.url, base_url='http://master.lab',
                headers=headers, json={'confirm_agent_id':'old-agent'})
        self.assertEqual(call({}).status_code, 403)
        self.assertEqual(call({'Origin':'http://evil.lab','X-CSRF-Token':csrf}).status_code, 403)
        self.assertEqual(call({'Origin':'http://master.lab','X-CSRF-Token':csrf,'Sec-Fetch-Site':'cross-site'}).status_code, 403)
        self.assertEqual(call({'Origin':'http://master.lab','X-CSRF-Token':csrf}).status_code, 200)
        archived = self.store.list_agents(include_removed=True)[0]
        self.assertEqual(archived['removal']['actor'], 'lab-operator')
        result = self.client.post('/api/master/agents/register', base_url='http://master.lab',
            headers={'Authorization':'Bearer '+self.token}, json=dict(protocol_version=1, agent_id='old-agent', name='OldSlave'))
        self.assertEqual(result.status_code, 401)

    def test_distribution_hashes_and_fresh_install_downloads(self):
        base = WEB.parent
        manifest = dict(line.split('|', 1)[::-1] for line in
                        (base/'update-manifest.txt').read_text().splitlines() if line and not line.startswith('#'))
        userdata = (WEB.parents[2]/'MRNOBODY/mrnobody_userdata.yaml').read_text()
        for relative in ('web/master_registry.py', 'web/master_admin.py', 'web/static/app.js', 'docs/agent-removal.md'):
            self.assertEqual(manifest[relative], hashlib.sha256((base/relative).read_bytes()).hexdigest())
            self.assertIn('"'+relative+'"', userdata)
        self.assertFalse(any('registry.sqlite3' in path or 'credential.json' in path for path in manifest))


if __name__ == '__main__':
    unittest.main()
