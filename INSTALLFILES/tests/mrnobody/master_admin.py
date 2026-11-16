"""Authentication prerequisite and explicit absence of web job authority."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from flask import Flask

WEB = Path(__file__).resolve().parents[2] / 'TESTFILES/ATTACKER-V2/web'
sys.path.insert(0, str(WEB))
from master_admin import install_admin_auth, load_credential, provision, COOKIE, PREFIX
from master_api import install_master_api
from master_jobs import Jobs


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.secret = 'a' * 43
        self.record = dict(version=1, origin='https://master.lab',
                           sha256=hashlib.sha256(self.secret.encode()).hexdigest())
        self.loader = patch('master_admin.load_credential', side_effect=lambda _: self.record)
        self.loader.start(); self.addCleanup(self.loader.stop)
        self.now = 1000
        self.config = types.SimpleNamespace(role='master', config_status='loaded', lab_http=True)
        self.app = Flask(__name__, template_folder=str(WEB / 'templates'))
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.store = Jobs(Path(self.tmp.name) / 'master/registry.sqlite3')
        self.agent_token = self.store.issue('agent-1')
        self.store.register('agent-1', self.agent_token, 'Slave')
        install_master_api(self.app, lambda: self.config, registry_path=self.store.path)
        install_admin_auth(self.app, lambda: self.config, clock=lambda: self.now, registry_path=self.store.path)
        @self.app.route('/api/update', methods=['POST'])
        def legacy_update():
            return {'protected': True}
        self.client = self.app.test_client()

    def call(self, method='GET', data=None, headers=None, base='https://master.lab'):
        options = dict(base_url=base, headers={'Origin': 'https://master.lab', **(headers or {})})
        if data is not None:
            options['json'] = data
        return self.client.open(PREFIX + '/session', method=method, **options)

    def login(self):
        return self.call('POST', {'credential': self.secret})

    def test_login_cookie_and_no_credential_disclosure(self):
        result = self.login()
        self.assertEqual(result.status_code, 200)
        for flag in ('Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=900'):
            self.assertIn(flag, result.headers['Set-Cookie'])
        self.assertNotIn(self.secret, result.get_data(as_text=True))
        self.assertEqual(result.headers['Cache-Control'], 'no-store')
        self.assertTrue(result.json['web_job_control'])
        self.assertEqual(self.call().status_code, 200)

    def test_anonymous_and_agent_credentials_rejected(self):
        self.assertEqual(self.call().status_code, 401)
        self.assertEqual(self.call(headers={'Authorization': 'Bearer ' + self.secret}).status_code, 401)
        self.assertEqual(self.call('POST', {'credential': 'b' * 43}).status_code, 401)

    def test_missing_credential_fails_closed_and_revokes_sessions(self):
        self.login()
        self.loader.stop()
        with patch('master_admin.load_credential', side_effect=OSError()):
            self.assertEqual(self.call().status_code, 503)
        self.loader.start()
        self.assertEqual(self.call().status_code, 401)

    def test_tls_required_even_in_http_lab_and_no_remote_header_trust(self):
        self.assertEqual(self.call('POST', {'credential': self.secret}, base='http://master.lab').status_code, 403)
        result = self.client.post(PREFIX + '/session', json={'credential': self.secret},
                base_url='http://master.lab', headers={'X-Forwarded-Proto': 'https'},
                environ_overrides={'REMOTE_ADDR': '10.1.2.3'})
        self.assertEqual(result.status_code, 403)
        # Actual nginx runs on loopback and sets the scheme itself.
        self.assertEqual(self.call('POST', {'credential': self.secret}, base='http://master.lab',
                headers={'X-Forwarded-Proto': 'https'}).status_code, 200)

    def test_origin_and_host_enforced_for_login(self):
        for source in ('https://evil.lab', 'null', ''):
            self.assertEqual(self.call('POST', {'credential': self.secret}, headers={'Origin': source}).status_code, 403)
        self.assertEqual(self.call('POST', {'credential': self.secret}, base='https://evil.lab').status_code, 403)

    def test_logout_csrf_and_replay(self):
        csrf = self.login().json['csrf']
        self.assertEqual(self.call('DELETE', {}).status_code, 403)
        self.assertEqual(self.call('DELETE', {}, headers={'X-CSRF-Token': 'wrong'}).status_code, 403)
        self.assertEqual(self.call('DELETE', {}, headers={'X-CSRF-Token': csrf, 'Origin': 'https://evil.lab'}).status_code, 403)
        self.assertEqual(self.call('DELETE', {}, headers={'X-CSRF-Token': csrf}).status_code, 200)
        self.assertEqual(self.call().status_code, 401)

    def test_expiry_and_rotation(self):
        self.login(); self.now += 900
        self.assertEqual(self.call().status_code, 401)
        self.login(); self.record['sha256'] = 'f' * 64
        self.assertEqual(self.call().status_code, 401)

    def test_restart_loses_sessions(self):
        self.login()
        new = Flask('new')
        install_admin_auth(new, lambda: self.config)
        other = new.test_client()
        other.set_cookie(COOKIE, self.client.get_cookie(COOKIE, domain='master.lab', path='/').value,
                         domain='master.lab', path='/')
        self.assertEqual(other.get(PREFIX + '/session', base_url='https://master.lab').status_code, 401)

    def test_global_rate_limit_cannot_be_bypassed_by_client_ip(self):
        for index in range(5):
            self.assertEqual(self.call('POST', {'credential': 'b' * 43}, headers={'X-Real-IP': str(index)}).status_code, 401)
        result = self.login()
        self.assertEqual(result.status_code, 429)
        self.assertEqual(result.headers['Retry-After'], '60')
        self.now += 60
        self.assertEqual(self.login().status_code, 200)

    def test_bounded_strict_requests(self):
        self.assertEqual(self.call('POST', {'credential': self.secret, 'extra': 1}).status_code, 401)
        self.assertEqual(self.call('POST', {'credential': 'b' * 1025}).status_code, 413)
        for raw in ('[]', '{"credential":"a","credential":"b"}', '{'):
            result = self.client.post(PREFIX + '/session', base_url='https://master.lab',
                    headers={'Origin': 'https://master.lab'}, data=raw, content_type='application/json')
            self.assertEqual(result.status_code, 400)
        self.assertEqual(self.call('POST', None).status_code, 415)
        self.assertEqual(self.client.get(PREFIX + '/session?token=secret', base_url='https://master.lab').status_code, 400)

    def test_role_and_configuration_gate(self):
        for role, status in (('slave', 'loaded'), ('master', 'invalid')):
            self.config.role, self.config.config_status = role, status
            expected = 503 if status == 'invalid' else 404
            self.assertEqual(self.login().status_code, expected)
            self.assertEqual(self.client.get('/master/admin').status_code, expected)

    def test_no_generic_job_routes_even_after_administrator_login(self):
        self.login()
        for path in ('/api/master/jobs', '/api/master/jobs/start', '/api/master/admin/jobs/stop'):
            self.assertIn(self.job_call(path=path, body={}).status_code, (404, 405))

    def test_login_page_has_csp_and_explicit_blocker(self):
        result = self.client.get('/master/admin', base_url='https://master.lab')
        self.assertEqual(result.status_code, 200)
        self.assertIn('Master P11 job control', result.get_data(as_text=True))
        self.assertIn("frame-ancestors 'none'", result.headers['Content-Security-Policy'])

    def job_call(self, method='POST', body=None, path=PREFIX + '/jobs', csrf=None):
        if csrf is None:
            result = self.call()
            csrf = result.json.get('csrf', '')
        return self.client.open(path, method=method, base_url='https://master.lab',
                headers={'Origin':'https://master.lab', 'X-CSRF-Token':csrf}, json=body)

    def test_anonymous_master_surface_and_agent_token_cannot_write_jobs(self):
        for path in (PREFIX + '/jobs', '/api/update', '/api/master/agents'):
            result = self.client.post(path, base_url='https://master.lab',
                    headers={'Authorization':'Bearer ' + self.agent_token}, json={})
            self.assertEqual(result.status_code, 401)
        self.assertEqual(self.store.history(), [])

    def test_existing_master_mutations_share_session_csrf_and_origin_boundary(self):
        csrf = self.login().json['csrf']
        self.assertEqual(self.client.post('/api/update', base_url='https://master.lab', json={}).status_code, 403)
        self.assertEqual(self.job_call(path='/api/update', body={}, csrf=csrf).status_code, 200)
        self.record['sha256'] = 'b' * 64
        self.assertEqual(self.job_call(path='/api/update', body={}, csrf=csrf).status_code, 401)

    def test_fixed_job_authorization_idempotence_status_and_confirmed_stop(self):
        self.login()
        body = {'agent_id':'agent-1', 'request_key':'web-test-1'}
        first = self.job_call(body=body)
        self.assertEqual(first.status_code, 200)
        job = first.json['job']; ident = job['job_id']
        self.assertEqual(self.job_call(body=body).json['job']['job_id'], ident)
        self.assertEqual(self.job_call(body={**body, 'request_key':'different'}).status_code, 409)
        self.assertEqual(self.job_call(method='GET', path=PREFIX + '/jobs/' + ident).json['job']['status'], 'queued')
        stop_path = PREFIX + '/jobs/' + ident + '/stop'
        self.assertEqual(self.job_call(path=stop_path, body={}).status_code, 400)
        self.assertEqual(self.job_call(path=stop_path, body={'confirm_job_id':'wrong'}).status_code, 400)
        self.assertEqual(self.store.inspect(ident)['status'], 'queued')
        self.assertEqual(self.job_call(path=stop_path, body={'confirm_job_id':ident}).json['job']['status'], 'stopped')
        self.now += 60
        self.assertEqual(self.job_call(path=stop_path, body={'confirm_job_id':ident}).json['job']['status'], 'stopped')
        history = self.job_call(method='GET').json['jobs']
        self.assertEqual(history[0]['job_id'], ident)
        raw = json.dumps(history)
        for secret in (self.secret, self.agent_token, 'credential_hash', 'request_key'):
            self.assertNotIn(secret, raw)

    def test_fixed_schema_offline_and_csrf_rejection(self):
        self.login()
        body = {'agent_id':'agent-1', 'request_key':'web-test-2'}
        self.assertEqual(self.job_call(body=body, csrf='bad').status_code, 403)
        self.assertEqual(self.job_call(body={**body, 'operation':'P01'}).status_code, 400)
        self.store.revoke('agent-1')
        self.assertEqual(self.job_call(body=body).status_code, 409)
        self.assertEqual(self.store.history(), [])

    def test_job_request_bound_and_job_write_rate(self):
        self.login()
        self.assertEqual(self.job_call(body={'payload':'a' * 1025}).status_code, 413)
        for number in range(6):
            self.assertEqual(self.job_call(body={'unexpected':number}).status_code, 400)
        self.assertEqual(self.job_call(body={}).status_code, 429)

    def test_real_application_master_boundary_covers_all_mutation_routes(self):
        import app as application
        self.config.public_status = lambda: {'role':'master', 'config_status':'loaded'}
        with patch.object(application, 'DEPLOYMENT_CONFIG', self.config), patch.object(application.subprocess, 'Popen', side_effect=AssertionError('No subprocess expected')):
            client = application.app.test_client()
            # Legacy execution, update and scheduling paths all fail before dispatch.
            for path in ('/api/update', '/api/executions/run', '/api/schedules', '/api/custom-scenarios/import', PREFIX + '/jobs'):
                self.assertEqual(client.post(path, base_url='https://master.lab', json={}).status_code, 401)
            self.assertEqual(client.get('/', base_url='https://master.lab').status_code, 302)
            self.assertEqual(client.get('/api/config', base_url='https://master.lab').status_code, 401)
            self.assertEqual(client.get('/api/health', base_url='https://master.lab').status_code, 200)
            csrf = client.post(PREFIX + '/session', base_url='https://master.lab',
                    headers={'Origin':'https://master.lab'}, json={'credential':self.secret}).json['csrf']
            result = client.get('/', base_url='https://master.lab')
            self.assertEqual(result.status_code, 200)
            self.assertIn('data-master-admin="true"', result.get_data(as_text=True))
            self.assertIn("script-src 'self'", result.headers['Content-Security-Policy'])
            self.assertEqual(client.post('/api/update', base_url='https://master.lab', json={}).status_code, 403)

    def test_agent_protocol_keeps_bound_token_auth_and_no_admin_session(self):
        data = {'agent_id':'agent-1', 'protocol_version':1, 'report':None}
        result = self.client.post('/api/master/agents/job-poll', base_url='https://master.lab',
                headers={'Authorization':'Bearer ' + self.agent_token}, json=data)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.client.post('/api/master/agents/job-poll', base_url='https://master.lab', json=data).status_code, 401)

    def test_agent_and_standalone_local_behavior_is_unchanged(self):
        for role in ('agent', 'standalone'):
            self.config.role = role
            self.assertEqual(self.client.post('/api/update', json={}).status_code, 200)
            self.assertEqual(self.client.post(PREFIX + '/jobs', json={}).status_code, 404)

    def test_history_is_bounded_newest_first_and_preserves_cli_jobs(self):
        for number in range(52):
            job = self.store.enqueue('agent-1', 'history-' + str(number))
            self.store.inspect(job['job_id'], stop=True)
        self.login()
        history = self.job_call(method='GET').json['jobs']
        self.assertEqual(len(history), 50)
        self.assertEqual(history[0]['job_id'], job['job_id'])
        self.assertTrue(all(row['status'] == 'stopped' for row in history))

    def test_distribution_includes_prerequisite_without_credentials(self):
        platform = WEB.parent
        installer = (WEB.parents[2] / 'MRNOBODY/mrnobody_userdata.yaml').read_text()
        for name in ('web/master_admin.py', 'web/static/master_admin.js',
                     'web/templates/master_admin.html', 'docs/master-admin-prerequisite.md'):
            self.assertTrue((platform / name).is_file())
            self.assertIn('"' + name + '"', installer)
        self.assertFalse((platform / 'credential.json').exists())


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root ownership checks')
class CredentialFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'admin/credential.json'

    def test_provision_hash_only_and_no_replacement(self):
        secret = provision('https://master.lab', self.path)
        record = load_credential(self.path)
        self.assertEqual(record['sha256'], hashlib.sha256(secret.encode()).hexdigest())
        self.assertNotIn(secret, self.path.read_text())
        with self.assertRaises(FileExistsError): provision('https://master.lab', self.path)

    def test_permissions_symlinks_hardlinks_and_missing(self):
        with self.assertRaises(OSError): load_credential(self.path)
        provision('https://master.lab', self.path)
        self.path.chmod(0o644)
        with self.assertRaises(OSError): load_credential(self.path)
        self.path.chmod(0o600)
        linked = self.path.with_name('link')
        linked.symlink_to(self.path)
        with self.assertRaises(OSError): load_credential(linked)
        linked.unlink(); os.link(self.path, linked)
        with self.assertRaises(OSError): load_credential(self.path)
        linked.unlink(); self.path.parent.chmod(0o755)
        with self.assertRaises(OSError): load_credential(self.path)

    def test_invalid_origins_and_unprivileged_provision(self):
        for value in ('http://master.lab', 'https://master.lab/', 'https://u:p@master.lab', 'https://master.lab/?x=1'):
            with self.assertRaises(ValueError): provision(value, self.path)
        with patch('master_admin.os.geteuid', return_value=1000):
            with self.assertRaises(OSError): provision('https://master.lab', self.path)


if __name__ == '__main__':
    unittest.main()
