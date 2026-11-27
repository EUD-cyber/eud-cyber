"""Run the real embedded healthcheck against authenticated local TLS fixtures."""
import base64
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class WazuhHealthcheckTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.secret = 'fixture-secret-Only!123&'
        self.admin_secret = 'FixtureAdmin123@'
        self.indexer_secret = self.admin_secret
        self.token = 'fixture-token-must-not-be-logged'
        self.state = dict(indexer='yellow', dashboard='green', reject_auth=False)
        self.requests = []
        cert = self.root / 'server.pem'
        key = self.root / 'server.key'
        self.make_cert(cert, key)
        for component in ('indexer', 'manager', 'dashboard'):
            export = self.root / 'etc' / ('wazuh-' + component) / 'export'
            export.mkdir(parents=True)
            (export / 'ca.pem').write_bytes(cert.read_bytes())
            credential = 'WAZUH_MANAGER_API_PASSWORD' if component == 'manager' else 'WAZUH_INDEXER_ADMIN_PASSWORD'
            value = self.secret if component == 'manager' else self.admin_secret
            (export / 'credentials.env').write_text(credential + "='" + value + "'\n")
        self.indexer_export = self.root / 'etc/wazuh-indexer/export/credentials.env'
        state = self.root / 'var/lib/wazuh5x'
        state.mkdir(parents=True)
        (state / 'bootstrap.complete').touch()
        (state / 'admin-password').write_text(self.admin_secret + '\n')
        binary = self.root / 'bin'
        binary.mkdir()
        self.executable(binary / 'systemctl', '''#!/bin/bash
[[ "${FAIL_SERVICE:-}" != "${3:-}" ]]
''')
        self.executable(binary / 'cloud-init', '''#!/bin/bash
printf '{"status":"%s"}\\n' "${TEST_CLOUD_STATUS:-done}"
''')
        manager = self.root / 'var/wazuh-manager/bin/wazuh-manager-control'
        manager.parent.mkdir(parents=True)
        self.executable(manager, '#!/bin/bash\nexit 0\n')
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.handle_request('GET')

            def do_POST(self):
                self.handle_request('POST')

            def handle_request(self, method):
                fixture.requests.append((method, self.path))
                user = 'wazuh' if self.path.startswith('/manager/') else 'admin'
                secret = fixture.secret if user == 'wazuh' else fixture.indexer_secret
                expected = 'Basic ' + base64.b64encode((user + ':' + secret).encode()).decode()
                if self.path == '/dashboard/auth/login':
                    login = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    authorized = (login == {'username': 'admin', 'password': fixture.admin_secret}
                                  and self.headers.get('osd-xsrf') == 'true'
                                  and not fixture.state.get('reject_dashboard_login'))
                else:
                    authorized = self.headers.get('Authorization') == expected
                if not authorized or fixture.state['reject_auth']:
                    # Deliberately echo secrets into an error body: healthcheck must never log it.
                    status, body = 401, {'error': fixture.secret, 'token': fixture.token}
                elif self.path == '/indexer/_cluster/health' and method == 'GET':
                    status, body = 200, {'status': fixture.state['indexer'], 'timed_out': False}
                elif self.path == '/manager/security/user/authenticate' and method == 'POST':
                    status, body = 200, {'data': {'token': fixture.token}}
                elif self.path == '/dashboard/api/status' and method == 'GET':
                    status, body = 200, {'status': {'overall': {'state': fixture.state['dashboard']}}}
                elif self.path == '/dashboard/auth/login' and method == 'POST':
                    status, body = 200, {}
                else:
                    status, body = 404, {}
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                if self.path == '/dashboard/auth/login' and status == 200:
                    self.send_header('Set-Cookie', 'security_authentication=' + fixture.token)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        config = yaml.safe_load((ROOT / 'WAZUH/WAZUH_userdata.yaml').read_text())
        code = next(e['content'] for e in config['write_files'] if e['path'].endswith('wazuh5x-healthcheck'))
        for prefix in ('/etc/wazuh-', '/var/lib/wazuh5x', '/var/wazuh-manager'):
            code = code.replace(prefix, str(self.root) + prefix)
        base = 'https://127.0.0.1:' + str(self.server.server_port)
        code = code.replace('https://127.0.0.1:9200', base + '/indexer')
        code = code.replace('https://127.0.0.1:55000', base + '/manager')
        code = code.replace('https://127.0.0.1/api/status', base + '/dashboard/api/status')
        code = code.replace('https://127.0.0.1/auth/login', base + '/dashboard/auth/login')
        self.password_tool = self.root / 'password-tool.sh'
        code = code.replace('/usr/share/wazuh-indexer/tools/wazuh-passwords-tool.sh', str(self.password_tool))
        self.script = self.root / 'healthcheck.py'
        self.script.write_text(code)
        self.env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'], NO_PROXY='127.0.0.1', no_proxy='127.0.0.1')

    def make_cert(self, cert, key):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def executable(self, path, content):
        path.write_text(content)
        path.chmod(0o755)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def check(self, *args):
        result = subprocess.run([sys.executable, str(self.script), *args], env=self.env,
                                text=True, capture_output=True, timeout=20)
        self.assertNotIn(self.secret, result.stdout + result.stderr)
        self.assertNotIn(self.admin_secret, result.stdout + result.stderr)
        self.assertNotIn(self.token, result.stdout + result.stderr)
        return result

    def test_real_tls_auth_and_export_ca_layout_succeed(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.requests, [('GET', '/indexer/_cluster/health'),
                         ('POST', '/manager/security/user/authenticate'), ('GET', '/dashboard/api/status'),
                         ('POST', '/dashboard/auth/login')])
        self.assertIn('WAZUH5X healthy', result.stdout)

    def test_admin_rotation_and_idempotence(self):
        self.indexer_secret = self.secret
        internal = 'WAZUH_INDEXER_KIBANASERVER_PASSWORD=fixture-internal\n'
        self.indexer_export.write_text(f'WAZUH_INDEXER_ADMIN_PASSWORD={self.secret}\n' + internal)
        self.env.update(TEST_EXPORT=str(self.indexer_export), TEST_CALLS=str(self.root / 'calls'))
        self.executable(self.password_tool, '''#!/bin/bash
[[ "$#" == 3 && "$1" == -u && "$2" == admin && "$3" == -p ]] || exit 7
IFS= read -r secret || exit 8
printf '%s\n' "$secret"
printf 'called\n' >> "$TEST_CALLS"
if [[ "${TEST_TOOL_FAILURE:-}" == yes ]]; then exit 9; fi
sed -i "s/^WAZUH_INDEXER_ADMIN_PASSWORD=.*/WAZUH_INDEXER_ADMIN_PASSWORD=$secret/" "$TEST_EXPORT"
''')
        self.assertNotEqual(self.check('--bootstrap').returncode, 0)
        self.env['TEST_TOOL_FAILURE'] = 'yes'
        failed = self.check('--rotate-admin')
        self.assertEqual(failed.returncode, 2, failed.stderr)
        self.assertIn('Password tool failed', failed.stderr)
        del self.env['TEST_TOOL_FAILURE']
        rotated = self.check('--rotate-admin')
        self.assertEqual(rotated.returncode, 0, rotated.stderr)
        self.assertEqual(self.indexer_export.read_text(),
                         f'WAZUH_INDEXER_ADMIN_PASSWORD={self.admin_secret}\n' + internal)
        self.assertNotEqual(self.check('--bootstrap').returncode, 0)
        self.indexer_secret = self.admin_secret
        self.assertEqual(self.check('--rotate-admin').returncode, 0)
        self.assertEqual((self.root / 'calls').read_text().splitlines(), ['called', 'called'])
        self.assertEqual(self.check('--bootstrap').returncode, 0)

    def test_dashboard_session_requires_admin_login(self):
        self.state['reject_dashboard_login'] = True
        result = self.check('--bootstrap')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('[dashboard admin login]: HTTP 401', result.stderr)

    def test_missing_dashboard_ca_names_exact_path_and_stage(self):
        for component, phase in (('indexer', 'indexer HTTPS'), ('manager', 'manager API HTTPS'), ('dashboard', 'dashboard HTTPS')):
            with self.subTest(component=component):
                missing = self.root / ('etc/wazuh-' + component) / 'export/ca.pem'
                saved = missing.read_bytes()
                missing.unlink()
                result = self.check('--bootstrap')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('[' + phase + ']: missing file: ' + str(missing), result.stderr)
                missing.write_bytes(saved)
        missing = self.root / 'var/wazuh-manager/bin/wazuh-manager-control'
        missing.unlink()
        result = self.check('--bootstrap')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('[manager daemons]: missing file: ' + str(missing), result.stderr)

    def test_untrusted_ca_and_failed_auth_are_rejected_without_secrets(self):
        ca = self.root / 'etc/wazuh-indexer/export/ca.pem'
        original = ca.read_bytes()
        self.make_cert(ca, self.root / 'wrong-ca.key')
        result = self.check('--bootstrap')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('[indexer HTTPS]: TLS certificate verification failed', result.stderr)
        ca.write_bytes(original)
        self.state['reject_auth'] = True
        result = self.check('--bootstrap')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('[indexer HTTPS]: HTTP 401', result.stderr)

    def test_unhealthy_components_and_failed_service_never_pass(self):
        for component in ('indexer', 'dashboard'):
            with self.subTest(component=component):
                self.state[component] = 'red'
                result = self.check('--bootstrap')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('not ready', result.stderr)
                self.state[component] = 'green'
        self.env['FAIL_SERVICE'] = 'wazuh-manager'
        result = self.check('--bootstrap')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('[wazuh-manager service]: command exit 1', result.stderr)

    def test_cloud_init_state_gates_host_check_but_not_bootstrap_probe(self):
        self.env['TEST_CLOUD_STATUS'] = 'error'
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('[cloud-init status]', result.stderr)
        self.assertEqual(self.check('--bootstrap').returncode, 0)


if __name__ == '__main__':
    unittest.main()
