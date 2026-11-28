"""Verify cloud-init/Compose delivery of the connection API, including lab scope."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2] / 'GUACVM'


class InstallationTests(unittest.TestCase):
    def test_compose_scope_secret_and_delivery(self):
        source = (ROOT/'GUACVM_userdata.yaml').read_text(encoding='utf-8')
        cloud = yaml.safe_load(source.replace('__GUACVM_LAB_ID__','16'))
        compose = yaml.safe_load(next(f['content'] for f in cloud['write_files'] if f['path'].endswith('docker-compose.yml')))
        api = compose['services']['topology-api']
        self.assertEqual(api['environment']['GUACVM_LAB_ID'],'16')
        self.assertNotIn('ports',api)
        self.assertIn('./postgres-password:/run/secrets/postgres_password:ro',api['volumes'])
        self.assertEqual(next(f['permissions'] for f in cloud['write_files'] if f['path'].endswith('postgres-password')),'0600')
        for name in ['connections.py','legacy-sessions.json','connections.js','connections.css']:
            self.assertIn('wget -O /opt/guacamole/',source)
            self.assertIn('/'+name+' https://raw.githubusercontent.com/',source)
        self.assertIn('s/__GUACVM_LAB_ID__/${LAB}/g',(ROOT/'GUACVM_installer.sh').read_text(encoding='utf-8'))

    def test_portal_reads_api_without_legacy_fallback(self):
        self.assertNotIn('src="/sessions.js"',(ROOT/'nginx/web/index.html').read_text())
        app = (ROOT/'nginx/web/app.js').read_text()
        self.assertIn("fetch('/api/sessions'",app)
        self.assertNotIn('window.CYBERLAB_SESSIONS',app)


if __name__ == '__main__':
    unittest.main(verbosity=2)
