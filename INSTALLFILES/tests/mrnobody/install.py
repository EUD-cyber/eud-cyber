"""Verify fresh-install contents without running cloud-init or the installer."""
import ast
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
from reports import read_metadata
from scenario_model import catalogue
from retired_files import RETIRED_FILES


def installer():
    value = (ROOT / 'MRNOBODY/mrnobody_userdata.yaml').read_text(encoding='utf-8')
    config = yaml.safe_load(value)
    entry, = [item for item in config['write_files'] if item['path'] == '/usr/local/sbin/install-mrnobody']
    assert entry['owner'] == 'root:root' and entry['permissions'] == '0755'
    return value, entry['content']


class FreshInstall(unittest.TestCase):
    def test_nginx_removes_beacons_and_preserves_gui_proxy(self):
        config = (PLATFORM / 'nginx/nordic-incident.conf').read_text()
        self.assertNotIn('mrnobody-beacon', config)
        self.assertIn('location / { return 301 https://$host$request_uri; }', config)
        self.assertRegex(config, r'location / \{\s+proxy_pass\s+http://127\.0\.0\.1:8082;')

    def test_installer_downloads_every_distributed_runtime_file(self):
        userdata, script = installer()
        pairs = re.findall(r'download_file\s*\\\s*\n\s*"([^"]+)"\s*\\\s*\n\s*"\$INSTALL_DIR/([^"]+)"', script)
        downloaded = dict(pairs)
        expected = {line.split('|', 1)[1] for line in (PLATFORM / 'update-manifest.txt').read_text().splitlines() if line and not line.startswith('#')}
        self.assertEqual(expected, set(downloaded))
        self.assertEqual(len(downloaded), len(pairs), 'Duplicate downloads')
        self.assertTrue(all(source == target for source, target in pairs))
        self.assertTrue(set(RETIRED_FILES).isdisjoint(downloaded))
        self.assertIn('main/INSTALLFILES/TESTFILES/ATTACKER-V2', script)
        self.assertIn('  - /usr/local/sbin/install-mrnobody', userdata)
        self.assertIn('-m compileall -q', script)

        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            base = Path(tmp)
            for source, target in pairs:
                destination = base / target
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(PLATFORM / source, destination)
            for path in (base / 'web').glob('*.py'):
                ast.parse(path.read_text(encoding='utf-8'), filename=path.name)
            caps = catalogue(base / 'scripts', read_metadata)
            self.assertTrue({f'{n:02}' for n in range(1, 12)} == set(caps))
            self.assertTrue((base / 'web/windows_actions.py').is_file())
            phases = read_metadata(base / 'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(',')
            self.assertTrue(set(phases) <= set(caps))
            self.assertIn('09', phases)
            self.assertIn('10', phases)
            self.assertIn('11', phases)

            # Use only the files downloaded by cloud-init, without an updater
            # overlay. Import in a child so repository modules cannot mask gaps.
            # No scheduler thread, campaign, transport or service is started.
            smoke = '''
import app
import remote_actions
import p11_campaign
import reportlab
from pathlib import Path
import os
base = Path(os.environ['NORDIC_BASE_DIR'])
assert Path(app.__file__).parent == base / 'web'
assert Path(remote_actions.__file__).parent == base / 'web'
assert Path(p11_campaign.__file__).parent == base / 'web'
client = app.app.test_client()
for url in ('/', '/api/health', '/api/phases', '/api/planning/capabilities',
            '/api/custom-scenarios', '/api/schedules', '/api/reports',
            '/api/execution-status', '/static/app.js', '/static/planning.js',
            '/static/style.css'):
    response = client.get(url)
    assert response.status_code == 200, (url, response.status_code)
assert client.get('/api/health').get_json()['status'] == 'ok'
assert {f'{n:02}' for n in range(1, 12)} == set(app.planning.capabilities())
assert app.planning.store.path == base / 'data/planning/execution.sqlite3'
assert app.planning.store.path.is_file()
if os.name != 'nt':
    assert app.planning.store.directory.stat().st_mode & 0o777 == 0o700
    assert app.planning.store.path.stat().st_mode & 0o777 == 0o600
'''
            env = dict(os.environ, NORDIC_BASE_DIR=str(base),
                       PYTHONPATH=str(base / 'web') + os.pathsep + os.environ.get('PYTHONPATH', ''))
            result = subprocess.run([sys.executable, '-c', smoke], cwd=base / 'web',
                                    env=env, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Embedded Bash syntax checked on Linux CI')
    def test_cloud_init_embedded_installer_bash_syntax(self):
        # bash -n parses only; it never executes filesystem/service/network actions.
        _, script = installer()
        result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
