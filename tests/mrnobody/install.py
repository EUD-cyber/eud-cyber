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

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
from reports import read_metadata
from scenario_model import catalogue


def installer():
    value = (ROOT / 'MRNOBODY/mrnobody_userdata.yaml').read_text(encoding='utf-8')
    block = value.split('    content: |\n', 1)[1]
    lines = []
    for line in block.splitlines():
        if line and not line.startswith('      '):
            break
        lines.append(line[6:] if line else '')
    return value, '\n'.join(lines) + '\n'


class FreshInstall(unittest.TestCase):
    def test_installer_downloads_every_distributed_runtime_file(self):
        userdata, script = installer()
        pairs = re.findall(r'download_file\s*\\\s*\n\s*"([^"]+)"\s*\\\s*\n\s*"\$INSTALL_DIR/([^"]+)"', script)
        downloaded = dict(pairs)
        expected = {line.split('|', 1)[1] for line in (PLATFORM / 'update-manifest.txt').read_text().splitlines() if line and not line.startswith('#')}
        self.assertEqual(set(downloaded), expected)
        self.assertEqual(len(downloaded), len(pairs), 'Duplicate downloads')
        self.assertTrue(all(source == target for source, target in pairs))
        self.assertIn('main/TESTFILES/ATTACKER-V2', script)
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
            self.assertTrue({'09', '10'} <= set(caps))
            self.assertTrue((base / 'web/windows_actions.py').is_file())
            phases = read_metadata(base / 'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(',')
            self.assertTrue(set(phases) <= set(caps))
            self.assertIn('09', phases)
            self.assertIn('10', phases)

    @unittest.skipIf(os.name == 'nt', 'Embedded Bash syntax checked on Linux CI')
    def test_cloud_init_embedded_installer_bash_syntax(self):
        # bash -n parses only; it never executes filesystem/service/network actions.
        _, script = installer()
        result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
