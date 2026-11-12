"""Release gates using temporary fixtures only; never contact a lab or start services."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
from reports import read_metadata
from scenario_model import catalogue
from scheduler import timestamp


class ReleaseContracts(unittest.TestCase):
    def test_exact_supported_registry_and_dependency_order(self):
        caps = catalogue(BASE / 'scripts', read_metadata)
        self.assertEqual(set(caps), {f'{n:02}' for n in range(1, 12)})
        order = read_metadata(BASE / 'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(',')
        self.assertEqual(len(order), len(set(order)))
        self.assertEqual(set(order), set(caps))
        seen = set()
        for pid in order:
            self.assertTrue(set(caps[pid]['dependencies']) <= seen, pid)
            seen.add(pid)
        self.assertLess(order.index('05'), order.index('06'))
        self.assertLess(order.index('06'), order.index('07'))

    def test_manifest_is_complete_and_excludes_mutable_data(self):
        entries = [line.split('|', 1) for line in (BASE / 'update-manifest.txt').read_text().splitlines()
                   if line and not line.startswith('#')]
        paths = [p for _, p in entries]
        expected = {p.relative_to(BASE).as_posix() for p in BASE.rglob('*') if p.is_file()
                    and p.suffix != '.pyc' and '__pycache__' not in p.parts
                    and p.relative_to(BASE).parts[0] not in {'tools', 'state', 'logs', 'runtime', 'reports', 'data'}
                    and p.relative_to(BASE).as_posix() not in {'update-manifest.txt', 'config/local.conf'}}
        self.assertEqual(set(paths), expected)
        self.assertEqual(len(paths), len(set(paths)))
        for digest, path in entries:
            self.assertRegex(digest, r'^[0-9a-f]{64}$')
            self.assertEqual(hashlib.sha256((BASE / path).read_bytes()).hexdigest(), digest, path)

    def test_timezone_offsets_and_dst_instants(self):
        self.assertEqual(timestamp('2026-11-03T12:00:00+01:00'), timestamp('2026-11-03T11:00:00Z'))
        self.assertEqual(timestamp('2026-07-03T12:00:00+02:00'), timestamp('2026-07-03T10:00:00Z'))
        self.assertEqual(timestamp('2026-10-25T02:30:00+01:00') -
                         timestamp('2026-10-25T02:30:00+02:00'), 3600)
        with self.assertRaises(ValueError):
            timestamp('2026-11-03T12:00:00')


@unittest.skipIf(os.name == 'nt', 'Linux updater fixture')
class UpdaterFixtures(unittest.TestCase):
    def run_update(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            installed, remote, commands = [root / x for x in ('installed', 'remote', 'bin')]
            for p in (installed, remote, commands):
                p.mkdir()
            sentinels = {}
            for relative in ('reports/history.json', 'state/campaign.json', 'runtime/execution.lock',
                             'logs/history.log', 'data/planning/execution.sqlite3', 'config/local.conf'):
                path = installed / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'PRESERVE-EXACT-BYTES')
                sentinels[relative] = path.read_bytes()
            old = installed / 'config/defaults.conf'
            old.write_bytes(b'old defaults\n')
            (installed / 'web').mkdir()
            shutil.copyfile(BASE / 'web/retired_files.py', installed / 'web/retired_files.py')
            retired = installed / 'scripts/12-credential-access.sh'
            retired.parent.mkdir()
            retired.write_bytes(b'#!/bin/sh\nexit 99\n')
            payloads = {'config/defaults.conf': b'new defaults\n', 'scripts/release-fixture.sh': b'#!/bin/sh\nexit 0\n'}
            manifest = []
            for relative, data in payloads.items():
                path = remote / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                manifest.append(digest + '|' + relative)
            (remote / 'update-manifest.txt').write_text('\n'.join(manifest) + '\n')
            if mode == 'no-change':
                for relative, data in payloads.items():
                    path = installed / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
            if mode == 'bad-hash':
                (remote / 'scripts/release-fixture.sh').write_bytes(b'tampered\n')
            curl = """#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
url = next(x for x in args if x.startswith('https://'))
relative = url.split('/TESTFILES/ATTACKER-V2/', 1)[1]
shutil.copyfile(pathlib.Path(os.environ['FIXTURE_REMOTE']) / relative, args[args.index('-o') + 1])
"""
            (commands / 'curl').write_text(curl)
            real_install = shutil.which('install')
            self.assertTrue(real_install)
            install = """#!/usr/bin/env python3
import os, subprocess, sys
if os.environ['FIXTURE_MODE'] == 'rollback' and sys.argv[-1].endswith('/scripts/release-fixture.sh'):
    sys.exit(1)
sys.exit(subprocess.call([os.environ['REAL_INSTALL'], *sys.argv[1:]]))
"""
            (commands / 'install').write_text(install)
            for name in ('systemctl', 'nginx'):
                (commands / name).write_text('#!/bin/sh\nexit 0\n')
            for p in commands.iterdir():
                p.chmod(0o755)
            result = subprocess.run(['bash', str(BASE / 'scripts/update.sh')], env=dict(
                os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'],
                NORDIC_BASE_DIR=str(installed), FIXTURE_REMOTE=str(remote),
                FIXTURE_MODE=mode, REAL_INSTALL=real_install), capture_output=True, text=True, timeout=30)
            for relative, data in sentinels.items():
                self.assertEqual((installed / relative).read_bytes(), data, relative)
            if mode in {'success', 'no-change'}:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(retired.exists(), result.stdout + result.stderr)
                for relative, data in payloads.items():
                    self.assertEqual((installed / relative).read_bytes(), data)
                if mode == 'success':
                    self.assertEqual((installed / 'scripts/release-fixture.sh').stat().st_mode & 0o777, 0o755)
            else:
                self.assertTrue(retired.exists(), 'Retirement must follow successful activation only')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(old.read_bytes(), b'old defaults\n')
                self.assertFalse((installed / 'scripts/release-fixture.sh').exists())
                self.assertIn('Rollback completed.' if mode == 'rollback' else 'BAD HASH', result.stdout)

    def test_update_preserves_reports_state_and_planning(self):
        self.run_update('success')

    def test_failed_install_restores_previous_files(self):
        self.run_update('rollback')

    def test_old_updater_second_pass_cleans_even_without_changes(self):
        self.run_update('no-change')

    def test_bad_hash_aborts_before_mutation(self):
        self.run_update('bad-hash')


if __name__ == '__main__':
    unittest.main()
