"""Offline integration tests. No real VM, network request or package install."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import installer_menu as menu
import single_vm_install as single


class Wazuh5xTests(unittest.TestCase):
    def test_menu_and_isolated_dispatch(self):
        vm = next(vm for vm in menu.VMS if vm[0] == 'WAZUH5X')
        self.assertEqual(vm[3], 'WAZUH5X/wazuh5x_install.sh')
        profiles = {p: menu.hardware(ROOT, p, {}) for p in ('Big', 'Mini')}
        choice = dict(vm='WAZUH5X', profile='Big', role=None)
        selected, row, env = single.single_environment(choice, profiles, {'WAZUH_MEM': '999'})
        self.assertEqual(selected, vm)
        self.assertNotIn('WAZUH_MEM', env)
        self.assertEqual(row['memory_mib'], 16384)
        self.assertEqual(menu.validate_selection(dict(profile='Big', labs=1, components=['WAZUH', 'WAZUH5X']))['components'], ['WAZUH', 'WAZUH5X'])

    def test_cloud_init_and_embedded_syntax(self):
        for relative in ('WAZUH5X/WAZUH5X_userdata.yaml', 'TPOT01/TPOT01_userdata.yaml'):
            config = yaml.safe_load((ROOT / relative).read_text())
            for entry in config['write_files']:
                code = entry['content']
                if code.startswith('#!/usr/bin/env python3'):
                    compile(code, entry['path'], 'exec')
                elif code.startswith(('#!/bin/bash', '#!/usr/bin/env bash')):
                    subprocess.run(['bash', '-n'], input=code, text=True, check=True)
        config = yaml.safe_load((ROOT / 'WAZUH5X/WAZUH5X_userdata.yaml').read_text())
        self.assertFalse(config['ssh_pwauth'])
        self.assertTrue(config['users'][0]['lock_passwd'])

    def test_host_lifecycle_and_failure_paths(self):
        if os.geteuid() != 0:
            self.skipTest('Requires root; all host commands are stubbed')
        for mode in ('healthy', 'duplicate', 'failed', 'timeout', 'create-fails'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'WAZUH5X').mkdir()
                binary = root / 'bin'
                binary.mkdir()
                for name in ('wazuh5x_install.sh', 'WAZUH5X_userdata.yaml'):
                    shutil.copyfile(ROOT / 'WAZUH5X' / name, root / 'WAZUH5X' / name)
                (root / 'key.pub').write_text('ssh-ed25519 AAAATEST test-key')
                (root / 'ubuntu2604-image.sh').write_text('fetch_ubuntu2604() { IMG_PATH="$PWD/fake.img"; }\n')
                def stub(name, code):
                    path = binary / name
                    path.write_text('#!/bin/bash\n' + code)
                    path.chmod(0o755)
                stub('ip', 'exit 0\n')
                stub('sleep', 'exit 0\n')
                stub('pvesm', 'echo "$PWD/snippets/userdata.yaml"\n')
                stub('pvesh', '''if [[ "$3" == /cluster/resources ]]; then
                  if [[ "$MODE" == duplicate ]]; then echo '[{"name":"lab1-WAZUH5X","vmid":1010}]'; else echo '[]'; fi
                else echo 1011; fi
                ''')
                # pvesh argv is: get /cluster/resources ...
                path = binary / 'pvesh'
                path.write_text(path.read_text().replace('$3', '$2'))
                stub('qm', '''printf '%s\\n' "$*" >> "$PWD/events"
                case "$1" in
                  create) [[ "$MODE" != create-fails ]] ;;
                  config) echo 'unused0: custom-zfs:vm-1011-disk-0' ;;
                  status) echo 'status: stopped' ;;
                  guest)
                    if [[ "$MODE" == failed && "$*" == *bootstrap.failed* ]]; then echo '{"exitcode":0}';
                    elif [[ "$MODE" == healthy && "$*" == *wazuh5x-healthcheck* ]]; then echo '{"exitcode": 0}';
                    else echo '{"exitcode":1}'; fi ;;
                esac
                ''')
                env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'], MODE=mode,
                           WAZUH5X_SSH_PUBLIC_KEY_FILE=str(root / 'key.pub'), WAZUH5X_BOOT_TIMEOUT='1')
                result = subprocess.run(['bash', str(root / 'WAZUH5X/wazuh5x_install.sh'), '1'],
                                        env=env, text=True, capture_output=True, timeout=15)
                events = (root / 'events').read_text() if (root / 'events').exists() else ''
                if mode == 'healthy':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('--scsi0 custom-zfs:vm-1011-disk-0', events)
                    self.assertIn('snapshot 1011 First_snapshot', events)
                    self.assertIn('172.20.0.21', events)
                    self.assertNotIn('__WAZUH5X_SSH_KEY__', (root / 'snippets/userdata.yaml').read_text())
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('snapshot ', events)
                if mode == 'duplicate':
                    self.assertNotIn('create ', events)
                self.assertNotIn('destroy', events)

    def test_image_cache_checksum_and_custom_mirror(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'bin'
            binary.mkdir()
            image = b'test-qcow2-image'
            digest = hashlib.sha256(image).hexdigest()
            (root / 'source.img').write_bytes(image)
            for name, code in {
                'curl': 'cp "$PWD/source.img" "${@: -2:1}"\n',
                'qemu-img': 'echo "file format: qcow2"\n',
            }.items():
                path = binary / name
                path.write_text('#!/bin/bash\n' + code)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'],
                       UBUNTU2604_IMG='https://mirror.test/resolute.img', UBUNTU2604_SHA256=digest)
            script = f'set -euo pipefail; source "{ROOT}/ubuntu2604-image.sh"; fetch_ubuntu2604'
            def fetch():
                return subprocess.run(['bash', '-c', script], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(fetch().returncode, 0)
            cache = root / 'IMAGES' / f'resolute-{digest}.img'
            self.assertEqual(cache.read_bytes(), image)
            cache.write_bytes(b'bad-cache')
            self.assertEqual(fetch().returncode, 0)
            self.assertEqual(cache.read_bytes(), image)
            cache.unlink()
            (root / 'source.img').write_bytes(b'bad-download')
            self.assertNotEqual(fetch().returncode, 0)
            self.assertFalse(cache.exists())
            self.assertFalse(list((root / 'IMAGES').glob('*.??????')))
            env.pop('UBUNTU2604_SHA256')
            self.assertNotEqual(fetch().returncode, 0)

    def test_bootstrap_repeat_and_interrupted_install(self):
        config = yaml.safe_load((ROOT / 'WAZUH5X/WAZUH5X_userdata.yaml').read_text())
        source = next(e['content'] for e in config['write_files'] if e['path'].endswith('wazuh5x-bootstrap'))
        for partial in (False, True):
            with self.subTest(partial=partial), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = root / 'state'
                state.mkdir()
                binary = root / 'bin'
                binary.mkdir()
                (root / 'os-release').write_text('ID=ubuntu\nVERSION_ID=26.04\n')
                assistant = '#!/bin/bash\necho installed >> "$TEST_ROOT/assistant-calls"\n'
                digest = hashlib.sha256(assistant.encode()).hexdigest()
                (root / 'assistant-fixture').write_text(assistant)
                for component in ('indexer', 'manager'):
                    dest = root / component / 'export'
                    dest.mkdir(parents=True)
                    (dest / 'credentials.env').write_text('TEST_SECRET=not-printed\n')
                code = source.replace('/var/lib/wazuh5x', str(state)).replace('/var/log/wazuh5x', str(root / 'logs'))
                code = code.replace('/etc/os-release', str(root / 'os-release'))
                code = code.replace('/var/ossec', str(root / 'old-ossec')).replace('/etc/ossec-init.conf', str(root / 'old-init.conf'))
                code = code.replace('/etc/wazuh-indexer', str(root / 'indexer')).replace('/etc/wazuh-manager', str(root / 'manager'))
                code = code.replace('/usr/local/sbin/wazuh5x-healthcheck', str(binary / 'healthcheck'))
                code = code.replace('294255e2c6d7fbb96be50a6f8559667487c47464f6646f120141c7e2d98241df', digest)
                script = root / 'bootstrap.sh'
                script.write_text(code)
                stubs = {
                    'systemctl': 'exit 0\n',
                    'dpkg': 'echo amd64\n',
                    'dpkg-query': 'if [[ "$2" == *Version* ]]; then printf 5.0.0-rc2; else exit 1; fi\n',
                    'healthcheck': 'exit 0\n',
                    'curl': 'while [[ "$1" != -o ]]; do shift; done; cp "$TEST_ROOT/assistant-fixture" "$2"\n',
                }
                for name, content in stubs.items():
                    dest = binary / name
                    dest.write_text('#!/bin/bash\n' + content)
                    dest.chmod(0o755)
                if partial:
                    (state / 'assistant.started').touch()
                env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'], TEST_ROOT=str(root))
                for _ in range(2):
                    result = subprocess.run(['bash', str(script)], env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, not partial, result.stdout + result.stderr)
                    self.assertNotIn('not-printed', result.stdout + result.stderr)
                if partial:
                    self.assertFalse((root / 'assistant-calls').exists())
                    self.assertTrue((state / 'bootstrap.failed').exists())
                else:
                    self.assertEqual((root / 'assistant-calls').read_text(), 'installed\n')
                    self.assertTrue((state / 'bootstrap.complete').exists())
                    self.assertFalse((state / 'bootstrap.failed').exists())


if __name__ == '__main__':
    unittest.main()
