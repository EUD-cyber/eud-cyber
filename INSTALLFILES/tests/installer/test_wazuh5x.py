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
        vm = next(vm for vm in menu.VMS if vm[0] == 'WAZUH')
        self.assertEqual(vm[3], 'WAZUH/WAZUH_installer.sh')
        profiles = {p: menu.hardware(ROOT, p, {}) for p in ('Big', 'Mini')}
        choice = dict(vm='WAZUH', profile='Big', role=None)
        selected, row, env = single.single_environment(choice, profiles, {})
        self.assertEqual(selected, vm)
        self.assertEqual(row['memory_mib'], 16384)
        for profile in ('Big', 'Mini'):
            for labs in (1, 2, 16):
                value = dict(profile=profile, labs=labs, components=['WAZUH', 'WAZUH'])
                self.assertEqual(menu.validate_selection(value)['components'], ['WAZUH'])
        with self.assertRaises(ValueError):
            menu.validate_selection(dict(profile='Big', labs=1, components=['WAZUH5X']))

    def test_cloud_init_and_embedded_syntax(self):
        for relative in ('WAZUH/WAZUH_userdata.yaml', 'TPOT01/TPOT01_userdata.yaml'):
            config = yaml.safe_load((ROOT / relative).read_text())
            for entry in config['write_files']:
                code = entry['content']
                if code.startswith('#!/usr/bin/env python3'):
                    compile(code, entry['path'], 'exec')
                elif code.startswith(('#!/bin/bash', '#!/usr/bin/env bash')):
                    subprocess.run(['bash', '-n'], input=code, text=True, check=True)
        config = yaml.safe_load((ROOT / 'WAZUH/WAZUH_userdata.yaml').read_text())
        reference = yaml.safe_load((ROOT / 'TPOT01/TPOT01_userdata.yaml').read_text())
        self.assertTrue(config['ssh_pwauth'])
        user = config['users'][0]
        standard = next(user for user in reference['users'] if user['name'] == 'ubuntu')
        for field in ('name', 'sudo', 'shell', 'lock_passwd'):
            self.assertEqual(user[field], standard[field])
        archived = yaml.safe_load((ROOT / 'WAZUH_OLD/WAZUH_userdata.yaml').read_text())
        guacamole_user = next(user for user in config['users'] if user['name'] == 'wazuh')
        self.assertEqual(guacamole_user, archived['users'][0])
        self.assertFalse(config['chpasswd']['expire'])
        self.assertNotIn('ssh_authorized_keys', user)
        self.assertNotIn('__WAZUH5X_SSH_KEY__', (ROOT / 'WAZUH/WAZUH_userdata.yaml').read_text())

    def test_host_lifecycle_and_failure_paths(self):
        if os.geteuid() != 0:
            self.skipTest('Requires root; all host commands are stubbed')
        cases = [(mode, 1, list(range(11))) for mode in ('healthy', 'duplicate', 'legacy-test', 'archived', 'failed', 'timeout', 'create-fails')]
        cases += [('healthy', 2, []), ('healthy', 16, [0, 1, 3]), ('exhausted', 1, list(range(1000)))]
        for mode, lab, offsets in cases:
            with self.subTest(mode=mode, lab=lab), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'WAZUH').mkdir()
                binary = root / 'bin'
                binary.mkdir()
                for name in ('WAZUH_installer.sh', 'WAZUH_userdata.yaml'):
                    shutil.copyfile(ROOT / 'WAZUH' / name, root / 'WAZUH' / name)
                (root / 'ubuntu2604-image.sh').write_text('fetch_ubuntu2604() { IMG_PATH="$PWD/fake.img"; }\n')
                def stub(name, code):
                    path = binary / name
                    path.write_text('#!/bin/bash\n' + code)
                    path.chmod(0o755)
                stub('ip', 'exit 0\n')
                stub('sleep', 'exit 0\n')
                stub('pvesm', 'echo "$PWD/snippets/userdata.yaml"\n')
                stub('pvesh', '''if [[ "$1" == get && "$2" == /cluster/resources ]]; then
                  printf '%s\\n' "$TEST_INVENTORY"
                else exit 91; fi
                ''')
                stub('qm', '''printf '%s\\n' "$*" >> "$PWD/events"
                case "$1" in
                  create) [[ "$MODE" != create-fails ]] ;;
                  config) echo "unused0: custom-zfs:vm-$2-disk-0" ;;
                  status) echo 'status: stopped' ;;
                  guest)
                    if [[ "$MODE" == failed && "$*" == *bootstrap.failed* ]]; then echo '{"exitcode":0}';
                    elif [[ "$MODE" == healthy && "$*" == *wazuh5x-healthcheck* ]]; then echo '{"exitcode": 0}';
                    else echo '{"exitcode":1}'; fi ;;
                esac
                ''')
                inventory = [dict(vmid=lab * 1000 + offset, name='existing',
                                  type='lxc' if offset % 2 else 'qemu', node='another-node') for offset in offsets]
                inventory.append(dict(vmid=100, name='unrelated'))
                duplicate_names = {'duplicate': 'WAZUH-1', 'legacy-test': 'WAZUH5X', 'archived': 'WAZUH_OLD'}
                if mode in duplicate_names:
                    inventory.append(dict(vmid=lab * 1000 + 50, name=f'lab{lab}-{duplicate_names[mode]}'))
                inventory.append(dict(vmid=5000, name='lab5-WAZUH'))
                env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'], MODE=mode,
                           WAZUH_BOOT_TIMEOUT='1', TEST_INVENTORY=json.dumps(inventory))
                env.pop('WAZUH5X_SSH_PUBLIC_KEY_FILE', None)
                result = subprocess.run(['bash', str(root / 'WAZUH/WAZUH_installer.sh'), str(lab)],
                                        env=env, text=True, capture_output=True, timeout=15)
                events = (root / 'events').read_text() if (root / 'events').exists() else ''
                if mode == 'healthy':
                    expected_id = lab * 1000 + next(i for i in range(1000) if i not in offsets)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(f'create {expected_id} --name lab{lab}-WAZUH', events)
                    self.assertIn(f'--scsi0 custom-zfs:vm-{expected_id}-disk-0', events)
                    self.assertIn(f'snapshot {expected_id} First_snapshot', events)
                    self.assertIn('--ipconfig0 ip=192.168.2.20/24,gw=192.168.2.1', events)
                    self.assertIn('--ipconfig1 ip=172.20.0.20/24', events)
                    self.assertIn(f'bridge=lab{lab}_lan2', events)
                    self.assertIn(f'bridge=lab{lab}_oobm', events)
                    self.assertNotIn('__WAZUH5X_SSH_KEY__', (root / 'snippets/userdata.yaml').read_text())
                    snippet = yaml.safe_load((root / 'snippets/userdata.yaml').read_text())
                    self.assertTrue(snippet['ssh_pwauth'])
                    self.assertFalse(snippet['users'][0]['lock_passwd'])
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('snapshot ', events)
                if mode in duplicate_names or mode == 'exhausted':
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
        config = yaml.safe_load((ROOT / 'WAZUH/WAZUH_userdata.yaml').read_text())
        source = next(e['content'] for e in config['write_files'] if e['path'].endswith('wazuh5x-bootstrap'))
        for partial, version in ((False, '5.0.0-1'), (True, '5.0.0-1'), (False, '4.14.1-1'), (False, '5.0.1-1')):
            with self.subTest(partial=partial, version=version), tempfile.TemporaryDirectory() as temporary:
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
                    'dpkg-query': 'if [[ "$2" == *Version* ]]; then printf "%s" "$TEST_DEB_VERSION"; else exit 1; fi\n',
                    'healthcheck': 'exit 0\n',
                    'curl': 'while [[ "$1" != -o ]]; do shift; done; cp "$TEST_ROOT/assistant-fixture" "$2"\n',
                }
                for name, content in stubs.items():
                    dest = binary / name
                    dest.write_text('#!/bin/bash\n' + content)
                    dest.chmod(0o755)
                if partial:
                    (state / 'assistant.started').touch()
                env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'], TEST_ROOT=str(root), TEST_DEB_VERSION=version)
                success = not partial and version == '5.0.0-1'
                for _ in range(2):
                    result = subprocess.run(['bash', str(script)], env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                    self.assertNotIn('not-printed', result.stdout + result.stderr)
                if partial:
                    self.assertFalse((root / 'assistant-calls').exists())
                    self.assertTrue((state / 'bootstrap.failed').exists())
                else:
                    self.assertEqual((root / 'assistant-calls').read_text(), 'installed\n')
                if success:
                    self.assertTrue((state / 'bootstrap.complete').exists())
                    self.assertFalse((state / 'bootstrap.failed').exists())
                else:
                    self.assertFalse((state / 'bootstrap.complete').exists())
                    self.assertTrue((state / 'bootstrap.failed').exists())
                if not partial and not success:
                    logs = '\n'.join(p.read_text() for p in (root / 'logs').glob('*.log'))
                    self.assertIn('Unexpected wazuh-indexer DEB version: ' + version, logs)

    def test_terminal_optout_runs_before_bootstrap_and_is_repeatable(self):
        config = yaml.safe_load((ROOT / 'WAZUH/WAZUH_userdata.yaml').read_text())
        command = '/usr/local/sbin/wazuh5x-terminal-compat'
        self.assertEqual(config['runcmd'][0], ['bash', command])
        code = next(e['content'] for e in config['write_files'] if e['path'] == command)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / 'etc/profile.d'
            profile.mkdir(parents=True)
            vendor = root / 'vendor.sh'
            vendor.write_text('# vendor script\n')
            hook = profile / '80-systemd-osc-context.sh'
            hook.symlink_to(vendor)
            other = profile / '99-unrelated.sh'
            other.write_text('TERM=xterm-256color\nPROMPT_COMMAND=(unrelated_hook)\n')
            fixture = code.replace('/etc/', str(root / 'etc') + '/')
            for _ in range(2):
                subprocess.run(['bash', '-c', fixture], check=True)
            self.assertFalse(hook.is_symlink())
            self.assertEqual(vendor.read_text(), '# vendor script\n')
            self.assertEqual((root / 'etc/tmpfiles.d/20-systemd-osc-context.conf').readlink(), Path('/dev/null'))
            self.assertEqual(other.read_text(), 'TERM=xterm-256color\nPROMPT_COMMAND=(unrelated_hook)\n')


if __name__ == '__main__':
    unittest.main()
