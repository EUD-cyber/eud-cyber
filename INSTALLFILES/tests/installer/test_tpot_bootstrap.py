"""TPOT bootstrap handoff regressions; no package/network/VM operations."""
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


def embedded(name):
    config = yaml.safe_load((ROOT / 'TPOT01/TPOT01_userdata.yaml').read_text())
    return next(entry['content'] for entry in config['write_files'] if entry['path'].endswith(name))


class TpotBootstrapTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, 'Drops privileges to test real write permissions')
    def test_unprivileged_installer_uses_checkout_and_target_home(self):
        account = pwd.getpwnam('nobody')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            checkout = root / 'checkout'
            checkout.mkdir(mode=0o755)
            os.chown(checkout, account.pw_uid, account.pw_gid)
            playbook = checkout / 'installer/install'
            playbook.mkdir(parents=True)
            (playbook / 'tpot.yml').write_text('fixture: no download needed\n')
            home = root / 'target-home'
            home.mkdir()
            os.chown(home, account.pw_uid, account.pw_gid)
            readonly = root / 'opt'
            readonly.mkdir(mode=0o755)
            binary = root / 'bin'
            binary.mkdir(mode=0o755)
            # Simulate sudo's target identity, -H and cwd preservation without
            # requiring an ubuntu account or changing sudo/PAM on the test host.
            sudo = binary / 'sudo'
            sudo.write_text(f'''#!/usr/bin/python3
import os, sys
args=sys.argv[1:]
assert args[:3] == ['-H', '-u', 'ubuntu'], args
os.environ['HOME']={str(home)!r}
os.setgid({account.pw_gid})
os.setuid({account.pw_uid})
os.execvp(args[3], args[3:])
''')
            sudo.chmod(0o755)
            installer = checkout / 'install.sh'
            installer.write_text('''#!/bin/bash
set -euo pipefail
[[ "$HOME" == "$EXPECTED_HOME" ]]
[[ "$DEBIAN_FRONTEND" == noninteractive ]]
if [[ ! -r installer/install/tpot.yml ]]; then
  # The reported bug: fallback download writes in the inherited readonly cwd.
  : > tpot.yml
fi
: > .write-probe
''')
            installer.chmod(0o755)
            env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'], EXPECTED_HOME=str(home))
            before = subprocess.run(['bash', '-c',
                f'sudo -H -u ubuntu env DEBIAN_FRONTEND=noninteractive bash {installer}'],
                cwd=readonly, env=env, capture_output=True, text=True)
            self.assertNotEqual(before.returncode, 0)
            self.assertIn('Permission denied', before.stderr)
            source = embedded('tpot-install.sh')
            start = source.index('cd /opt/tpotce\n')
            end = source.index('\nRC=$?', start)
            handoff = source[start:end].replace('/opt/tpotce', str(checkout))
            result = subprocess.run(['bash', '-euc', handoff], cwd=readonly,
                env=dict(env, TPOT_TYPE='h', TPOT_USER='admin', TPOT_PASS='fixture-secret', TPOT_REF='fixture-ref'),
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((checkout / '.write-probe').exists())
            self.assertFalse((readonly / 'tpot.yml').exists())
            self.assertNotIn('fixture-secret', result.stdout + result.stderr)

    def test_terminal_optout_repeat_preserves_prompt_and_login_configuration(self):
        for symlink in (True, False):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                profile = root / 'etc/profile.d'
                profile.mkdir(parents=True)
                pam = root / 'etc/pam.d'
                pam.mkdir()
                (pam / 'common-session').write_text('session optional pam_systemd.so\n')
                other = profile / '99-unrelated.sh'
                other.write_text('PROMPT_COMMAND=(unrelated_hook)\nTERM=xterm-256color\n')
                package_hook = root / 'package-hook.sh'
                package_hook.write_text('# vendor shell OSC implementation\n')
                hook = profile / '80-systemd-osc-context.sh'
                if symlink:
                    hook.symlink_to(package_hook)
                else:
                    hook.write_text(package_hook.read_text())
                source = embedded('tpot-terminal-compat').replace('/etc/', str(root / 'etc') + '/')
                for _ in range(2):
                    result = subprocess.run(['bash', '-c', source], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(hook.exists())
                self.assertEqual((root / 'etc/tmpfiles.d/20-systemd-osc-context.conf').readlink(), Path('/dev/null'))
                self.assertEqual(package_hook.read_text(), '# vendor shell OSC implementation\n')
                self.assertEqual(other.read_text(), 'PROMPT_COMMAND=(unrelated_hook)\nTERM=xterm-256color\n')
                self.assertEqual((pam / 'common-session').read_text(), 'session optional pam_systemd.so\n')
                if not symlink:
                    self.assertTrue(Path(str(hook) + '.tpot-disabled').is_file())


if __name__ == '__main__':
    unittest.main()
