"""Updater agent state checks; shell tests use fake systemctl, never real services."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / "TESTFILES/ATTACKER-V2"
SOURCE = (PLATFORM / "scripts/update.sh").read_text(encoding="utf-8")
HELPERS = SOURCE[SOURCE.index("capture_agent_state() {"):SOURCE.index("\nfor agent_file in")]
ROLE_CHECK = HELPERS.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
BASH = shutil.which("bash") if os.name != "nt" else None


class AgentUpdate(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        assert self.root.resolve().parent == ROOT.resolve()
        self.web = self.root / "web"
        self.web.mkdir()
        self.config = self.root / "deployment.conf"
        source = (PLATFORM / "web/deployment_config.py").read_text(encoding="utf-8")
        source = source.replace('DEPLOYMENT_FILE = Path("/etc/mrnobody/deployment.conf")',
                                "DEPLOYMENT_FILE = Path(" + json.dumps(str(self.config)) + ")")
        (self.web / "deployment_config.py").write_text(source, encoding="utf-8")
        self.config.write_text('MRNOBODY_ROLE="agent"\nMRNOBODY_MASTER_URL="https://master.test"\n', encoding="utf-8")

    def test_actual_role_gate_uses_parser_and_refuses_other_roles_or_invalid_config(self):
        for role, expected in (("agent", 0), ("master", 1), ("standalone", 1), ("bad", 1)):
            self.config.write_text('MRNOBODY_ROLE="'+role+'"\nMRNOBODY_MASTER_URL=""\n', encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", "-c", ROLE_CHECK, str(self.web)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, expected, result.stdout+result.stderr)
        self.config.write_text('MRNOBODY_ROLE="agent"\nMRNOBODY_ROLE="master"\n', encoding="utf-8")
        result = subprocess.run([sys.executable, "-B", "-c", ROLE_CHECK, str(self.web)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)

    @unittest.skipUnless(BASH, "Bash lifecycle runs on Linux/CI")
    def test_full_updater_shell_syntax(self):
        result = subprocess.run([BASH, "-n", str(PLATFORM / "scripts/update.sh")],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(BASH, "Bash lifecycle runs on Linux/CI")
    def test_only_previously_active_agent_restarts_and_failure_is_propagated(self):
        for role, active, changed, fail, expected in (
            ("agent", 0, 1, 0, 0), ("agent", 1, 0, 0, 0),
            ("master", 1, 1, 0, 0), ("standalone", 1, 1, 0, 0),
            ("agent", 1, 1, 0, 1), ("agent", 1, 1, 1, 1),
        ):
            with self.subTest(role=role, active=active, changed=changed, fail=fail):
                self.config.write_text('MRNOBODY_ROLE="'+role+'"\nMRNOBODY_MASTER_URL=""\n', encoding="utf-8")
                script = r"""
set -eu
AGENT_WAS_ACTIVE=0
log() { :; }
systemctl() {
    printf '%s\n' "$*" >> "$TEST_CALLS"
    if [[ "$1" == "is-active" ]]; then
        [[ "$TEST_ACTIVE" == 1 ]]
    elif [[ "$1" == "restart" ]]; then
        [[ "$TEST_FAIL" == 0 ]]
    else
        return 0
    fi
}
""" + HELPERS + """
capture_agent_state
if restart_updated_agent; then
    printf 'RESULT:0'
else
    printf 'RESULT:%s' "$?"
fi
"""
                calls = self.root / "calls"
                calls.write_text("")
                env = dict(os.environ, INSTALL_DIR=str(self.root), AGENT_CHANGED=str(changed),
                           TEST_CALLS=str(calls), TEST_ACTIVE=str(active), TEST_FAIL=str(fail))
                result = subprocess.run([BASH], input=script, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                operations = calls.read_text().splitlines()
                self.assertEqual(sum(line.startswith("restart ") for line in operations), expected)
                self.assertIn("RESULT:1" if expected and fail else "RESULT:0", result.stdout)
                self.assertFalse(any(line.startswith(("enable ", "start ", "disable ", "stop ")) for line in operations))


if __name__ == "__main__":
    unittest.main()
