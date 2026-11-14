"""Updater agent state checks; shell tests use fake systemctl, never real services."""
import json
import hashlib
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
ROLE_HELPER = SOURCE[SOURCE.index("is_agent_deployment() {"):SOURCE.index("install_agent_unit() {")]
HELPERS = ROLE_HELPER + SOURCE[SOURCE.index("capture_agent_state() {"):SOURCE.index("\nfor agent_file in")]
ROLE_CHECK = ROLE_HELPER.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
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

    @unittest.skipUnless(BASH, "Bash lifecycle runs on Linux/CI")
    def test_missing_or_stale_unit_without_credentials_is_repaired_only_for_valid_agent(self):
        unit = self.root / "installed.service"
        source = self.root / "systemd/mrnobody-agent.service"
        source.parent.mkdir()
        source.write_text("new unit\n")
        backup = self.root / "backup"
        backup.mkdir()
        helpers = SOURCE[SOURCE.index("is_agent_deployment() {"):SOURCE.index("if (( NEW == 0 && CHANGED == 0 )); then")]
        helpers = helpers.replace('/etc/systemd/system/mrnobody-agent.service', str(unit))
        for role in ("master", "standalone", "bad", "agent"):
            self.config.write_text('MRNOBODY_ROLE="'+role+'"\n', encoding="utf-8")
            for previous in (None, "old unit\n", "new unit\n"):
                if previous is None:
                    unit.unlink(missing_ok=True)
                else:
                    unit.write_text(previous)
                script = 'set -eu\nlog() { :; }\nsystemctl() { printf "CALL:%s\\n" "$*"; }\n' + helpers + '\ninstall_agent_unit\n'
                result = subprocess.run([BASH], input=script, text=True, capture_output=True,
                                        env=dict(os.environ, INSTALL_DIR=str(self.root), BACKUP_DIR=str(backup)), timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                if role == "agent":
                    self.assertEqual(unit.read_text(), "new unit\n")
                    self.assertEqual("CALL:daemon-reload" in result.stdout, previous != "new unit\n")
                    if previous == "old unit\n":
                        self.assertEqual((backup / "system/systemd/mrnobody-agent.service").read_text(), previous)
                else:
                    self.assertEqual(unit.read_text() if unit.exists() else None, previous)
                    self.assertNotIn("CALL:", result.stdout)
                self.assertNotIn("enable", result.stdout)
                self.assertNotIn("start", result.stdout)

    @unittest.skipUnless(BASH, "Bash lifecycle runs on Linux/CI")
    def test_full_update_no_change_repair_and_rollback_preserve_data_and_backups(self):
        remote = self.root / "remote"
        remote.mkdir()
        payload = b"new release\n"
        (remote / "release").write_bytes(payload)
        (remote / "update-manifest.txt").write_text(hashlib.sha256(payload).hexdigest()+"|release\n")
        (self.root / "release").write_text("old release\n")
        (self.root / "systemd").mkdir()
        (self.root / "systemd/mrnobody-agent.service").write_text("new unit\n")
        unit = self.root / "active.service"
        unit.write_text("old unit\n")
        backups = self.root / "backups"
        backups.mkdir()
        sentinels = {self.root / "agent.json": b"private identity", self.root / "registry.sqlite3": b"registry data"}
        for path, content in sentinels.items():
            path.write_bytes(content)
        original_config = self.config.read_bytes()
        binary = self.root / "bin"
        binary.mkdir()
        curl = binary / "curl"
        curl.write_text("#!"+sys.executable+"\n" + '''import os, pathlib, shutil, sys
args=sys.argv[1:]
url=next(arg for arg in args if arg.startswith("https://"))
shutil.copyfile(pathlib.Path(os.environ["TEST_REMOTE"])/url.rsplit("/",1)[1], args[args.index("-o")+1])
''')
        curl.chmod(0o755)
        systemctl = binary / "systemctl"
        systemctl.write_text('''#!/bin/sh
echo "$*" >> "$TEST_CALLS"
[ "$1" != is-active ] || exit 1
if [ "$1" = daemon-reload ] && [ "$TEST_FAIL" = 1 ]; then exit 1; fi
exit 0
''')
        systemctl.chmod(0o755)
        script = self.root / "update.sh"
        script.write_text(SOURCE.replace("/var/backups", str(backups)).replace(
            "/etc/systemd/system/mrnobody-agent.service", str(unit)))
        calls = self.root / "calls"
        env = dict(os.environ, PATH=str(binary)+os.pathsep+os.environ["PATH"], NORDIC_BASE_DIR=str(self.root),
                   TEST_REMOTE=str(remote), TEST_CALLS=str(calls), TEST_FAIL="0")
        for iteration in range(2):
            if iteration:
                unit.unlink()  # All hashes match, but the installed service is missing.
            result = subprocess.run([BASH, str(script)], env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(unit.read_text(), "new unit\n")
            self.assertEqual((self.root / "release").read_bytes(), payload)
        self.assertTrue(list(backups.glob("*/install/release")))
        operations = calls.read_text()
        self.assertNotIn("enable", operations)
        self.assertNotIn("start", operations)
        # A failed systemd reload after installation must restore both code and unit.
        unit.write_text("old unit\n")
        (self.root / "release").write_text("old release\n")
        env["TEST_FAIL"] = "1"
        result = subprocess.run([BASH, str(script)], env=env, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn("Rollback completed", result.stdout)
        self.assertEqual(unit.read_text(), "old unit\n")
        self.assertEqual((self.root / "release").read_text(), "old release\n")
        # The no-change path also restores a stale unit if daemon-reload fails.
        (self.root / "release").write_bytes(payload)
        result = subprocess.run([BASH, str(script)], env=env, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn("Agent service repair failed", result.stdout)
        self.assertEqual(unit.read_text(), "old unit\n")
        for path, content in sentinels.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertEqual(self.config.read_bytes(), original_config)

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
    def test_actual_cloud_init_block_without_credentials_installs_only_agent(self):
        import yaml
        data = yaml.safe_load((ROOT / "MRNOBODY/mrnobody_userdata.yaml").read_text())
        bootstrap = next(item["content"] for item in data["write_files"] if item["path"] == "/usr/local/sbin/install-mrnobody")
        syntax = subprocess.run([BASH, "-n"], input=bootstrap, text=True, capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        block = bootstrap[bootstrap.index("# Install only on a valid agent deployment."):]
        block = block[:block.index("# ======================================================")]
        unit = self.root / "active.service"
        block = block.replace("/etc/systemd/system/mrnobody-agent.service", str(unit))
        (self.root / "systemd").mkdir()
        (self.root / "systemd/mrnobody-agent.service").write_text("agent unit\n")
        for role in ("agent", "master", "standalone", "bad"):
            unit.unlink(missing_ok=True)
            self.config.write_text('MRNOBODY_ROLE="'+role+'"\n')
            result = subprocess.run([BASH], input='set -eu\nlog() { :; }\nsystemctl() { echo "CALL:$*"; }\n'+block,
                                    text=True, capture_output=True, env=dict(os.environ, INSTALL_DIR=str(self.root)))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(unit.exists(), role == "agent")
            self.assertEqual("CALL:daemon-reload" in result.stdout, role == "agent")
            self.assertNotIn("enable", result.stdout)
            self.assertNotIn("start", result.stdout)

    @unittest.skipUnless(BASH, "Bash lifecycle runs on Linux/CI")
    def test_lab_cloud_init_and_update_bootstrap_enable_offline_and_preserve_identity(self):
        import yaml
        data=yaml.safe_load((ROOT/"MRNOBODY/mrnobody_userdata.yaml").read_text())
        bootstrap=next(item["content"] for item in data["write_files"] if item["path"]=="/usr/local/sbin/install-mrnobody")
        cloud=bootstrap[bootstrap.index("# Install only on a valid agent deployment."):]
        cloud=cloud[:cloud.index("# ======================================================")]
        update=SOURCE[SOURCE.index("is_agent_deployment() {"):SOURCE.index("if (( NEW == 0 && CHANGED == 0 )); then")]+"\ninstall_agent_unit\n"
        credentials=self.root/"agent.json"
        for name in ("agent_client.py","master_registry.py"):
            text=(PLATFORM/"web"/name).read_text()
            text=text.replace('CREDENTIALS=Path("/etc/mrnobody/agent.json")',
                              "CREDENTIALS=Path("+json.dumps(str(credentials))+")")
            (self.web/name).write_text(text)
        unit=self.root/"installed.service"
        (self.root/"systemd").mkdir()
        (self.root/"systemd/mrnobody-agent.service").write_text("agent unit\n")
        backup=self.root/"backup"
        backup.mkdir()
        original=None
        for role in ("master","standalone","bad","agent","agent"):
            self.config.write_text('MRNOBODY_ROLE="'+role+'"\nMRNOBODY_MASTER_URL="http://10.134.71.3"\nMRNOBODY_LAB_HTTP="1"\n')
            for block in (cloud,update):
                script='set -eu\nlog() { :; }\nsystemctl() { echo "CALL:$*"; }\n'+block
                script=script.replace("/etc/systemd/system/mrnobody-agent.service",str(unit))
                result=subprocess.run([BASH],input=script,text=True,capture_output=True,
                                      env=dict(os.environ,INSTALL_DIR=str(self.root),BACKUP_DIR=str(backup)),timeout=10)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual("CALL:enable --now mrnobody-agent.service" in result.stdout,role=="agent")
                if role=="agent":
                    if original is None:
                        original=credentials.read_bytes()
                    self.assertEqual(credentials.read_bytes(),original)
                    self.assertEqual(credentials.stat().st_mode&0o777,0o600)
                else:
                    self.assertFalse(credentials.exists())
                    self.assertFalse(unit.exists())

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
