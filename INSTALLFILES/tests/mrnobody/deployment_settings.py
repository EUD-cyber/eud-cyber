"""Offline deployment configuration and additive health metadata checks."""
import ast
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "TESTFILES/ATTACKER-V2/web"
sys.path.insert(0, str(WEB))
from deployment_config import DeploymentConfig, load_deployment_config


class DeploymentSettings(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        assert self.directory.resolve().parent == ROOT.resolve()
        self.config = self.directory / "deployment.conf"

    def read(self, text):
        self.config.write_bytes(text.encode("utf-8"))
        return load_deployment_config(self.config)

    def test_plain_http_is_an_explicit_lab_choice(self):
        self.assertEqual(self.read("MRNOBODY_ROLE=agent\nMRNOBODY_MASTER_URL=http://master.test\n").config_status,"invalid")
        loaded=self.read("MRNOBODY_ROLE=agent\nMRNOBODY_MASTER_URL=http://master.test\nMRNOBODY_LAB_HTTP=1\n")
        self.assertEqual((loaded.role,loaded.master_url,loaded.lab_http),("agent","http://master.test",True))
        self.assertEqual(loaded.public_status()["master_scheme"],"http")
        self.assertIsNone(loaded.public_status()["transport_enabled"])
        master=self.read("MRNOBODY_ROLE=master\nMRNOBODY_LAB_HTTP=1\n")
        self.assertTrue(master.public_status()["lab_http_enabled"])
        self.assertEqual(self.read("MRNOBODY_LAB_HTTP=true\n").config_status,"invalid")
        self.assertEqual(self.read("MRNOBODY_LAB_HTTP=1\nMRNOBODY_LAB_HTTP=0\n").config_status,"invalid")

    def test_missing_file_preserves_standalone(self):
        self.assertEqual(load_deployment_config(self.config), DeploymentConfig())

    def test_installer_quotes_and_line_endings(self):
        for role in ("standalone", "agent", "master"):
            for url in ("", "https://master.example", "https://192.0.2.1:8443/api/v1/"):
                for newline in ("\n", "\r\n"):
                    with self.subTest(role=role, url=url, newline=repr(newline)):
                        text = newline.join((
                            "# Local deployment settings",
                            f"MRNOBODY_ROLE={shlex.quote(role)}",
                            f"MRNOBODY_MASTER_URL={shlex.quote(url)}",
                            "",
                        ))
                        self.assertEqual(self.read(text), DeploymentConfig(role, url, "loaded"))

    def test_empty_and_partial_files_keep_compatible_defaults(self):
        self.assertEqual(self.read("# comment only\n"), DeploymentConfig(config_status="loaded"))
        self.assertEqual(self.read('MRNOBODY_MASTER_URL=""\n'), DeploymentConfig(config_status="loaded"))
        self.assertEqual(self.read("MRNOBODY_ROLE=agent\n"),
                         DeploymentConfig("agent", "", "loaded"))

    def test_invalid_settings_never_become_active(self):
        invalid = (
            "MRNOBODY_ROLE=controller", "MRNOBODY_ROLE=slave", "MRNOBODY_ROLE=",
            "MRNOBODY_ROLE=agent extra", 'MRNOBODY_ROLE="agent',
            "MRNOBODY_ROLE=agent\nMRNOBODY_ROLE=standalone",
            "OTHER_SETTING=agent", "export MRNOBODY_ROLE=agent", "not an assignment",
            "MRNOBODY_MASTER_URL=http://master.example",
            "MRNOBODY_MASTER_URL=https://user:secret@master.example",
            "MRNOBODY_MASTER_URL=https://master.example?token=secret",
            "MRNOBODY_MASTER_URL=https://master.example/#fragment",
            "MRNOBODY_MASTER_URL=https://master.example:0",
            "MRNOBODY_MASTER_URL=https://master.example:65536",
            "MRNOBODY_MASTER_URL=https://master.example:123456",
            "MRNOBODY_MASTER_URL=https://master.example/path more",
        )
        for text in invalid:
            with self.subTest(text=text):
                self.assertEqual(self.read(text), DeploymentConfig(config_status="invalid"))

    def test_shell_and_environment_are_not_executed_or_expanded(self):
        with patch("subprocess.run", side_effect=AssertionError("unexpected process")), \
             patch("socket.create_connection", side_effect=AssertionError("unexpected network")), \
             patch.dict("os.environ", {"MRNOBODY_ROLE": "master", "MRNOBODY_MASTER_URL": "https://stale.example"}):
            self.assertEqual(load_deployment_config(self.config), DeploymentConfig())
            for text in ("MRNOBODY_ROLE=$(id)", "MRNOBODY_ROLE=$MRNOBODY_ROLE",
                         'MRNOBODY_MASTER_URL="https://master.example/$(id)"'):
                self.assertEqual(self.read(text).config_status, "invalid")

    def test_unreadable_and_non_utf8_files_remain_inactive(self):
        with patch.object(Path, "read_text", side_effect=PermissionError):
            self.assertEqual(load_deployment_config(self.config).config_status, "invalid")
        self.config.write_bytes(b"\xff\xfe")
        self.assertEqual(load_deployment_config(self.config).config_status, "invalid")

    def test_configuration_is_a_snapshot(self):
        first = self.read("MRNOBODY_ROLE=agent\n")
        second = self.read("MRNOBODY_ROLE=standalone\n")
        self.assertEqual(first.role, "agent")
        self.assertEqual(second.role, "standalone")

    def test_health_contract_without_importing_campaign_runtime(self):
        # Execute the actual route body in isolation; importing the full backend
        # and its downloaded dependencies is covered by existing install tests.
        source = ast.parse((WEB / "app.py").read_text(encoding="utf-8"))
        health = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == "health")
        health.decorator_list = []
        code = compile(ast.Module(body=[health], type_ignores=[]), str(WEB / "app.py"), "exec")
        for config in (DeploymentConfig(), DeploymentConfig("agent", "", "loaded"), DeploymentConfig("master", "", "loaded"),
                       DeploymentConfig("agent", "https://master.example/private", "loaded"),
                       DeploymentConfig(config_status="invalid")):
            namespace = {"jsonify": lambda value: value, "DEPLOYMENT_CONFIG": config}
            exec(code, namespace)
            result = namespace["health"]()
            self.assertEqual({key: result[key] for key in ("status", "service", "version")},
                             {"status": "ok", "service": "MrNobody Incident Platform", "version": "2.1"})
            self.assertEqual(result["deployment"], config.public_status())
            self.assertFalse(result["deployment"]["transport_enabled"])
            self.assertEqual(result["deployment"]["master_url_configured"], bool(config.master_url))
            self.assertNotIn("master_url", result["deployment"])
            self.assertNotIn("https://", str(result))


if __name__ == "__main__":
    unittest.main()
