"""Isolated checks: Flask and every process launch are replaced with test doubles."""
import ast
import importlib.util
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import Mock, patch

routes = {}

class FakeFlask:
    def __init__(self, *args):
        self.url_map = types.SimpleNamespace()

    def errorhandler(self, code):
        return lambda function: function

    def route(self, url, **options):
        def register(function):
            routes[url] = (function, options)
            return function
        return register

request = types.SimpleNamespace(is_json=True, files={})
fake_flask = types.ModuleType("flask")
fake_flask.Flask = FakeFlask
fake_flask.Response = Mock()
fake_flask.jsonify = lambda data: data
fake_flask.render_template = Mock()
fake_flask.request = request
source = Path(__file__).resolve().parents[2] / "TESTFILES/ATTACKER-V2/web/app.py"
sys.path.insert(0, str(source.parent))
ast.parse(source.read_text(encoding="utf-8"))
with patch.dict(sys.modules, {"flask": fake_flask}):
    spec = importlib.util.spec_from_file_location("application", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

assert module.health()["service"] == "MrNobody Incident Platform"

with tempfile.TemporaryDirectory(dir=source.parent.parent.resolve()) as temporary:
    root = Path(temporary)
    module.BASE_DIR = root
    module.SCENARIO_DIR = root / "scenarios"
    module.SCENARIO_DIR.mkdir()
    module.STATE_DIR = root / "state"
    module.LOG_DIR = root / "logs"
    module.CAMPAIGN_LOG = root / "logs" / "campaign.log"
    module.CONFIG_FILE = root / "missing.conf"
    for filename, scenario_id in [("full-incident", "full-incident"), ("different-filename", "custom")]:
        (module.SCENARIO_DIR / (filename + ".sh")).write_text(
            '# SCENARIO_ID="' + scenario_id + '"\n# SCENARIO_NAME="Test ' + scenario_id + '"\n',
            encoding="utf-8",
        )
    (module.SCENARIO_DIR / "fallback.sh").write_text("# no metadata\n")
    assert module.find_scenario("fallback")["path"].name == "fallback.sh"
    assert module.find_scenario("../outside") is None
    assert module.api_scenarios()["count"] == 3
    assert routes["/api/start"][1]["defaults"] == {"scenario_id": "full-incident"}
    assert routes["/api/start"][0] is routes["/api/scenario/<scenario_id>/start"][0]
    payload = {"incident_ip": "192.168.1.254", "ssh_password": "ssh-test-secret",
               "rdp_password": "rdp-test-secret"}
    request.get_json = lambda **kwargs: payload.copy()
    with patch.object(module, "determine_incident_ip", return_value="192.168.1.254"), patch.object(
        module, "launch"
    ) as launch:
        launch.return_value.pid = 123
        launch.return_value.poll.return_value = None
        for scenario_id, filename in [("full-incident", "full-incident"), ("custom", "different-filename")]:
            module.campaign_process = None
            result = module.api_start() if scenario_id == "full-incident" else module.api_start(scenario_id)
            assert result["scenario_id"] == scenario_id
            assert result["pid"] == 123
            args, kwargs = launch.call_args
            assert args[1][-1] == str(module.SCENARIO_DIR / (filename + ".sh"))
            assert kwargs["env"]["NORDIC_SSH_PASSWORD"] == payload["ssh_password"]
            assert kwargs["env"]["NORDIC_RDP_PASSWORD"] == payload["rdp_password"]
            kwargs["stdout"].close()
        assert module.api_start("custom")[1] == 409
        module.campaign_process = None
        launch.reset_mock()
        assert module.api_start("missing")[1] == 404
        payload["ssh_password"] = ""
        assert module.api_start("custom")[1] == 400
        launch.assert_not_called()
        log = module.CAMPAIGN_LOG.read_text()
        assert "Test custom (custom)" in log
        assert "ssh-test-secret" not in log and "rdp-test-secret" not in log
    # The phase body must remain in its own function after relocating the scenario route.
    module.SCRIPT_DIR = root / "missing-scripts"
    assert module.api_run_phase("01")[1] == 404

    # Existing shared log/state files are read verbatim, including historical IDs.
    historical = "H3-20261031-072933"
    module.CAMPAIGN_LOG.write_text(historical + " historical output\n", encoding="utf-8")
    request.args = {"lines": "300"}
    assert historical in module.api_log()["log"]
    request.args = {"lines": "invalid"}
    assert historical in module.api_log()["log"]

with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temporary:
    from reports import save_report
    module.BASE_DIR = Path(temporary)
    assert module.api_reports() == {"count": 0, "reports": []}
    report = {"schema_version": 1, "incident": {"id": "MRN-fixture", "status": "complete", "started": "2026-11-01"},
              "summary": {"hosts": 2}}
    save_report(module.BASE_DIR, report)
    assert module.api_reports()["reports"][0]["summary"]["hosts"] == 2
    assert module.api_report("MRN-fixture")["report_type"] == "campaign"
    request.args = {"raw": "1"}
    assert module.api_report("MRN-fixture") == report
    request.args = {}
    phase_report = {**report, "report_type": "standalone_phase", "phase_id": "03",
                    "incident": {**report["incident"], "id": "MRN-phase"}}
    save_report(module.BASE_DIR, phase_report)
    assert module.api_report("MRN-phase")["phase_id"] == "03"
    assert {r["report_type"] for r in module.api_reports()["reports"]} == {"campaign", "standalone_phase"}
    for identifier in ["MRN-missing", "../campaign", "MRN-../outside"]:
        assert module.api_report(identifier)[1] == 404
    (module.BASE_DIR / "reports/MRN-corrupt.json").write_text("{broken", encoding="utf8")
    (module.BASE_DIR / "reports/MRN-invalid.json").write_text('{"schema_version":1,"incident":[]}', encoding="utf8")
    assert module.api_reports()["count"] == 2
    assert module.api_report("MRN-corrupt")[1] == 404
    assert module.api_report("MRN-invalid")[1] == 404

print("Python syntax and isolated backend checks passed; no processes launched.")

