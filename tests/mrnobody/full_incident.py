"""Offline orchestration regression tests; no real phase programs are executed.

Run: python3 -m unittest discover -s tests/mrnobody -p full_incident.py
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "TESTFILES/ATTACKER-V2/scenarios/full-incident.sh"
IDS = "01 02 03 09 11 04 05 06 07".split()
INCIDENT = "MRN-20261107-125354-69f8804a7a49"


class FullIncidentTests(unittest.TestCase):
    def run_campaign(self, *, mode="normal", child_code=0, target_mode="fixed", corrupt=None):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in ("config", "scripts", "web", "state", "logs"):
                (base / name).mkdir()
            defaults = {
                "NORDIC_DEFAULT_WEB_PORTS": "80", "NORDIC_DEFAULT_EXFIL_PORT": "8080",
                "NORDIC_DEFAULT_SSH_USER": "stub", "NORDIC_DEFAULT_SSH_PASSWORD": "stub",
                "NORDIC_DEFAULT_SSH_PORT": "22", "NORDIC_DEFAULT_RDP_USER": "stub",
                "NORDIC_DEFAULT_RDP_PASSWORD": "stub", "NORDIC_DEFAULT_RDP_PORT": "3389",
                "NORDIC_STATE_DIR": str(base / "state"),
                "NORDIC_GROUND_TRUTH_LOG": str(base / "logs/truth.log"),
            }
            for key, filename in {
                "NETWORK": "network", "DISCOVERED": "discovered", "WEB": "web",
                "COMPROMISED": "compromised", "CAMPAIGN": "campaign",
                "STAGING": "staged-data", "EXFIL": "exfiltration", "IMPACT": "impact",
            }.items():
                defaults[f"NORDIC_{key}_STATE"] = str(base / f"state/{filename}.json")
            (base / "config/defaults.conf").write_text("".join(
                f"{key}={json.dumps(value)}\n" for key, value in defaults.items()))
            # Every validated executable is a harmless stub, even disabled phases.
            for filename in re.findall(r'PHASE_\d+="\$SCRIPT_DIR/([^"]+)"', SOURCE.read_text()):
                path = base / "scripts" / filename
                path.write_text("#!/usr/bin/env bash\ncat >/dev/null\nexit 0\n")
                path.chmod(0o755)
            (base / "web/reports.py").write_text("# Reporting is outside this test.\n")
            (base / "web/execution.py").write_text('''import json, os, sys
from pathlib import Path
base = Path(os.environ["NORDIC_BASE_DIR"])
ids = [p["id"] for p in json.loads(os.environ["MRN_EXECUTION"])["phases"]]
mode = os.environ["TEST_LIST_MODE"]
if "--list" in sys.argv:
    if mode == "empty": sys.exit(0)
    if mode == "failed": sys.exit(42)
    if mode == "partial_failure":
        print(ids[0])
        sys.exit(42)
    if mode == "invalid": ids[2] = "../invalid"
    if mode == "duplicate": ids[2] = ids[0]
    if mode == "mismatch": ids = ids[:-1]
    if mode == "reordered": ids.reverse()
    print("\\n".join(ids))
else:
    pid = sys.argv[sys.argv.index("--phase") + 1]
    with (base / "dispatched").open("a") as handle: handle.write(pid + "\\n")
    # Deliberately consume inherited stdin: this drained the old outer loop.
    if pid == "03": sys.stdin.read()
    corrupt = os.environ.get("TEST_CORRUPT")
    if pid == ids[-1] and corrupt:
        path = base / "state/campaign.json"
        data = json.loads(path.read_text())
        if corrupt == "missing": data["phases"].pop(ids[0])
        else: data["phases"][ids[0]] = corrupt
        path.write_text(json.dumps(data))
    sys.exit(int(os.environ["TEST_CHILD_CODE"]) if pid == "11" else 0)
''')
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("NORDIC_", "MRN_", "MRNOBODY_"))}
            env.update(NORDIC_BASE_DIR=str(base), NORDIC_INCIDENT_ID=INCIDENT,
                       MRN_EXECUTION=json.dumps({"id": "full-incident", "name": "fixture",
                           "target_mode": target_mode, "phases": [{"id": pid} for pid in IDS]}),
                       TEST_LIST_MODE=mode, TEST_CHILD_CODE=str(child_code),
                       TEST_CORRUPT=corrupt or "")
            result = subprocess.run(["bash", str(SOURCE)], input="", text=True,
                                    capture_output=True, env=env, timeout=30)
            dispatched = (base / "dispatched").read_text().splitlines() if (base / "dispatched").exists() else []
            state = json.loads((base / "state/campaign.json").read_text())
            truth = (base / "logs/truth.log").read_text()
            return result, dispatched, state, truth

    def test_stdin_reader_dispatches_entire_incident_plan(self):
        result, dispatched, state, truth = self.run_campaign(child_code=78)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(dispatched, IDS)
        self.assertEqual(state["incident_id"], INCIDENT)
        self.assertEqual(state["status"], "complete")
        self.assertEqual(state["phases"]["11"], "skipped")
        for pid in ("08", "10"):
            self.assertEqual(state["phases"][pid], "disabled")
        self.assertNotIn("pending", state["phases"].values())
        self.assertIn("CAMPAIGN_COMPLETE", truth)

    def test_bad_lists_fail_before_dispatch(self):
        for mode in ("empty", "failed", "partial_failure", "invalid", "duplicate", "mismatch", "reordered"):
            with self.subTest(mode=mode):
                result, dispatched, state, truth = self.run_campaign(mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(dispatched, [])
                self.assertEqual(state["status"], "failed")
                self.assertNotIn("completed", state)
                self.assertNotIn("CAMPAIGN_COMPLETE", truth)

    def test_windows_access_skip_is_preserved(self):
        result, dispatched, state, _ = self.run_campaign(target_mode="auto")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(dispatched, [pid for pid in IDS if pid != "09"])
        self.assertEqual(state["phases"]["09"], "disabled")

    def test_child_failure_stops_and_records_failure(self):
        result, dispatched, state, truth = self.run_campaign(child_code=23)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(dispatched, IDS[:5])
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["phases"]["11"], "failed")
        self.assertNotIn("completed", state)
        self.assertNotIn("CAMPAIGN_COMPLETE", truth)

    def test_completion_guard_rejects_unfinished_or_missing_steps(self):
        for corrupt in ("pending", "running", "missing", "failed"):
            with self.subTest(corrupt=corrupt):
                result, dispatched, state, truth = self.run_campaign(corrupt=corrupt)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(dispatched, IDS)
                self.assertEqual(state["status"], "failed" if corrupt == "failed" else "partial")
                self.assertNotIn("completed", state)
                self.assertNotIn("CAMPAIGN_COMPLETE", truth)
                self.assertIn("CAMPAIGN_INCOMPLETE", truth)


if __name__ == "__main__":
    unittest.main()
