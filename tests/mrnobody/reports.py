"""Ground-truth snapshots and real scenario orchestration with harmless mock phases."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / "TESTFILES/ATTACKER-V2"
sys.path.insert(0, str(PLATFORM / "web"))
from reports import build_report, save_report, load_report, list_reports, read_metadata, mitre_url, redact, run_phase


class Reports(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2])
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        for name in ["state", "logs", "scripts"]:
            (self.base / name).mkdir()
        self.id = "MRN-20261101-120000"
        self.write("campaign.json", {"started": "2026-11-01T12:00:00.123+00:00",
                   "completed": "2026-11-01T12:01:00+00:00", "status": "complete",
                   "phases": {"01": "complete", "03": "complete", "08": "disabled"}})
        self.write("discovered-hosts.json", {"hosts": [{"ip": "192.168.1.20"}]})
        self.write("compromised-hosts.json", {"hosts": [{"ip": "192.168.1.20", "password": "SECRET",
                   "access_methods": {"ssh": {"password": "NESTED", "username": "student"}}}]})
        self.write("staged-data.json", {"hosts": [{"ip": "192.168.1.20", "file": "/tmp/sample", "sha256": "abc"}]})
        self.write("exfiltration.json", {"transfers": [{"source": "192.168.1.20", "destination": "192.168.1.254", "successful": True}]})
        shutil.copy(PLATFORM / "scripts/03-access.sh", self.base / "scripts/03-access.sh")
        lines = [
            f"2026-11-01T12:00:00+00:00 INCIDENT={self.id} CAMPAIGN PHASE_START phase=03 name=\"Initial Access\"",
            f"2026-11-01T12:00:01+00:00 INCIDENT={self.id} PHASE=03 ACCESS_SUCCESS access=ssh ip=192.168.1.20 os=Ubuntu Linux",
            f"2026-11-01T12:00:02+00:00 INCIDENT={self.id} PHASE=03 ACCESS_FAILED access=rdp ip=192.168.1.21",
            f"2026-11-01T12:00:03+00:00 INCIDENT={self.id} PHASE=03 RDP_AUTH_SKIPPED ip=192.168.1.22 reason=client_unavailable",
            f"2026-11-01T12:00:04+00:00 INCIDENT={self.id} CAMPAIGN PHASE_COMPLETE phase=03",
            "2026-11-01T12:00:04+00:00 INCIDENT=MRN-other PHASE=03 ACCESS_SUCCESS ip=other",
            f"2026-10-31T12:00:00+00:00 INCIDENT={self.id} PHASE=03 ACCESS_SUCCESS ip=old",
        ]
        (self.base / "logs/incident-ground-truth.log").write_text("\n".join(lines), encoding="utf8")

    def write(self, filename, data):
        (self.base / "state" / filename).write_text(json.dumps({"incident_id": self.id, **data}), encoding="utf8")

    def test_snapshot_evidence_and_outcomes(self):
        before = {p: p.read_bytes() for p in self.base.rglob("*") if p.is_file()}
        report = build_report(self.base, self.id)
        self.assertEqual(report["incident"]["status"], "complete")
        self.assertEqual(report["summary"], {"hosts": 1, "compromised": 1, "exfiltration": 1, "impact": 0})
        self.assertEqual([p["id"] for p in report["phases"]], ["01", "02", "03", "08", "04", "05", "06", "07"])
        phase = report["phases"][2]
        self.assertEqual(phase["status"], "success")
        self.assertEqual(phase["outcomes"]["failure"], 1)
        self.assertEqual(phase["outcomes"]["skipped"], 1)
        self.assertIsNotNone(phase["started"])  # Second-resolution logs versus subsecond state.
        self.assertEqual(phase["mitre"]["techniques"], [{"id": "T1078", "name": "Valid Accounts", "url": mitre_url("T1078")}])
        self.assertEqual(phase["events"][1]["protocol"], "ssh")
        self.assertEqual(phase["events"][1]["fields"]["os"], "Ubuntu Linux")
        self.assertEqual(phase["events"][1]["mitre_technique_ids"], ["T1078"])
        self.assertEqual(report["phases"][3]["status"], "skipped")
        self.assertEqual(len(report["events"]), 5)
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertNotIn("NESTED", json.dumps(report))
        path = save_report(self.base, report)
        original = path.read_bytes()
        save_report(self.base, {**report, "warnings": ["replacement"]})
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(load_report(path.parent, self.id), report)
        self.assertEqual(len(list_reports(path.parent)), 1)
        second = {**report, "incident": {**report["incident"], "id": "MRN-newer", "started": "2026-11-02T00:00:00+00:00"}}
        save_report(self.base, second)
        self.assertEqual([r["id"] for r in list_reports(path.parent)], ["MRN-newer", self.id])
        self.assertEqual(list(path.parent.glob(".report-*")), [])
        for p, content in before.items():
            self.assertEqual(p.read_bytes(), content)

    def test_missing_corrupt_and_foreign_state(self):
        self.write("impact.json", {"incident_id": "MRN-other", "hosts": [{"ip": "foreign"}]})
        (self.base / "state/web-targets.json").write_text("{broken", encoding="utf8")
        report = build_report(self.base, self.id, 1)
        self.assertEqual(report["incident"]["status"], "failed")
        self.assertIsNone(report["evidence"]["impact"])
        self.assertIsNone(report["evidence"]["web_targets"])
        self.assertTrue(report["warnings"])
        self.assertEqual(build_report(self.base, self.id, 143)["incident"]["status"], "interrupted")
        with self.assertRaises(ValueError):
            build_report(self.base, "MRN-other")
        for identifier in ["../campaign", "MRN-../outside", "MRN-x/other"]:
            with self.assertRaises(ValueError):
                load_report(self.base, identifier)
        (self.base / "MRN-broken.json").write_text("[]", encoding="utf8")
        self.assertEqual(list_reports(self.base), [])
        if os.name != "nt":
            directory = self.base / "reports"
            directory.mkdir()
            (directory / "MRN-link.json").symlink_to(self.base / "state/campaign.json")
            with self.assertRaises(ValueError):
                load_report(directory, "MRN-link")

    def test_metadata_compatibility(self):
        path = self.base / "scripts/09-custom.sh"
        path.write_text('# ATTACK_ID = "09"\n# MITRE_TECHNIQUES="T9999"\n# ATTACK_NAME="Custom"\n', encoding="utf8")
        self.assertEqual(read_metadata(path)["ATTACK_ID"], "09")
        self.assertEqual(read_metadata(path)["ATTACK_NAME"], "Custom")

    def test_educational_sections_and_mitre(self):
        report = build_report(self.base, self.id)
        phase = report["phases"][2]
        analysis = phase["analysis"]
        self.assertIn("ACCESS_FAILED", " ".join(analysis["findings"]))
        self.assertIn("RDP_AUTH_SKIPPED", " ".join(analysis["findings"]))
        for key in ["what_happened", "findings", "evidence", "detection", "investigation_tasks", "prevention", "guidance_notice", "mitre_notice"]:
            self.assertTrue(analysis[key], key)
        self.assertIn("Wazuh", analysis["detection"][0])
        self.assertIn("No action-level evidence", report["phases"][3]["analysis"]["findings"][0])
        self.assertEqual(report["mitre_summary"][0]["mapping"], "phase_metadata")
        self.assertEqual(mitre_url("T1110.001"), "https://attack.mitre.org/techniques/T1110/001/")
        for invalid in [None, "T1078/../../", "javascript:alert(1)", "T1234.1"]:
            self.assertIsNone(mitre_url(invalid))

    def test_redaction_and_historical_view(self):
        dirty = {"password": "SECRET", "ssh_password": "SECRET", "candidate_passwords": ["SECRET"],
                 "wordlist_contents": "SECRET", "credential_method": "wordlist",
                 "message": "ACTION password=SECRET WITH SPACES target=host", "url": "https://user:SECRET@host/"}
        self.assertNotIn("SECRET", json.dumps(redact(dirty)))
        self.assertEqual(redact({"candidate_passwords": 12}), {"candidate_passwords": 12})
        old = {"schema_version": 1, "incident": {"id": self.id}, "phases": [], "message": "password=SECRET"}
        path = save_report(self.base, old)
        before = path.read_bytes()
        self.assertEqual(load_report(path.parent, self.id)["report_type"], "campaign")
        self.assertNotIn("analysis_version", load_report(path.parent, self.id, enrich=False))
        self.assertNotIn("SECRET", json.dumps(load_report(path.parent, self.id)))
        self.assertEqual(path.read_bytes(), before)

    def test_standalone_wrapper_status_isolation_and_failures(self):
        before = (self.base / "state/campaign.json").read_bytes()
        for code in [0, 7, -15]:
            child = Mock()
            child.wait.return_value = code
            with patch("reports.subprocess.Popen", return_value=child) as launch:
                self.assertEqual(run_phase(self.base, "03", self.base / "scripts/03-access.sh", {}), 143 if code == -15 else code)
            env = launch.call_args.kwargs["env"]
            self.assertRegex(env["NORDIC_INCIDENT_ID"], r"^MRN-\d{8}-\d{6}-[a-f0-9]{12}$")
            report = load_report(self.base / "reports", env["NORDIC_INCIDENT_ID"])
            self.assertEqual(report["report_type"], "standalone_phase")
            self.assertEqual(report["phase_id"], "03")
            self.assertEqual(len(report["phases"]), 1)
            self.assertIsNone(report["inventory"])  # Foreign incident state is not attributed to this run.
            self.assertEqual(report["events"], [])
            self.assertTrue(report["phases"][0]["started"])
        self.assertEqual(len(list_reports(self.base / "reports")), 3)
        self.assertEqual((self.base / "state/campaign.json").read_bytes(), before)
        with patch("reports.subprocess.Popen", return_value=child), patch("reports.save_report", side_effect=OSError):
            self.assertEqual(run_phase(self.base, "03", Path("fixture"), {}), 143)


@unittest.skipUnless("--bash" in sys.argv or os.environ.get("REPORT_TEST_BASH"), "Bash orchestration enabled explicitly")
class CampaignIntegration(unittest.TestCase):
    def test_standalone_runner_with_mock_phase(self):
        shell = os.environ.get("REPORT_TEST_BASH", "bash")
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            base = Path(temporary).resolve()
            for directory in ["scripts", "web", "config", "state", "logs", "bin"]:
                (base / directory).mkdir()
            shutil.copy(PLATFORM / "scripts/run-phase.sh", base / "scripts/run-phase.sh")
            shutil.copy(PLATFORM / "web/reports.py", base / "web/reports.py")
            (base / "config/defaults.conf").write_text(
                'NORDIC_STATE_DIR="$NORDIC_BASE_DIR/state"\nNORDIC_GROUND_TRUTH_LOG="$NORDIC_BASE_DIR/logs/incident-ground-truth.log"\n', encoding="utf8")
            campaign = base / "state/campaign.json"
            campaign.write_text('{"incident_id":"MRN-campaign","status":"complete"}', encoding="utf8")
            before = campaign.read_bytes()
            script = base / "scripts/03-access.sh"
            script.write_text('''#!/usr/bin/env bash
# ATTACK_ID="03"
# ATTACK_NAME="Fixture access"
# ATTACK_ALIAS="access"
# MITRE_TECHNIQUES="T1078,T1110.001"
printf '%s INCIDENT=%s PHASE=03 ACCESS_FAILED target=fixture protocol=ssh password=SECRET\\n' "$(date --iso-8601=seconds)" "$NORDIC_INCIDENT_ID" >> "$NORDIC_GROUND_TRUTH_LOG"
if [[ "${FIXTURE_EXIT:-0}" == signal ]]; then kill -TERM "$PPID"; exit 0; fi
exit "${FIXTURE_EXIT:-0}"
''', encoding="utf8", newline="\n")
            script.chmod(0o755)
            wrapper = base / "bin/python3"
            wrapper.write_text('#!/bin/sh\nexec "' + Path(sys.executable).as_posix() + '" "$@"\n', encoding="utf8", newline="\n")
            wrapper.chmod(0o755)
            env = {**os.environ, "NORDIC_BASE_DIR": base.as_posix(), "NORDIC_INCIDENT_ID": "MRN-campaign",
                   "PATH": str(base / "bin") + os.pathsep + os.environ["PATH"]}
            runner = [shell, str(base / "scripts/run-phase.sh"), "03"]
            dry = subprocess.run(runner + ["--dry-run"], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(dry.returncode, 0, dry.stderr)
            self.assertFalse((base / "reports").exists())
            for exit_code, options in [("0", []), ("7", ["--target", "fixture"]), ("signal", [])]:
                result = subprocess.run(runner + options, env={**env, "FIXTURE_EXIT": exit_code}, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 143 if exit_code == "signal" else int(exit_code), result.stdout + result.stderr)
            rows = list_reports(base / "reports")
            self.assertEqual(len(rows), 3)
            self.assertEqual({r["status"] for r in rows}, {"complete", "failed", "interrupted"})
            self.assertEqual(len({r["id"] for r in rows}), 3)
            for row in rows:
                report = load_report(base / "reports", row["id"])
                self.assertEqual(row["report_type"], "standalone_phase")
                self.assertEqual([p["id"] for p in report["phases"]], ["03"])
                self.assertEqual(len(report["events"]), 1)
                self.assertIn("ACCESS_FAILED", report["phases"][0]["analysis"]["findings"][0])
                self.assertNotIn("SECRET", json.dumps(report))
                self.assertEqual(report["phases"][0]["mitre"]["techniques"][1]["url"], mitre_url("T1110.001"))
            self.assertEqual(campaign.read_bytes(), before)

    def test_campaigns_with_mock_phases(self):
        shell = os.environ.get("REPORT_TEST_BASH", "bash")
        for failure, wordlist, broken_reporter in [(False, False, False), (False, True, False), (True, False, False), ("interrupt", False, False), (False, False, True)]:
            with self.subTest(failure=failure, wordlist=wordlist, broken_reporter=broken_reporter), tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temporary:
                base = Path(temporary).resolve()
                for directory in ["scripts", "web", "config", "bin"]:
                    (base / directory).mkdir()
                # Only the scenario orchestrator runs. Every numbered phase is a harmless fixture.
                scenario = (PLATFORM / "scenarios/full-incident.sh").read_text(encoding="utf8")
                scenario = scenario.replace('BASE_DIR="/opt/nordic-attack"', 'BASE_DIR="$REPORT_FIXTURE_BASE"', 1)
                (base / "scenario.sh").write_text(scenario, encoding="utf8", newline="\n")
                defaults = (PLATFORM / "config/defaults.conf").read_text(encoding="utf8")
                defaults = defaults.replace('NORDIC_BASE_DIR="/opt/nordic-attack"', 'NORDIC_BASE_DIR="$REPORT_FIXTURE_BASE"')
                defaults += '\nNORDIC_PHASE_DELAY_MIN=0\nNORDIC_PHASE_DELAY_MAX=0\n'
                (base / "config/defaults.conf").write_text(defaults, encoding="utf8", newline="\n")
                if not broken_reporter:
                    shutil.copy(PLATFORM / "web/reports.py", base / "web/reports.py")
                for source in (PLATFORM / "scripts").glob("0*.sh"):
                    script = base / "scripts" / source.name
                    action = 'kill -TERM "$PPID"\nexit 0' if failure == "interrupt" and source.name.startswith("03") else (
                        "exit " + ("7" if failure and source.name.startswith("03") else "0"))
                    script.write_text('#!/bin/sh\n' + action + '\n', encoding="utf8", newline="\n")
                    script.chmod(0o755)
                # Use the test interpreter, not a host-specific python3 installation.
                wrapper = base / "bin/python3"
                wrapper.write_text('#!/bin/sh\nexec "' + Path(sys.executable).as_posix() + '" "$@"\n', encoding="utf8", newline="\n")
                wrapper.chmod(0o755)
                wordlist_path = base / "wordlist.txt"
                wordlist_path.write_text("fixture\n", encoding="utf8")
                env = {k: v for k, v in os.environ.items() if not k.startswith("NORDIC_")}
                env.update(REPORT_FIXTURE_BASE=base.as_posix(), NORDIC_INCIDENT_ID="MRN-fixture",
                           NORDIC_SSH_PASSWORD="fixture", NORDIC_RDP_PASSWORD="fixture", NORDIC_INCIDENT_IP="192.168.1.254",
                           NORDIC_PHASE_DELAY_MIN="0", NORDIC_PHASE_DELAY_MAX="0", NORDIC_WORDLIST_ENABLED=str(int(wordlist)),
                           NORDIC_WORDLIST_FILE=wordlist_path.as_posix(), PATH=str(base / "bin") + os.pathsep + os.environ["PATH"])
                result = subprocess.run([shell, str(base / "scenario.sh")], env=env, stdin=subprocess.DEVNULL,
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 143 if failure == "interrupt" else int(failure), result.stdout + result.stderr)
                path = base / "reports/MRN-fixture.json"
                if broken_reporter:
                    self.assertFalse(path.exists())
                    self.assertIn("[WARN]", result.stdout)
                    continue
                self.assertTrue(path.exists(), result.stdout + result.stderr)
                report = json.loads(path.read_text(encoding="utf8"))
                self.assertEqual(report["incident"]["status"], "interrupted" if failure == "interrupt" else "failed" if failure else "complete")
                phases = {phase["id"]: phase for phase in report["phases"]}
                self.assertEqual(phases["08"]["status"], "success" if wordlist else "skipped")
                self.assertEqual(phases["04"]["status"], "not_run" if failure else "success")
                self.assertEqual((base / "state/campaign.json").exists(), True)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
