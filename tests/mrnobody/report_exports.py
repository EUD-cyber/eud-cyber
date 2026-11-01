"""Real Flask responses and generated PDF content; no campaigns or services run."""
import copy
from io import BytesIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "TESTFILES/ATTACKER-V2/web"))
import app as web
from report_exports import export_html, export_pdf


class Exports(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / "reports").mkdir()
        self.addCleanup(patch.stopall)
        patch.object(web, "BASE_DIR", self.base).start()
        self.client = web.app.test_client()
        self.report = {
            "schema_version": 1,
            "incident": {"id": "MRN-export", "scenario": "full-incident", "status": "complete", "started": "2026-11-01T12:00:00Z", "ended": "2026-11-01T12:01:00Z"},
            "summary": {"hosts": 2, "compromised": 1, "exfiltration": 1, "impact": 0},
            "inventory": {"hosts": [{"ip": "inventory-host", "hostname": '<img src="file:///etc/passwd" onerror="attack()">'}]},
            "compromised_hosts": {"hosts": [{"ip": "compromised-answer", "password": "STRUCTURED_SECRET"}]},
            "phases": [{"id": "03", "name": "Initial Access", "status": "success", "started": "2026-11-01T12:00:01Z", "ended": "2026-11-01T12:00:03Z",
                        "mitre": {"techniques": [{"id": "T1078", "name": "Valid Accounts"}, {"id": "T1110.001", "name": "Password Guessing", "url": "javascript:attack()"}]},
                        "outcomes": {"success": 1, "failure": 1, "skipped": 1},
                        "events": [{"event": "ACCESS_SUCCESS", "outcome": "success", "source": "source-answer", "target": "target-answer", "timestamp": "precise-time", "protocol": "ssh", "message": '<script>attack()</script> password="QUOTED_SECRET with spaces"'},
                                   {"event": "ACCESS_FAILED", "outcome": "failure"}, {"event": "AUTH_SKIPPED", "outcome": "skipped"}]}],
            "evidence": {"staging": {"path": "/tmp/staging-answer"}, "exfiltration": {"bytes": 1234}, "impact": {"successful": False},
                         "api_key": "API_SECRET", "wordlist": {"words": ["WORDLIST_SECRET"]}, "note": "Authorization: Bearer BEARER_SECRET", "other": 'token: "COLON_SECRET"', "uri": "ssh://user:URL_SECRET@host"},
            "warnings": ["Unavailable optional snapshot"]}
        self.write()

    def write(self):
        self.file = self.base / "reports" / (self.report["incident"]["id"] + ".json")
        self.file.write_text(json.dumps(self.report), encoding="utf8")
        self.before = self.file.read_bytes()

    def get(self, suffix):
        return self.client.get("/api/reports/" + self.report["incident"]["id"] + suffix)

    def test_html_default_and_ground_truth(self):
        investigation = self.get("/export/html")
        self.assertEqual(investigation.status_code, 200)
        self.assertEqual(investigation.mimetype, "text/html")
        html = investigation.get_data(as_text=True)
        for expected in ["Investigation View", "Incident overview", "Summary metrics", "Attack timeline", "MITRE ATT", "Affected assets", "Phase-by-phase", "Detection guidance", "Investigation tasks", "Prevention / Mitigation", "Recommendations"]:
            self.assertIn(expected, html)
        for hidden in ["source-answer", "target-answer", "compromised-answer", "ACCESS_SUCCESS", "/tmp/staging-answer", "precise-time"]:
            self.assertNotIn(hidden, html)
        ground = self.get("/export/html?view=ground-truth")
        html = ground.get_data(as_text=True)
        for expected in ["Ground Truth View", "source-answer", "target-answer", "compromised-answer", "ACCESS_SUCCESS", "ACCESS_FAILED", "AUTH_SKIPPED", "/tmp/staging-answer", "precise-time", "Technical evidence / ground-truth appendix"]:
            self.assertIn(expected, html)
        for url in ["https://attack.mitre.org/techniques/T1078/", "https://attack.mitre.org/techniques/T1110/001/"]:
            self.assertIn('href="' + url + '"', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img", html)
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img ", html)
        self.assertNotIn("javascript:", html)
        self.assertIn("Password Guessing", html)
        self.assertIn("attachment;", ground.headers["Content-Disposition"])
        self.assertEqual(ground.headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'none'", ground.headers["Content-Security-Policy"])
        self.assertEqual(self.file.read_bytes(), self.before)

    def test_pdf_content_links_redaction_and_pagination(self):
        response = self.get("/export/pdf?view=ground-truth")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertTrue(response.data.startswith(b"%PDF-"))
        reader = PdfReader(BytesIO(response.data))
        content = "\n".join(page.extract_text() for page in reader.pages)
        self.assertGreater(len(reader.pages), 1)
        for expected in ["MRN-export", "Full Incident", "Ground Truth View", "Recommendations", "source-answer", "ACCESS_FAILED", "AUTH_SKIPPED", "Page 1"]:
            self.assertIn(expected, content)
        for secret in ["STRUCTURED_SECRET", "API_SECRET", "WORDLIST_SECRET", "QUOTED_SECRET", "COLON_SECRET", "BEARER_SECRET", "URL_SECRET"]:
            self.assertNotIn(secret, content)
            self.assertNotIn(secret, self.get("/export/html?view=ground-truth").get_data(as_text=True))
        uris = [a.get_object().get("/A", {}).get("/URI") for p in reader.pages for a in p.get("/Annots", [])]
        self.assertIn("https://attack.mitre.org/techniques/T1110/001/", uris)
        default = PdfReader(BytesIO(self.get("/export/pdf").data))
        default_text = "\n".join(p.extract_text() for p in default.pages)
        self.assertIn("Investigation View", default_text)
        self.assertNotIn("source-answer", default_text)
        self.assertEqual(self.file.read_bytes(), self.before)

    def test_standalone_same_routes(self):
        self.report.update(report_type="standalone_phase", phase_id="03")
        self.report["incident"]["id"] = "MRN-phase"
        self.write()
        self.assertIn("Standalone phase 03", self.get("/export/html").get_data(as_text=True))
        pdf = PdfReader(BytesIO(self.get("/export/pdf").data))
        self.assertIn("Standalone phase 03", "\n".join(p.extract_text() for p in pdf.pages))

    def test_historical_minimal_raw_and_immutability(self):
        self.report = {"schema_version": 1, "incident": {"id": "H3-historical"}, "phases": []}
        self.write()
        for format in ("html", "pdf"):
            self.assertEqual(self.get("/export/" + format).status_code, 200)
        raw = self.get("?raw=1").json
        self.assertEqual(raw, self.report)
        self.assertNotIn("analysis_version", raw)
        self.assertEqual(self.file.read_bytes(), self.before)
        self.assertEqual(len(list((self.base / "reports").glob("H3-historical*"))), 1)

    def test_invalid_missing_and_unavailable_dependency(self):
        for suffix in ("/export/html?view=teacher", "/export/txt"):
            self.assertEqual(self.get(suffix).status_code, 400)
        self.assertEqual(self.client.get("/api/reports/MRN-missing/export/html").status_code, 404)
        self.assertEqual(self.client.get("/api/reports/not-valid/export/pdf").status_code, 404)
        with patch.object(web, "export_pdf", side_effect=ImportError("missing")):
            self.assertEqual(self.get("/export/pdf").status_code, 503)
            self.assertEqual(self.get("/export/html").status_code, 200)
        self.file.write_text("not json")
        self.assertEqual(self.get("/export/html").status_code, 404)

    def test_long_evidence_and_host_text_never_interpreted(self):
        self.report["events"] = [{"message": "x" * 18000 + '<img src="https://example.invalid/x">'}]
        pdf = PdfReader(BytesIO(export_pdf(self.report, "ground-truth")))
        self.assertGreater(len(pdf.pages), 2)
        with patch.dict(os.environ, {"NORDIC_SSH_PASSWORD": "ENV_SECRET"}):
            self.report["events"] = [{"message": "ENV_SECRET"}]
            self.assertNotIn("ENV_SECRET", export_html(self.report, "ground-truth"))


if __name__ == "__main__":
    unittest.main()
