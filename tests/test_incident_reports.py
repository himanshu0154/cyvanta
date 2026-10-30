import io
import json
from pathlib import Path
import tempfile
import unittest

from app import app
from incident_ai import AIConfig, IncidentAIService, empty_content
from incident_reports import build_incident_report
from incident_store import IncidentStore

BASE = Path(__file__).resolve().parents[1]


def report_fixture():
    return {"incident_id": "incident-report", "analysis_id": "analysis-report", "evidence_hash": "evidence-report", "revision": 1,
            "event_total": 1, "overview": {"event_count": 1, "severity_counts": {"HIGH": 1}},
            "events": [{"event_id": "event-report", "record_index": 0, "timestamp": None, "observed_at": None,
                        "source_ip": None, "destination_ip": None, "protocol": None, "decision_score": -.12,
                        "deviation_strength": .08, "severity": "HIGH", "features": {"Flow Duration": 900}, "input_warnings": []}],
            "analysis": {"dataset_name": "<script>alert(1)</script>.csv", "model_version": "version-report"},
            "timeline": {"ordering": "source_row", "limitations": ["Timestamps unavailable"]},
            "correlations": {"rules": "Shared real fields only", "window_seconds": 300, "reasons": [], "relationships": []},
            "notes": "Analyst <script>alert('notes')</script>", "status": "in_review", "conclusion": "Not yet determined",
            "recommendation_states": {}, "registered_recommendations": []}


class ReportRenderingTests(unittest.TestCase):
    def test_factual_report_is_actual_escaped_printable_html_without_fabricated_fields(self):
        html, report_id = build_incident_report(report_fixture())
        self.assertTrue(report_id.startswith("report-"))
        self.assertIn("<!doctype html>", html)
        self.assertIn("@media print", html)
        self.assertIn("Factual evidence report", html)
        self.assertIn("event-report", html)
        self.assertIn("Included 1 of 1", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertIn("Timestamps unavailable", html)
        self.assertNotIn("192.0.2", html)
        self.assertIn("default-src &#", html.replace("'", "&#39;"))

    def test_ai_snapshot_mismatch_is_not_presented_as_current_narrative(self):
        fixture = report_fixture()
        result = {"evidence_hash": "old", "content": {"executive_summary": "STALE NARRATIVE"}}
        html, _ = build_incident_report(fixture, result)
        self.assertNotIn("STALE NARRATIVE", html)
        self.assertIn("Factual evidence report", html)

    def test_current_ai_is_labelled_and_bounded_appendix_discloses_omissions(self):
        fixture = report_fixture()
        fixture["event_total"] = 9000
        result = {"evidence_hash": fixture["evidence_hash"], "model": "test-model", "generated_at": "2026-01-01Z", "content": empty_content(fixture)}
        result["content"]["executive_summary"] = "Grounded <b>summary</b>"
        html, _ = build_incident_report(fixture, result)
        self.assertIn("AI-generated narrative", html)
        self.assertIn("Grounded &lt;b&gt;summary&lt;/b&gt;", html)
        self.assertIn("Included 1 of 9000", html)
        self.assertIn("Some records are omitted", html)

    def test_saved_recommendation_decisions_survive_missing_ai_and_show_staleness(self):
        fixture = report_fixture()
        fixture["registered_recommendations"] = [{"action_id": "action-old", "title": "Review logs", "category": "investigation", "rationale": "Recorded advice",
            "supporting_event_ids": ["event-report"], "evidence_hash": "earlier", "is_current": False,
            "analyst_state": {"status": "recorded_completed", "note": "Analyst says review finished"}}]
        html, _ = build_incident_report(fixture)
        self.assertIn("Review logs", html)
        self.assertIn("Analyst recorded as completed; not technically verified", html)
        self.assertIn("Historical advice; evidence or notes changed", html)
        self.assertIn("Analyst says review finished", html)


class IncidentAIRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_store = app.extensions["investigations"]
        self.old_ai = app.extensions.get("incident_ai")
        app.extensions["investigations"] = IncidentStore(Path(self.temp.name) / "test.sqlite")
        app.extensions["incident_ai"] = IncidentAIService(config_factory=lambda: AIConfig())
        self.client = app.test_client()
        response = self.client.post("/api/analyze", data={"file": (io.BytesIO((BASE / "ml/data/sample_network_flows.csv").read_bytes()), "sample.csv")})
        self.assertEqual(response.status_code, 200)
        self.analysis = response.get_json()
        groups = self.client.get(f"/api/investigations/analyses/{self.analysis['analysis_id']}/incidents").get_json()
        self.incident_id = groups["incidents"][0]["incident_id"]
        self.route = f"/api/investigations/incidents/{self.incident_id}"

    def tearDown(self):
        app.extensions["investigations"] = self.old_store
        if self.old_ai is None:
            app.extensions.pop("incident_ai", None)
        else:
            app.extensions["incident_ai"] = self.old_ai
        self.temp.cleanup()

    def test_status_missing_key_and_deterministic_chat_factual_report_work(self):
        status = self.client.get("/api/ai/status").get_json()
        self.assertFalse(status["available"])
        failed = self.client.post(self.route + "/ai", json={"task": "summary"})
        self.assertEqual(failed.status_code, 503)
        self.assertEqual(failed.get_json()["code"], "ai_not_configured")
        counted = self.client.post(self.route + "/ai", json={"task": "chat", "question": "How many anomalous events?"})
        self.assertEqual(counted.status_code, 200)
        self.assertEqual(counted.get_json()["source"], "deterministic")
        history = self.client.get(self.route + "/ai/history").get_json()
        self.assertEqual(len(history["messages"]), 1)
        report = self.client.post(self.route + "/report", json={"format": "html", "include_ai": True})
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.mimetype, "text/html")
        self.assertIn("attachment; filename=", report.headers["Content-Disposition"])
        self.assertEqual(report.headers["X-Cyvanta-Report-Status"], "factual-only")
        self.assertIn("default-src 'none'", report.headers["Content-Security-Policy"])
        self.assertIn(self.incident_id, report.get_data(as_text=True))

    def test_cross_browser_evidence_cannot_be_accessed_through_ai_or_report(self):
        outsider = app.test_client()
        for suffix, payload in [("/ai", {"task": "summary"}), ("/report", {"format": "html"})]:
            self.assertEqual(outsider.post(self.route + suffix, json=payload).status_code, 404)
        self.assertEqual(outsider.get(self.route + "/ai/history").status_code, 404)

    def test_client_evidence_and_bad_input_are_rejected(self):
        for payload in [{"task": "summary", "evidence": [{"prediction": -1}]}, {"task": []},
                        {"task": "summary", "regenerate": "true"}, {"task": "chat", "question": 9}]:
            response = self.client.post(self.route + "/ai", json=payload)
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.post(self.route + "/ai", data="{}").status_code, 415)
        self.assertEqual(self.client.post(self.route + "/report", json={"format": "pdf"}).status_code, 400)
        self.assertEqual(self.client.post(self.route + "/ai", json={"task": "summary"}, headers={"Origin": "https://untrusted.example"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
