"""Cross-feature checks using actual saved-model uploads and private snapshots."""

import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import app
from incident_store import IncidentStore
from ml.pipeline import load_model

FIXTURE = Path(__file__).parent / "fixtures" / "incident_flows.csv"


class IncidentWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.original_store = app.extensions["investigations"]
        app.extensions["investigations"] = IncidentStore(Path(self.directory.name) / "evidence.sqlite3")
        self.client = app.test_client()
        self.environment = patch.dict(os.environ, {"AI_API_KEY": "", "AI_MODEL": "", "AI_ENABLED": "true"})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        app.extensions["investigations"] = self.original_store
        self.directory.cleanup()

    def upload(self):
        response = self.client.post("/api/analyze", data={"file": (io.BytesIO(FIXTURE.read_bytes()), "incident_test_fixture.csv")})
        self.assertEqual(response.status_code, 200, response.get_json())
        data = response.get_json()
        self.assertEqual(data["investigation"]["status"], "ready")
        return data

    def select_group(self, analysis):
        response = self.client.get(f'/api/investigations/analyses/{analysis["analysis_id"]}/incidents')
        self.assertEqual(response.status_code, 200)
        groups = response.get_json()["incidents"]
        self.assertEqual(sorted(group["event_count"] for group in groups), [1, 3])
        group = next(group for group in groups if group["event_count"] == 3)
        return self.client.get(f'/api/investigations/incidents/{group["incident_id"]}').get_json()

    def test_real_upload_to_private_timeline_preserves_the_detection_baseline(self):
        model, _features = load_model()
        with patch.object(model, "fit", side_effect=AssertionError("Upload must never train")):
            analysis = self.upload()
        self.assertEqual(analysis["summary"]["normal_count"], 2)
        self.assertEqual(analysis["summary"]["anomaly_count"], 4)
        expected_scores = [-.05232646875784153, -.16894951716979068, -.16894951716979068,
                           .13953730563896766, -.16894951716979068, -.03380229259717071]
        for row, score in zip(analysis["results"], expected_scores):
            self.assertAlmostEqual(row["decision_score"], score, places=12)
        detail = self.select_group(analysis)
        self.assertEqual(detail["timeline"]["ordering"], "chronological")
        self.assertEqual([event["record_index"] for event in detail["events"]], [0, 1, 2])
        self.assertEqual(detail["overview"]["source_counts"], {"192.0.2.10": 3})
        actual_ids = {row["alert_id"] for row in analysis["alerts"]}
        self.assertTrue({event["event_id"] for event in detail["events"]}.issubset(actual_ids))
        for relationship in detail["correlations"]["relationships"]:
            self.assertTrue(set(relationship["supporting_event_ids"]).issubset(actual_ids))
        stranger = app.test_client()
        self.assertEqual(stranger.get(f'/api/investigations/incidents/{detail["incident_id"]}').status_code, 404)

    def test_metadata_survives_storage_reopen_and_reanalysis_has_distinct_identity(self):
        first = self.upload()
        detail = self.select_group(first)
        path = f'/api/investigations/incidents/{detail["incident_id"]}'
        note = 'Analyst note: <script>alert("test")</script> & uncertain behavior.'
        saved = self.client.patch(path, json={"revision": detail["revision"], "notes": note, "status": "in_review"})
        self.assertEqual(saved.status_code, 200)
        self.assertNotEqual(saved.get_json()["evidence_hash"], detail["evidence_hash"])
        app.extensions["investigations"] = IncidentStore(Path(self.directory.name) / "evidence.sqlite3")
        reopened = self.client.get(path).get_json()
        self.assertEqual(reopened["notes"], note)
        self.assertEqual(reopened["status"], "in_review")
        self.assertEqual(self.client.patch(path, json={"revision": detail["revision"], "notes": "stale"}).status_code, 409)
        second = self.upload()
        other = self.select_group(second)
        self.assertNotEqual(other["incident_id"], detail["incident_id"])
        self.assertEqual(other["notes"], "")
        self.assertEqual(self.client.get(path).get_json()["notes"], note)
        analyses = self.client.get("/api/investigations/analyses").get_json()["analyses"]
        self.assertEqual({item["analysis_id"] for item in analyses}, {first["analysis_id"], second["analysis_id"]})

    def test_ai_unavailable_keeps_factual_report_and_core_upload_working(self):
        analysis = self.upload()
        detail = self.select_group(analysis)
        path = f'/api/investigations/incidents/{detail["incident_id"]}'
        result = self.client.post(path + "/ai", json={"task": "summary"})
        self.assertEqual(result.status_code, 503, result.get_json())
        self.assertEqual(self.client.get(path).get_json()["evidence_hash"], detail["evidence_hash"])
        note = '<script>alert("report")</script> & saved note'
        saved = self.client.patch(path, json={"revision": detail["revision"], "notes": note})
        self.assertEqual(saved.status_code, 200)
        report = self.client.post(path + "/report", json={"format": "html", "include_ai": True})
        self.assertEqual(report.status_code, 200)
        self.assertIn("text/html", report.content_type)
        self.assertIn("attachment;", report.headers["Content-Disposition"])
        html = report.get_data(as_text=True)
        self.assertIn(detail["incident_id"], html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn('<script>alert("report")</script>', html)
        for event in detail["events"]:
            self.assertIn(event["event_id"], html)
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.upload()["summary"], analysis["summary"])

    def test_optional_snapshot_failure_cannot_break_original_prediction_contract(self):
        with patch.object(app.extensions["investigations"], "save_analysis", side_effect=OSError("private local path")):
            response = self.client.post("/api/analyze", data={"file": (io.BytesIO(FIXTURE.read_bytes()), "fixture.csv")})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["summary"]["anomaly_count"], 4)
        self.assertEqual(len(data["results"]), 6)
        self.assertEqual(len(data["alerts"]), 4)
        self.assertEqual(data["investigation"]["status"], "unavailable")
        self.assertNotIn("private local path", str(data))


if __name__ == "__main__":
    unittest.main()
