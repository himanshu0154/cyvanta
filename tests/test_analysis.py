import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

from app import app
from ml.pipeline import (
    MODEL_DIR, THRESHOLD, ModelUnavailableError, get_model_version,
    load_model, predict_csv, score_features,
)
from ml.severity import load_severity_policy

BASE = Path(__file__).resolve().parents[1]
SAMPLE = BASE / "ml/data/sample_network_flows.csv"


class RealAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model, cls.features = load_model()
        cls.sample = pd.read_csv(SAMPLE)
        cls.result = predict_csv(SAMPLE)

    def test_actual_saved_model_and_existing_cutoff_are_preserved(self):
        expected = self.model.decision_function(self.sample[self.features])
        records = self.result["results"]
        np.testing.assert_allclose(records["decision_score"], expected, rtol=0, atol=1e-12)
        np.testing.assert_array_equal(records["model_prediction"], np.where(expected < THRESHOLD, -1, 1))
        np.testing.assert_allclose(records["deviation_strength"], np.maximum(0, THRESHOLD - expected))
        # A negative sklearn score above Cyvanta's custom boundary stays normal.
        between = records[(records.decision_score < 0) & (records.decision_score >= THRESHOLD)]
        self.assertGreater(len(between), 0)
        self.assertTrue(between.severity.isna().all())
        self.assertTrue((between.prediction == "Normal").all())

    def test_calibrated_summary_and_priorities_match_all_records(self):
        policy = load_severity_policy(MODEL_DIR / "severity_policy.json", get_model_version(), THRESHOLD)
        self.assertTrue(policy.calibrated, policy.reason)
        summary = self.result["summary"]
        records = self.result["results"]
        self.assertEqual(summary["total_flows"], len(self.sample))
        self.assertEqual(summary["normal_count"] + summary["anomaly_count"], len(records))
        self.assertEqual(summary["anomaly_count"], len(self.result["alerts"]))
        self.assertEqual(sum(summary["severity_counts"].values()) + summary["uncalibrated_count"], len(self.result["alerts"]))
        for level, count in summary["severity_counts"].items():
            self.assertEqual(count, int((records.severity == level).sum()))
        priorities = [row["priority"] for row in self.result["alerts"]]
        self.assertEqual(priorities, list(range(1, len(priorities) + 1)))
        self.assertEqual(records.record_index.tolist(), list(range(len(records))))

    def test_identical_records_have_identical_severity_in_other_batches(self):
        single = self.sample.iloc[[0]].copy()
        repeated = pd.concat([self.sample.iloc[[3]], single, single], ignore_index=True)
        result = predict_csv(io.StringIO(repeated.to_csv(index=False)))
        row = self.result["results"].iloc[0]
        for index in (1, 2):
            other = result["results"].iloc[index]
            self.assertEqual(other.severity, row.severity)
            self.assertAlmostEqual(other.decision_score, row.decision_score, places=12)

    def test_all_normal_and_all_anomalous_inputs(self):
        for values, expected in [(self.model.steps[0][1].statistics_, "Normal"), ([1e18] * len(self.features), "Anomaly")]:
            frame = pd.DataFrame([values] * 3, columns=self.features)
            result = predict_csv(io.StringIO(frame.to_csv(index=False)))
            self.assertEqual(result["results"].prediction.tolist(), [expected] * 3)
            if expected == "Normal":
                self.assertEqual(result["alerts"], [])
                self.assertTrue(result["results"].severity.isna().all())
            else:
                self.assertEqual([x["record_index"] for x in result["alerts"]], [0, 1, 2])

    def test_missing_or_mismatched_policy_keeps_genuine_scores(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            for content in [None, {"schema_version": 1, "reference_model_version": "wrong"}]:
                if content is not None:
                    path.write_text(json.dumps(content), encoding="utf-8")
                result = predict_csv(SAMPLE, severity_policy_path=path)
                self.assertEqual(result["severity_policy"]["calibration_status"], "uncalibrated")
                self.assertEqual(result["summary"]["uncalibrated_count"], result["summary"]["anomaly_count"])
                self.assertTrue(result["results"].severity.isna().all())
                np.testing.assert_array_equal(result["results"].decision_score, self.result["results"].decision_score)

    def test_saved_imputer_reports_bad_cells_without_shifting_rows(self):
        frame = self.sample.copy()
        frame["Flow ID"] = ["first", "second", "third", "fourth", "fifth"]
        frame.loc[1, self.features[0]] = np.inf
        result = predict_csv(io.StringIO(frame.to_csv(index=False)))
        self.assertEqual(result["results"]["Flow ID"].tolist(), frame["Flow ID"].tolist())
        self.assertEqual(result["input_warnings"][0]["record_index"], 1)
        self.assertIn(self.features[0], result["input_warnings"][0]["fields"])
        self.assertEqual(result["summary"]["imputed_records"], 1)

    def test_no_network_metadata_or_flow_timestamp_is_invented(self):
        self.assertTrue(self.result["results"].Timestamp.isna().all())
        self.assertNotIn("Source IP", self.result["results"].columns)
        frame = self.sample.copy()
        frame["Timestamp"] = "2026-01-02 03:04:05"
        frame["Source IP"] = "192.0.2.1"
        result = predict_csv(io.StringIO(frame.to_csv(index=False)))
        self.assertEqual(result["results"].Timestamp.tolist(), frame.Timestamp.tolist())
        self.assertEqual(result["results"]["Source IP"].tolist(), frame["Source IP"].tolist())

    def test_invalid_model_outputs_are_not_classified(self):
        for scores in [[np.nan] * len(self.sample), [np.inf] * len(self.sample), [0]]:
            with self.subTest(scores=scores), patch.object(self.model, "decision_function", return_value=scores):
                with self.assertRaises(ModelUnavailableError):
                    score_features(self.model, self.sample[self.features])


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def upload(self, content, filename="traffic.csv"):
        return self.client.post("/api/analyze", data={"file": (io.BytesIO(content), filename)}, content_type="multipart/form-data")

    def test_real_upload_response_is_strict_json_and_backward_compatible(self):
        response = self.upload(SAMPLE.read_bytes(), "folder/traffic.csv")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data, parse_constant=lambda x: self.fail(f"Nonstandard JSON {x}"))
        self.assertEqual(data["dataset_name"], "traffic.csv")
        self.assertEqual(len(data["results"]), data["summary"]["total_flows"])
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["model_status"], "ready")
        self.assertEqual(data["severity_policy"]["calibration_status"], "calibrated")
        for row in data["results"]:
            self.assertIn("anomaly_score", row)
            self.assertIn("prediction", row)
            self.assertEqual(row["anomaly_score"], row["decision_score"])

    def test_invalid_csv_and_schema_errors_are_actionable(self):
        cases = [(b"", "empty"), (b"foo\n1\n", "missing required"), (b"a,b\n", "no data"),
                 (b"\xff\xfe\x00", "valid CSV")]
        for content, expected in cases:
            with self.subTest(expected=expected):
                response = self.upload(content)
                self.assertEqual(response.status_code, 400)
                self.assertIn(expected, response.get_json()["error"])
        self.assertEqual(self.client.post("/api/analyze").status_code, 400)
        self.assertEqual(self.upload(b"abc", "traffic.exe").status_code, 400)

    def test_entirely_invalid_row_rejects_batch_with_record_reference(self):
        frame = pd.read_csv(SAMPLE).astype(object)
        frame.iloc[2] = "invalid"
        response = self.upload(frame.to_csv(index=False).encode())
        self.assertEqual(response.status_code, 400)
        self.assertIn("record indices: 2", response.get_json()["error"])

    def test_duplicate_headers_and_surplus_fields_cannot_shift_feature_alignment(self):
        sample = SAMPLE.read_text().splitlines()
        header = sample[0]
        surplus = "\n".join([header, sample[1] + ",extra", sample[2] + ",extra"])
        duplicate = "\n".join([header + ",Packet Length Std", sample[1] + ",1"])
        whitespace_duplicate = "\n".join([header + ", Packet Length Std ", sample[1] + ",1"])
        for csv in [surplus, duplicate, whitespace_duplicate]:
            with self.subTest(csv=csv):
                response = self.upload(csv.encode())
                self.assertEqual(response.status_code, 400)
                self.assertIn("CSV", response.get_json()["error"])

    def test_optional_nonfinite_values_become_null(self):
        frame = pd.read_csv(SAMPLE)
        frame["optional"] = np.inf
        response = self.upload(frame.to_csv(index=False).encode())
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data, parse_constant=lambda x: self.fail(x))
        self.assertTrue(all(row["optional"] is None for row in data["results"]))
        self.assertTrue(all(row["optional"] is None for row in data["alerts"]))

    def test_model_failure_is_sanitized_and_upload_limit_is_json(self):
        with patch("app.predict_csv", side_effect=ModelUnavailableError("private server path")):
            response = self.upload(SAMPLE.read_bytes())
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("private", response.get_json()["error"])
        with patch.dict(app.config, {"MAX_CONTENT_LENGTH": 32}):
            response = self.upload(b"x" * 128)
            self.assertEqual(response.status_code, 413)
            self.assertIsNotNone(response.get_json())

    def test_existing_dashboard_and_health_still_load(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/api/health").get_json()["status"], "healthy")


if __name__ == "__main__":
    unittest.main()
