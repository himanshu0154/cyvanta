import copy
import json
import math
from pathlib import Path
import tempfile
import unittest

from ml.severity import (
    PREPROCESSING_VERSION, SCORE_BASIS, SeverityPolicy,
    build_prioritized_alerts, calculate_deviation_strength,
    classify_severity, load_severity_policy, validate_policy,
)


def policy_artifact():
    """Explicit fixture thresholds, never used by the application."""
    return {
        "schema_version": 1,
        "method": "reference_percentiles",
        "score_basis": SCORE_BASIS,
        "preprocessing_version": PREPROCESSING_VERSION,
        "reference_model_version": "test-model",
        "decision_threshold": -0.04,
        "thresholds": {"medium": 0.02, "high": 0.06},
        "quantiles": [1 / 3, 2 / 3],
        "reference": {
            "sample_count": 300, "anomaly_count": 90,
            "unique_strength_count": 80, "independent_reference": True,
            "source": "unit test fixture", "provenance": "independent fixture",
            "dataset_sha256": "a" * 64,
        },
    }


class SeverityTests(unittest.TestCase):
    def setUp(self):
        self.policy = validate_policy(policy_artifact(), "test-model", -0.04)

    def test_existing_boundary_and_score_direction(self):
        self.assertAlmostEqual(calculate_deviation_strength(-0.10, -0.04), 0.06)
        self.assertEqual(calculate_deviation_strength(-0.02, -0.04), 0)
        self.assertEqual(calculate_deviation_strength(-0.04, -0.04), 0)

    def test_normal_never_receives_severity(self):
        self.assertIsNone(classify_severity(1, 1000, self.policy))

    def test_bands_and_exact_boundaries(self):
        for strength, expected in [(0, "LOW"), (.019, "LOW"), (.02, "MEDIUM"),
                                   (.059, "MEDIUM"), (.06, "HIGH"), (1000, "HIGH")]:
            with self.subTest(strength=strength):
                self.assertEqual(classify_severity(-1, strength, self.policy), expected)

    def test_monotonic_categories_and_identical_scores(self):
        rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        strengths = [0, .01, .02, .04, .06, .06, .9]
        categories = [classify_severity(-1, x, self.policy) for x in strengths]
        self.assertEqual([rank[x] for x in categories], sorted(rank[x] for x in categories))
        self.assertEqual(categories[4], categories[5])

    def test_invalid_values_fail_instead_of_becoming_high(self):
        for value in [None, math.nan, math.inf, -math.inf, "bad", True]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                calculate_deviation_strength(value, -0.04)
            with self.subTest(value=value), self.assertRaises(ValueError):
                classify_severity(-1, value, self.policy)
        for prediction in [0, 2, None, "Anomaly", True]:
            with self.subTest(prediction=prediction), self.assertRaises(ValueError):
                classify_severity(prediction, .1, self.policy)
        with self.assertRaises(ValueError):
            classify_severity(-1, -.1, self.policy)

    def test_missing_policy_keeps_normal_and_anomaly_unclassified(self):
        policy = SeverityPolicy("test-model", -0.04)
        self.assertIsNone(classify_severity(-1, .9, policy))
        self.assertIsNone(classify_severity(1, 0, policy))
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(load_severity_policy(Path(directory) / "missing.json", "test-model", -.04).calibrated)

    def test_stale_or_degenerate_calibration_rejected(self):
        changes = [
            ("reference_model_version", "different"),
            ("preprocessing_version", "different"),
            ("decision_threshold", 0),
            ("thresholds", {"medium": .02, "high": .02}),
            ("thresholds", {"medium": .02, "high": math.inf}),
            ("quantiles", [.7, .3]),
        ]
        for key, value in changes:
            artifact = policy_artifact()
            artifact[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_policy(artifact, "test-model", -.04)
        for key, value in [("anomaly_count", 2), ("unique_strength_count", 1),
                           ("independent_reference", False), ("provenance", ""),
                           ("dataset_sha256", "not-a-hash")]:
            artifact = policy_artifact()
            artifact["reference"][key] = value
            with self.subTest(reference_key=key), self.assertRaises(ValueError):
                validate_policy(artifact, "test-model", -.04)

    def test_invalid_artifact_falls_back_without_blocking_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps({"schema_version": 99}), encoding="utf-8")
            policy = load_severity_policy(path, "test-model", -.04)
            self.assertFalse(policy.calibrated)
            self.assertIsNone(classify_severity(-1, .9, policy))

    def test_priority_uses_severity_strength_and_stable_record_order(self):
        records = [
            {"record_index": 5, "model_prediction": -1, "severity": "LOW", "deviation_strength": .01},
            {"record_index": 3, "model_prediction": -1, "severity": "HIGH", "deviation_strength": .10},
            {"record_index": 2, "model_prediction": -1, "severity": "HIGH", "deviation_strength": .10},
            {"record_index": 4, "model_prediction": -1, "severity": "HIGH", "deviation_strength": .12},
            {"record_index": 0, "model_prediction": 1, "severity": None, "deviation_strength": 0},
        ]
        original = copy.deepcopy(records)
        alerts = build_prioritized_alerts(records)
        self.assertEqual([x["record_index"] for x in alerts], [4, 2, 3, 5])
        self.assertEqual([x["priority"] for x in alerts], [1, 2, 3, 4])
        self.assertEqual(records, original)
        self.assertEqual(build_prioritized_alerts([]), [])


if __name__ == "__main__":
    unittest.main()
