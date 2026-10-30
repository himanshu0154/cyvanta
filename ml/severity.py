"""Versioned, reference-calibrated statistical severity (never attack probability)."""

from dataclasses import dataclass
import json
import math
from pathlib import Path
import re


SCORE_BASIS = "distance_beyond_configured_decision_boundary"
PREPROCESSING_VERSION = "cyvanta-network-features-v1"
MIN_REFERENCE_ANOMALIES = 30
SEVERITY_RANK = {None: 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def finite_number(value):
    if isinstance(value, bool):
        raise ValueError("Scores and thresholds must be finite numbers.")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Scores and thresholds must be finite numbers.") from exc
    if not math.isfinite(number):
        raise ValueError("Scores and thresholds must be finite numbers.")
    return number


def calculate_deviation_strength(decision_score, decision_threshold=0.0):
    """Distance beyond the application's existing anomaly boundary in score units."""
    return max(0.0, finite_number(decision_threshold) - finite_number(decision_score))


@dataclass(frozen=True)
class SeverityPolicy:
    model_version: str
    decision_threshold: float
    medium: float | None = None
    high: float | None = None
    reason: str | None = "No independent reference calibration has been configured."
    metadata: dict | None = None

    def __post_init__(self):
        finite_number(self.decision_threshold)
        if self.reason is None:
            medium, high = finite_number(self.medium), finite_number(self.high)
            if not 0 < medium < high:
                raise ValueError("Severity thresholds must satisfy 0 < medium < high.")

    @property
    def calibrated(self):
        return self.reason is None and self.medium is not None and self.high is not None

    def to_dict(self):
        artifact = self.metadata or {}
        return {
            "schema_version": 1,
            "method": "reference_percentiles" if self.calibrated else None,
            "calibration_status": "calibrated" if self.calibrated else "uncalibrated",
            "reason": self.reason,
            "score_basis": SCORE_BASIS,
            "score_transformation": "max(0, decision_threshold - decision_score)",
            "decision_threshold": self.decision_threshold,
            "thresholds": {"medium": self.medium, "high": self.high} if self.calibrated else None,
            "reference_model_version": artifact.get("reference_model_version"),
            "preprocessing_version": PREPROCESSING_VERSION,
            "quantiles": artifact.get("quantiles"),
            "reference": artifact.get("reference"),
            "calibrated_at": artifact.get("calibrated_at"),
            "interpretation": "Statistical unusualness, not attack probability or confirmed security impact.",
        }


def validate_policy(data, model_version, decision_threshold):
    """Reject stale, incomplete and degenerate calibration artifacts explicitly."""
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("Unsupported severity-policy schema.")
    if data.get("reference_model_version") != model_version:
        raise ValueError("Severity calibration does not match the current model version.")
    if data.get("preprocessing_version") != PREPROCESSING_VERSION:
        raise ValueError("Severity calibration uses an incompatible preprocessing version.")
    if data.get("method") != "reference_percentiles" or data.get("score_basis") != SCORE_BASIS:
        raise ValueError("Unsupported severity calibration method or score transformation.")
    if finite_number(data.get("decision_threshold")) != finite_number(decision_threshold):
        raise ValueError("Severity calibration uses a different anomaly decision boundary.")
    thresholds = data.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise ValueError("Severity thresholds must be an object.")
    medium = finite_number(thresholds.get("medium"))
    high = finite_number(thresholds.get("high"))
    if not 0 < medium < high:
        raise ValueError("Severity thresholds must satisfy 0 < medium < high.")
    quantiles = data.get("quantiles", [])
    if not isinstance(quantiles, (list, tuple)) or len(quantiles) != 2 or not 0 < finite_number(quantiles[0]) < finite_number(quantiles[1]) < 1:
        raise ValueError("Severity reference quantiles must be two ordered fractions.")
    reference = data.get("reference", {})
    if not isinstance(reference, dict):
        raise ValueError("Severity calibration reference must be an object.")
    for key in ("sample_count", "anomaly_count", "unique_strength_count"):
        value = reference.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("Severity calibration reference counts are invalid.")
    if not (
        reference["sample_count"] >= reference["anomaly_count"] >= MIN_REFERENCE_ANOMALIES
        and reference["anomaly_count"] >= reference["unique_strength_count"] >= 3
    ):
        raise ValueError("Severity calibration reference is insufficient or degenerate.")
    if reference.get("independent_reference") is not True:
        raise ValueError("Severity calibration requires a documented independent reference.")
    if not all(isinstance(reference.get(key), str) and reference[key].strip() for key in ("source", "provenance")):
        raise ValueError("Severity calibration reference provenance is missing.")
    if not re.fullmatch(r"[0-9a-f]{64}", str(reference.get("dataset_sha256", ""))):
        raise ValueError("Severity calibration reference fingerprint is missing.")
    return SeverityPolicy(model_version, decision_threshold, medium, high, None, data)


def load_severity_policy(path, model_version, decision_threshold):
    """Missing/invalid calibration never blocks inference or fabricates a category."""
    try:
        with Path(path).open(encoding="utf-8") as handle:
            data = json.load(handle)
        return validate_policy(data, model_version, decision_threshold)
    except FileNotFoundError:
        return SeverityPolicy(model_version, decision_threshold)
    except (OSError, ValueError, TypeError, AttributeError):
        return SeverityPolicy(
            model_version, decision_threshold,
            reason="The severity calibration is invalid or incompatible with this model; recalibration is required.",
        )


def classify_severity(prediction, deviation_strength, policy):
    if prediction not in (-1, 1) or isinstance(prediction, bool):
        raise ValueError("The anomaly prediction must be -1 or 1.")
    strength = finite_number(deviation_strength)
    if strength < 0:
        raise ValueError("Deviation strength cannot be negative.")
    if prediction == 1 or not policy.calibrated:
        return None
    if strength < policy.medium:
        return "LOW"
    if strength < policy.high:
        return "MEDIUM"
    return "HIGH"


def build_prioritized_alerts(records):
    """Use input record index to break equal-score ties reproducibly."""
    alerts = [dict(record) for record in records if record["model_prediction"] == -1]
    alerts.sort(key=lambda row: (
        -SEVERITY_RANK[row["severity"]],
        -finite_number(row["deviation_strength"]),
        row["record_index"],
    ))
    for priority, alert in enumerate(alerts, start=1):
        alert["priority"] = priority
    return alerts
