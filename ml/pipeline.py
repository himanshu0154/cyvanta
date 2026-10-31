"""Existing saved model inference, enriched with calibrated anomaly severity."""

from datetime import datetime, timezone
import csv
from functools import lru_cache
import hashlib
import io
import json
from pathlib import Path
from uuid import uuid4
import warnings

import joblib
import numpy as np
import pandas as pd

try:
    from .severity import (
        PREPROCESSING_VERSION, build_prioritized_alerts,
        classify_severity, load_severity_policy,
    )
except ImportError:  # Preserve `from pipeline import predict_csv` from the ml directory.
    from severity import (
        PREPROCESSING_VERSION, build_prioritized_alerts,
        classify_severity, load_severity_policy,
    )

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
THRESHOLD = -0.04045090522184547
MAX_ROWS = 750_000


class ModelUnavailableError(RuntimeError):
    """The saved inference artifacts cannot be safely used."""


def _artifact_paths():
    return MODEL_DIR / "isolation_forest.joblib", MODEL_DIR / "features.joblib"


def _artifact_key():
    paths = _artifact_paths()
    try:
        return tuple((str(path), path.stat().st_mtime_ns, path.stat().st_size) for path in paths)
    except OSError as exc:
        raise ModelUnavailableError("The saved analysis model is unavailable.") from exc


@lru_cache(maxsize=2)
def _load_artifacts(key):
    try:
        model, features = (joblib.load(item[0]) for item in key)
        features = list(features)
        if not features or len(set(features)) != len(features) or not all(isinstance(f, str) for f in features):
            raise ValueError("Invalid model feature schema")
        if not callable(getattr(model, "decision_function", None)):
            raise ValueError("Missing fitted decision function")
        if getattr(model, "n_features_in_", len(features)) != len(features):
            raise ValueError("Model feature count mismatch")
        if hasattr(model, "feature_names_in_") and list(model.feature_names_in_) != features:
            raise ValueError("Model feature order mismatch")
        return model, features
    except Exception as exc:
        raise ModelUnavailableError("The saved analysis model is incompatible or could not be loaded.") from exc


def load_model():
    """Reuse the actual fitted pipeline and its exact saved input order."""
    return _load_artifacts(_artifact_key())


@lru_cache(maxsize=2)
def _version_for_artifacts(key):
    digest = hashlib.sha256()
    for path, _mtime, _size in key:
        with Path(path).open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    # Bind calibration to the fitted preprocessing AND external cleaning/boundary.
    digest.update(json.dumps({
        "preprocessing_version": PREPROCESSING_VERSION,
        "cleaning": "strip_columns;numeric_coerce;nonfinite_to_missing;negative_duration_or_rate_to_missing;reject_all_missing",
        "decision_threshold": THRESHOLD,
    }, sort_keys=True).encode("utf-8"))
    return "sha256:" + digest.hexdigest()


def get_model_version():
    return _version_for_artifacts(_artifact_key())


def read_network_csv(file):
    if file is None:
        raise ValueError("Please upload a CSV file.")
    try:
        # pandas renames exact duplicate headers; validate the original header first.
        close_handle = isinstance(file, (str, Path))
        handle = Path(file).open("rb") if close_handle else file
        position = handle.tell()
        header_handle = io.TextIOWrapper(handle, encoding="utf-8-sig", newline="") if isinstance(handle.read(0), bytes) else handle
        try:
            header = next((row for row in csv.reader(header_handle) if row and any(value.strip() for value in row)), [])
            stripped_header = [value.strip() for value in header]
            if len(set(stripped_header)) != len(stripped_header):
                raise ValueError("The CSV contains duplicate column names.")
        finally:
            if header_handle is not handle:
                header_handle.detach()  # Keep the upload stream open for pandas.
            if close_handle:
                handle.close()
            else:
                handle.seek(position)
        # A surplus field can otherwise become an implicit index and shift every
        # feature onto the wrong column. Reject parser truncation instead.
        with warnings.catch_warnings():
            warnings.simplefilter("error", pd.errors.ParserWarning)
            df = pd.read_csv(file, nrows=MAX_ROWS + 1, index_col=False)
    except pd.errors.EmptyDataError as exc:
        raise ValueError("The uploaded CSV is empty.") from exc
    except (pd.errors.ParserError, pd.errors.ParserWarning, UnicodeDecodeError, csv.Error) as exc:
        raise ValueError("Unable to read this file as a valid CSV.") from exc
    if df.empty:
        raise ValueError("The CSV contains no data rows.")
    if len(df) > MAX_ROWS:
        raise ValueError(f"The current CSV limit is {MAX_ROWS:,} rows.")
    df.columns = df.columns.astype(str).str.strip()
    if df.columns.duplicated().any():
        raise ValueError("The CSV contains duplicate column names.")
    return df


def prepare_features(df, features, model):
    """Retain the existing cleaning and saved imputer; never fit on an upload."""
    missing = [column for column in features if column not in df.columns]
    if missing:
        raise ValueError("CSV is missing required network-flow features: " + ", ".join(missing))
    X = df[features].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    for column in ("Flow Bytes/s", "Flow Packets/s", "Flow Duration"):
        if column in X.columns:
            X.loc[X[column] < 0, column] = np.nan
    unusable = X.isna().all(axis=1)
    if unusable.any():
        indices = ", ".join(str(index) for index in np.flatnonzero(unusable)[:10])
        raise ValueError(f"{int(unusable.sum())} row(s) contain no usable feature values (record indices: {indices}).")
    missing_mask = X.isna()
    has_imputer = any(
        step.__class__.__name__ == "SimpleImputer" and hasattr(step, "statistics_")
        for _name, step in getattr(model, "steps", [])
    )
    if missing_mask.any().any() and not has_imputer:
        raise ValueError("Some required feature values are missing or invalid; this saved model has no fitted imputer.")
    warnings = [
        {
            "record_index": int(index),
            "fields": [column for column in features if missing_mask.loc[index, column]],
            "reason": "Missing or invalid feature values were handled by the saved fitted imputer.",
        }
        for index in X.index[missing_mask.any(axis=1)]
    ]
    return X, warnings


def score_features(model, X):
    try:
        scores = np.asarray(model.decision_function(X), dtype=float)
    except Exception as exc:
        raise ModelUnavailableError("The saved model could not analyze this data.") from exc
    if scores.shape != (len(X),) or not np.isfinite(scores).all():
        raise ModelUnavailableError("The saved model returned invalid analysis scores.")
    predictions = np.where(scores < THRESHOLD, -1, 1)
    return scores, predictions


def predict_csv(file, *, analysis_id=None, severity_policy_path=None):
    """Real CSV -> saved preprocessing/model -> fixed severity policy -> aligned results."""
    df = read_network_csv(file)
    model, features = load_model()
    X, input_warnings = prepare_features(df, features, model)
    scores, model_predictions = score_features(model, X)
    version = get_model_version()
    policy = load_severity_policy(
        severity_policy_path or MODEL_DIR / "severity_policy.json", version, THRESHOLD,
    )
    analysis_id = analysis_id or "analysis-" + uuid4().hex
    deviations = np.maximum(0.0, THRESHOLD - scores)
    severities = [classify_severity(int(pred), float(strength), policy) for pred, strength in zip(model_predictions, deviations)]
    results = df.copy()
    if "Timestamp" not in results.columns:
        results["Timestamp"] = None
    results["record_index"] = np.arange(len(results))
    results["anomaly_score"] = scores
    results["decision_score"] = scores
    results["model_prediction"] = model_predictions
    results["prediction"] = np.where(model_predictions == -1, "Anomaly", "Normal")
    results["status"] = np.where(model_predictions == -1, "ANOMALY", "NORMAL")
    results["deviation_strength"] = deviations
    results["severity"] = severities
    results["severity_status"] = [
        "not_applicable" if pred == 1 else "calibrated" if policy.calibrated else "uncalibrated"
        for pred in model_predictions
    ]
    results["alert_id"] = [f"{analysis_id}-alert-{i}" if pred == -1 else None for i, pred in enumerate(model_predictions)]
    results["priority"] = None
    alerts = build_prioritized_alerts(results.loc[model_predictions == -1].to_dict(orient="records"))
    for alert in alerts:
        results.at[alert["record_index"], "priority"] = alert["priority"]
    counts = {severity: severities.count(severity) for severity in ("LOW", "MEDIUM", "HIGH")}
    anomalies = int((model_predictions == -1).sum())
    total = len(results)
    return {
        "analysis_id": analysis_id,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "model_version": version,
        "model_name": "Isolation Forest",
        "model_status": "ready",
        "status": "completed",
        "severity_policy": policy.to_dict(),
        "input_warnings": input_warnings,
        "alerts": alerts,
        "results": results,
        "summary": {
            "total_flows": total,
            "anomaly_count": anomalies,
            "normal_count": total - anomalies,
            "anomaly_percentage": round(anomalies / total * 100, 2),
            "total_records": total,
            "analyzed_records": total,
            "excluded_records": 0,
            "anomalous_records": anomalies,
            "normal_records": total - anomalies,
            "severity_counts": counts,
            "classified_anomalies": sum(counts.values()),
            "uncalibrated_count": anomalies - sum(counts.values()),
            "highest_deviation_strength": float(deviations.max()) if anomalies else None,
            "imputed_records": len(input_warnings),
        },
    }
