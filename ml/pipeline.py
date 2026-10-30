
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

THRESHOLD = -0.03
MAX_ROWS = 750_000


def load_model():
    """Load the trained model and its required features."""
    model_path = MODEL_DIR / "isolation_forest.joblib"
    features_path = MODEL_DIR / "features.joblib"

    if not model_path.exists() or not features_path.exists():
        raise FileNotFoundError(
            "Model files not found. Check that ml/models/ contains "
            "isolation_forest.joblib and features.joblib."
        )

    model = joblib.load(model_path)
    features = joblib.load(features_path)

    return model, features


def predict_csv(file):
    """Validate a network-flow CSV and predict anomalous activity."""

    if file is None:
        raise ValueError("Please upload a CSV file.")

    try:
        df = pd.read_csv(file)
    except pd.errors.EmptyDataError:
        raise ValueError("The uploaded CSV is empty.")
    except (pd.errors.ParserError, UnicodeDecodeError):
        raise ValueError("Unable to read this file as a valid CSV.")

    if df.empty:
        raise ValueError("The CSV contains no data rows.")

    if len(df) > MAX_ROWS:
        raise ValueError(
            f"CSV contains {len(df):,} rows. "
            f"The current limit is {MAX_ROWS:,} rows."
        )

    df.columns = df.columns.astype(str).str.strip()

    if df.columns.duplicated().any():
        raise ValueError("The CSV contains duplicate column names.")

    model, features = load_model()

    missing = [col for col in features if col not in df.columns]

    if missing:
        raise ValueError(
            "CSV is missing required network-flow features: "
            + ", ".join(missing)
        )

    X = df[features].copy()

    for col in features:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    X.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Reject rows with no usable values across all required features.
    unusable_rows = X.isna().all(axis=1)

    if unusable_rows.any():
        raise ValueError(
            f"{unusable_rows.sum()} row(s) contain no usable values "
            "in the required features. Please check your CSV."
        )

    # The trained pipeline imputes individual missing feature values.
    scores = model.decision_function(X)
    predictions = np.where(scores < THRESHOLD, "Anomaly", "Normal")

    results = df.copy()
    results["anomaly_score"] = scores
    results["prediction"] = predictions

    anomaly_count = int((predictions == "Anomaly").sum())
    total_rows = len(results)

    summary = {
        "total_flows": total_rows,
        "anomaly_count": anomaly_count,
        "normal_count": total_rows - anomaly_count,
        "anomaly_percentage": round(
            anomaly_count / total_rows * 100, 2
        ),
    }

    return {
        "results": results,
        "summary": summary,
    }