
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

THRESHOLD = 0.02


def load_model():
    """Load the trained model and required features."""
    model = joblib.load(MODEL_DIR / "isolation_forest.joblib")
    features = joblib.load(MODEL_DIR / "features.joblib")
    return model, features


def predict_csv(file):
    """Analyze network flows and flag anomalous activity."""
    model, features = load_model()

    df = pd.read_csv(file)
    df.columns = df.columns.str.strip()

    # Check required features
    missing = [col for col in features if col not in df.columns]
    if missing:
        raise ValueError(
            f"CSV is missing required columns: {missing}"
        )

    # Select and prepare model features
    X = df[features].copy()

    for col in features:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    X.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Predict anomalies
    scores = model.decision_function(X)
    predictions = np.where(
        scores < THRESHOLD, "Anomaly", "Normal"
    )

    # Attach results to original rows
    results = df.copy()
    results["anomaly_score"] = scores
    results["prediction"] = predictions

    return results
