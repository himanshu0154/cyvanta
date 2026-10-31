"""Reconstruct a fixed calibration reference; never train or replace the model.

This deliberately follows cells 4/5, 53/62 and 73 of the existing training
notebook. It refuses changed source archives, unexpected split counts, or a
saved model that does not reproduce the documented fit/validation evidence.
The reference is drawn only from Wednesday's final test partition, excluding
effective feature vectors used for fitting, cutoff selection, or Friday's
earlier feature selection. This is ordinal severity calibration, not a fresh
evaluation of attack detection or impact.
"""

from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_curve
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent
ARCHIVES = {
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.zip":
        "d6839aecc1ff9fb45e27832b1f157c42c77601b83cff0befcac4f5bf10770b19",
    "Wednesday-workingHours.pcap_ISCX.csv.zip":
        "8c0de47c4b523d9d7961125fc38e3ec979c4f4fc20f268bca0a9ca7f9c7ae0ea",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def effective_signatures(model, frame):
    """Hash actual imputed float32 inputs, matching IsolationForest's dtype."""
    values = model[:-1].transform(frame).astype(np.float32)
    return pd.util.hash_pandas_object(pd.DataFrame(values), index=False).to_numpy()


def reconstruct_reference(model, features, decision_threshold):
    paths = [BASE_DIR / "data" / name for name in ARCHIVES]
    for path in paths:
        require(sha256_file(path) == ARCHIVES[path.name],
                "Source archive changed; independently review reference provenance.")

    friday = pd.read_csv(paths[0])
    friday.columns = friday.columns.str.strip()
    friday = friday.replace([np.inf, -np.inf], np.nan).dropna()
    require(len(friday) == 225711, "Friday cleanup differs from the notebook.")
    wednesday = pd.read_csv(paths[1])
    wednesday.columns = wednesday.columns.str.strip()
    # Do not add a source column before deduplication: that changes the split.
    combined = pd.concat([friday, wednesday], ignore_index=True).drop_duplicates()
    friday_end = len(friday)
    require(combined.shape == (831135, 79), "Combined data differs from the notebook.")
    labels = combined["Label"].str.strip().ne("BENIGN").astype(int)
    require(int(labels.eq(0).sum()) == 509362, "Label counts differ from the notebook.")
    inputs = combined[features].replace([np.inf, -np.inf], np.nan).copy()
    for column in ["Flow Bytes/s", "Flow Packets/s", "Flow Duration"]:
        if column in inputs:
            inputs.loc[inputs[column] < 0, column] = np.nan

    train, temporary, y_train, y_temp = train_test_split(
        inputs, labels, test_size=0.40, random_state=42, stratify=labels,
    )
    validation, test, y_validation, y_test = train_test_split(
        temporary, y_temp, test_size=0.50, random_state=42, stratify=y_temp,
    )
    benign_train = train.loc[y_train.eq(0)]
    require(len(benign_train) == 305617 and len(validation) == len(test) == 166227,
            "Reconstructed split sizes differ from the notebook.")
    require(list(model.feature_names_in_) == list(features),
            "Saved model features differ from the reference inputs.")
    require(len(model.steps) == 2 and model[0].strategy == "median",
            "Saved preprocessing differs from the documented pipeline.")
    forest = model[-1]
    require(forest.n_estimators == 200 and len(forest.estimators_) == 200
            and forest.contamination == "auto" and forest.random_state == 42
            and forest._n_samples == len(benign_train),
            "Saved model does not match the documented final fit.")
    np.testing.assert_allclose(model[0].statistics_, benign_train.median().to_numpy(),
                               rtol=0, atol=1e-9,
                               err_msg="Saved imputer differs from reconstructed training medians.")

    validation_scores = model.decision_function(validation)
    precision, recall, thresholds = precision_recall_curve(y_validation, -validation_scores)
    f1 = 2 * precision[:-1] * recall[:-1] / (precision[:-1] + recall[:-1] + 1e-12)
    selected_threshold = float(-thresholds[np.argmax(f1)])
    require(abs(selected_threshold - (-0.04045090522184547)) < 1e-12,
        "Saved model does not reproduce the notebook validation cutoff.")
    require(abs(float(np.max(f1)) - 0.8051429304752937) < 1e-10,
            "Saved model does not reproduce the notebook validation F1.")
    test_scores = model.decision_function(test)
    observed_matrix = confusion_matrix(y_test, test_scores < selected_threshold)
    require(observed_matrix.tolist() == [[91801, 10072], [14649, 49705]],
            "Saved model does not reproduce the notebook final test counts.")

    # No exact model input in the reference may have been observed in fitting,
    # cutoff tuning, or Friday's earlier feature-selection exercise. Hash
    # collisions can only exclude additional rows, not introduce overlap.
    excluded = pd.concat([benign_train, validation, inputs.loc[inputs.index < friday_end]])
    exclusion_signatures = effective_signatures(model, excluded)
    candidates = test.loc[test.index >= friday_end]
    candidate_signatures = effective_signatures(model, candidates)
    keep = ~np.isin(candidate_signatures, exclusion_signatures)
    reference = candidates.loc[keep]
    reference_scores = pd.Series(test_scores, index=test.index).loc[reference.index].to_numpy()
    strengths = np.maximum(0, decision_threshold - reference_scores)
    anomaly_strengths = strengths[reference_scores < decision_threshold]
    require(len(anomaly_strengths) >= 30 and len(np.unique(anomaly_strengths)) >= 3,
            "Independent reference anomalies are insufficient for three severity bands.")
    medium, high = np.quantile(anomaly_strengths, [1 / 3, 2 / 3], method="linear")
    require(0 < medium < high, "Independent reference severity quantiles are degenerate.")

    # Canonical ordered row ids plus actual float32 model inputs identify the
    # selected reference, not the full source archives or current uploads.
    effective = model[:-1].transform(reference).astype("<f4")
    digest = hashlib.sha256(reference.index.to_numpy(dtype="<i8").tobytes())
    digest.update(effective.tobytes())
    metadata = {
        "source": "Wednesday-only final test subset reconstructed from ml/01_network_traffic_analysis.ipynb",
        "dataset_sha256": digest.hexdigest(),
        "sample_count": len(reference),
        "anomaly_count": len(anomaly_strengths),
        "unique_strength_count": len(np.unique(anomaly_strengths)),
        "independent_reference": True,
        "provenance": (
            "Notebook cells 4/5, 53/62, 73/75; exact source archive SHA256s and "
            "60/20/20 stratified seed-42 split reproduced. Saved imputer medians, "
            "305617 benign fit samples, model parameters, validation cutoff/F1 and "
            "final test confusion counts verified without fitting. Reference uses "
            "Wednesday final-test rows only. Inputs overlapping benign fit data, "
            "cutoff validation or any Friday feature-selection data were excluded "
            "after saved imputation and float32 conversion."
        ),
        "source_archive_sha256": ARCHIVES,
        "combined_records": len(combined),
        "benign_training_records": len(benign_train),
        "validation_records": len(validation),
        "final_test_records": len(test),
        "wednesday_test_candidates": len(candidates),
        "excluded_overlapping_candidates": int((~keep).sum()),
        "reference_index_basis": "zero-based concatenated source position before full-row deduplication",
        "fingerprint_basis": "ordered little-endian int64 source indices followed by imputed float32 inputs",
        "quantile_method": "linear",
        "validation_cutoff": selected_threshold,
        "validation_f1": float(np.max(f1)),
        "notebook_test_confusion_matrix": observed_matrix.tolist(),
        "limitations": (
            "Fixed ordinal statistical heuristic, not calibrated attack probability "
            "or operational impact. This notebook test partition was previously "
            "evaluated; its subsequent use for severity calibration means it is no "
            "longer a fresh severity evaluation set. Wednesday traffic was also "
            "inspected during earlier model exploration. External validation and "
            "analyst assessment are still required."
        ),
    }
    return float(medium), float(high), metadata


def main():
    try:
        from .pipeline import load_model, get_model_version, THRESHOLD
        from .severity import PREPROCESSING_VERSION, SCORE_BASIS, validate_policy
    except ImportError:
        from pipeline import load_model, get_model_version, THRESHOLD
        from severity import PREPROCESSING_VERSION, SCORE_BASIS, validate_policy
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=BASE_DIR / "models" / "severity_policy.json")
    args = parser.parse_args()
    model, features = load_model()
    model_version = get_model_version()
    medium, high, reference = reconstruct_reference(model, features, THRESHOLD)
    artifact = {
        "schema_version": 1,
        "method": "reference_percentiles",
        "score_basis": SCORE_BASIS,
        "score_transformation": "max(0, decision_threshold - decision_score)",
        "preprocessing_version": PREPROCESSING_VERSION,
        "reference_model_version": model_version,
        "decision_threshold": THRESHOLD,
        "thresholds": {"medium": medium, "high": high},
        "quantiles": [1 / 3, 2 / 3],
        "calibrated_at": datetime.now(timezone.utc).isoformat(),
        "reference": reference,
    }
    validate_policy(artifact, model_version, THRESHOLD)
    args.output.write_text(json.dumps(artifact, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"policy": str(args.output), "thresholds": artifact["thresholds"],
                      "sample_count": reference["sample_count"], "anomaly_count": reference["anomaly_count"]}))


if __name__ == "__main__":
    main()
