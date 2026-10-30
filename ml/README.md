# Cyvanta — ML Pipeline

## Overview
Cyvanta uses an Isolation Forest model to identify potentially anomalous network flows.

## Files
- `pipeline.py` — CSV validation, prediction, and summary generation.
- `models/isolation_forest.joblib` — Trained model.
- `models/features.joblib` — Required model features.
- `data/sample_network_flows.csv` — Synthetic sample for testing.

## Required Features
1. Packet Length Std
2. Packet Length Mean
3. ACK Flag Count
4. Flow IAT Mean
5. Total Length of Bwd Packets
6. Total Fwd Packets
7. Flow Duration
8. Total Backward Packets

## Usage
```python
from pipeline import predict_csv

output = predict_csv("data/sample_network_flows.csv")

print(output["summary"])
print(output["results"])
```

## Output
The pipeline returns:
- `results`: Original CSV data with `anomaly_score` and `prediction` columns.
- `summary`: Total flows, normal count, anomaly count, and anomaly percentage.

Predictions are `Normal` or `Anomaly`.

## Important Limitations
An anomaly is not necessarily a cyberattack. The model does not currently identify specific attack types. Its predictions require further validation on independent datasets.