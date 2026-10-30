import pandas as pd


def generate_attack_timeline(results):
    if results is None or results.empty:
        return {
            "events": [],
            "total_events": 0,
            "timestamp_type": "Unavailable"
        }

    anomalies = results[
        results["prediction"] == "Anomaly"
    ].copy()

    if anomalies.empty:
        return {
            "events": [],
            "total_events": 0,
            "timestamp_type": "Unavailable"
        }

    events = []

    for index, row in anomalies.iterrows():
        timestamp = row.get("Timestamp")
        timestamp_type = row.get("Timestamp Type", "Actual")

        parsed_time = pd.to_datetime(
            timestamp,
            errors="coerce"
        )

        events.append({
            "event_id": str(index),
            "timestamp": (
                parsed_time.isoformat()
                if pd.notna(parsed_time)
                else None
            ),
            "timestamp_type": timestamp_type,
            "event_type": "Network Anomaly",
            "anomaly_score": round(
                float(row["anomaly_score"]), 6
            )
        })

    events.sort(
        key=lambda event: event["timestamp"] or ""
    )

    return {
        "events": events,
        "total_events": len(events),
        "timestamp_type": (
            "Simulated"
            if any(
                event["timestamp_type"] == "Simulated"
                for event in events
            )
            else "Actual"
        )
    }