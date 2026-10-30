"""Deterministic investigation evidence; never changes the detection pipeline."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


FEATURES = (
    "Packet Length Std", "Packet Length Mean", "ACK Flag Count", "Flow IAT Mean",
    "Total Length of Bwd Packets", "Total Fwd Packets", "Flow Duration", "Total Backward Packets",
)
NETWORK_FIELDS = {
    "source_ip": ("source_ip", "Source IP", "Src IP", "src_ip"),
    "destination_ip": ("destination_ip", "Destination IP", "Dst IP", "dst_ip"),
    "source_port": ("source_port", "Source Port", "Src Port", "src_port"),
    "destination_port": ("destination_port", "Destination Port", "Dst Port", "dst_port"),
    "protocol": ("protocol", "Protocol"),
    "timestamp": ("timestamp", "Timestamp"),
}
RANK = {None: 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
CORRELATION_RULE = "All group members share an actual source or destination IP and fall within a fixed window anchored at the first event; port or protocol alone never groups events."


def number(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        result = float(value)
        return result if math.isfinite(result) else None
    except (ValueError, TypeError, OverflowError):
        return None


def text(value, limit=250):
    if value is None or (isinstance(value, float) and not math.isfinite(value)):
        return None
    return str(value)[:limit]


def first(row, aliases):
    for key in aliases:
        if key in row and row[key] is not None and row[key] != "":
            return row[key]
    return None


def normalized_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip())) if value is not None else None
    except ValueError:
        return None


def port(value):
    result = number(value)
    return int(result) if result is not None and result.is_integer() and 0 <= result <= 65535 else None


def parse_timestamp(value, timezone_name=None, timestamp_format=None):
    """Normalize only explicit ISO offsets or an operator-configured local zone."""
    raw = text(value, 150)
    if not raw:
        return None, "Traffic timestamp is missing; source-row order is not chronology."
    try:
        parsed = datetime.strptime(raw, timestamp_format) if timestamp_format else datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            if not timezone_name:
                return None, "Traffic timestamp has no timezone; chronological interpretation is unavailable."
            zone = ZoneInfo(timezone_name)
            first_fold, second_fold = parsed.replace(tzinfo=zone, fold=0), parsed.replace(tzinfo=zone, fold=1)
            if first_fold.utcoffset() != second_fold.utcoffset():
                return None, "Traffic timestamp is ambiguous or nonexistent in the configured timezone."
            parsed = first_fold
        return parsed.astimezone(timezone.utc).isoformat(), None
    except (ValueError, TypeError, OverflowError, ZoneInfoNotFoundError):
        return None, "Traffic timestamp could not be normalized; source-row order is retained."


def normalize_events(result, *, timezone_name=None, timestamp_format=None, reference_medians=None):
    warnings = {item["record_index"]: item for item in result.get("input_warnings", [])}
    reference_medians = reference_medians or {}
    events = []
    for row in result.get("alerts", []):
        if row.get("model_prediction") != -1 or not row.get("alert_id"):
            raise ValueError("Investigation evidence requires actual anomalous model outputs.")
        raw = {field: first(row, aliases) for field, aliases in NETWORK_FIELDS.items()}
        observed_at, time_limitation = parse_timestamp(raw["timestamp"], timezone_name, timestamp_format)
        features = {field: number(row.get(field)) for field in FEATURES}
        event = {
            "event_id": row["alert_id"], "alert_id": row["alert_id"],
            "record_index": int(row["record_index"]), "prediction": row["prediction"],
            "status": row["status"], "model_prediction": -1,
            "decision_score": number(row["decision_score"]),
            "deviation_strength": number(row["deviation_strength"]),
            "severity": row.get("severity"), "severity_status": row.get("severity_status"),
            "priority": int(row["priority"]), "flow_id": text(first(row, ("Flow ID", "flow_id"))),
            "timestamp": text(raw["timestamp"], 150), "observed_at": observed_at,
            "timestamp_limitation": time_limitation,
            "source_ip": normalized_ip(raw["source_ip"]), "destination_ip": normalized_ip(raw["destination_ip"]),
            "source_port": port(raw["source_port"]), "destination_port": port(raw["destination_port"]),
            "protocol": text(raw["protocol"], 30), "features": features,
            "feature_observations": [
                {"feature": field, "value": value, "reference_median": number(reference_medians.get(field)),
                 "label": "Observed value and fitted benign-training median; descriptive comparison, not feature attribution."}
                for field, value in features.items()
            ],
            "input_warnings": [warnings[row["record_index"]]] if row["record_index"] in warnings else [],
        }
        if event["decision_score"] is None or event["deviation_strength"] is None:
            raise ValueError("Investigation evidence contains invalid model scores.")
        events.append(event)
    return events


def _entities(event):
    return {(field, event[field]) for field in ("source_ip", "destination_ip") if event.get(field)}


def correlate_events(events, analysis_id, window_seconds=300):
    """Conservative fixed-anchor groups; no bridging into unbounded attack chains."""
    if not isinstance(window_seconds, int) or not 1 <= window_seconds <= 86400:
        raise ValueError("Correlation window must be between 1 and 86400 seconds.")
    ordered = sorted(events, key=lambda e: (e["observed_at"] is None, e["observed_at"] or "", e["record_index"], e["event_id"]))
    groups, active = [], {}
    for event in ordered:
        entities = _entities(event)
        time = datetime.fromisoformat(event["observed_at"]).timestamp() if event["observed_at"] else None
        match = None
        if time is not None and entities:
            candidates = set()
            for entity in entities:
                candidates.update(active.get(entity, ()))
            eligible = [index for index in candidates if time - groups[index]["anchor"] <= window_seconds and entities & groups[index]["common"]]
            if eligible:
                match = min(eligible, key=lambda index: (-len(entities & groups[index]["common"]), groups[index]["anchor"], index))
        if match is None:
            match = len(groups)
            groups.append({"events": [], "common": entities, "anchor": time})
        group = groups[match]
        old_common = set(group["common"])
        group["events"].append(event)
        group["common"] &= entities
        if time is not None:
            for entity in old_common - group["common"]:
                active.get(entity, set()).discard(match)
            for entity in group["common"]:
                indices = active.setdefault(entity, set())
                # Remove expired anchors as we encounter the entity again.
                indices.difference_update({i for i in indices if time - groups[i]["anchor"] > window_seconds})
                indices.add(match)
    output = []
    for group in groups:
        records = group["events"]
        record_ids = sorted(event["event_id"] for event in records)
        identity = hashlib.sha256("\n".join(record_ids).encode()).hexdigest()[:20]
        relationships = []
        reasons = []
        if len(records) > 1:
            for field, value in sorted(group["common"]):
                reason = f"Shared {field.replace('_', ' ')} {value} within {window_seconds} seconds of the first recorded event."
                reasons.append(reason)
                relationships.append({"reason": reason, "entity": {"field": field, "value": value}, "supporting_event_ids": record_ids})
        limitations = []
        for event in records:
            if event["timestamp_limitation"]:
                limitations.append(event["timestamp_limitation"])
        if not all(_entities(event) for event in records):
            limitations.append("Valid source/destination IP metadata is missing; address-based correlation is unavailable.")
        if len(records) == 1:
            limitations.append("This is one anomalous observation, not an established security incident.")
        limitations.extend(["Correlation indicates shared observations, not confirmed coordinated malicious activity.", "Feature-level causal attribution and MITRE technique mapping are not established by this telemetry."])
        output.append({
            "incident_id": f"{analysis_id}-incident-{identity}", "analysis_id": analysis_id,
            "events": records, "overview": summarize_events(records),
            "timeline": {"ordering": "chronological" if all(e["observed_at"] for e in records) else "source_row",
                         "timestamped_events": sum(e["observed_at"] is not None for e in records), "count": len(records),
                         "limitations": sorted(set(limitations))},
            "correlations": {"rules": CORRELATION_RULE, "window_seconds": window_seconds, "reasons": reasons, "relationships": relationships},
            "limitations": sorted(set(limitations)),
        })
    return sorted(output, key=lambda item: (item["overview"]["priority"], item["incident_id"]))


def summarize_events(events):
    times = [event["observed_at"] for event in events if event["observed_at"]]
    severity = max((event["severity"] for event in events), key=lambda value: RANK.get(value, 0), default=None)
    def counts(field):
        return dict(sorted(Counter(str(event[field]) for event in events if event.get(field) is not None).items()))
    return {
        "event_count": len(events), "anomaly_count": len(events),
        "kind": "correlated_observations" if len(events) > 1 else "single_anomaly",
        "severity": severity, "severity_counts": {level: sum(event["severity"] == level for event in events) for level in ("LOW", "MEDIUM", "HIGH")},
        "uncalibrated_count": sum(event["severity"] is None for event in events),
        "priority": min((event["priority"] for event in events), default=None),
        "highest_deviation_strength": max((event["deviation_strength"] for event in events), default=None),
        "first_observed": min(times) if times else None, "last_observed": max(times) if times else None,
        "source_counts": counts("source_ip"), "destination_counts": counts("destination_ip"),
        "protocol_counts": counts("protocol"), "port_counts": counts("destination_port"),
    }


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
