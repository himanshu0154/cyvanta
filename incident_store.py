"""Bounded local SQLite snapshots and analyst metadata, separate from ML outputs."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
import time

from incident_evidence import correlate_events, fingerprint, normalize_events


class IncidentNotFound(LookupError):
    pass


class IncidentConflict(ValueError):
    pass


class IncidentValidationError(ValueError):
    pass


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class IncidentStore:
    """Private browser-session snapshots; retention is explicit and bounded."""

    def __init__(self, path, *, max_events=100_000, retention_days=7,
                 max_analyses_per_owner=3, max_total_bytes=128 * 1024 * 1024,
                 window_seconds=300, timezone_name=None, timestamp_format=None):
        self.path = Path(path)
        self.max_events = max_events
        self.retention_seconds = retention_days * 86400
        self.max_analyses_per_owner = max_analyses_per_owner
        self.max_total_bytes = max_total_bytes
        self.window_seconds = window_seconds
        self.timezone_name, self.timestamp_format = timezone_name, timestamp_format
        self.lock = threading.RLock()
        self.initialized = False

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        if not self.initialized:
            with self.lock:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS analyses (
                        id TEXT PRIMARY KEY, owner TEXT NOT NULL, created REAL NOT NULL,
                        metadata TEXT NOT NULL, logical_bytes INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS analyses_owner ON analyses(owner,created);
                    CREATE TABLE IF NOT EXISTS incidents (
                        id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
                        owner TEXT NOT NULL, snapshot TEXT NOT NULL, base_hash TEXT NOT NULL,
                        priority INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', notes TEXT NOT NULL DEFAULT '',
                        conclusion TEXT NOT NULL DEFAULT '', revision INTEGER NOT NULL DEFAULT 0,
                        recommendation_states TEXT NOT NULL DEFAULT '{}'
                    );
                    CREATE INDEX IF NOT EXISTS incidents_analysis ON incidents(analysis_id,priority);
                    CREATE TABLE IF NOT EXISTS events (
                        id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                        ordinal INTEGER NOT NULL, priority INTEGER NOT NULL, record_index INTEGER NOT NULL,
                        deviation REAL NOT NULL, event TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS events_incident ON events(incident_id,ordinal);
                    CREATE TABLE IF NOT EXISTS ai_results (
                        incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                        cache_key TEXT NOT NULL, evidence_hash TEXT NOT NULL, task TEXT NOT NULL,
                        result TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(incident_id,cache_key)
                    );
                    CREATE TABLE IF NOT EXISTS recommendations (
                        incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                        action_id TEXT NOT NULL, evidence_hash TEXT NOT NULL, action TEXT NOT NULL,
                        PRIMARY KEY(incident_id,action_id)
                    );
                    CREATE TABLE IF NOT EXISTS chat_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                        evidence_hash TEXT NOT NULL, question TEXT NOT NULL, response TEXT NOT NULL
                    );
                """)
                self.initialized = True
        return connection

    def _cleanup(self, connection, owner=None):
        connection.execute("DELETE FROM analyses WHERE created < ?", (time.time() - self.retention_seconds,))
        if owner:
            connection.execute("DELETE FROM analyses WHERE owner=? AND id NOT IN (SELECT id FROM analyses WHERE owner=? ORDER BY created DESC LIMIT ?)", (owner, owner, self.max_analyses_per_owner))
        while (connection.execute("SELECT COALESCE(SUM(logical_bytes),0) FROM analyses").fetchone()[0] > self.max_total_bytes):
            connection.execute("DELETE FROM analyses WHERE id=(SELECT id FROM analyses ORDER BY created LIMIT 1)")

    @staticmethod
    def _check_auxiliary_budget(connection, additional_bytes=0):
        """Bound metadata too, rather than counting only immutable snapshots."""
        used = connection.execute("""SELECT
            (SELECT COALESCE(SUM(LENGTH(CAST(result AS BLOB))),0) FROM ai_results) +
            (SELECT COALESCE(SUM(LENGTH(CAST(question AS BLOB))+LENGTH(CAST(response AS BLOB))),0) FROM chat_history) +
            (SELECT COALESCE(SUM(LENGTH(CAST(action AS BLOB))),0) FROM recommendations) +
            (SELECT COALESCE(SUM(LENGTH(CAST(notes AS BLOB))+LENGTH(CAST(conclusion AS BLOB))+LENGTH(CAST(recommendation_states AS BLOB))),0) FROM incidents)
        """).fetchone()[0]
        if used + additional_bytes > 32 * 1024 * 1024:
            raise IncidentValidationError("Local investigation metadata storage is full; retain fewer analyses before adding more annotations or AI output.")

    def save_analysis(self, owner, result, *, reference_medians=None):
        if len(result.get("alerts", [])) > self.max_events:
            raise IncidentValidationError(f"Investigation snapshots support at most {self.max_events:,} anomalies per analysis. Core analysis is complete.")
        events = normalize_events(result, timezone_name=self.timezone_name,
                                  timestamp_format=self.timestamp_format, reference_medians=reference_medians)
        groups = correlate_events(events, result["analysis_id"], self.window_seconds)
        metadata = {key: result.get(key) for key in (
            "analysis_id", "analyzed_at", "dataset_name", "data_source", "model_version", "model_name", "model_status", "severity_policy", "summary",
        )}
        metadata["investigation_policy"] = self.policy()
        metadata_text = encoded(metadata)
        prepared, event_rows, logical_bytes = [], [], len(metadata_text.encode())
        for group in groups:
            group_events = group["events"]
            snapshot = {key: value for key, value in group.items() if key != "events"}
            snapshot_text = encoded(snapshot)
            prepared.append((group["incident_id"], result["analysis_id"], owner, snapshot_text, fingerprint(group), group["overview"]["priority"]))
            logical_bytes += len(snapshot_text.encode())
            for ordinal, event in enumerate(group_events):
                event_text = encoded(event)
                logical_bytes += len(event_text.encode())
                event_rows.append((event["event_id"], group["incident_id"], ordinal, event["priority"], event["record_index"], event["deviation_strength"], event_text))
        if logical_bytes > min(self.max_total_bytes, 64 * 1024 * 1024):
            raise IncidentValidationError("Investigation snapshot exceeds the 64 MB local storage limit. Core analysis is complete.")
        with self.lock, self._connect() as connection:
            connection.execute("INSERT INTO analyses VALUES (?,?,?,?,?)", (result["analysis_id"], owner, time.time(), metadata_text, logical_bytes))
            connection.executemany("INSERT INTO incidents(id,analysis_id,owner,snapshot,base_hash,priority) VALUES(?,?,?,?,?,?)", prepared)
            connection.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?)", event_rows)
            self._cleanup(connection, owner)
        return {"status": "ready", "analysis_id": result["analysis_id"], "incident_count": len(groups),
                "reason": None, "policy": self.policy()}

    def policy(self):
        return {"retention_days": self.retention_seconds // 86400,
                "max_analyses_per_browser": self.max_analyses_per_owner,
                "max_anomalies": self.max_events, "correlation_window_seconds": self.window_seconds,
                "timestamp_timezone": self.timezone_name, "timestamp_format": self.timestamp_format,
                "storage": "Local SQLite; private to this browser session cookie. Evicted or expired references return not found."}

    def _incident(self, connection, owner, incident_id):
        self._cleanup(connection)
        row = connection.execute("SELECT i.*,a.metadata FROM incidents i JOIN analyses a ON a.id=i.analysis_id WHERE i.id=? AND i.owner=?", (incident_id, owner)).fetchone()
        if row is None:
            raise IncidentNotFound("This investigation is unavailable, expired, or belongs to another browser session.")
        return row

    @staticmethod
    def _evidence_hash(row):
        # Review bookkeeping does not change the telemetry/analyst narrative
        # supplied to AI. It must not erase the advice being reviewed.
        return fingerprint({"snapshot": row["base_hash"],
                            "notes": row["notes"], "status": row["status"], "conclusion": row["conclusion"]})

    def list_analyses(self, owner):
        with self._connect() as connection:
            self._cleanup(connection)
            rows = connection.execute("SELECT a.*,COUNT(i.id) incident_count FROM analyses a LEFT JOIN incidents i ON i.analysis_id=a.id WHERE a.owner=? GROUP BY a.id ORDER BY a.created DESC", (owner,)).fetchall()
            return {"analyses": [dict(json.loads(row["metadata"]), incident_count=row["incident_count"]) for row in rows], "policy": self.policy()}

    def list_incidents(self, owner, analysis_id, *, limit=50, offset=0, event_id=None):
        with self._connect() as connection:
            self._cleanup(connection)
            analysis = connection.execute("SELECT metadata FROM analyses WHERE id=? AND owner=?", (analysis_id, owner)).fetchone()
            if analysis is None:
                raise IncidentNotFound("This analysis is unavailable, expired, or belongs to another browser session.")
            clause, params = "i.analysis_id=? AND i.owner=?", [analysis_id, owner]
            if event_id:
                clause += " AND EXISTS(SELECT 1 FROM events e WHERE e.incident_id=i.id AND e.id=?)"
                params.append(event_id)
            total = connection.execute("SELECT COUNT(*) FROM incidents i WHERE " + clause, params).fetchone()[0]
            rows = connection.execute("SELECT i.* FROM incidents i WHERE " + clause + " ORDER BY priority,id LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
            items = []
            for row in rows:
                snapshot = json.loads(row["snapshot"])
                items.append({**snapshot["overview"], "incident_id": row["id"], "analysis_id": row["analysis_id"],
                              "status": row["status"], "revision": row["revision"], "ordering": snapshot["timeline"]["ordering"],
                              "correlation_reasons": snapshot["correlations"]["reasons"]})
            return {"analysis_id": analysis_id, "analysis": json.loads(analysis["metadata"]),
                    "incidents": items, "total": total, "limit": limit, "offset": offset,
                    "limitations": ["Groups represent anomalous observations, not confirmed attacks."], "policy": self.policy()}

    def get_incident(self, owner, incident_id, *, limit=50, offset=0, search="", sort="timeline", direction="asc"):
        with self._connect() as connection:
            row = self._incident(connection, owner, incident_id)
            snapshot, metadata = json.loads(row["snapshot"]), json.loads(row["metadata"])
            evidence_hash = self._evidence_hash(row)
            order = {"timeline": "ordinal", "priority": "priority", "deviation": "deviation"}.get(sort)
            if order is None or direction not in ("asc", "desc"):
                raise IncidentValidationError("Unsupported evidence sort.")
            clause, params = "incident_id=?", [incident_id]
            if search:
                # Escaped LIKE applies to all canonical evidence, not only a visible page.
                clause += " AND event LIKE ? ESCAPE '\\'"
                params.append("%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
            total = snapshot["overview"]["event_count"]
            filtered_total = connection.execute("SELECT COUNT(*) FROM events WHERE " + clause, params).fetchone()[0]
            sql = "SELECT event FROM events WHERE " + clause + f" ORDER BY {order} {direction},record_index,id"
            if limit is not None:
                sql += " LIMIT ? OFFSET ?"
                params.extend([limit, offset])
            events = [json.loads(item[0]) for item in connection.execute(sql, params)]
            cached = connection.execute("SELECT task,result FROM ai_results WHERE incident_id=? AND evidence_hash=? ORDER BY created", (incident_id, evidence_hash)).fetchall()
            states = json.loads(row["recommendation_states"])
            registered = connection.execute("SELECT action,evidence_hash FROM recommendations WHERE incident_id=? ORDER BY action_id", (incident_id,)).fetchall()
            recommendations = [{**json.loads(item["action"]), "evidence_hash": item["evidence_hash"],
                                "is_current": item["evidence_hash"] == evidence_hash,
                                "analyst_state": states.get(json.loads(item["action"])["action_id"], {"status": "suggested", "note": "", "technically_verified": False})}
                               for item in registered]
            return {**snapshot, "analysis": metadata, "analysis_id": row["analysis_id"], "incident_id": row["id"],
                    "evidence_hash": evidence_hash, "revision": row["revision"], "notes": row["notes"],
                    "status": row["status"], "conclusion": row["conclusion"],
                    "recommendation_states": states, "registered_recommendations": recommendations,
                    "events": events, "event_total": total, "filtered_total": filtered_total, "limit": limit, "offset": offset,
                    "ai_results": {item["task"]: json.loads(item["result"]) for item in cached if item["task"] != "chat"}}

    def get_context(self, owner, incident_id, max_events=50):
        context = self.get_incident(owner, incident_id, limit=max_events, sort="priority")
        context["context_coverage"] = {"included_events": len(context["events"]), "total_events": context["event_total"],
                                       "selection": "Highest original alert priorities, with chronology endpoints when available.",
                                       "truncated": context["event_total"] > len(context["events"])}
        if context["context_coverage"]["truncated"] and max_events >= 3:
            earliest = self.get_incident(owner, incident_id, limit=1)["events"]
            latest = self.get_incident(owner, incident_id, limit=1, direction="desc")["events"]
            endpoints = {event["event_id"]: event for event in earliest + latest}
            middle = [event for event in context["events"] if event["event_id"] not in endpoints]
            context["events"] = list(endpoints.values()) + middle[:max_events - len(endpoints)]
            context["context_coverage"]["included_events"] = len(context["events"])
        # Never send previously generated prose as if it were authoritative evidence.
        context.pop("ai_results", None)
        context.pop("registered_recommendations", None)
        context["supporting_event_ids"] = [event["event_id"] for event in context["events"]]
        selected = set(context["supporting_event_ids"])
        for relationship in context["correlations"]["relationships"]:
            all_ids = relationship["supporting_event_ids"]
            relationship["supporting_event_count"] = len(all_ids)
            relationship["supporting_event_ids"] = [identifier for identifier in all_ids if identifier in selected]
        if len(context["notes"]) > 4000:
            context["notes"] = context["notes"][:4000]
            context["context_coverage"]["notes_truncated"] = True
        return context

    def get_event(self, owner, incident_id, event_id):
        with self._connect() as connection:
            self._incident(connection, owner, incident_id)
            row = connection.execute("SELECT event FROM events WHERE incident_id=? AND id=?", (incident_id, event_id)).fetchone()
            if row is None:
                raise IncidentNotFound("The event does not belong to this investigation.")
            return json.loads(row[0])

    def update_incident(self, owner, incident_id, data):
        allowed = {"revision", "notes", "status", "conclusion", "recommendation_states"}
        if not isinstance(data, dict) or set(data) - allowed or "revision" not in data or len(data) == 1:
            raise IncidentValidationError("Supply a revision and supported investigation metadata fields.")
        if not isinstance(data["revision"], int) or isinstance(data["revision"], bool) or data["revision"] < 0:
            raise IncidentValidationError("Investigation revision must be a nonnegative integer.")
        for key, limit in (("notes", 10000), ("conclusion", 2000)):
            if key in data and (not isinstance(data[key], str) or len(data[key]) > limit):
                raise IncidentValidationError(f"{key.title()} must be text of at most {limit} characters.")
        if "status" in data and data["status"] not in ("open", "in_review", "resolved"):
            raise IncidentValidationError("Unsupported investigation status.")
        with self.lock, self._connect() as connection:
            row = self._incident(connection, owner, incident_id)
            if row["revision"] != data["revision"]:
                raise IncidentConflict("Investigation changed. Reload before saving your edits.")
            states = json.loads(row["recommendation_states"])
            updates = data.get("recommendation_states", {})
            if not isinstance(updates, dict) or len(updates) > 50:
                raise IncidentValidationError("Recommendation states must be a bounded object.")
            for action_id, state in updates.items():
                if not isinstance(state, dict) or set(state) - {"status", "note"}:
                    raise IncidentValidationError("Recommendation state accepts status and note only.")
                if state.get("status") not in ("suggested", "reviewed", "planned", "recorded_completed"):
                    raise IncidentValidationError("Unsupported recommendation state.")
                if not isinstance(state.get("note", ""), str) or len(state.get("note", "")) > 2000:
                    raise IncidentValidationError("Recommendation note must contain at most 2000 characters.")
                registered = connection.execute("SELECT 1 FROM recommendations WHERE incident_id=? AND action_id=?", (incident_id, action_id)).fetchone()
                if registered is None:
                    raise IncidentValidationError("A recommendation identifier is not registered for this investigation.")
                states[action_id] = {"status": state["status"], "note": state.get("note", ""),
                                     "recorded_at": datetime.now(timezone.utc).isoformat(), "technically_verified": False}
            cursor = connection.execute("UPDATE incidents SET status=?,notes=?,conclusion=?,recommendation_states=?,revision=revision+1 WHERE id=? AND owner=? AND revision=?", (
                data.get("status", row["status"]), data.get("notes", row["notes"]), data.get("conclusion", row["conclusion"]), encoded(states), incident_id, owner, data["revision"],
            ))
            if cursor.rowcount != 1:
                raise IncidentConflict("Investigation changed. Reload before saving your edits.")
            self._check_auxiliary_budget(connection)
        return self.get_incident(owner, incident_id)

    def get_ai_result(self, owner, incident_id, cache_key):
        with self._connect() as connection:
            row = self._incident(connection, owner, incident_id)
            cached = connection.execute("SELECT result FROM ai_results WHERE incident_id=? AND cache_key=? AND evidence_hash=?", (incident_id, cache_key, self._evidence_hash(row))).fetchone()
            return json.loads(cached[0]) if cached else None

    def save_ai_result(self, owner, incident_id, cache_key, result, evidence_hash=None, task=None):
        evidence_hash = evidence_hash or result.get("evidence_hash")
        task = task or result.get("task", "unknown")
        serialized = encoded(result)
        if len(serialized) > 100000:
            raise IncidentValidationError("AI result exceeds the storage limit.")
        with self.lock, self._connect() as connection:
            row = self._incident(connection, owner, incident_id)
            if self._evidence_hash(row) != evidence_hash:
                raise IncidentConflict("Investigation changed while AI was generating. Regenerate using current evidence.")
            connection.execute("INSERT OR REPLACE INTO ai_results VALUES (?,?,?,?,?,?)", (incident_id, cache_key, evidence_hash, task, serialized, time.time()))
            connection.execute("DELETE FROM ai_results WHERE incident_id=? AND cache_key NOT IN (SELECT cache_key FROM ai_results WHERE incident_id=? ORDER BY created DESC LIMIT 20)", (incident_id, incident_id))
            self._check_auxiliary_budget(connection)

    def register_recommendations(self, owner, incident_id, actions, evidence_hash):
        with self.lock, self._connect() as connection:
            row = self._incident(connection, owner, incident_id)
            if self._evidence_hash(row) != evidence_hash:
                raise IncidentConflict("Investigation changed before recommendations were saved.")
            for action in actions:
                connection.execute("INSERT OR REPLACE INTO recommendations VALUES (?,?,?,?)", (incident_id, action["action_id"], evidence_hash, encoded(action)))
            # Keep current recommendations plus historical IDs whose decisions
            # are recorded, with an explicit bound on accumulated regeneration.
            count = connection.execute("SELECT COUNT(*) FROM recommendations WHERE incident_id=?", (incident_id,)).fetchone()[0]
            if count > 100:
                raise IncidentValidationError("This investigation has reached its 100 registered-recommendation limit.")
            self._check_auxiliary_budget(connection)

    def get_chat_history(self, owner, incident_id, evidence_hash):
        with self._connect() as connection:
            self._incident(connection, owner, incident_id)
            rows = connection.execute("SELECT question,response FROM (SELECT id,question,response FROM chat_history WHERE incident_id=? AND evidence_hash=? ORDER BY id DESC LIMIT 10) ORDER BY id", (incident_id, evidence_hash)).fetchall()
            return [{"question": row["question"], "response": json.loads(row["response"])} for row in rows]

    def append_chat_history(self, owner, incident_id, evidence_hash, question, response):
        with self.lock, self._connect() as connection:
            row = self._incident(connection, owner, incident_id)
            if self._evidence_hash(row) != evidence_hash:
                raise IncidentConflict("Investigation changed while the answer was generated.")
            connection.execute("INSERT INTO chat_history(incident_id,evidence_hash,question,response) VALUES (?,?,?,?)", (incident_id, evidence_hash, question[:2000], encoded(response)))
            connection.execute("DELETE FROM chat_history WHERE incident_id=? AND id NOT IN (SELECT id FROM chat_history WHERE incident_id=? ORDER BY id DESC LIMIT 10)", (incident_id, incident_id))
            self._check_auxiliary_budget(connection)
