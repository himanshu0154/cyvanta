"""Additive, ID-based AI and HTML report endpoints; never accept client evidence."""

from urllib.parse import urlsplit
import json
import sqlite3
import threading

from flask import Blueprint, Response, current_app, jsonify, request

from incident_ai import AIError, IncidentAIService
from incident_reports import build_incident_report
from incident_store import IncidentNotFound, IncidentConflict, IncidentValidationError

incident_ai_blueprint = Blueprint("incident_ai", __name__)
_service_lock = threading.Lock()


def get_ai_service():
    if "incident_ai" not in current_app.extensions:
        with _service_lock:
            if "incident_ai" not in current_app.extensions:
                current_app.extensions["incident_ai"] = IncidentAIService()
    return current_app.extensions["incident_ai"]


def _json(allowed):
    origin = request.headers.get("Origin")
    if origin:
        try:
            expected, received = urlsplit(request.host_url), urlsplit(origin)
        except ValueError:
            raise AIError("The request origin is invalid.", "invalid_origin", 403) from None
        if (expected.scheme, expected.netloc) != (received.scheme, received.netloc) or received.path not in ("", "/") or received.query or received.fragment:
            raise AIError("Cross-origin investigation changes are not allowed.", "invalid_origin", 403)
    if not request.is_json:
        raise AIError("Send a JSON object for this operation.", "invalid_request", 415)
    if request.content_length is not None and request.content_length > 12_000:
        raise AIError("This investigation request is too large.", "invalid_request", 413)
    raw = request.stream.read(12_001)
    if len(raw) > 12_000:
        raise AIError("This investigation request is too large.", "invalid_request", 413)
    try:
        data = json.loads(raw, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise AIError("Send a valid JSON object for this operation.", "invalid_request", 400) from None
    if not isinstance(data, dict) or set(data) - set(allowed):
        raise AIError("The request contains invalid or unsupported fields.", "invalid_request", 400)
    return data


@incident_ai_blueprint.errorhandler(AIError)
def ai_error(error):
    return jsonify({"error": str(error), "code": error.code, "retryable": error.retryable}), error.status


@incident_ai_blueprint.errorhandler(IncidentNotFound)
def incident_missing(error):
    return jsonify({"error": str(error), "code": "incident_not_found", "retryable": False}), 404


@incident_ai_blueprint.errorhandler(IncidentConflict)
def incident_changed(error):
    return jsonify({"error": str(error), "code": "stale_evidence", "retryable": True}), 409


@incident_ai_blueprint.errorhandler(IncidentValidationError)
def incident_invalid(error):
    return jsonify({"error": str(error), "code": "invalid_request", "retryable": False}), 400


@incident_ai_blueprint.errorhandler(sqlite3.Error)
@incident_ai_blueprint.errorhandler(OSError)
def storage_error(_error):
    current_app.logger.error("Incident interpretation storage unavailable")
    return jsonify({"error": "Local investigation storage is unavailable. Core traffic analysis remains available.", "code": "storage_unavailable", "retryable": True}), 503


@incident_ai_blueprint.get("/api/ai/status")
def ai_status():
    return jsonify(get_ai_service().config_factory().status())


@incident_ai_blueprint.post("/api/investigations/incidents/<incident_id>/ai")
def incident_ai(incident_id):
    from incident_routes import current_owner, get_store, valid_identifier
    data = _json({"task", "event_id", "question", "regenerate"})
    if not isinstance(data.get("regenerate", False), bool):
        raise AIError("regenerate must be true or false.", "invalid_request", 400)
    if data.get("task") not in ("summary", "explain", "recommendations", "timeline", "chat"):
        raise AIError("Choose a supported AI task.", "invalid_request", 400)
    result = get_ai_service().run(get_store(), current_owner(), valid_identifier(incident_id), data.get("task"),
                                  question=data.get("question"), event_id=data.get("event_id"), regenerate=data.get("regenerate", False))
    return jsonify(result)


@incident_ai_blueprint.get("/api/investigations/incidents/<incident_id>/ai/history")
def incident_ai_history(incident_id):
    from incident_routes import current_owner, get_store, valid_identifier
    owner, store = current_owner(), get_store()
    context = store.get_context(owner, valid_identifier(incident_id), max_events=1)
    return jsonify({"incident_id": incident_id, "evidence_hash": context["evidence_hash"],
                    "messages": store.get_chat_history(owner, incident_id, context["evidence_hash"])})


@incident_ai_blueprint.post("/api/investigations/incidents/<incident_id>/report")
def incident_report(incident_id):
    from incident_routes import current_owner, get_store, valid_identifier
    data = _json({"format", "include_ai"})
    if data.get("format", "html") != "html" or not isinstance(data.get("include_ai", True), bool):
        raise AIError("Reports support HTML format and a boolean include_ai option.", "invalid_request", 400)
    store, owner = get_store(), current_owner()
    valid_identifier(incident_id)
    # Resolve and authorize evidence even if the provider is unavailable.
    incident = store.get_incident(owner, incident_id, limit=2000, offset=0)
    result, reason = None, None
    if data.get("include_ai", True):
        try:
            result = get_ai_service().run(store, owner, incident_id, "report")
        except AIError as error:
            reason = str(error)
        incident = store.get_incident(owner, incident_id, limit=2000, offset=0)
    html, report_id = build_incident_report(incident, result, reason)
    response = Response(html, mimetype="text/html")
    response.headers["Content-Disposition"] = f'attachment; filename="cyvanta-{report_id}.html"'
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Cyvanta-Report-Status"] = "ai-assisted" if result and result.get("evidence_hash") == incident.get("evidence_hash") else "factual-only"
    return response
