"""Additive investigation routes; browser-owned snapshots, bounded input, safe errors."""

import os
from pathlib import Path
import re
import secrets
import sqlite3
from datetime import timedelta
from urllib.parse import urlsplit

from flask import Blueprint, current_app, jsonify, request, session

from incident_store import IncidentConflict, IncidentNotFound, IncidentStore, IncidentValidationError


incident_blueprint = Blueprint("investigations", __name__, url_prefix="/api/investigations")
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,200}\Z")


def current_owner():
    if "investigation_owner" not in session:
        session["investigation_owner"] = secrets.token_hex(24)
    session.permanent = True
    return session["investigation_owner"]


def get_store():
    return current_app.extensions["investigations"]


def require_json_request():
    """Cross-origin browser pages cannot use this local advisory service."""
    if not request.is_json:
        raise IncidentValidationError("Send a JSON object with Content-Type application/json.")
    origin = request.headers.get("Origin")
    if origin:
        supplied, expected = urlsplit(origin), urlsplit(request.host_url)
        if supplied.scheme != expected.scheme or supplied.netloc != expected.netloc or supplied.path not in ("", "/"):
            return jsonify({"error": "Cross-origin investigation requests are not permitted."}), 403
    return None


def valid_identifier(value):
    if not IDENTIFIER.fullmatch(value):
        raise IncidentValidationError("Invalid analysis, incident, or event identifier.")
    return value


def pagination():
    try:
        limit = int(request.args.get("limit", "50"))
        offset = int(request.args.get("offset", "0"))
    except (ValueError, TypeError) as exc:
        raise IncidentValidationError("Pagination requires integer limit and offset.") from exc
    if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
        raise IncidentValidationError("Pagination limit must be 1–100 and offset 0–100000.")
    return limit, offset


@incident_blueprint.errorhandler(IncidentNotFound)
def not_found(error):
    return jsonify({"error": str(error)}), 404


@incident_blueprint.errorhandler(IncidentConflict)
def conflict(error):
    return jsonify({"error": str(error)}), 409


@incident_blueprint.errorhandler(IncidentValidationError)
def invalid(error):
    return jsonify({"error": str(error)}), 400


@incident_blueprint.errorhandler(sqlite3.Error)
@incident_blueprint.errorhandler(OSError)
def storage_error(_error):
    current_app.logger.error("Investigation storage unavailable")
    return jsonify({"error": "Local investigation storage is unavailable. Core traffic analysis remains available."}), 503


@incident_blueprint.get("/analyses")
def analyses():
    return jsonify(get_store().list_analyses(current_owner()))


@incident_blueprint.get("/analyses/<analysis_id>/incidents")
def incidents(analysis_id):
    limit, offset = pagination()
    event_id = request.args.get("event_id")
    if event_id:
        valid_identifier(event_id)
    return jsonify(get_store().list_incidents(current_owner(), valid_identifier(analysis_id), limit=limit, offset=offset, event_id=event_id))


@incident_blueprint.get("/incidents/<incident_id>")
def incident(incident_id):
    limit, offset = pagination()
    search = request.args.get("search", "")
    if len(search) > 250:
        raise IncidentValidationError("Evidence search is limited to 250 characters.")
    return jsonify(get_store().get_incident(current_owner(), valid_identifier(incident_id), limit=limit, offset=offset,
                                           search=search, sort=request.args.get("sort", "timeline"), direction=request.args.get("direction", "asc")))


@incident_blueprint.get("/incidents/<incident_id>/events/<event_id>")
def event(incident_id, event_id):
    return jsonify(get_store().get_event(current_owner(), valid_identifier(incident_id), valid_identifier(event_id)))


@incident_blueprint.patch("/incidents/<incident_id>")
def update_incident(incident_id):
    error = require_json_request()
    if error:
        return error
    if request.content_length and request.content_length > 40000:
        raise IncidentValidationError("Investigation metadata exceeds the 40 KB request limit.")
    data = request.get_json(silent=True)
    return jsonify(get_store().update_incident(current_owner(), valid_identifier(incident_id), data))


def env_integer(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
        return value if minimum <= value <= maximum else default
    except ValueError:
        return default


def initialize_investigations(app):
    """No model or AI call on startup; storage failure cannot disable detection."""
    instance = Path(app.instance_path)
    secret = os.environ.get("CYVANTA_SESSION_SECRET")
    if not secret:
        try:
            instance.mkdir(parents=True, exist_ok=True)
            secret_path = instance / "session-secret"
            try:
                with secret_path.open("x", encoding="ascii") as handle:
                    handle.write(secrets.token_hex(32))
            except FileExistsError:
                pass
            secret = secret_path.read_text(encoding="ascii").strip()
            if len(secret) < 32:
                raise ValueError("Invalid local session secret")
        except (OSError, ValueError):
            app.logger.error("Persistent session secret unavailable; using a process-local secret")
            secret = secrets.token_hex(32)
    app.config.update(SECRET_KEY=secret, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      PERMANENT_SESSION_LIFETIME=timedelta(days=7))
    app.extensions["investigations"] = IncidentStore(
        instance / "investigations.sqlite3",
        max_events=env_integer("MAX_INVESTIGATION_EVENTS", 20_000, 1, 1_000_000),
        max_analyses_per_owner=env_integer("MAX_ANALYSES_PER_OWNER", 50, 1, 1000),
        max_total_bytes=env_integer("MAX_INVESTIGATION_BYTES", 512 * 1024 * 1024, 1, 4 * 1024 * 1024 * 1024),
        window_seconds=env_integer("CORRELATION_WINDOW_SECONDS", 300, 1, 86400),
        timezone_name=os.environ.get("TRAFFIC_TIMEZONE") or None,
        timestamp_format=os.environ.get("TRAFFIC_TIMESTAMP_FORMAT") or None,
    )
    app.register_blueprint(incident_blueprint)
