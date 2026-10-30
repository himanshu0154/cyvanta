"""Optional, bounded LLM interpretation. This module never performs detection."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
import ipaddress
import json
import os
import re
import socket
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from incident_prompts import PROMPT_VERSION, SYSTEM_INSTRUCTIONS, TASK_INSTRUCTIONS, response_schema

MAX_CONTEXT_BYTES = 64_000
MAX_PROVIDER_BYTES = 256_000
MAX_QUESTION_LENGTH = 2000
MAX_OUTPUT_TOKENS = 4000


class AIError(Exception):
    def __init__(self, message, code="ai_unavailable", status=503, retryable=False):
        super().__init__(message)
        self.code, self.status, self.retryable = code, status, retryable


@dataclass(frozen=True)
class AIConfig:
    api_key: str = field(default="", repr=False)
    model: str = ""
    base_url: str = "https://api.openai.com/v1"
    timeout: float = 30
    max_retries: int = 2
    enabled: bool = True
    invalid: bool = False

    @classmethod
    def from_env(cls):
        try:
            enabled_text = os.getenv("AI_ENABLED", "true").lower().strip()
            if enabled_text not in ("true", "false", "1", "0"):
                raise ValueError()
            timeout = float(os.getenv("AI_TIMEOUT_SECONDS", "30"))
            retries = int(os.getenv("AI_MAX_RETRIES", "2"))
            base = (os.getenv("AI_BASE_URL", "").strip() or "https://api.openai.com/v1").rstrip("/")
            parsed = urlsplit(base)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError()
            if not 1 <= timeout <= 120 or not 0 <= retries <= 3 or len(base) > 500:
                raise ValueError()
            key = os.getenv("AI_API_KEY", "").strip()
            model = os.getenv("AI_MODEL", "").strip()
            if len(key) > 4096 or "\n" in key or "\r" in key or len(model) > 200 or re.search(r"[\r\n]", model):
                raise ValueError()
            return cls(key, model, base, timeout, retries, enabled_text in ("true", "1"))
        except (ValueError, TypeError, OverflowError):
            return cls(invalid=True)

    def status(self):
        reason = ("AI configuration is invalid. Ask the application operator to review its environment settings." if self.invalid
                  else "AI is disabled by the application operator." if not self.enabled
                  else "Set AI_API_KEY and AI_MODEL on the server to enable AI interpretation." if not self.api_key or not self.model
                  else None)
        return {"enabled": self.enabled and not self.invalid, "available": reason is None,
                "model": self.model or None, "reason": reason,
                "provider": "OpenAI-compatible Chat Completions"}

    def fingerprint(self):
        material = [self.base_url, self.model, hashlib.sha256(self.api_key.encode()).hexdigest(), PROMPT_VERSION, response_schema()]
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OpenAICompatibleProvider:
    def __init__(self, opener=None, sleeper=time.sleep, clock=time.monotonic):
        self.opener = opener or build_opener(NoRedirect())
        self.sleeper, self.clock = sleeper, clock

    def generate(self, config, messages):
        if not config.status()["available"]:
            raise AIError(config.status()["reason"], "ai_not_configured")
        payload = {"model": config.model, "messages": messages, "max_completion_tokens": MAX_OUTPUT_TOKENS,
                   "store": False, "response_format": {"type": "json_schema", "json_schema": {
                       "name": "cyvanta_incident_intelligence", "strict": True, "schema": response_schema()}}}
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        deadline = self.clock() + config.timeout
        for attempt in range(config.max_retries + 1):
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise AIError("The AI provider timed out. Your evidence and notes are unchanged.", "ai_timeout", 504, True)
            request = Request(config.base_url + "/chat/completions", data=body, method="POST",
                              headers={"Authorization": "Bearer " + config.api_key, "Content-Type": "application/json"})
            try:
                with self.opener.open(request, timeout=remaining) as response:
                    raw = response.read(MAX_PROVIDER_BYTES + 1)
                if len(raw) > MAX_PROVIDER_BYTES:
                    raise AIError("The AI provider returned an oversized response.", "ai_invalid_response", 502)
                parsed = json.loads(raw)
                choice = parsed["choices"][0]
                if choice.get("finish_reason") != "stop" or choice["message"].get("refusal"):
                    raise AIError("The AI provider could not complete this evidence-grounded response.", "ai_refused", 502)
                text = choice["message"]["content"]
                if not isinstance(text, str):
                    raise ValueError()
                return json.loads(text, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            except HTTPError as exc:
                if exc.code in (401, 403):
                    raise AIError("The AI provider rejected its server credentials. Ask the application operator to review configuration.", "ai_authentication", 503) from None
                retryable = exc.code == 429 or 500 <= exc.code < 600
                error = AIError("The AI provider is rate limited. Please retry later." if exc.code == 429 else "The AI provider is unavailable or rejected this request.",
                                "ai_rate_limit" if exc.code == 429 else "ai_provider_error", 429 if exc.code == 429 else 503 if retryable else 502, retryable)
                if not retryable or attempt == config.max_retries:
                    raise error from None
            except (TimeoutError, socket.timeout):
                error = AIError("The AI provider timed out. Your evidence and notes are unchanged.", "ai_timeout", 504, True)
                if attempt == config.max_retries:
                    raise error from None
            except (URLError, OSError, HTTPException):
                error = AIError("Unable to reach the AI provider. Detection and factual reports remain available.", "ai_network_error", 503, True)
                if attempt == config.max_retries:
                    raise error from None
            except (ValueError, KeyError, IndexError, TypeError, UnicodeError):
                raise AIError("The AI provider returned an invalid structured response. Please retry.", "ai_invalid_response", 502, True) from None
            delay = min(.5 * (2 ** attempt), max(0, deadline - self.clock()))
            if delay:
                self.sleeper(delay)
        raise AIError("AI interpretation is unavailable.")


def _fail(message="The AI response contained unsupported or invalid claims."):
    raise AIError(message, "ai_invalid_response", 502, True)


def _string(value, maximum=3000, allow_empty=True):
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value.strip()):
        _fail()
    return value


def _strings(value, maximum=20):
    if not isinstance(value, list) or len(value) > maximum:
        _fail()
    for item in value:
        _string(item, 1000, False)
    return value


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)


def _event_entities(events):
    entities = {key: set() for key in ("source_ips", "destination_ips", "ports", "protocols", "timestamps")}
    for event in events:
        for field, entity in [("source_ip", "source_ips"), ("destination_ip", "destination_ips"),
                              ("source_port", "ports"), ("destination_port", "ports"),
                              ("protocol", "protocols"), ("timestamp", "timestamps"), ("observed_at", "timestamps")]:
            if event.get(field) is not None:
                entities[entity].add(str(event[field]))
    return entities


def validate_ai_content(content, context):
    """Constrain structured fields and known unsafe narrative claims; not a proof of truth."""
    schema_keys = set(response_schema()["properties"])
    if not isinstance(content, dict) or set(content) != schema_keys:
        _fail()
    events = context.get("events", [])
    known_ids = {event["event_id"] for event in events}
    if not known_ids:
        _fail("No validated event evidence is available for AI interpretation.")
    def references(value, required=False):
        _strings(value, 50)
        if (required and not value) or not set(value).issubset(known_ids):
            _fail("The AI response referenced unavailable event evidence.")
    for key in ("executive_summary", "technical_summary", "answer"):
        _string(content[key])
    if not any(content[key].strip() for key in ("executive_summary", "technical_summary", "answer")):
        _fail()
    for key in ("observations", "interpretations", "hypotheses"):
        if not isinstance(content[key], list) or len(content[key]) > 12:
            _fail()
        for claim in content[key]:
            if not isinstance(claim, dict) or set(claim) != {"text", "supporting_event_ids"}:
                _fail()
            _string(claim["text"], 1500, False)
            references(claim["supporting_event_ids"], required=True)
    for key in ("limitations", "unknowns"):
        _strings(content[key])
    references(content["supporting_event_ids"], required=True)
    if not isinstance(content["observed_event_count"], int) or isinstance(content["observed_event_count"], bool) or content["observed_event_count"] != context.get("event_total"):
        _fail("The AI response changed the server-computed event count.")
    allowed = _event_entities(events)
    entities = content["observed_entities"]
    if not isinstance(entities, dict) or set(entities) != set(allowed):
        _fail()
    for key in allowed:
        _strings(entities[key], 50)
        if not set(entities[key]).issubset(allowed[key]):
            _fail("The AI response invented network entities or timestamps.")
    actions = content["recommended_actions"]
    if not isinstance(actions, list) or len(actions) > 8:
        _fail()
    action_keys = set(response_schema()["properties"]["recommended_actions"]["items"]["properties"])
    for action in actions:
        if not isinstance(action, dict) or set(action) != action_keys:
            _fail()
        for key in ("action_id", "title", "rationale", "expected_benefit", "operational_caution"):
            _string(action[key], 1500, False)
        if not isinstance(action["category"], str) or not isinstance(action["priority"], str) or action["category"] not in {"triage", "investigation", "containment", "hardening"} or action["priority"] not in {"low", "medium", "high"} or action["status"] != "suggested":
            _fail()
        references(action["supporting_event_ids"], required=True)
        _strings(action["prerequisites"])
        if action["category"] == "containment" and not action["prerequisites"]:
            _fail("Containment advice requires explicit validation and human-approval prerequisites.")
        identity = json.dumps([context.get("incident_id"), context.get("evidence_hash"), action["title"], action["category"], action["supporting_event_ids"]], sort_keys=True)
        action["action_id"] = "action-" + hashlib.sha256(identity.encode()).hexdigest()[:20]
    narrative = "\n".join(_walk_strings(content))
    if re.search(r"\bT\d{4}(?:\.\d{3})?\b", narrative):
        _fail("Technique mappings are not supported by this statistical network evidence.")
    allowed_ips = allowed["source_ips"] | allowed["destination_ips"]
    for token in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)", narrative):
        try:
            normalized = str(ipaddress.ip_address(token))
        except ValueError:
            _fail()
        if normalized not in allowed_ips:
            _fail("The AI response mentioned an IP address absent from its evidence context.")
    for token in re.findall(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?![\w:])", narrative):
        try:
            normalized = str(ipaddress.ip_address(token))
        except ValueError:
            continue
        if normalized not in allowed_ips:
            _fail("The AI response mentioned an IP address absent from its evidence context.")
    for token in re.findall(r"\b\d{4}-\d{2}-\d{2}(?:[T ][0-9:.]+(?:Z|[+-]\d\d:\d\d)?)?", narrative):
        if not any(token in known for known in allowed["timestamps"]):
            _fail("The AI response mentioned an unsupported timestamp.")
    for token in re.findall(r"\b\d{1,2}/\d{1,2}/\d{2,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?", narrative):
        if not any(token in known for known in allowed["timestamps"]):
            _fail("The AI response mentioned an unsupported timestamp.")
    for token in re.findall(r"\b(?:port|ports)\s*[:=]?\s*(\d{1,5})\b", narrative, re.I):
        if token not in allowed["ports"]:
            _fail("The AI response mentioned an unsupported network port.")
    # Explicit unsafe assertions are rejected. Hypotheses are separately labelled;
    # this conservative filter is an additional guard, not semantic verification.
    for sentence in re.split(r"[\n.!?]", narrative):
        sentence = sentence.strip()
        sentence = re.sub(r"\b(?:not|no|unconfirmed|cannot establish|does not establish|does not confirm|is not|was not)\s+(?:a |an |the )?(?:confirmed (?:attack|compromise)|feature (?:importance|attribution)|(?:attack|compromise)|(?:compromised|malicious attack))\b", "", sentence, flags=re.I)
        if re.search(r"\b(confirmed (?:attack|compromise|malicious)|(?:is|was|are|were) (?:a |an )?(?:DDoS attack|compromised|malicious attack)|(?:blocked|isolated|disabled) (?:the |all )?(?:host|IP|account|traffic)|caused the (?:model|prediction)|feature (?:importance|attribution) (?:shows|indicates|caused)|feature (?:importance|attribution) is (?!not\b|unavailable\b)|\d+(?:\.\d+)?% (?:attack|malicious|confidence|probability))\b", sentence, re.I):
            _fail("The AI response made an unsupported attribution, certainty, or action-execution claim.")
    for count in re.findall(r"\b(\d+)\s+(?:anomalous\s+)?(?:events?|flows?|records?|observations?)\b", narrative, re.I):
        permitted = {1, context.get("event_total"), len(events)}
        for value in context.get("overview", {}).values():
            if isinstance(value, int) and not isinstance(value, bool):
                permitted.add(value)
            elif isinstance(value, dict):
                permitted.update(item for item in value.values() if isinstance(item, int) and not isinstance(item, bool))
        if int(count) not in permitted:
            _fail("The AI response included an unsupported event count.")
    return content


def empty_content(context, answer=""):
    return {"executive_summary": "", "technical_summary": "", "answer": answer,
            "observations": [], "interpretations": [], "hypotheses": [],
            "limitations": ["Statistical anomalies do not establish malicious activity or attack impact."],
            "unknowns": [], "recommended_actions": [],
            "supporting_event_ids": [event["event_id"] for event in context.get("events", [])[:5]],
            "observed_event_count": context.get("event_total", 0),
            "observed_entities": {key: [] for key in ("source_ips", "destination_ips", "ports", "protocols", "timestamps")}}


def deterministic_answer(question, context):
    lower = question.lower().strip()
    overview = context.get("overview", {})
    if re.search(r"\b(most|frequent|frequency|top)\b", lower) and "source" in lower:
        counts = overview.get("source_counts", {})
        ranked = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))[:10]
        answer = "Source IP frequencies computed over all stored incident events: " + "; ".join(f"{ip}: {count}" for ip, count in ranked) + "." if ranked else "Source IP fields are unavailable for this incident; a source-frequency comparison cannot be made."
        return empty_content(context, answer)
    if re.search(r"\b(how many|count|number of)\b", lower) and re.search(r"\b(events?|flows?|anomalies|records?|observations?)\b", lower):
        if re.search(r"\b(last|yesterday|today|after|before|between|since|during|malicious|attacks?|failed|duration|bytes|packets|greater|above|below|less|larger|smaller)\b", lower):
            return empty_content(context, "That filtered count is not available from the selected incident's aggregate fields. No numerical estimate has been generated; inspect the underlying evidence or choose a supported filter.")
        severity = re.search(r"\b(high|medium|low|uncalibrated)\b", lower)
        protocol = re.search(r"\b(tcp|udp|icmp|icmpv6)\b", lower)
        port_match = re.search(r"\bport\s*(\d{1,5})\b", lower)
        match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}", lower)
        selector_count = sum(bool(value) for value in (severity, protocol, port_match, match))
        unspecified_entity_with_other_selector = bool(severity or protocol) and ("source" in lower or "destination" in lower)
        if selector_count > 1 or unspecified_entity_with_other_selector:
            return empty_content(context, "A combined filtered count cannot be obtained from separate marginal aggregates. Choose a single severity, recorded protocol, destination port, or source/destination IP filter; no joint count has been guessed.")
        if "normal" in lower or "benign" in lower:
            return empty_content(context, "This investigation snapshot contains anomalous observations only. Normal-traffic counts belong to the overall analysis, rather than this incident evidence.")
        if severity:
            level = severity.group(1).upper()
            count = overview.get("uncalibrated_count", 0) if level == "UNCALIBRATED" else overview.get("severity_counts", {}).get(level, 0)
            return empty_content(context, f"The selected investigation contains {count} {level} anomalous observations. This count is computed over its complete stored evidence.")
        if protocol:
            observed = {str(key).lower(): (str(key), count) for key, count in overview.get("protocol_counts", {}).items()}
            if protocol.group(1) not in observed:
                return empty_content(context, "That protocol label is not present in this incident's recorded protocol aggregate. No equivalent protocol or count has been inferred.")
            label, count = observed[protocol.group(1)]
            return empty_content(context, f"The selected investigation contains {count} anomalous observations with recorded protocol {label}. This is a complete server-computed count.")
        if port_match:
            if "source port" in lower:
                return empty_content(context, "The available port aggregate describes destination ports. A source-port count has not been inferred from it.")
            value = str(int(port_match.group(1)))
            count = overview.get("port_counts", {}).get(value, 0)
            return empty_content(context, f"The selected investigation contains {count} anomalous observations with destination port {value}. This is a complete server-computed count.")
        if match:
            try:
                ip = str(ipaddress.ip_address(match.group()))
            except ValueError:
                return empty_content(context, "That question does not contain a valid IP address. Select a recorded source or destination address.")
            if "source" in lower:
                return empty_content(context, f"The source IP {ip} appears in {overview.get('source_counts', {}).get(ip, 0)} stored anomalous observations in this investigation. This is an exact server-computed count.")
            if "destination" in lower:
                return empty_content(context, f"The destination IP {ip} appears in {overview.get('destination_counts', {}).get(ip, 0)} stored anomalous observations in this investigation. This is an exact server-computed count.")
            return empty_content(context, f"For {ip}, the source count is {overview.get('source_counts', {}).get(ip, 0)} and the destination count is {overview.get('destination_counts', {}).get(ip, 0)}. Counts are separate roles and must not be added as a unique-event total.")
        if "source" in lower or "destination" in lower:
            return empty_content(context, "Specify an actual source or destination IP to count matching events. Overall, this investigation contains " + str(context['event_total']) + " anomalous observations.")
        # Unrecognized temporal/behavioral qualifiers must not silently turn into
        # an unfiltered total or be delegated to an LLM over sampled rows.
        qualifiers = re.search(r"\b(last|yesterday|today|after|before|between|since|during|suspicious|malicious|attack|failed|same|different|with|where|over|under|more|less|from|to)\b", lower)
        if qualifiers:
            return empty_content(context, "That filtered count is not available from the selected incident's aggregate fields. No numerical estimate has been generated; inspect the underlying evidence or choose a supported filter.")
        return empty_content(context, f"The selected investigation contains {context['event_total']} anomalous observations. This count is computed from all stored incident events, not the visible page.")
    return None


class IncidentAIService:
    def __init__(self, provider=None, config_factory=AIConfig.from_env):
        self.provider = provider or OpenAICompatibleProvider()
        self.config_factory = config_factory
        self._guard = threading.Lock()
        self._inflight = set()
        self._rates = defaultdict(deque)
        self._capacity = threading.BoundedSemaphore(2)

    def _enter(self, owner, key):
        now = time.monotonic()
        with self._guard:
            if key in self._inflight:
                raise AIError("This AI request is already being processed. Please wait before retrying.", "ai_in_progress", 409, True)
            for old in list(self._rates):
                if not self._rates[old] or self._rates[old][-1] < now - 60:
                    del self._rates[old]
            if owner not in self._rates and len(self._rates) >= 256:
                raise AIError("The AI service is busy. Please retry shortly.", "ai_busy", 429, True)
            bucket = self._rates[owner]
            while bucket and bucket[0] < now - 60:
                bucket.popleft()
            if len(bucket) >= 12:
                raise AIError("AI request limit reached. Please retry in a minute.", "ai_rate_limit", 429, True)
            if not self._capacity.acquire(blocking=False):
                raise AIError("The AI service is busy. Please retry shortly.", "ai_busy", 429, True)
            bucket.append(now)
            self._inflight.add(key)

    def run(self, store, owner, incident_id, task, question=None, event_id=None, regenerate=False):
        if not isinstance(task, str) or task not in TASK_INSTRUCTIONS:
            raise AIError("Choose a supported AI task.", "invalid_request", 400)
        if task == "chat" and (not isinstance(question, str) or not question.strip() or len(question) > MAX_QUESTION_LENGTH):
            raise AIError("Enter an investigation question of at most 2,000 characters.", "invalid_request", 400)
        if question is not None and task != "chat":
            raise AIError("Questions are accepted only for the chat task.", "invalid_request", 400)
        context = store.get_context(owner, incident_id, max_events=30)
        if not context.get("events"):
            raise AIError("No validated event evidence is available.", "missing_evidence", 422)
        if event_id is not None:
            if not isinstance(event_id, str) or len(event_id) > 200:
                raise AIError("Select a valid event identifier.", "invalid_request", 400)
            focus = store.get_event(owner, incident_id, event_id)
            context["events"] = [focus] + [event for event in context["events"] if event["event_id"] != event_id][:29]
            context["focus_event_id"] = event_id
            context.setdefault("context_coverage", {})["included_events"] = len(context["events"])
            context["context_coverage"]["focus_event_included"] = True
        config = self.config_factory()
        if task == "chat":
            answer = deterministic_answer(question, context)
            if answer:
                result = self._envelope(context, task, answer, "deterministic", None)
                store.append_chat_history(owner, incident_id, context["evidence_hash"], question.strip(), result)
                return result
        if not config.status()["available"]:
            raise AIError(config.status()["reason"], "ai_not_configured")
        history = store.get_chat_history(owner, incident_id, context["evidence_hash"]) if task == "chat" else []
        cache_key = hashlib.sha256(json.dumps([owner, incident_id, context["evidence_hash"], task, question, event_id,
                                               config.fingerprint(), history], sort_keys=True, default=str).encode()).hexdigest()
        if not regenerate:
            cached = store.get_ai_result(owner, incident_id, cache_key)
            if cached:
                cached = json.loads(json.dumps(cached))
                cached["cached"] = True
                return cached
        self._enter(owner, cache_key)
        try:
            # Never send arbitrary uploaded fields or the whole data frame.
            safe_keys = {"incident_id", "analysis_id", "evidence_hash", "overview", "events", "event_total", "timeline", "correlations", "notes", "status", "conclusion", "analysis", "focus_event_id", "context_coverage"}
            compact = {key: context[key] for key in safe_keys if key in context}
            compact["overview"] = dict(compact.get("overview", {}))
            for field_name in ("source_counts", "destination_counts", "protocol_counts", "port_counts"):
                counts = compact["overview"].get(field_name)
                if isinstance(counts, dict) and len(counts) > 20:
                    compact["overview"][field_name] = dict(sorted(counts.items(), key=lambda pair: (-pair[1], str(pair[0])))[:20])
                    compact.setdefault("context_coverage", {})[field_name + "_truncated"] = True
            evidence_text = json.dumps(compact, ensure_ascii=False, allow_nan=False, default=str)
            while len(evidence_text.encode()) > MAX_CONTEXT_BYTES and len(compact["events"]) > 1:
                compact["events"] = compact["events"][:max(1, len(compact["events"]) // 2)]
                compact["context_coverage"] = {"included_events": len(compact["events"]), "total_events": context["event_total"], "limited": True}
                evidence_text = json.dumps(compact, ensure_ascii=False, allow_nan=False, default=str)
            if len(evidence_text.encode()) > MAX_CONTEXT_BYTES:
                raise AIError("The selected incident context is too large for a bounded AI request. Shorten analyst notes and retry.", "context_limit", 422)
            bounded_history = []
            for pair in history[-5:]:
                previous_content = pair.get("response", {}).get("content", {})
                bounded_history.append({"question": str(pair.get("question", ""))[:1000],
                                        "answer": str(previous_content.get("answer") or previous_content.get("executive_summary") or "")[:1200]})
            prompt_data = {"task": TASK_INSTRUCTIONS[task], "context": compact, "question": question,
                           "prior_incident_conversation": bounded_history}
            # Account for the question, task and history too, not only telemetry.
            while len(json.dumps(prompt_data, ensure_ascii=False).encode()) > MAX_CONTEXT_BYTES and prompt_data["prior_incident_conversation"]:
                prompt_data["prior_incident_conversation"].pop(0)
            while len(json.dumps(prompt_data, ensure_ascii=False).encode()) > MAX_CONTEXT_BYTES and len(compact["events"]) > 1:
                compact["events"].pop()
                compact.setdefault("context_coverage", {})["included_events"] = len(compact["events"])
                compact["context_coverage"]["truncated"] = True
            if len(json.dumps(prompt_data, ensure_ascii=False).encode()) > MAX_CONTEXT_BYTES:
                raise AIError("The selected evidence exceeds the bounded AI context limit.", "context_limit", 422)
            selected_ids = {event["event_id"] for event in compact["events"]}
            for relationship in compact.get("correlations", {}).get("relationships", []):
                if isinstance(relationship, dict) and "supporting_event_ids" in relationship:
                    relationship["supporting_event_ids"] = [identifier for identifier in relationship["supporting_event_ids"] if identifier in selected_ids]
            context["context_coverage"] = compact.get("context_coverage", {})
            messages = [{"role": "system", "content": SYSTEM_INSTRUCTIONS},
                        {"role": "user", "content": json.dumps(prompt_data, ensure_ascii=False, allow_nan=False, default=str)}]
            content = validate_ai_content(self.provider.generate(config, messages), compact)
            latest = store.get_context(owner, incident_id, max_events=1)
            if latest["evidence_hash"] != context["evidence_hash"]:
                raise AIError("The investigation changed during AI generation. Regenerate against the current evidence and notes.", "stale_evidence", 409, True)
            result = self._envelope(context, task, content, "ai", config.model)
            store.save_ai_result(owner, incident_id, cache_key, result, evidence_hash=context["evidence_hash"], task=task)
            if content["recommended_actions"]:
                store.register_recommendations(owner, incident_id, content["recommended_actions"], context["evidence_hash"])
            if task == "chat":
                store.append_chat_history(owner, incident_id, context["evidence_hash"], question.strip(), result)
            return result
        finally:
            with self._guard:
                self._inflight.discard(cache_key)
            self._capacity.release()

    @staticmethod
    def _envelope(context, task, content, source, model):
        return {"incident_id": context["incident_id"], "evidence_hash": context["evidence_hash"],
                "task": task, "source": source, "model": model, "generated_at": datetime.now(timezone.utc).isoformat(),
                "focus_event_id": context.get("focus_event_id"), "context_coverage": context.get("context_coverage", {}),
                "cached": False, "content": content,
                "disclosure": "AI interpretations and recommendations need analyst review; authoritative model predictions remain unchanged." if source == "ai" else "Computed locally from the complete server-owned event aggregate."}
