/* Additive incident workspace. Only the server can supply evidence or AI findings. */
(function () {
    "use strict";
    const store = window.CyvantaAnalysis, display = window.CyvantaInvestigationData;
    const format = window.CyvantaData.formatNumber, $ = id => document.getElementById(id);
    const PAGE = 50, base = "/api/investigations";
    const state = { epoch: 0, analysisId: null, incidentId: null, detail: null, listOffset: 0,
        listTotal: 0, evidenceOffset: 0, eventId: null, outputs: new Map(), eventCache: new Map(), chat: [], pending: new Set() };
    const controllers = new Set(), drafts = new Map();
    let lastAnalysis = null, historyRequest = 0, groupRequest = 0, evidenceRequest = 0, drawerRequest = 0, drawerSelection = null, metadataDirty = false;
    function node(tag, text, className) { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (className) element.className = className; return element; }
    function status(id, message, error = false) { $(id).textContent = message; $(id).classList.toggle("investigation-error", error); }
    function ticket() { return { epoch: state.epoch, analysisId: state.analysisId, incidentId: state.incidentId }; }
    function current(value) { return display.currentRequest(value, state); }
    function cancel() { state.epoch++; for (const controller of controllers) controller.abort(); controllers.clear(); state.pending.clear(); drawerRequest++; updateBusy(); $("saveIncidentMetadata").disabled = false; $("generateIncidentReport").disabled = false; }
    function aborted(error) { return error?.name === "AbortError"; }
    async function request(path, options = {}) {
        const controller = new AbortController(); controllers.add(controller);
        try {
            const response = await fetch(path, { method: options.method || "GET", credentials: "same-origin", signal: controller.signal,
                headers: options.body === undefined ? {} : { "Content-Type": "application/json" },
                body: options.body === undefined ? undefined : JSON.stringify(options.body) });
            if (options.raw && response.ok) return response;
            let data; try { data = await response.json(); } catch { throw new Error(`The investigation service returned an invalid response (HTTP ${response.status}).`); }
            if (!response.ok) { const error = new Error(data.error || `Investigation request failed (HTTP ${response.status}).`); error.code = data.code; error.status = response.status; throw error; }
            return data;
        } finally { controllers.delete(controller); }
    }
    function endpoint(id = state.incidentId) { return `${base}/incidents/${encodeURIComponent(id)}`; }
    function context(detail, extraEvent) {
        const analysis = detail.analysis || detail.analysis_metadata || {};
        return { ...analysis, analysis_id: detail.analysis_id,
            dataset_name: analysis.dataset_name ?? detail.dataset_name,
            model_version: analysis.model_version ?? detail.model_version,
            severity_policy: analysis.severity_policy ?? detail.severity_policy,
            input_warnings: [...(detail.events || []), ...(extraEvent && !(detail.events || []).some(event => event.event_id === extraEvent.event_id) ? [extraEvent] : [])].flatMap(event => (event.input_warnings || []).map(warning => typeof warning === "string" ? { record_index: event.record_index, reason: warning } : { ...warning, record_index: event.record_index })) };
    }
    function overview(values) {
        const list = $("incidentOverview"); list.replaceChildren();
        for (const [label, value] of values) { const group = node("div"); group.append(node("dt", label), node("dd", display.humanValue(value))); list.append(group); }
    }
    function resetSelected() {
        if (state.incidentId && metadataDirty) {
            drafts.set(state.incidentId, { notes: $("incidentNotes").value, conclusion: $("incidentConclusion").value, status: $("incidentStatus").value });
            if (drafts.size > 10) drafts.delete(drafts.keys().next().value);
        }
        state.detail = null; state.incidentId = null; state.eventId = null; state.evidenceOffset = 0;
        state.outputs.clear(); state.eventCache.clear(); state.chat = []; metadataDirty = false;
        $("selectedIncident").hidden = true; $("incidentInsights").replaceChildren(); $("incidentConversation").replaceChildren();
        $("incidentFeatureComparison").replaceChildren(); status("selectedEvidence", "");
        $("incidentRecommendations").replaceChildren(node("p", "No recommendations generated.", "muted"));
        $("saveIncidentMetadata").disabled = false; $("generateIncidentReport").disabled = false; updateBusy();
        status("incidentInsightStatus", "Generate an insight when needed."); status("incidentChatStatus", ""); status("reportStatus", "");
    }
    async function refreshAnalyses(preferred = state.analysisId || store.current?.analysis_id) {
        const serial = ++historyRequest;
        $("reloadSavedAnalyses").disabled = true;
        try {
            const data = await request(`${base}/analyses`);
            if (serial !== historyRequest) return;
            const analyses = Array.isArray(data.analyses) ? data.analyses : [];
            const select = $("savedAnalysisSelect"), fragment = document.createDocumentFragment(); fragment.append(node("option", "Select a saved analysis"));
            fragment.firstChild.value = "";
            for (const analysis of analyses) { const option = node("option", `${analysis.dataset_name || "Uploaded CSV"} · ${analysis.analyzed_at || analysis.analysis_id} · ${analysis.incident_count ?? "—"} groups`); option.value = analysis.analysis_id; fragment.append(option); }
            select.replaceChildren(fragment);
            if (analyses.some(analysis => analysis.analysis_id === preferred)) select.value = preferred;
            if (!analyses.length && !store.current) status("investigationStatus", "No saved analyses. Upload traffic to begin an investigation.");
        } catch (error) { if (!aborted(error) && serial === historyRequest) status("investigationStatus", error.message + " Existing traffic analysis remains available.", true); }
        finally { if (serial === historyRequest) $("reloadSavedAnalyses").disabled = false; }
    }
    async function chooseAnalysis(id) {
        cancel(); resetSelected(); state.analysisId = id || null; state.listOffset = 0; state.listTotal = 0;
        $("incidentSelect").replaceChildren(node("option", "Select an investigation")); $("incidentSelect").disabled = true;
        $("incidentListPrevious").disabled = true; $("incidentListNext").disabled = true;
        status("incidentListCount", id ? "Loading recorded groups…" : "No investigations loaded.");
        if (!id) { status("investigationStatus", "Select an analysis to inspect recorded evidence."); return false; }
        return loadGroups();
    }
    async function loadGroups() {
        const stamp = ticket(), serial = ++groupRequest; status("investigationStatus", "Loading recorded investigations…");
        try {
            const data = await request(`${base}/analyses/${encodeURIComponent(state.analysisId)}/incidents?limit=${PAGE}&offset=${state.listOffset}`);
            if (!current(stamp) || serial !== groupRequest) return false;
            const groups = data.incidents || []; state.listTotal = Number(data.total || 0);
            const select = $("incidentSelect"), fragment = document.createDocumentFragment(), placeholder = node("option", "Select an investigation"); placeholder.value = ""; fragment.append(placeholder);
            for (const group of groups) {
                const option = node("option", `${group.incident_id} · ${group.event_count} anomalous ${group.event_count === 1 ? "observation" : "observations"} · ${group.severity || "Uncalibrated"} · ${group.status || "open"}`);
                option.value = group.incident_id; fragment.append(option);
            }
            select.replaceChildren(fragment); select.disabled = !groups.length;
            if (groups.some(group => group.incident_id === state.incidentId)) select.value = state.incidentId;
            $("incidentListPrevious").disabled = state.listOffset === 0; $("incidentListNext").disabled = state.listOffset + PAGE >= state.listTotal;
            status("incidentListCount", groups.length ? `Groups ${state.listOffset + 1}–${state.listOffset + groups.length} of ${state.listTotal}` : "No anomalous observations in this analysis.");
            status("investigationStatus", groups.length ? "Select an observation or potential correlated group. Grouping is not confirmation of an attack." : "No anomalies detected. No incident has been manufactured.");
            return true;
        } catch (error) { if (!aborted(error) && current(stamp) && serial === groupRequest) status("investigationStatus", error.message, true); return false; }
    }
    function evidenceQuery() { return new URLSearchParams({ limit: PAGE, offset: state.evidenceOffset, search: $("incidentEvidenceSearch").value.trim(), sort: $("incidentEvidenceSort").value, direction: $("incidentEvidenceDirection").value }).toString(); }
    async function chooseIncident(id, requestedEvent = null) {
        cancel(); resetSelected(); state.incidentId = id || null;
        if (!id) return false;
        $("incidentEvidenceSearch").value = ""; $("incidentEvidenceSort").value = "timeline"; $("incidentEvidenceDirection").value = "asc";
        const loaded = await loadEvidence(true);
        if (loaded && requestedEvent) await selectEvent(requestedEvent, false);
        return loaded;
    }
    async function loadEvidence(initial = false) {
        if (!state.incidentId) return false;
        const stamp = ticket(), serial = ++evidenceRequest; status("investigationStatus", "Loading investigation evidence…");
        try {
            const detail = await request(`${endpoint()}?${evidenceQuery()}`);
            if (!current(stamp) || serial !== evidenceRequest) return false;
            const oldHash = state.detail?.evidence_hash;
            state.detail = detail;
            for (const event of detail.events || []) state.eventCache.set(event.event_id, event);
            if (state.eventCache.size > 500) { const selected = state.eventCache.get(state.eventId); state.eventCache.clear(); for (const event of detail.events || []) state.eventCache.set(event.event_id, event); if (selected) state.eventCache.set(selected.event_id, selected); }
            if (oldHash && oldHash !== detail.evidence_hash) invalidateInsights();
            for (const response of Object.values(detail.ai_results || {})) if (display.validInsight(response, detail)) state.outputs.set(`${response.task}|${response.focus_event_id || ""}`, response);
            $("selectedIncident").hidden = false;
            status("incidentTitle", detail.overview?.kind === "single_anomaly" ? "Single anomalous observation" : "Potential correlated observations");
            const analysis = context(detail);
            status("incidentContext", `${detail.incident_id} · ${analysis.dataset_name || "Saved analysis"} · ${detail.analysis_id} · ${analysis.model_version || "Model version unavailable"}`);
            const values = detail.overview || {};
            overview([["Recorded anomalies", values.event_count ?? detail.event_total], ["Model severity counts", values.severity_counts], ["Recorded status", detail.status], ["Highest deviation", format(values.highest_deviation_strength)], ["First observed", values.first_observed], ["Last observed", values.last_observed], ["Model priority", values.priority], ["Evidence revision", detail.revision]]);
            const limits = [...(detail.timeline?.limitations || []), ...(detail.limitations || [])];
            status("incidentLimitations", limits.join(" ") || "Anomalies are statistical observations; malicious intent and organizational impact are unconfirmed.");
            if (initial || !metadataDirty) {
                $("incidentNotes").value = detail.notes || ""; $("incidentConclusion").value = detail.conclusion || ""; $("incidentStatus").value = detail.status || "open";
                metadataDirty = false;
                const draft = initial ? drafts.get(detail.incident_id) : null;
                if (draft) { $("incidentNotes").value = draft.notes; $("incidentConclusion").value = draft.conclusion; $("incidentStatus").value = draft.status; metadataDirty = true; }
            }
            status("incidentChatContext", `Context: ${detail.incident_id}. Questions use this saved evidence snapshot. Conversation is isolated per investigation.`);
            renderEvidence(); renderCorrelations(); renderRecommendations(); renderInsights();
            updateBusy();
            status("investigationStatus", `Loaded ${detail.event_total} anomalous observations from the selected saved analysis.`);
            if (initial) {
                status("incidentSaveStatus", metadataDirty ? "Unsaved draft restored for this investigation. Save to persist it on the server." : "Notes and status are stored on this local server when saved.");
                $("incidentWorkspace").open = true;
                loadConversation();
            }
            return true;
        } catch (error) { if (!aborted(error) && current(stamp) && serial === evidenceRequest) status("investigationStatus", error.message, true); return false; }
    }
    function invalidateInsights() {
        state.outputs.clear(); state.chat = [];
        $("incidentConversation").replaceChildren();
        status("incidentInsightStatus", "The saved investigation changed. Previous AI insights are outdated; generate them again.");
        status("incidentChatStatus", "Conversation view reset for the changed evidence snapshot.");
    }
    function renderEvidence() {
        const detail = state.detail, rows = detail.events || [], fragment = document.createDocumentFragment();
        for (const event of rows) {
            const row = node("tr"); row.dataset.eventId = event.event_id;
            const cell = text => { const td = node("td", text); row.append(td); return td; };
            cell(`${event.event_id} / row ${Number(event.record_index) + 1}`);
            cell(event.observed_at || event.timestamp || "Unavailable");
            cell("").append(store.badge(event.severity || "Uncalibrated", event.severity ? `severity-${event.severity.toLowerCase()}` : "severity-unavailable"));
            cell(format(event.decision_score)); cell(format(event.deviation_strength));
            const actions = cell(""), inspect = node("button", "Inspect", "secondary-btn row-action"); inspect.type = "button"; inspect.addEventListener("click", () => selectEvent(event.event_id, true, inspect));
            const copy = node("button", "Copy ID", "investigation-reference"); copy.type = "button"; copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(event.event_id); status("investigationStatus", "Event identifier copied."); } catch { status("investigationStatus", "Clipboard unavailable. The event identifier is displayed in the evidence table.", true); } });
            actions.append(inspect, copy); fragment.append(row);
        }
        if (!rows.length) { const row = node("tr"), cell = node("td", "No evidence matches the selected filters.", "empty-state"); cell.colSpan = 6; row.append(cell); fragment.append(row); }
        $("incidentEvidenceBody").replaceChildren(fragment);
        const total = detail.filtered_total ?? detail.event_total;
        status("incidentEvidenceCount", rows.length ? `Showing ${state.evidenceOffset + 1}–${state.evidenceOffset + rows.length} of ${total} matching · ${detail.event_total} total recorded anomalies` : `0 matching · ${detail.event_total} total recorded anomalies`);
        $("incidentEvidencePrevious").disabled = state.evidenceOffset === 0;
        $("incidentEvidenceNext").disabled = state.evidenceOffset + PAGE >= total;
        const ordering = detail.timeline?.ordering || "source_row";
        status("incidentTimelineBasis", `${ordering === "chronological" ? "Chronological recorded timestamps" : "Original source-row order; no inferred chronology"}. Timeline shows the displayed evidence page; filters and pagination apply to the entire group. ${detail.timeline?.limitations?.join(" ") || ""}`);
        const timeline = $("incidentTimeline"); timeline.replaceChildren();
        for (const event of display.timelineRows(rows, ordering)) {
            const li = node("li"), button = node("button", `${event.observed_at || (ordering === "source_row" ? `Source row ${Number(event.record_index) + 1}` : "Time unavailable")} · ${event.event_id} · ${event.severity || "Uncalibrated"}`);
            button.type = "button"; button.dataset.eventId = event.event_id; button.addEventListener("click", () => selectEvent(event.event_id, true, button)); li.append(button); timeline.append(li);
        }
        if (!rows.length) timeline.append(node("li", "No recorded events on this evidence page.", "muted"));
        highlightSelection();
    }
    async function selectEvent(id, inspect = false, trigger = null) {
        const stamp = ticket();
        try {
            let event = state.eventCache.get(id);
            if (!event) { const response = await request(`${endpoint()}/events/${encodeURIComponent(id)}`); if (!current(stamp)) return; event = response.event || response; state.eventCache.set(id, event); }
            if (!current(stamp) || event.event_id !== id) return;
            state.eventId = id; highlightSelection();
            const features = Object.entries(event.features || {}).map(([field, value]) => `${field}: ${display.humanValue(value)}`).join(" · ");
            status("selectedEvidence", `Selected ${id}. Observed input values: ${features || "No feature fields available"}. Descriptive inputs do not establish causal model attribution.`);
            const comparison = $("incidentFeatureComparison"); comparison.replaceChildren();
            for (const observation of event.feature_observations || []) { const group = node("div"); group.append(node("dt", observation.feature), node("dd", `Observed ${display.humanValue(observation.value)} · Fitted benign-training median ${display.humanValue(observation.reference_median)}`)); comparison.append(group); }
            if (inspect) store.inspect(display.evidenceRow(event), trigger, context(state.detail, event));
        } catch (error) { if (!aborted(error) && current(stamp)) status("investigationStatus", error.message, true); }
    }
    function highlightSelection() {
        $("incidentWorkspace").querySelectorAll("[data-event-id]").forEach(element => element.dataset.selectedEvent = String(element.dataset.eventId === state.eventId));
        $("explainSelectedEvent").disabled = !state.eventId || state.pending.has("explain");
    }
    function references(ids, onReference = (id, button) => selectEvent(id, true, button)) {
        const fragment = document.createDocumentFragment();
        for (const id of (ids || []).slice(0, 25)) { const button = node("button", id, "investigation-reference"); button.type = "button"; button.addEventListener("click", () => onReference(id, button)); fragment.append(button); }
        if ((ids || []).length > 25) fragment.append(node("span", ` Showing 25 of ${ids.length} supporting references; use the evidence table to explore the complete group.`, "muted"));
        return fragment;
    }
    function renderCorrelations() {
        const data = state.detail.correlations || {}, target = $("incidentCorrelations"); target.replaceChildren();
        target.append(node("p", `Configured window: ${data.window_seconds ?? "unavailable"} seconds. ${display.humanValue(data.rules)}`));
        for (const reason of data.reasons || []) target.append(node("p", display.humanValue(reason)));
        for (const relationship of data.relationships || []) {
            const p = node("p", `${relationship.reason || "Recorded relationship"} · ${display.humanValue(relationship.entity)}`); p.append(references(relationship.supporting_event_ids)); target.append(p);
        }
        if (!(data.relationships || []).length) target.append(node("p", "No supported multi-event relationship is available for this observation."));
        target.append(node("p", "Shared telemetry is a correlation indicator, not proof of a coordinated attack. Insufficient evidence for technique mapping."));
    }
    function insightBlock(response, title, onReference) {
        const content = response.content || {}, section = node("article", undefined, "investigation-insight");
        section.append(node("h4", title), node("p", `${response.source === "deterministic" ? "Calculated from recorded evidence" : "AI-generated interpretation"} · ${response.model || "Local calculation"} · ${response.generated_at || "Generation time unavailable"}${response.cached ? " · Reused matching evidence snapshot" : ""}`, "investigation-ai-label"));
        const coverage = response.context_coverage;
        if (coverage) section.append(node("p", `Context coverage: ${coverage.included_events ?? "—"} of ${coverage.total_events ?? "—"} recorded events.${coverage.truncated ? " Interpretation uses a bounded subset; global totals are calculated by the backend." : ""}`, "investigation-ai-label"));
        const summary = $("incidentSummaryView").value === "technical" ? content.technical_summary : content.executive_summary;
        if (summary) section.append(node("p", summary));
        if (content.answer && content.answer !== summary) section.append(node("p", content.answer));
        for (const [key, label] of [["observations", "Observed facts"], ["interpretations", "Interpretations"], ["hypotheses", "Unconfirmed hypotheses"]]) {
            if (!(content[key] || []).length) continue;
            section.append(node("h4", label)); const list = node("ul");
            for (const claim of content[key]) { const item = node("li", claim.text); item.append(references(claim.supporting_event_ids, onReference)); list.append(item); }
            section.append(list);
        }
        for (const [key, label] of [["unknowns", "Missing evidence"], ["limitations", "Limitations"]]) {
            if (!(content[key] || []).length) continue;
            section.append(node("h4", label)); const list = node("ul"); for (const value of content[key]) list.append(node("li", value)); section.append(list);
        }
        section.append(references(content.supporting_event_ids, onReference)); return section;
    }
    function renderInsights() {
        const target = $("incidentInsights"); target.replaceChildren();
        const labels = { summary: "Incident summary", explain: "Selected anomaly explanation", timeline: "Timeline interpretation" };
        for (const [key, response] of state.outputs) { if (display.validInsight(response, state.detail) && labels[response.task]) target.append(insightBlock(response, `${labels[response.task]}${response.task === "explain" ? ` · ${key.split("|").slice(1).join("|")}` : ""}`)); }
    }
    function renderRecommendations() {
        const target = $("incidentRecommendations"); target.replaceChildren();
        const actions = new Map();
        for (const action of state.detail.registered_recommendations || []) actions.set(action.action_id, action);
        for (const response of state.outputs.values()) if (display.validInsight(response, state.detail)) for (const action of response.content.recommended_actions || []) actions.set(action.action_id, action);
        if (!actions.size) { target.append(node("p", "No recommendations generated for the current evidence snapshot.", "muted")); return; }
        for (const action of actions.values()) {
            const section = node("article", undefined, "investigation-recommendation"), saved = state.detail.recommendation_states?.[action.action_id] || action.analyst_state || {};
            if (action.evidence_hash && action.evidence_hash !== state.detail.evidence_hash) section.append(node("p", "Generated for an earlier investigation snapshot. Review against current notes and evidence before relying on this suggestion.", "investigation-ai-label"));
            section.append(node("h4", `${action.title} · ${action.category} · ${action.priority} advisory priority`), node("p", action.rationale), references(action.supporting_event_ids), node("p", `Prerequisites: ${(action.prerequisites || []).join("; ") || "None specified"}`), node("p", `Expected benefit: ${action.expected_benefit}`), node("p", `Operational caution: ${action.operational_caution}`));
            const label = node("label", "Analyst decision"), select = node("select");
            for (const [value, text] of [["suggested", "Suggested"], ["reviewed", "Reviewed"], ["planned", "Planned"], ["recorded_completed", "Recorded as completed (unverified)"]]) { const option = node("option", text); option.value = value; select.append(option); }
            select.value = saved.status || "suggested"; label.append(select);
            const noteLabel = node("label", "Decision note"), note = node("textarea"); note.rows = 2; note.maxLength = 2000; note.value = saved.note || ""; noteLabel.append(note);
            const button = node("button", "Save recommendation decision", "secondary-btn"), feedback = node("p", "", "muted"); button.type = "button";
            button.addEventListener("click", async () => { button.disabled = true; const success = await saveMetadata({ recommendation_states: { [action.action_id]: { status: select.value, note: note.value } } }, false); if (button.isConnected) { button.disabled = false; feedback.textContent = success ? "Analyst decision recorded; no external action was performed." : "Unable to save decision. Check the investigation status message."; } });
            section.append(label, noteLabel, button, feedback); target.append(section);
        }
    }
    async function runTask(task, question = null, regenerate = false) {
        if (!state.detail || state.pending.has(task)) return;
        const stamp = ticket(), detail = state.detail, eventId = task === "explain" ? state.eventId : null;
        if (task === "explain" && !eventId) { status("incidentInsightStatus", "Select an event in evidence or timeline first.", true); return; }
        state.pending.add(task); updateBusy();
        const targetStatus = task === "chat" ? "incidentChatStatus" : "incidentInsightStatus";
        status(targetStatus, task === "chat" ? "Checking this investigation's evidence…" : "Generating evidence-grounded interpretation…");
        if (task === "chat") { state.chat.push({ role: "user", text: question }); state.chat = state.chat.slice(-20); renderConversation(); }
        try {
            const response = await request(`${endpoint()}/ai`, { method: "POST", body: { task, ...(eventId ? { event_id: eventId } : {}), ...(question ? { question } : {}), regenerate } });
            if (!current(stamp)) return;
            if (!display.validInsight(response, state.detail, task === "explain" ? eventId : undefined)) throw new Error("The investigation changed while this response was generated. Refresh evidence and retry.");
            if (task === "chat") { state.chat.push({ role: "assistant", response }); state.chat = state.chat.slice(-20); $("incidentQuestion").value = ""; renderConversation(); }
            else { state.outputs.set(`${task}|${eventId || ""}`, response); if (state.outputs.size > 25) state.outputs.delete(state.outputs.keys().next().value); renderInsights(); renderRecommendations(); }
            status(targetStatus, `${response.source === "deterministic" ? "Answer calculated from recorded evidence." : "AI interpretation generated. Validate hypotheses against recorded evidence."}${response.cached ? " A matching cached response was reused." : ""}`);
        } catch (error) { if (!aborted(error) && current(stamp)) status(targetStatus, error.message + " You can retry this action; recorded evidence remains available.", true); }
        finally { if (current(stamp)) { state.pending.delete(task); updateBusy(); } }
    }
    function updateBusy() {
        const ids = { summary: "generateIncidentSummary", explain: "explainSelectedEvent", recommendations: "generateRecommendations", timeline: "analyzeIncidentTimeline", chat: "askIncidentQuestion" };
        for (const [task, id] of Object.entries(ids)) $(id).disabled = !state.detail || state.pending.has(task) || (task === "explain" && !state.eventId);
        $("regenerateIncidentSummary").disabled = !state.detail || state.pending.has("summary");
        $("askIncidentCount").disabled = !state.detail || state.pending.has("chat");
    }
    function renderConversation() {
        const target = $("incidentConversation"); target.replaceChildren();
        for (const message of state.chat.slice(-20)) {
            const article = node("article", undefined, "investigation-message"); article.append(node("strong", message.role === "user" ? "Analyst question" : message.response?.source === "deterministic" ? "Recorded-evidence calculation" : "AI-assisted response"));
            if (message.text) article.append(node("p", message.text)); else if (message.response) article.append(insightBlock(message.response, "Investigation answer"));
            target.append(article);
        }
    }
    async function loadConversation() {
        const stamp = ticket(), initialLength = state.chat.length;
        try {
            const data = await request(`${endpoint()}/ai/history`);
            if (!current(stamp) || data.evidence_hash !== state.detail?.evidence_hash || state.pending.has("chat") || state.chat.length !== initialLength) return;
            state.chat = [];
            for (const message of data.messages || []) {
                if (!display.validInsight(message.response, state.detail)) continue;
                state.chat.push({ role: "user", text: message.question }, { role: "assistant", response: message.response });
            }
            renderConversation();
        } catch (error) { if (!aborted(error) && current(stamp)) status("incidentChatStatus", "Previous conversation is unavailable. New questions still use this investigation's evidence.", true); }
    }
    async function saveMetadata(changes, fromForm = true) {
        if (!state.detail || state.pending.has("save")) return false;
        const stamp = ticket(); state.pending.add("save"); $("saveIncidentMetadata").disabled = true; status("incidentSaveStatus", "Saving investigation metadata…");
        try {
            const response = await request(endpoint(), { method: "PATCH", body: { revision: state.detail.revision, ...changes } });
            if (!current(stamp)) return false;
            if (fromForm) { metadataDirty = false; drafts.delete(state.incidentId); }
            if (!await loadEvidence(false)) return false;
            status("incidentSaveStatus", "Saved on this local server. Reports use saved notes and status." + (metadataDirty ? " Your unsaved editor changes are still retained." : ""));
            renderInsights(); renderRecommendations();
            return true;
        } catch (error) { if (!aborted(error) && current(stamp)) { status("incidentSaveStatus", error.status === 409 ? "This investigation changed elsewhere. Your unsaved fields are retained. Refresh the selected investigation before saving again." : error.message, true); status("investigationStatus", error.message, true); } return false; }
        finally { if (current(stamp)) { state.pending.delete("save"); $("saveIncidentMetadata").disabled = false; } }
    }
    async function generateReport() {
        if (!state.detail || state.pending.has("report")) return;
        const stamp = ticket(); state.pending.add("report"); $("generateIncidentReport").disabled = true;
        status("reportStatus", "Generating a printable HTML report from saved evidence and notes…");
        try {
            const response = await request(`${endpoint()}/report`, { method: "POST", body: { format: "html", include_ai: true }, raw: true });
            const blob = await response.blob(); if (!current(stamp)) return;
            if (!response.headers.get("Content-Type")?.includes("text/html") || !blob.size) throw new Error("The report service returned an invalid report file.");
            const url = URL.createObjectURL(blob), link = node("a"); link.href = url; link.download = display.downloadFilename(response.headers.get("Content-Disposition"), "cyvanta_incident_report.html"); document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
            status("reportStatus", "HTML report downloaded. Open it to print. The report identifies whether AI narrative was available; factual evidence is retained if AI is unavailable." + (metadataDirty ? " Unsaved editor changes are not included." : ""));
        } catch (error) { if (!aborted(error) && current(stamp)) status("reportStatus", error.message + " Retry report generation when ready.", true); }
        finally { if (current(stamp)) { state.pending.delete("report"); $("generateIncidentReport").disabled = false; } }
    }
    async function findIncident(analysisId, eventId) {
        const response = await request(`${base}/analyses/${encodeURIComponent(analysisId)}/incidents?event_id=${encodeURIComponent(eventId)}&limit=1`);
        const incident = response.incidents?.[0]; if (!incident) throw new Error("This recorded event has no available investigation snapshot."); return incident.incident_id;
    }
    async function openForEvent(row, analysis, explain = false) {
        const analysisId = analysis?.analysis_id || store.current?.analysis_id, eventId = row.alert_id || row.event_id;
        if (!analysisId || !eventId) { status("drawerAIStatus", "A saved anomalous event is required for investigation.", true); return; }
        const serial = drawerRequest; status("drawerAIStatus", "Loading the saved investigation for this event…");
        $("investigateFlow").disabled = true; $("explainFlow").disabled = true;
        try {
            const id = await findIncident(analysisId, eventId);
            if (serial !== drawerRequest) return;
            if (explain) {
                const detail = await request(`${base}/incidents/${encodeURIComponent(id)}?limit=1`);
                if (serial !== drawerRequest) return;
                const response = await request(`${base}/incidents/${encodeURIComponent(id)}/ai`, { method: "POST", body: { task: "explain", event_id: eventId, regenerate: false } });
                if (serial !== drawerRequest) return;
                if (!display.validInsight(response, detail, eventId)) throw new Error("The saved evidence changed. Reopen this event and retry the explanation.");
                $("drawerAIResult").replaceChildren(insightBlock(response, "Evidence-grounded anomaly explanation", async (id, trigger) => {
                    const currentDrawer = drawerRequest;
                    try { const linked = await request(`${base}/incidents/${encodeURIComponent(detail.incident_id)}/events/${encodeURIComponent(id)}`); const event = linked.event || linked; if (currentDrawer === drawerRequest) store.inspect(display.evidenceRow(event), trigger, context(detail, event)); }
                    catch (error) { if (!aborted(error) && currentDrawer === drawerRequest) status("drawerAIStatus", error.message, true); }
                }));
                status("drawerAIStatus", `${response.cached ? "Matching cached" : "New"} AI interpretation. Feature values are observations, not causal feature attributions.`);
            } else {
                const navigate = async () => {
                    $("incidentWorkspace").open = true;
                    if (!await chooseAnalysis(analysisId)) return;
                    $("savedAnalysisSelect").value = analysisId;
                    if (await chooseIncident(id, eventId)) { location.hash = "incidentWorkspace"; $("incidentTitle").tabIndex = -1; $("incidentTitle").focus({ preventScroll: true }); }
                };
                if ($("alertDrawer").open) { $("alertDrawer").addEventListener("close", navigate, { once: true }); $("alertDrawer").close(); } else await navigate();
            }
        } catch (error) { if (!aborted(error) && serial === drawerRequest) status("drawerAIStatus", error.message + " Recorded model details remain available.", true); }
        finally { if (serial === drawerRequest) { $("investigateFlow").disabled = false; $("explainFlow").disabled = false; } }
    }
    async function aiStatus() {
        try { const data = await request("/api/ai/status"); status("investigationAIStatus", data.available ? `AI configured: ${data.model || "configured model"}. On-demand requests send bounded recorded evidence to the configured provider.` : `AI unavailable: ${data.reason || "Configure a server-side API key and model."} Evidence, notes, correlation, factual counts, and reports remain usable.`); }
        catch (error) { if (!aborted(error)) status("investigationAIStatus", "AI status unavailable. Core traffic analysis remains usable.", true); }
    }
    function onAnalysisChange() {
        if (store.status === "loading") { cancel(); status("investigationStatus", "New traffic analysis in progress. Pending requests were cancelled; any displayed investigation belongs to its labeled saved analysis."); return; }
        if (store.status === "error") status("investigationStatus", "Latest traffic analysis failed. Any selected saved investigation remains unchanged and labeled with its own analysis.", true);
        if (store.current === lastAnalysis) return;
        lastAnalysis = store.current;
        if (!lastAnalysis) return;
        cancel(); resetSelected();
        const saved = lastAnalysis.investigation;
        if (saved?.status === "ready") { chooseAnalysis(lastAnalysis.analysis_id); refreshAnalyses(lastAnalysis.analysis_id); aiStatus(); }
        else { state.analysisId = null; status("investigationStatus", saved?.reason || "The investigation snapshot is unavailable for this analysis. Existing model results remain available.", true); refreshAnalyses(); }
    }
    $("savedAnalysisSelect").addEventListener("change", () => chooseAnalysis($("savedAnalysisSelect").value));
    $("reloadSavedAnalyses").addEventListener("click", () => { refreshAnalyses(); aiStatus(); });
    $("incidentSelect").addEventListener("change", () => chooseIncident($("incidentSelect").value));
    $("incidentListPrevious").addEventListener("click", () => { state.listOffset = Math.max(0, state.listOffset - PAGE); loadGroups(); });
    $("incidentListNext").addEventListener("click", () => { state.listOffset += PAGE; loadGroups(); });
    $("applyEvidenceFilters").addEventListener("click", () => { state.evidenceOffset = 0; loadEvidence(); });
    $("incidentEvidenceSearch").addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); state.evidenceOffset = 0; loadEvidence(); } });
    $("resetEvidenceFilters").addEventListener("click", () => { $("incidentEvidenceSearch").value = ""; $("incidentEvidenceSort").value = "timeline"; $("incidentEvidenceDirection").value = "asc"; state.evidenceOffset = 0; loadEvidence(); });
    $("incidentEvidencePrevious").addEventListener("click", () => { state.evidenceOffset = Math.max(0, state.evidenceOffset - PAGE); loadEvidence(); });
    $("incidentEvidenceNext").addEventListener("click", () => { state.evidenceOffset += PAGE; loadEvidence(); });
    $("generateIncidentSummary").addEventListener("click", () => runTask("summary"));
    $("regenerateIncidentSummary").addEventListener("click", () => runTask("summary", null, true));
    $("explainSelectedEvent").addEventListener("click", () => runTask("explain"));
    $("generateRecommendations").addEventListener("click", () => runTask("recommendations"));
    $("analyzeIncidentTimeline").addEventListener("click", () => runTask("timeline"));
    $("incidentSummaryView").addEventListener("change", renderInsights);
    $("generateIncidentReport").addEventListener("click", generateReport);
    $("refreshIncident").addEventListener("click", () => loadEvidence(false));
    $("incidentMetadataForm").addEventListener("submit", event => { event.preventDefault(); saveMetadata({ notes: $("incidentNotes").value, conclusion: $("incidentConclusion").value, status: $("incidentStatus").value }); });
    for (const id of ["incidentNotes", "incidentConclusion", "incidentStatus"]) $(id).addEventListener("input", () => { metadataDirty = true; status("incidentSaveStatus", "Unsaved changes. Save to include them in reports and AI context."); });
    $("incidentChatForm").addEventListener("submit", event => { event.preventDefault(); const question = $("incidentQuestion").value.trim(); if (question) runTask("chat", question); });
    $("askIncidentCount").addEventListener("click", () => runTask("chat", "How many anomalous events are recorded in this investigation?"));
    window.addEventListener("cyvanta:draweropen", event => {
        drawerRequest++; drawerSelection = event.detail;
        const anomaly = window.CyvantaData.isAnomaly(event.detail.row);
        $("drawerAISection").hidden = !anomaly; $("drawerAIResult").replaceChildren(); status("drawerAIStatus", "Generate interpretation on demand, or open this event's saved investigation.");
        $("investigateFlow").disabled = false; $("explainFlow").disabled = false;
    });
    $("alertDrawer").addEventListener("close", () => { drawerRequest++; });
    $("investigateFlow").addEventListener("click", () => { if (drawerSelection) openForEvent(drawerSelection.row, drawerSelection.context); });
    $("explainFlow").addEventListener("click", () => { if (drawerSelection) openForEvent(drawerSelection.row, drawerSelection.context, true); });
    window.CyvantaInvestigation = { openForEvent };
    store.subscribe(onAnalysisChange); updateBusy(); refreshAnalyses(); aiStatus();
})();
