/* Integrated Incident Intelligence & AI Copilot in Flow Inspection Drawer. */
(function () {
    "use strict";
    const store = window.CyvantaAnalysis, display = window.CyvantaInvestigationData;
    const format = window.CyvantaData?.formatNumber || (v => String(v));
    const $ = id => document.getElementById(id);
    const base = "/api/investigations";
    let currentIncidentId = null, currentEventId = null, drawerSelection = null, busy = false;
    const controllers = new Set();

    function node(tag, text, className) {
        const el = document.createElement(tag);
        if (text !== undefined) el.textContent = text;
        if (className) el.className = className;
        return el;
    }

    function status(id, message, error = false) {
        const el = $(id);
        if (!el) return;
        el.textContent = message;
        el.classList.toggle("investigation-error", error);
    }

    async function request(path, options = {}) {
        const controller = new AbortController();
        controllers.add(controller);
        try {
            const response = await fetch(path, {
                method: options.method || "GET",
                credentials: "same-origin",
                signal: controller.signal,
                headers: options.body === undefined ? {} : { "Content-Type": "application/json" },
                body: options.body === undefined ? undefined : JSON.stringify(options.body)
            });
            if (options.raw && response.ok) return response;
            let data;
            try { data = await response.json(); } catch { throw new Error(`The investigation service returned an invalid response (HTTP ${response.status}).`); }
            if (!response.ok) {
                const error = new Error(data.error || `Investigation request failed (HTTP ${response.status}).`);
                error.code = data.code;
                error.status = response.status;
                throw error;
            }
            return data;
        } finally {
            controllers.delete(controller);
        }
    }

    async function findIncident(analysisId, eventId) {
        const response = await request(`${base}/analyses/${encodeURIComponent(analysisId)}/incidents?event_id=${encodeURIComponent(eventId)}&limit=1`);
        let incident = response.incidents?.[0];
        if (!incident) {
            const fallback = await request(`${base}/analyses/${encodeURIComponent(analysisId)}/incidents?limit=1`);
            incident = fallback.incidents?.[0];
        }
        if (!incident) throw new Error("This recorded event has no available investigation record.");
        return incident.incident_id;
    }

    async function aiStatus() {
        try {
            const data = await request("/api/ai/status");
            const isAvail = data.available;
            const statusEl = $("drawerAIStatusPill");
            if (statusEl) {
                statusEl.className = isAvail ? "ai-status-pill ai-online" : "ai-status-pill ai-offline";
                statusEl.textContent = isAvail ? `● AI Copilot Active (${data.model || "Ready"})` : `○ AI Narrative Offline`;
                statusEl.title = isAvail
                    ? `Connected to ${data.model}. On-demand requests send bounded recorded evidence to provider.`
                    : (data.reason || "Configure AI_API_KEY and AI_MODEL on server to enable AI interpretation.");
            }
        } catch {
            const statusEl = $("drawerAIStatusPill");
            if (statusEl) {
                statusEl.className = "ai-status-pill ai-offline";
                statusEl.textContent = "○ AI Status Offline";
            }
        }
    }

    function references(ids) {
        const fragment = document.createDocumentFragment();
        for (const id of (ids || []).slice(0, 8)) {
            const badge = node("span", id, "investigation-reference");
            fragment.append(badge);
        }
        if ((ids || []).length > 8) fragment.append(node("span", ` +${ids.length - 8} more`, "muted small-caption"));
        return fragment;
    }

    function insightBlock(response, title) {
        const content = response.content || {}, section = node("article", undefined, "investigation-insight");
        const header = node("div", undefined, "insight-header");
        header.append(node("h4", title));
        const meta = node("span", `${response.source === "deterministic" ? "Deterministic" : "AI Copilot"} · ${response.model || "Local"} · ${response.cached ? "Cached" : "Live"}`, "insight-badge");
        header.append(meta);
        section.append(header);

        const summary = content.executive_summary || content.technical_summary || content.answer;
        if (summary) section.append(node("p", summary, "insight-summary-lead"));
        if (content.technical_summary && content.technical_summary !== summary) {
            const techBlock = node("div", undefined, "insight-section insight-assessment");
            techBlock.append(node("h5", "Technical Breakdown"));
            techBlock.append(node("p", content.technical_summary));
            section.append(techBlock);
        }

        for (const [key, label, cls] of [
            ["observations", "Observed Telemetry Facts", "insight-facts"],
            ["interpretations", "Analysis & Assessment", "insight-assessment"],
            ["hypotheses", "Potential Threat Hypotheses", "insight-hypothesis"]
        ]) {
            if (!(content[key] || []).length) continue;
            const block = node("div", undefined, `insight-section ${cls}`);
            block.append(node("h5", label));
            const list = node("ul");
            for (const claim of content[key]) {
                const item = node("li", claim.text || (typeof claim === "string" ? claim : JSON.stringify(claim)));
                if (claim.supporting_event_ids) item.append(references(claim.supporting_event_ids));
                list.append(item);
            }
            block.append(list);
            section.append(block);
        }

        if ((content.recommended_actions || []).length) {
            section.append(recommendationsList(content.recommended_actions));
        }

        for (const [key, label, cls] of [
            ["unknowns", "Information Gaps / Missing Telemetry", "insight-unknowns"],
            ["limitations", "Investigation Caveats", "insight-limitations"]
        ]) {
            if (!(content[key] || []).length) continue;
            const block = node("div", undefined, `insight-section ${cls}`);
            block.append(node("h5", label));
            const list = node("ul");
            for (const value of content[key]) list.append(node("li", String(value)));
            block.append(list);
            section.append(block);
        }

        return section;
    }

    function recommendationsList(actions) {
        const wrap = node("div", undefined, "rec-container");
        wrap.append(node("h5", "Recommended Defensive Actions", "recommendations-heading"));
        for (const action of actions) {
            const card = node("article", undefined, "investigation-recommendation");
            const cardHeader = node("div", undefined, "rec-header");
            cardHeader.append(node("h5", action.title));
            const prio = (action.priority || "medium").toLowerCase();
            cardHeader.append(node("span", action.priority || "Advisory", `rec-prio rec-prio-${prio}`));
            if (action.category) cardHeader.append(node("span", action.category, "rec-cat"));
            card.append(cardHeader);

            if (action.rationale) card.append(node("p", action.rationale, "rec-rationale"));

            const callouts = node("div", undefined, "rec-callouts");
            if (action.expected_benefit) {
                const ben = node("div", undefined, "rec-callout rec-benefit");
                ben.append(node("strong", "Expected Benefit: "), document.createTextNode(action.expected_benefit));
                callouts.append(ben);
            }
            if (action.operational_caution) {
                const caut = node("div", undefined, "rec-callout rec-caution");
                caut.append(node("strong", "Operational Caution: "), document.createTextNode(action.operational_caution));
                callouts.append(caut);
            }
            if (callouts.children.length) card.append(callouts);
            wrap.append(card);
        }
        return wrap;
    }

    function setBusy(isBusy) {
        busy = isBusy;
        for (const id of ["drawerExplainFlow", "drawerSummaryFlow", "drawerRecommendationsFlow", "drawerReportFlow", "drawerChatSubmit"]) {
            const btn = $(id);
            if (btn) btn.disabled = isBusy;
        }
    }

    async function runAITask(task, question = null) {
        if (!currentIncidentId || busy) return;
        setBusy(true);
        const actionLabel = task === "explain" ? "Generating AI flow explanation..."
            : task === "summary" ? "Synthesizing incident summary..."
            : task === "recommendations" ? "Determining defensive recommendations..."
            : task === "chat" ? "Consulting AI Copilot..." : "Processing AI task...";
        status("drawerAIStatus", actionLabel);

        try {
            const body = { task, event_id: currentEventId, regenerate: false };
            if (question) body.question = question;
            const response = await request(`${base}/incidents/${encodeURIComponent(currentIncidentId)}/ai`, {
                method: "POST",
                body
            });
            const title = task === "explain" ? "Evidence-Grounded Flow Explanation"
                : task === "summary" ? "AI Incident Summary & Hypotheses"
                : task === "recommendations" ? "Recommended Defensive Actions"
                : `Copilot: "${question}"`;

            const block = insightBlock(response, title);
            if (task === "chat") {
                $("drawerAIResult")?.append(block);
            } else {
                $("drawerAIResult")?.replaceChildren(block);
            }
            status("drawerAIStatus", `${response.cached ? "Cached" : "Live"} AI interpretation complete.`);
        } catch (error) {
            status("drawerAIStatus", (error.message || "AI interpretation could not be completed.") + " Model evidence remains available.", true);
        } finally {
            setBusy(false);
        }
    }

    async function generateReport() {
        if (!currentIncidentId || busy) return;
        setBusy(true);
        status("drawerAIStatus", "Generating comprehensive HTML incident report with AI synthesis...");
        try {
            const response = await request(`${base}/incidents/${encodeURIComponent(currentIncidentId)}/report`, {
                method: "POST",
                body: { format: "html", include_ai: true },
                raw: true
            });
            const blob = await response.blob();
            if (!blob.size) throw new Error("Report response was empty.");
            const url = URL.createObjectURL(blob);
            const link = node("a");
            link.href = url;
            link.download = display?.downloadFilename ? display.downloadFilename(response.headers.get("Content-Disposition"), "cyvanta_incident_report.html") : "cyvanta_incident_report.html";
            document.body.append(link);
            link.click();
            link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            status("drawerAIStatus", "Incident report generated and downloaded successfully (HTML).");
        } catch (error) {
            status("drawerAIStatus", "Report generation failed: " + (error.message || "Unknown error") + ". You can retry.", true);
        } finally {
            setBusy(false);
        }
    }

    window.addEventListener("cyvanta:draweropen", async event => {
        drawerSelection = event.detail;
        const row = event.detail?.row;
        const analysis = event.detail?.context || store?.current;
        const analysisId = analysis?.analysis_id || store?.current?.analysis_id;
        const eventId = row?.alert_id || row?.event_id;
        const isAnomaly = window.CyvantaData ? window.CyvantaData.isAnomaly(row) : true;

        const aiSec = $("drawerAISection");
        if (aiSec) aiSec.hidden = !isAnomaly;
        $("drawerAIResult")?.replaceChildren();

        if (!isAnomaly) {
            status("drawerAIStatus", "This flow is classified as normal; AI incident copilot is only active for anomalous traffic.");
            return;
        }

        if (!analysisId || !eventId) {
            status("drawerAIStatus", "Saved analysis or alert identifier unavailable.", true);
            return;
        }

        currentEventId = eventId;
        status("drawerAIStatus", "Connecting to Incident Copilot...");
        setBusy(true);

        try {
            const incidentId = await findIncident(analysisId, eventId);
            currentIncidentId = incidentId;
            status("drawerAIStatus", "Ready for AI interpretation. Choose an analysis action below.");
            aiStatus();
        } catch (error) {
            currentIncidentId = null;
            status("drawerAIStatus", error.message || "Incident details unavailable for this flow.", true);
        } finally {
            setBusy(false);
        }
    });

    $("drawerExplainFlow")?.addEventListener("click", () => runAITask("explain"));
    $("drawerSummaryFlow")?.addEventListener("click", () => runAITask("summary"));
    $("drawerRecommendationsFlow")?.addEventListener("click", () => runAITask("recommendations"));
    $("drawerReportFlow")?.addEventListener("click", generateReport);

    $("drawerChatForm")?.addEventListener("submit", event => {
        event.preventDefault();
        const input = $("drawerChatInput");
        const query = input?.value.trim();
        if (query) {
            input.value = "";
            runAITask("chat", query);
        }
    });

    document.querySelectorAll(".drawer-ai-section .chat-chip").forEach(chip => {
        chip.addEventListener("click", () => {
            const prompt = chip.dataset.prompt;
            if (prompt) {
                runAITask("chat", prompt);
            }
        });
    });

    function openForEvent(row, analysis, explain = false) {
        if (explain) {
            window.dispatchEvent(new CustomEvent("cyvanta:draweropen", { detail: { row, context: analysis } }));
            setTimeout(() => runAITask("explain"), 200);
        }
    }

    store?.subscribe?.(() => {
        currentIncidentId = null;
        currentEventId = null;
        drawerSelection = null;
        busy = false;
        $("drawerAIResult")?.replaceChildren();
        status("drawerAIStatus", "Ready for AI interpretation. Choose an analysis action below.");
    });

    window.CyvantaInvestigation = { openForEvent, generateReport, runAITask };
    aiStatus();
})();
