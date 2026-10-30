/* Replaceable anomaly severity views, driven only by the completed API analysis. */
(function () {
    "use strict";
    const store = window.CyvantaAnalysis;
    const tools = window.CyvantaData;
    const $ = id => document.getElementById(id);
    const PAGE_SIZE = 50;
    let page = 0, sortKey = "priority", sortDirection = "asc", selected = null, returnFocus = null, previousAnalysis = null;
    const colors = { HIGH: "#c2414b", MEDIUM: "#a96710", LOW: "#277b97", UNCALIBRATED: "#94a3b8" };
    const optional = (row, fields) => {
        for (const field of fields) if (row[field] !== undefined && row[field] !== null && row[field] !== "") return row[field];
        return "—";
    };
    const network = {
        timestamp: ["timestamp", "Timestamp"]
    };
    const ML_FEATURES = [
        "Packet Length Std", "Packet Length Mean", "ACK Flag Count", "Flow IAT Mean",
        "Total Length of Bwd Packets", "Total Fwd Packets", "Flow Duration", "Total Backward Packets"
    ];
    function text(id, value) { $(id).textContent = value; }
    function make(tag, value, className) { const node = document.createElement(tag); if (value !== undefined) node.textContent = value; if (className) node.className = className; return node; }
    function badge(row) {
        const severity = row.severity;
        return store.badge(severity || (tools.isAnomaly(row) ? "Uncalibrated" : "Not applicable"), severity ? `severity-${severity.toLowerCase()}` : "severity-unavailable");
    }
    function policyText(policy) {
        if (policy.calibration_status !== "calibrated") return `Calibration pending. ${policy.reason || "A validated, independent reference distribution is required before severity can be assigned."}`;
        return `Calibrated reference policy · Medium ≥ ${tools.formatNumber(policy.thresholds?.medium)} · High ≥ ${tools.formatNumber(policy.thresholds?.high)} · score basis: ${policy.score_basis || "configured decision boundary"}.`;
    }
    function render() {
        const data = store.current;
        const changed = data !== previousAnalysis;
        if (changed) { previousAnalysis = data; page = 0; if ($("alertDrawer").open) $("alertDrawer").close(); }
        const statusText = store.status === "loading" ? "Analyzing uploaded CSV. " + (data ? "Previous completed results remain visible." : "")
            : store.status === "error" ? "Unable to load alert results. " + store.error + (data ? " Showing previous completed analysis." : "") : "";
        text("alertsStatus", statusText);
        $("alertsStatus").classList.toggle("analysis-error", store.status === "error");
        $("retryAnalysis").hidden = store.status !== "error";
        $("alerts").setAttribute("aria-busy", String(store.status === "loading"));
        if (data && changed) {
            const summary = data.summary, counts = summary.severity_counts || {};
            const classified = summary.classified_anomalies ?? ((counts.HIGH || 0) + (counts.MEDIUM || 0) + (counts.LOW || 0));
            for (const severity of ["HIGH", "MEDIUM", "LOW"]) {
                const name = severity.toLowerCase();
                text(`${name}Count`, tools.formatNumber(counts[severity] ?? 0, 0));
                text(`${name}Percent`, classified ? `${((counts[severity] || 0) / classified * 100).toFixed(1)}% of classified anomalies` : "No classified anomalies");
            }
            const date = data.analyzed_at ? new Date(data.analyzed_at) : null;
            const time = date && !Number.isNaN(date.getTime()) ? date.toLocaleString() : "Analysis time unavailable";
            text("analysisMetadata", `${data.dataset_name || "Uploaded CSV"} · ${data.analysis_id || "Analysis identifier unavailable"} · ${time} · CSV batch · ${data.model_name || "Isolation Forest"}: ${data.model_status || "status unavailable"} · ${data.model_version || "version unavailable"} · Severity ${data.severity_policy?.calibration_status === "calibrated" ? "calibrated" : "uncalibrated"}`);
            text("severityPolicy", policyText(data.severity_policy || {}));
            text("severityTotals", `${tools.formatNumber(summary.total_flows, 0)} analyzed flows · ${tools.formatNumber(summary.normal_count, 0)} normal · ${tools.formatNumber(summary.anomaly_count, 0)} anomalies · ${tools.formatNumber(summary.anomaly_percentage, 2)}% anomaly rate · ${tools.formatNumber(summary.uncalibrated_count ?? 0, 0)} uncalibrated · Highest deviation: ${tools.formatNumber(summary.highest_deviation_strength)}`);
            renderVisualizations(data);
        }
        renderTable();
    }
    function allAlerts() { return store.current?.alerts || []; }
    function renderTable() {
        const rows = tools.sortAlerts(tools.searchRows(allAlerts(), $("alertSearch").value, $("alertSeverity").value), sortKey, sortDirection);
        page = Math.min(page, Math.max(0, Math.ceil(rows.length / PAGE_SIZE) - 1));
        const start = page * PAGE_SIZE, fragment = document.createDocumentFragment();
        for (const item of rows.slice(start, start + PAGE_SIZE)) {
            const row = make("tr");
            const values = [
                item.priority ?? "—",
                null,
                `${item.alert_id || "Anomaly"} / row ${Number(item.record_index) + 1}`,
                ...ML_FEATURES.map(feat => tools.formatNumber(item[feat])),
                tools.formatNumber(item.deviation_strength),
                tools.formatNumber(item.decision_score),
                "ANOMALY",
                null
            ];
            values.forEach((value, index) => {
                const td = make("td", value === null ? "" : value);
                if (index === 1) td.append(badge(item));
                if (index >= 3 && index <= 12) td.className = "telemetry";
                if (index === 14) {
                    const button = make("button", "Inspect", "secondary-btn row-action"); button.type = "button";
                    button.setAttribute("aria-label", `Inspect alert for source row ${Number(item.record_index) + 1}`);
                    button.addEventListener("click", () => openDrawer(item, button)); td.append(button);
                }
                row.append(td);
            });
            fragment.append(row);
        }
        if (!rows.length) {
            const state = !store.current ? (store.status === "error" ? "Unable to load alert results." : store.status === "loading" ? "Analyzing traffic..." : "Awaiting traffic analysis.")
                : !allAlerts().length ? "No anomalies detected in the analyzed records." : "No alerts match the selected filters.";
            const row = make("tr"), td = make("td", state, "empty-state"); td.colSpan = 15; row.append(td); fragment.append(row);
        }
        $("alertsBody").replaceChildren(fragment);
        text("alertsFooter", rows.length ? `Showing ${start + 1}–${Math.min(start + PAGE_SIZE, rows.length)} of ${rows.length.toLocaleString()} matching alerts · ${allAlerts().length.toLocaleString()} total anomalies` : `0 matching alerts · ${allAlerts().length.toLocaleString()} total anomalies`);
        $("alertsPrevious").disabled = page === 0; $("alertsNext").disabled = start + PAGE_SIZE >= rows.length;
        document.querySelectorAll("[data-severity]").forEach(card => { card.setAttribute("aria-pressed", String(card.dataset.severity === $("alertSeverity").value)); });
        document.querySelectorAll("[data-alert-sort]").forEach(button => button.closest("th").setAttribute("aria-sort", button.dataset.alertSort === sortKey ? (sortDirection === "asc" ? "ascending" : "descending") : "none"));
    }
    function renderVisualizations(data) {
        const counts = data.summary.severity_counts || {}, uncalibrated = data.summary.uncalibrated_count || 0;
        const total = data.summary.anomaly_count || 0;
        const distribution = $("severityDistribution"); distribution.replaceChildren();
        const label = ["HIGH", "MEDIUM", "LOW"].map(level => `${level}: ${counts[level] || 0}`).concat(`Uncalibrated: ${uncalibrated}`).join(" · ");
        distribution.setAttribute("aria-label", label); text("severityDistributionText", total ? label : "No anomalies detected.");
        if (total) {
            for (const level of ["HIGH", "MEDIUM", "LOW", "UNCALIBRATED"]) {
                const count = level === "UNCALIBRATED" ? uncalibrated : counts[level] || 0;
                if (!count) continue;
                const segment = make("span"); segment.style.width = `${count / total * 100}%`; segment.style.background = colors[level]; segment.title = `${level}: ${count}`; distribution.append(segment);
            }
        }
        const strongest = tools.sortAlerts(allAlerts(), "deviation_strength", "desc").slice(0, 5), top = $("topAnomalies"); top.replaceChildren();
        for (const item of strongest) {
            const li = make("li"), button = make("button", `Row ${Number(item.record_index) + 1} · ${tools.formatNumber(item.deviation_strength)}`, "top-flow-button");
            button.type = "button"; button.addEventListener("click", () => openDrawer(item, button));
            const track = make("span", "", "top-flow-track"), bar = make("span");
            const maximum = Number(strongest[0]?.deviation_strength) || 0;
            bar.style.width = maximum ? `${Number(item.deviation_strength) / maximum * 100}%` : "0%"; bar.style.background = colors[item.severity] || colors.UNCALIBRATED; track.append(bar); li.append(button, track); top.append(li);
        }
        if (!strongest.length) top.append(make("li", "No anomalies detected.", "muted"));
        const histogram = tools.histogram(allAlerts().map(row => row.deviation_strength));
        const chart = $("deviationHistogram"); chart.replaceChildren();
        let peak = 0; for (const bin of histogram.bins) peak = Math.max(peak, bin.count);
        const description = histogram.bins.map(bin => `${tools.formatNumber(bin.start)}–${tools.formatNumber(bin.end)}: ${bin.count} anomalies`).join("; ");
        chart.setAttribute("aria-label", description || "No anomaly deviation scores");
        for (const bin of histogram.bins) {
            const column = make("div", "", "histogram-column"); column.title = `${tools.formatNumber(bin.start)}–${tools.formatNumber(bin.end)}: ${bin.count}`;
            const count = make("span", String(bin.count)), bar = make("span", "", "histogram-bar"); bar.style.height = `${peak ? bin.count / peak * 115 : 0}px`; column.append(count, bar); chart.append(column);
        }
        if (!histogram.bins.length) chart.append(make("p", "No anomaly deviation scores to display.", "muted"));
        const policy = data.severity_policy || {};
        text("deviationRange", histogram.bins.length ? `Deviation ${tools.formatNumber(histogram.min)} → ${tools.formatNumber(histogram.max)} · ${policy.calibration_status === "calibrated" ? `Medium boundary ${tools.formatNumber(policy.thresholds?.medium)}; High boundary ${tools.formatNumber(policy.thresholds?.high)}.` : "Severity boundaries await calibration."}` : "No anomalies in this analysis.");
    }
    function details(id, values) {
        const list = $(id); list.replaceChildren();
        for (const [key, value] of values) { const group = make("div"); group.append(make("dt", key), make("dd", value ?? "—")); list.append(group); }
    }
    function openDrawer(row, trigger, context) {
        selected = row; returnFocus = trigger;
        const data = context || store.current || {}, policy = data.severity_policy || {};
        text("drawerTitle", row.alert_id || `Source row ${Number(row.record_index) + 1}`);
        $("drawerBadges").replaceChildren(badge(row), store.badge(row.prediction || row.status || "Unknown", tools.isAnomaly(row) ? "anomaly" : "normal"));
        const explanations = {
            LOW: "This anomalous flow has a comparatively small deviation beyond the configured model boundary under the reference severity policy.",
            MEDIUM: "This anomalous flow has a moderate deviation compared with the calibrated reference anomaly distribution.",
            HIGH: "This anomalous flow has a comparatively strong deviation under the calibrated reference severity policy."
        };
        text("drawerExplanation", tools.isAnomaly(row) ? explanations[row.severity] || "This flow is anomalous, but severity is unavailable until a valid reference policy is calibrated. Priority currently follows deviation strength." : "This flow is normal under the existing configured anomaly boundary and has no anomaly severity.");
        details("drawerNetwork", [
            ["Source row (1-based)", Number(row.record_index) + 1], ["Timestamp", optional(row, network.timestamp)],
            ["Packet Length Std", tools.formatNumber(row["Packet Length Std"])],
            ["Packet Length Mean", tools.formatNumber(row["Packet Length Mean"])],
            ["ACK Flag Count", tools.formatNumber(row["ACK Flag Count"])],
            ["Flow IAT Mean", tools.formatNumber(row["Flow IAT Mean"])],
            ["Total Length of Bwd Packets", tools.formatNumber(row["Total Length of Bwd Packets"])],
            ["Total Fwd Packets", tools.formatNumber(row["Total Fwd Packets"])],
            ["Flow Duration", tools.formatNumber(row["Flow Duration"])],
            ["Total Backward Packets", tools.formatNumber(row["Total Backward Packets"])],
            ["Forward bytes", optional(row, ["Total Length of Fwd Packets"])]
        ]);
        const warnings = (data.input_warnings || []).filter(warning => warning.record_index === row.record_index);
        details("drawerModel", [
            ["Model", "Isolation Forest"], ["Model version", data.model_version], ["Analysis", data.analysis_id],
            ["Prediction", row.prediction], ["Decision score", tools.formatNumber(row.decision_score ?? row.anomaly_score)], ["Deviation strength", tools.formatNumber(row.deviation_strength)],
            ["Anomaly severity", row.severity || (tools.isAnomaly(row) ? "Uncalibrated" : "Not applicable")], ["Calibration", policy.calibration_status || "Unavailable"],
            ["Decision boundary", tools.formatNumber(policy.decision_threshold)], ["Medium threshold", tools.formatNumber(policy.thresholds?.medium)], ["High threshold", tools.formatNumber(policy.thresholds?.high)],
            ["Scoring basis", policy.score_basis || "Unavailable"], ["Reference policy", policyText(policy)],
            ["Input validation", warnings.length ? warnings.map(warning => warning.reason || warning.message || JSON.stringify(warning)).join("; ") : "No row validation warnings reported."]
        ]);
        if (!$("alertDrawer").open) $("alertDrawer").showModal();
        $("closeDrawer").focus();
        if ($("showRelatedTraffic")) $("showRelatedTraffic").disabled = Boolean(data.analysis_id && data.analysis_id !== store.current?.analysis_id);
        window.dispatchEvent(new CustomEvent("cyvanta:draweropen", { detail: { row, context: data } }));
    }
    $("closeDrawer").addEventListener("click", () => $("alertDrawer").close());
    $("alertDrawer").addEventListener("close", () => {
        if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
    });
    $("alertDrawer").addEventListener("click", event => { if (event.target === $("alertDrawer")) { const rect = $("alertDrawer").getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) $("alertDrawer").close(); } });
    if ($("showRelatedTraffic")) $("showRelatedTraffic").addEventListener("click", () => { returnFocus = null; $("alertDrawer").close(); });
    $("exportAlert").addEventListener("click", () => { if (selected) store.exportRows([selected], "cyvanta_flow.csv"); });
    window.addEventListener("cyvanta:inspect", event => openDrawer(event.detail.row, event.detail.trigger, event.detail.context));
    for (const id of ["alertSearch", "alertSeverity"]) $(id).addEventListener(id === "alertSearch" ? "input" : "change", () => { page = 0; renderTable(); });
    document.querySelectorAll("[data-severity]").forEach(card => card.addEventListener("click", () => { $("alertSeverity").value = $("alertSeverity").value === card.dataset.severity ? "ALL" : card.dataset.severity; page = 0; renderTable(); }));
    $("resetAlertFilters").addEventListener("click", () => { $("alertSearch").value = ""; $("alertSeverity").value = "ALL"; sortKey = "priority"; sortDirection = "asc"; page = 0; renderTable(); });
    document.querySelectorAll("[data-alert-sort]").forEach(button => button.addEventListener("click", () => { const key = button.dataset.alertSort; sortDirection = sortKey === key && sortDirection === "desc" ? "asc" : key === "priority" && sortKey !== key ? "asc" : "desc"; sortKey = key; page = 0; renderTable(); }));
    $("alertsPrevious").addEventListener("click", () => { page--; renderTable(); });
    $("alertsNext").addEventListener("click", () => { page++; renderTable(); });
    store.subscribe(render); render();
})();
