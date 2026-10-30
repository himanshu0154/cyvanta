(function () {
    "use strict";
    const dataTools = window.CyvantaData;
    const $ = id => document.getElementById(id);
    const events = new EventTarget();
    const store = window.CyvantaAnalysis = {
        current: null, status: "initial", error: "", focusedRecord: null,
        subscribe(listener) { events.addEventListener("change", listener); },
        publish() { events.dispatchEvent(new Event("change")); },
        inspect(row, trigger, context) { window.dispatchEvent(new CustomEvent("cyvanta:inspect", { detail: { row, trigger, context } })); },
        showRecord(row) { this.focusedRecord = row.record_index; }
    };
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const chartOptions = {
        responsive: true, maintainAspectRatio: false, animation: reducedMotion ? false : undefined,
        plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1" } } }
    };
    const charts = {};
    function createChart(id, type, dataset) {
        if (typeof window.Chart !== "function") {
            const notice = document.createElement("p"); notice.className = "muted";
            notice.textContent = "Chart library unavailable. Analysis totals and tables remain available.";
            $(id).replaceWith(notice); return null;
        }
        return new Chart($(id), {
            type, data: { labels: [], datasets: [dataset] },
            options: type === "bar" ? { ...chartOptions, plugins: { legend: { labels: { color: "#cbd5e1" } } }, scales: {
                x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
                y: { beginAtZero: true, ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "#263247" } }
            } } : chartOptions
        });
    }
    charts.traffic = createChart("trafficChart", "doughnut", { data: [], backgroundColor: ["#10b981", "#f43f5e"], borderWidth: 0 });
    charts.scores = createChart("scoreChart", "bar", { label: "Number of flows", data: [], backgroundColor: "#818cf8", borderRadius: 5 });
    function showMessage(text, type) { $("message").textContent = text; $("message").className = `message ${type}`; }
    async function analyzeFile(file) {
        const body = new FormData(); body.append("file", file);
        const response = await fetch("/api/analyze", { method: "POST", body });
        let data;
        try { data = await response.json(); }
        catch { throw new Error(`The analysis service returned an invalid response (HTTP ${response.status}). Please retry.`); }
        if (!response.ok) throw new Error(data.error || "Analysis failed. Please retry.");
        if (!Array.isArray(data.results) || !data.summary) throw new Error("The analysis response is incomplete. Please retry.");
        return data;
    }
    $("csvFile").addEventListener("change", () => { $("fileName").textContent = $("csvFile").files[0]?.name || "No file selected"; });
    $("uploadForm").addEventListener("submit", async event => {
        event.preventDefault();
        if (store.status === "loading") return;
        const file = $("csvFile").files[0];
        if (!file || !file.name.toLowerCase().endsWith(".csv")) { showMessage("Please select a CSV file.", "error"); return; }
        store.status = "loading"; store.error = ""; store.publish();
        $("analyzeBtn").disabled = true; $("analyzeBtn").textContent = "Analyzing...";
        $("engineStatus").textContent = "Analyzing uploaded CSV";
        showMessage("Analyzing network traffic. Please wait...", "info");
        try {
            const data = await analyzeFile(file);
            store.current = data; store.status = "completed"; store.focusedRecord = null;
            if ($("downloadBtn")) $("downloadBtn").disabled = !data.results.length;
            $("engineStatus").textContent = "Model inference completed";
            updateDashboard(data); store.publish();
            const warning = data.input_warnings?.length ? " Input validation warnings are available in flow details." : "";
            showMessage("Analysis completed successfully." + warning, "success");
        } catch (error) {
            store.status = "error"; store.error = error.message || "Unable to reach the analysis service. Please retry.";
            $("engineStatus").textContent = "Latest analysis failed";
            showMessage(store.error + (store.current ? " Previous completed results remain visible." : ""), "error"); store.publish();
        } finally { $("analyzeBtn").disabled = false; $("analyzeBtn").textContent = "Analyze Traffic →"; }
    });
    $("retryAnalysis").addEventListener("click", () => $("uploadForm").requestSubmit());
    function updateDashboard(data) {
        const summary = data.summary;
        $("totalFlows").textContent = dataTools.formatNumber(summary.total_flows, 0);
        $("normalFlows").textContent = dataTools.formatNumber(summary.normal_count, 0);
        $("anomalyFlows").textContent = dataTools.formatNumber(summary.anomaly_count, 0);
        $("anomalyRate").textContent = `${Number(summary.anomaly_percentage ?? 0).toFixed(2)}%`;
        const counts = summary.severity_counts || {};
        $("overviewSeverity").replaceChildren(document.createTextNode(`Anomaly severity: ${counts.HIGH ?? 0} High · ${counts.MEDIUM ?? 0} Medium · ${counts.LOW ?? 0} Low · ${summary.uncalibrated_count ?? 0} uncalibrated. `));
        const link = document.createElement("a"); link.href = "#alerts"; link.textContent = "View prioritized alerts →"; $("overviewSeverity").append(link);
        if (charts.traffic) {
            charts.traffic.data.labels = ["Normal", "Anomaly"];
            charts.traffic.data.datasets[0].data = [summary.normal_count, summary.anomaly_count]; charts.traffic.update();
        }
        if (charts.scores) {
            const histogram = dataTools.histogram(data.results.map(row => row.anomaly_score));
            charts.scores.data.labels = histogram.bins.map(bin => `${bin.start.toFixed(3)}–${bin.end.toFixed(3)}`);
            charts.scores.data.datasets[0].data = histogram.bins.map(bin => bin.count); charts.scores.update();
        }
    }
    function badge(value, type) { const span = document.createElement("span"); span.textContent = value; span.className = `badge ${type}`; return span; }
    store.badge = badge;
    store.exportRows = function (rows, filename) {
        if (!rows.length) return;
        const url = URL.createObjectURL(new Blob([dataTools.toCsv(rows)], { type: "text/csv;charset=utf-8;" }));
        const link = document.createElement("a"); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    if ($("downloadBtn")) $("downloadBtn").addEventListener("click", () => store.exportRows(store.current?.results || [], "cyvanta_analysis.csv"));
    document.querySelectorAll(".nav-item").forEach(link => link.addEventListener("click", () => { document.querySelectorAll(".nav-item").forEach(item => item.classList.toggle("active", item === link)); }));
    window.addEventListener("pagehide", () => Object.values(charts).forEach(chart => chart?.destroy()));
})();
