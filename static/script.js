const uploadForm = document.getElementById("uploadForm");
const csvFile = document.getElementById("csvFile");
const fileName = document.getElementById("fileName");
const analyzeBtn = document.getElementById("analyzeBtn");
const message = document.getElementById("message");

const totalFlows = document.getElementById("totalFlows");
const normalFlows = document.getElementById("normalFlows");
const anomalyFlows = document.getElementById("anomalyFlows");
const anomalyRate = document.getElementById("anomalyRate");

const resultsBody = document.getElementById("resultsBody");
const searchInput = document.getElementById("searchInput");
const predictionFilter = document.getElementById("predictionFilter");
const downloadBtn = document.getElementById("downloadBtn");
const tableFooter = document.getElementById("tableFooter");

let allResults = [];

const trafficChart = new Chart(
    document.getElementById("trafficChart"),
    {
        type: "doughnut",
        data: {
            labels: ["Normal", "Anomaly"],
            datasets: [{
                data: [0, 0],
                backgroundColor: ["#10b981", "#f43f5e"],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { color: "#cbd5e1" }
                }
            }
        }
    }
);

const scoreChart = new Chart(
    document.getElementById("scoreChart"),
    {
        type: "bar",
        data: {
            labels: [],
            datasets: [{
                label: "Number of flows",
                data: [],
                backgroundColor: "#818cf8",
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: "#cbd5e1" }
                }
            },
            scales: {
                x: {
                    ticks: { color: "#94a3b8" },
                    grid: { display: false }
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: "#94a3b8", precision: 0 },
                    grid: { color: "#263247" }
                }
            }
        }
    }
);

csvFile.addEventListener("change", () => {
    fileName.textContent = csvFile.files.length
        ? csvFile.files[0].name
        : "No file selected";
});

uploadForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const file = csvFile.files[0];

    if (!file) {
        showMessage("Please select a CSV file.", "error");
        return;
    }

    if (!file.name.toLowerCase().endsWith(".csv")) {
        showMessage("Please upload a CSV file.", "error");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing...";
    showMessage("Analyzing network traffic. Please wait...", "info");

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            body: formData
        });

        const text = await response.text();

let data;
try {
    data = JSON.parse(text);
} catch {
    throw new Error(`Server returned HTML instead of JSON (HTTP ${response.status}). Check the Flask terminal.`);
}

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed.");
        }

        allResults = data.results || [];

        updateDashboard(data.summary, allResults);
        renderTable();

        showMessage("Analysis completed successfully.", "success");
    } catch (error) {
        showMessage(error.message || "Something went wrong.", "error");
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze Traffic";
    }
});

function updateDashboard(summary, results) {
    totalFlows.textContent = summary.total_flows ?? 0;
    normalFlows.textContent = summary.normal_count ?? 0;
    anomalyFlows.textContent = summary.anomaly_count ?? 0;
    anomalyRate.textContent =
        `${Number(summary.anomaly_percentage ?? 0).toFixed(2)}%`;

    trafficChart.data.datasets[0].data = [
        Number(summary.normal_count ?? 0),
        Number(summary.anomaly_count ?? 0)
    ];
    trafficChart.update();

    updateScoreChart(results);
}

function updateScoreChart(results) {
    const scores = results
        .map(row => Number(row.anomaly_score))
        .filter(Number.isFinite);

    const binCount = 10;
    const bins = Array(binCount).fill(0);
    const labels = [];

    if (scores.length === 0) {
        scoreChart.data.labels = [];
        scoreChart.data.datasets[0].data = [];
        scoreChart.update();
        return;
    }

    const min = Math.min(...scores);
    const max = Math.max(...scores);

    if (min === max) {
        labels.push(min.toFixed(4));
        bins[0] = scores.length;
        scoreChart.data.labels = labels;
        scoreChart.data.datasets[0].data = [scores.length];
    } else {
        const width = (max - min) / binCount;

        for (let i = 0; i < binCount; i++) {
            const start = min + i * width;
            const end = start + width;

            labels.push(`${start.toFixed(3)}–${end.toFixed(3)}`);
        }

        scores.forEach(score => {
            const index = Math.min(
                Math.floor((score - min) / width),
                binCount - 1
            );
            bins[index]++;
        });

        scoreChart.data.labels = labels;
        scoreChart.data.datasets[0].data = bins;
    }

    scoreChart.update();
}

function renderTable() {
    const query = searchInput.value.trim().toLowerCase();
    const filter = predictionFilter.value.toLowerCase();

    const filteredResults = allResults.filter(item => {
        const prediction = String(item.prediction ?? "").toLowerCase();

        const matchesFilter =
            filter === "all" || prediction === filter;

        const matchesSearch = Object.values(item).some(value =>
            String(value ?? "").toLowerCase().includes(query)
        );

        return matchesFilter && matchesSearch;
    });

    resultsBody.replaceChildren();

    if (!filteredResults.length) {
        resultsBody.innerHTML =
            '<tr><td colspan="6" class="empty-state">No results found.</td></tr>';
    } else {
        filteredResults.forEach((item, index) => {
            const row = document.createElement("tr");
            row.className =
    String(item.prediction).toLowerCase() === "anomaly"
        ? "anomaly-row"
        : "normal-row";

            const values = [
    item.Timestamp ?? "—",
    item["Flow ID"] ?? item.flow_id ?? index + 1,
    item.prediction ?? "Unknown",
    formatNumber(item.anomaly_score, 6),
    formatNumber(item["Packet Length Std"]),
    formatNumber(item["Packet Length Mean"]),
    formatNumber(item["ACK Flag Count"]),
    formatNumber(item["Flow IAT Mean"]),
    formatNumber(item["Total Length of Bwd Packets"]),
    formatNumber(item["Total Fwd Packets"]),
    formatNumber(item["Flow Duration"])
];

            values.forEach((value, columnIndex) => {
                const cell = document.createElement("td");
                cell.textContent = value;

                if (columnIndex === 1) {
                    cell.innerHTML = "";
                    const badge = document.createElement("span");
                    badge.textContent = value;
                    badge.className =
                        String(value).toLowerCase() === "anomaly"
                            ? "badge anomaly"
                            : "badge normal";
                    cell.appendChild(badge);
                }

                row.appendChild(cell);
            });

            resultsBody.appendChild(row);
        });
    }

    tableFooter.textContent =
        `Showing ${filteredResults.length} of ${allResults.length} flows`;
}
function formatNumber(value, decimals = 2) {
    if (value === null || value === undefined || value === "") {
        return "—";
    }

    const number = Number(value);

    return Number.isFinite(number)
        ? number.toLocaleString("en-US", {
            maximumFractionDigits: decimals
        })
        : String(value);
}

function showMessage(text, type) {
    message.textContent = text;
    message.className = `message ${type}`;
}

searchInput.addEventListener("input", renderTable);
predictionFilter.addEventListener("change", renderTable);

downloadBtn.onclick = function () {
    console.log("Export button clicked", allResults.length);
    if (!allResults || allResults.length === 0) {
        alert("Analyze a CSV first!");
        return;
    }

    const columns = Object.keys(allResults[0]);

    const csv = [
        columns.join(","),
        ...allResults.map(row =>
            columns.map(col =>
                JSON.stringify(row[col] ?? "")
            ).join(",")
        )
    ].join("\n");

    const blob = new Blob([csv], {
        type: "text/csv;charset=utf-8;"
    });

    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "cyvanta_results.csv";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(link.href);
};

renderTable();

downloadBtn.disabled = false;

downloadBtn.addEventListener("click", () => {
    if (!allResults.length) {
        alert("Analyze a CSV file first.");
        return;
    }

    const headers = Object.keys(allResults[0]);

    const csv = [
        headers.join(","),
        ...allResults.map(row =>
            headers.map(key =>
                `"${String(row[key] ?? "").replace(/"/g, '""')}"`
            ).join(",")
        )
    ].join("\n");

    const blob = new Blob([csv], {
        type: "text/csv;charset=utf-8;"
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "cyvanta_analysis.csv";
    link.click();

    URL.revokeObjectURL(url);
});