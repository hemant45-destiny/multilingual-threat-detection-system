/**
 * PolyShield™ Enterprise Cyber Defense: Front-End Core
 * Powers the Real-Time Threat Gateway, SOC Incident Triage,
 * IoC Threat Intelligence, and Security Policy Configuration.
 */

document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

let currentAnalysis = null;
let allAlerts = [];
let currentModalAlert = null;

function initApp() {
    setupTabNavigation();
    loadPresets();
    setupEventListeners();
    loadAlertsQueue();
    loadResearcherIocs();
    loadModelEvaluation();
    loadDecisionLogs();
}

function setupTabNavigation() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");

            const targetTab = btn.getAttribute("data-tab");
            document.querySelectorAll(".tab-content").forEach(tab => {
                tab.classList.add("hidden");
            });

            const activeTabEl = document.getElementById(targetTab);
            if (activeTabEl) {
                activeTabEl.classList.remove("hidden");
            }

            if (targetTab === "tabAnalyst") {
                loadAlertsQueue();
            } else if (targetTab === "tabThreatIntel") {
                loadResearcherIocs();
            } else if (targetTab === "tabCoordinator" || targetTab === "tabAnalytics") {
                loadModelEvaluation();
                loadDecisionLogs();
            }
        });
    });
}

function setupEventListeners() {
    const btnAnalyze = document.getElementById("btnAnalyze");
    if (btnAnalyze) {
        btnAnalyze.addEventListener("click", performAnalysis);
    }
}

async function loadPresets() {
    try {
        const res = await fetch("/api/presets");
        const presets = await res.json();
        const container = document.getElementById("presetsContainer");
        if (!container) return;
        container.innerHTML = "";

        presets.forEach(preset => {
            const chip = document.createElement("button");
            chip.type = "button";
            chip.className = "preset-chip";
            chip.textContent = preset.title;
            chip.onclick = () => {
                document.getElementById("inputSender").value = preset.sender;
                document.getElementById("inputSourceType").value = preset.source_type;
                document.getElementById("inputReliability").value = preset.source_reliability || 0.5;
                document.getElementById("inputText").value = preset.text;
                performAnalysis();
            };
            container.appendChild(chip);
        });
    } catch (err) {
        console.error("Failed to load presets:", err);
    }
}

async function performAnalysis() {
    const sender = document.getElementById("inputSender").value;
    const sourceType = document.getElementById("inputSourceType").value;
    const reliability = parseFloat(document.getElementById("inputReliability").value) || 0.5;
    const text = document.getElementById("inputText").value;

    if (!text.trim()) {
        alert("Please enter communication payload content to analyze.");
        return;
    }

    const btn = document.getElementById("btnAnalyze");
    btn.disabled = true;
    btn.textContent = "Scanning & Decoupling Threat Signals...";

    try {
        const res = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                text: text,
                sender: sender,
                source_type: sourceType,
                source_reliability: reliability
            })
        });

        const data = await res.json();
        currentAnalysis = data;
        renderAnalysisOutput(data);
    } catch (err) {
        console.error("Analysis request failed:", err);
        alert("Gateway analysis failed. Check server connection.");
    } finally {
        btn.disabled = false;
        btn.textContent = "⚡ Deep Threat Analysis & Evidence Extraction";
    }
}

function renderAnalysisOutput(data) {
    document.getElementById("latencyVal").textContent = `${data.latency_ms} ms`;
    
    // Score & Badges
    const scoreValEl = document.getElementById("scoreVal");
    const riskBadgeEl = document.getElementById("riskBadge");
    
    scoreValEl.textContent = `${data.risk_score}%`;
    scoreValEl.className = `score-number ${data.severity_band.toLowerCase()}`;
    
    riskBadgeEl.textContent = `ALERT STATUS: ${data.severity_band} RISK (${data.risk_score}%)`;
    riskBadgeEl.className = `risk-badge ${data.severity_band.toLowerCase()}`;

    document.getElementById("categoryVal").textContent = data.category_display_name;
    document.getElementById("dialectVal").textContent = data.script_info.dialect_label;

    // Formula Factors Grid
    document.getElementById("valFactorC").textContent = data.risk_factors.factor_c.toFixed(2);
    document.getElementById("valFactorS").textContent = data.risk_factors.factor_s.toFixed(2);
    document.getElementById("valFactorR").textContent = data.risk_factors.factor_r.toFixed(2);
    document.getElementById("valFactorI").textContent = data.risk_factors.factor_i.toFixed(2);
    document.getElementById("valFactorT").textContent = data.risk_factors.factor_t.toFixed(2);
    document.getElementById("valFactorK").textContent = data.risk_factors.factor_k.toFixed(2);

    // Normalization Box
    document.getElementById("originalTextVal").textContent = data.original_text;
    document.getElementById("normalizedTextVal").innerHTML = highlightCanonicalTokens(data.normalized_text);

    // IoCs Table
    const iocsBody = document.getElementById("iocsTableBody");
    iocsBody.innerHTML = "";
    if (data.extracted_iocs && data.extracted_iocs.length > 0) {
        data.extracted_iocs.forEach(ioc => {
            const tr = document.createElement("tr");
            const typeClass = ioc.ioc_type.toLowerCase().includes("url") ? "url" :
                             ioc.ioc_type.toLowerCase().includes("ip") ? "ip" :
                             ioc.ioc_type.toLowerCase().includes("cve") ? "cve" :
                             ioc.ioc_type.toLowerCase().includes("hash") ? "hash" :
                             ioc.ioc_type.toLowerCase().includes("attach") ? "attachment" : "malware";
            tr.innerHTML = `
                <td><span class="ioc-badge ${typeClass}">${ioc.ioc_type}</span></td>
                <td style="font-family:var(--font-code); font-size:0.85rem;">${ioc.value}</td>
                <td><span style="color:${ioc.reputation === 'Malicious' ? 'var(--cyber-red)' : ioc.reputation === 'Suspicious' ? 'var(--cyber-amber)' : 'var(--cyber-green)'}; font-weight:600;">${ioc.reputation}</span></td>
                <td>${ioc.mitre_technique || 'N/A'}</td>
            `;
            iocsBody.appendChild(tr);
        });
    } else {
        iocsBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-dim);">No Indicators of Compromise extracted.</td></tr>`;
    }

    // Rules
    const reasonsList = document.getElementById("topReasonsList");
    reasonsList.innerHTML = "";
    data.triggered_rules.forEach(rule => {
        const li = document.createElement("li");
        li.textContent = rule;
        reasonsList.appendChild(li);
    });

    // Action Guidance
    const actionCard = document.getElementById("actionCard");
    actionCard.className = `action-card ${data.severity_band.toLowerCase()}`;
    document.getElementById("actionText").textContent = data.recommended_action;
}

function highlightCanonicalTokens(text) {
    return text.replace(/(\[[A-Z_]+\])/g, '<span class="norm-token">$1</span>');
}

async function submitFeedback(rating) {
    if (!currentAnalysis) {
        alert("Run a threat analysis first before recording verification.");
        return;
    }
    try {
        await fetch("/api/explanation/feedback", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                message_id: currentAnalysis.message_id,
                alert_id: currentAnalysis.alert_id,
                feedback_rating: rating,
                analyst_notes: "Analyst verified via Live Gateway interface."
            })
        });
        alert(`Verification status '${rating}' committed to immutable audit history.`);
    } catch (e) {
        console.error(e);
    }
}

async function loadAlertsQueue() {
    try {
        const res = await fetch("/api/alerts");
        allAlerts = await res.json();
        renderAlertsTable(allAlerts);
    } catch (e) {
        console.error("Failed to load alerts queue:", e);
    }
}

function renderAlertsTable(alerts) {
    const tbody = document.getElementById("alertsQueueTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-dim); padding:20px;">No incidents pending triage.</td></tr>`;
        return;
    }

    alerts.forEach(al => {
        const tr = document.createElement("tr");
        const sevClass = (al.severity_band || "LOW").toLowerCase();
        tr.innerHTML = `
            <td style="font-family:var(--font-code); font-weight:600; color:#818cf8;">${al.alert_id}</td>
            <td style="font-size:0.8rem; color:var(--text-dim);">${new Date((al.created_at || Date.now()/1000) * 1000).toLocaleTimeString()}</td>
            <td>${al.primary_language || 'English'}</td>
            <td><strong style="color:#ffffff;">${al.predicted_category || 'N/A'}</strong></td>
            <td style="font-family:var(--font-code); font-weight:700;">${al.score || 0}%</td>
            <td><span class="risk-badge ${sevClass}" style="padding:2px 8px; font-size:0.75rem;">${al.severity_band || 'LOW'}</span></td>
            <td><span style="color:#cbd5e1;">${al.disposition || 'Pending'}</span></td>
            <td>
                <button class="btn-secondary" style="padding:4px 10px; font-size:0.78rem;" onclick="openAlertModal('${al.alert_id}')">
                    Inspect & Triage
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function filterAlerts() {
    const sev = document.getElementById("filterSeverity").value;
    const cat = document.getElementById("filterCategory").value;
    const lang = document.getElementById("filterLanguage").value;
    const search = document.getElementById("filterSearch").value.toLowerCase();

    let filtered = allAlerts.filter(a => {
        if (sev !== "ALL" && (a.severity_band || "").toUpperCase() !== sev) return false;
        if (cat !== "ALL" && (a.predicted_category || "").toLowerCase() !== cat.toLowerCase()) return false;
        if (lang !== "ALL" && !(a.primary_language || "").toLowerCase().includes(lang.toLowerCase())) return false;
        if (search) {
            const textMatch = (a.raw_text || "").toLowerCase().includes(search);
            const idMatch = (a.alert_id || "").toLowerCase().includes(search);
            if (!textMatch && !idMatch) return false;
        }
        return true;
    });

    renderAlertsTable(filtered);
}

function openAlertModal(alertId) {
    const alertItem = allAlerts.find(a => a.alert_id === alertId);
    if (!alertItem) return;
    currentModalAlert = alertItem;

    document.getElementById("modalAlertId").textContent = `Incident Dossier: ${alertItem.alert_id}`;
    document.getElementById("modalTimestamp").textContent = `Logged: ${new Date(alertItem.created_at * 1000).toLocaleString()}`;
    document.getElementById("modalRawText").textContent = alertItem.raw_text;
    document.getElementById("modalNormalizedText").innerHTML = highlightCanonicalTokens(alertItem.safe_normalized_text || alertItem.raw_text);
    document.getElementById("modalCategory").textContent = alertItem.predicted_category;
    document.getElementById("modalRiskScore").textContent = `${alertItem.score}% (${alertItem.severity_band})`;
    document.getElementById("modalLanguage").textContent = `${alertItem.primary_language || 'English'} (${alertItem.dialect_label || 'Standard'})`;

    const iocsBody = document.getElementById("modalIocsBody");
    iocsBody.innerHTML = "";
    if (alertItem.iocs && alertItem.iocs.length > 0) {
        alertItem.iocs.forEach(ioc => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><span class="ioc-badge url">${ioc.ioc_type}</span></td>
                <td style="font-family:var(--font-code); font-size:0.82rem;">${ioc.value}</td>
                <td style="color:${ioc.reputation === 'Malicious' ? 'var(--cyber-red)' : 'var(--cyber-amber)'}; font-weight:600;">${ioc.reputation}</td>
                <td>${ioc.mitre_technique || 'N/A'}</td>
            `;
            iocsBody.appendChild(tr);
        });
    } else {
        iocsBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-dim);">No IoCs found.</td></tr>`;
    }

    document.getElementById("modalDispositionSelect").value = alertItem.disposition || "Pending Validation";
    document.getElementById("modalAnalystNotes").value = alertItem.analyst_notes || "";

    document.getElementById("alertModal").classList.remove("hidden");
}

function closeAlertModal() {
    document.getElementById("alertModal").classList.add("hidden");
    currentModalAlert = null;
}

async function saveModalDisposition() {
    if (!currentModalAlert) return;
    const disp = document.getElementById("modalDispositionSelect").value;
    const notes = document.getElementById("modalAnalystNotes").value;

    try {
        await fetch("/api/alerts/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                alert_id: currentModalAlert.alert_id,
                user_id: "SOC-Tier1-Analyst",
                action: "update_disposition",
                new_disposition: disp,
                notes: notes,
                reason: "SOC Analyst Triage Review"
            })
        });
        alert(`Incident ${currentModalAlert.alert_id} disposition committed successfully.`);
        closeAlertModal();
        loadAlertsQueue();
    } catch (e) {
        console.error(e);
        alert("Failed to commit disposition.");
    }
}

function exportCaseDossier() {
    if (!currentModalAlert) return;
    const exportData = {
        platform: "PolyShield Enterprise Cyber Defense",
        export_timestamp: new Date().toISOString(),
        incident_id: currentModalAlert.alert_id,
        classification: currentModalAlert.predicted_category,
        risk_score: currentModalAlert.score,
        severity_band: currentModalAlert.severity_band,
        disposition: currentModalAlert.disposition,
        raw_payload: currentModalAlert.raw_text,
        canonical_semantics: currentModalAlert.safe_normalized_text,
        language_profile: currentModalAlert.primary_language,
        extracted_indicators: currentModalAlert.iocs || [],
        triggered_rules: currentModalAlert.triggered_rules || [],
        recommended_action: currentModalAlert.recommended_action
    };

    const jsonStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Incident_Dossier_${currentModalAlert.alert_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

async function loadResearcherIocs() {
    try {
        const res = await fetch("/api/iocs");
        const iocs = await res.json();
        const tbody = document.getElementById("researcherIocsBody");
        if (!tbody) return;
        tbody.innerHTML = "";

        iocs.forEach(ioc => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="font-family:var(--font-code); font-size:0.85rem; color:#818cf8;">${ioc.value}</td>
                <td><span class="ioc-badge url">${ioc.ioc_type}</span></td>
                <td>${ioc.risk_score}</td>
                <td><span style="color:${ioc.reputation === 'Malicious' ? 'var(--cyber-red)' : 'var(--cyber-amber)'}; font-weight:600;">${ioc.reputation}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error(e);
    }
}

async function submitCuratedSample() {
    const text = document.getElementById("curateText").value;
    const cat = document.getElementById("curateCategory").value;
    const lang = document.getElementById("curateLanguage").value;

    if (!text.trim()) {
        alert("Please enter threat payload text.");
        return;
    }

    try {
        const res = await fetch("/api/curate-sample", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                text: text,
                category: cat,
                language: lang,
                source: "enterprise_threat_intel"
            })
        });
        const data = await res.json();
        alert(data.message || "Threat sample ingested and model updated!");
        document.getElementById("curateText").value = "";
        loadModelEvaluation();
    } catch (e) {
        console.error(e);
        alert("Failed to ingest sample.");
    }
}

function updateWeightLabels() {
    document.getElementById("lblWeightC").textContent = `${document.getElementById("rngC").value}%`;
    document.getElementById("lblWeightS").textContent = `${document.getElementById("rngS").value}%`;
    document.getElementById("lblWeightR").textContent = `${document.getElementById("rngR").value}%`;
    document.getElementById("lblWeightI").textContent = `${document.getElementById("rngI").value}%`;
    document.getElementById("lblWeightT").textContent = `${document.getElementById("rngT").value}%`;
    document.getElementById("lblWeightK").textContent = `${document.getElementById("rngK").value}%`;
}

async function saveRecalibratedWeights() {
    const c = parseFloat(document.getElementById("rngC").value);
    const s = parseFloat(document.getElementById("rngS").value);
    const r = parseFloat(document.getElementById("rngR").value);
    const i = parseFloat(document.getElementById("rngI").value);
    const t = parseFloat(document.getElementById("rngT").value);
    const k = parseFloat(document.getElementById("rngK").value);

    try {
        await fetch("/api/weights", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                weight_c: c,
                weight_s: s,
                weight_r: r,
                weight_i: i,
                weight_t: t,
                weight_k: k
            })
        });
        alert("Gateway security policy and risk formula weights updated successfully!");
    } catch (e) {
        console.error(e);
    }
}

async function loadModelEvaluation() {
    try {
        const res = await fetch("/api/model-evaluation");
        const data = await res.json();
        if (data.accuracy) {
            const accEl = document.getElementById("matrixAcc");
            const f1El = document.getElementById("matrixF1");
            const brierEl = document.getElementById("matrixBrier");
            const topF1El = document.getElementById("metricF1");

            if (accEl) accEl.textContent = `${data.accuracy}%`;
            if (f1El) f1El.textContent = `${data.macro_f1}%`;
            if (brierEl) brierEl.textContent = `${data.brier_score}`;
            if (topF1El) topF1El.textContent = `${data.macro_f1}%`;
        }
    } catch (e) {
        console.error(e);
    }
}

async function loadDecisionLogs() {
    try {
        const res = await fetch("/api/decision-logs");
        const logs = await res.json();
        const tbody = document.getElementById("decisionLogsTableBody");
        if (!tbody) return;
        tbody.innerHTML = "";

        logs.forEach(l => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="font-size:0.75rem; color:var(--text-dim);">${new Date(l.timestamp * 1000).toLocaleTimeString()}</td>
                <td style="font-weight:600; color:#818cf8;">${l.user_id}</td>
                <td><span style="font-family:var(--font-code); font-size:0.8rem;">${l.action}</span></td>
                <td><span style="color:#34d399; font-size:0.8rem;">${l.new_state}</span></td>
                <td style="font-size:0.8rem; color:#cbd5e1;">${l.reason}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error(e);
    }
}
