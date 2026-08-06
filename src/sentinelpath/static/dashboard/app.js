/*
 * app.js
 * ========
 * Bu dosya BILEREK iki bolume ayrilmistir:
 *   1. SAF FONKSIYONLAR (DOM'a, fetch'e, tarayiciya bagimli degil) --
 *      bu fonksiyonlar Node.js altinda test edilebilir (bkz.
 *      tests/dashboard/test_app_pure_functions.js). ADR 0003/0011'deki
 *      "framework I/O'yu saf mantiktan ayir" prensibinin bu kez
 *      backend Python degil, frontend JS icin uygulanmis halidir.
 *   2. DOM/fetch KODU -- sadece tarayicida calisir, bu ortamda test
 *      EDILEMEDI (headless browser aracı mevcut degil).
 */

// --- 1. SAF FONKSIYONLAR (test edilebilir) ---------------------------------

/**
 * Risk skoruna (0-100) gore bir renk dondurur: dusuk=yesil, orta=sari,
 * yuksek=kirmizi. style.css'teki degiskenlerle AYNI renk semasi
 * (backend'deki JSONReporting.RISK_GRADIENT_COLORS ile de tutarlidir).
 */
function riskColor(score) {
  if (score >= 60) return "#ff6666";
  if (score >= 30) return "#ffe766";
  return "#8ec843";
}

/**
 * API'den donen ReportResponse benzeri bir nesneyi, vis-network'un
 * bekledigi {nodes, edges} formatina cevirir.
 *
 * Node'lar: kaynak host (target_node) + her risk skorunun hedef host'u.
 * Edge'ler: kaynak -> her hedef, teknik ID'si ile etiketli, risk
 * skoruna gore renklendirilmis.
 */
function buildGraphData(report) {
  const nodeIds = new Set([report.target_node]);
  const edges = [];

  for (const rs of report.risk_scores) {
    nodeIds.add(rs.target_node);
    edges.push({
      from: report.target_node,
      to: rs.target_node,
      label: `${rs.technique_id} (%${Math.round(rs.probability * 100)})`,
      color: { color: riskColor(rs.score) },
      width: Math.max(1, rs.score / 20),
    });
  }

  const nodes = Array.from(nodeIds).map((id) => ({
    id,
    label: id,
    color: id === report.target_node ? "#ff9d4d" : "#4fa3ff",
  }));

  return { nodes, edges };
}

/**
 * baseline_confidence null olabilir (bkz. ADR 0010) -- bu durumda
 * "N/A" gosterilmelidir, "0.00" gibi yanlis-yorumlanabilir bir deger
 * DEGIL.
 */
function formatConfidence(confidence) {
  if (confidence === null || confidence === undefined) return "N/A";
  return confidence.toFixed(2);
}

/** Risk skorlarini azalan skora gore siralar (API zaten sirali doner,
 * ama dashboard'un kendi ic tutarliligi icin burada da garanti edilir). */
function sortRiskScoresDescending(riskScores) {
  return [...riskScores].sort((a, b) => b.score - a.score);
}

// Node.js altinda test edilebilmesi icin (tarayicida bu blok calismaz,
// `module` tanimsiz oldugu icin sessizce atlanir).
if (typeof module !== "undefined" && module.exports) {
  module.exports = { riskColor, buildGraphData, formatConfidence, sortRiskScoresDescending };
}

// --- 2. DOM/fetch KODU (sadece tarayicida calisir) -------------------------

if (typeof window !== "undefined") {
  const DEMO_EVENTS = buildDemoEvents();

  document.getElementById("load-demo-btn").addEventListener("click", runDemoScenario);

  async function runDemoScenario() {
    setStatus("Pipeline calistiriliyor...");
    document.getElementById("load-demo-btn").disabled = true;

    const requestBody = {
      events: DEMO_EVENTS,
      known_hosts: ["10.0.0.50", "10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.0.40"],
      start_node: "10.0.0.50",
      feature_window_start: "2026-08-05T00:00:00Z",
      feature_window_end: "2026-08-06T00:00:00Z",
      baseline_window_start: "2026-07-23T00:00:00Z",
      baseline_window_end: "2026-08-06T00:00:00Z",
      asset_criticality_map: { "10.0.0.10": 0.9, "10.0.0.20": 0.95, "10.0.0.30": 0.3, "10.0.0.40": 0.2 },
    };

    try {
      const response = await fetch("/api/v1/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(`API hatasi (${response.status}): ${detail}`);
      }
      const report = await response.json();
      renderReport(report);
      setStatus(`Tamamlandi -- ${report.risk_scores.length} risk skoru, ${report.recommendations.length} oneri.`);
    } catch (err) {
      setStatus(`Hata: ${err.message}`);
    } finally {
      document.getElementById("load-demo-btn").disabled = false;
    }
  }

  function setStatus(text) {
    document.getElementById("status-text").textContent = text;
  }

  function renderReport(report) {
    document.getElementById("results").hidden = false;
    renderRiskTable(report);
    renderRecommendations(report);
    renderGraph(report);
  }

  function renderRiskTable(report) {
    const tbody = document.getElementById("risk-table-body");
    tbody.innerHTML = "";
    for (const rs of sortRiskScoresDescending(report.risk_scores)) {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${rs.target_node}</td>
        <td>${rs.technique_id}</td>
        <td>${rs.probability.toFixed(2)}</td>
        <td>${rs.asset_criticality.toFixed(2)}</td>
        <td>${rs.technique_severity.toFixed(2)}</td>
        <td style="color:${riskColor(rs.score)}; font-weight:600">${rs.score.toFixed(1)}</td>
        <td>${formatConfidence(rs.baseline_confidence)}</td>
      `;
      tbody.appendChild(row);
    }
  }

  function renderRecommendations(report) {
    const list = document.getElementById("recommendations-list");
    list.innerHTML = "";
    for (const rec of report.recommendations) {
      const li = document.createElement("li");
      li.innerHTML = `
        <span class="mitigation-id">[${rec.mitigation_id || "N/A"}]</span> ${rec.action}
        <div class="rationale">${rec.rationale}</div>
      `;
      list.appendChild(li);
    }
  }

  function renderGraph(report) {
    const container = document.getElementById("graph-container");
    const { nodes, edges } = buildGraphData(report);
    const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
    const options = {
      nodes: { shape: "dot", size: 18, font: { color: "#e6e9ed" } },
      edges: { font: { color: "#e6e9ed", size: 11 }, arrows: "to", smooth: true },
      physics: { stabilization: true },
    };
    new vis.Network(container, data, options);
  }

  function buildDemoEvents() {
    // Ayni senaryo scripts/demo_end_to_end.py ile -- tutarlilik icin.
    return [
      { event_id: "net-1", timestamp: "2026-08-05T02:15:00Z", source: "network", source_host: "10.0.0.50", target_host: "10.0.0.10", raw_action: "tcp_connect:rdp", mitre_technique_id: "T1021.001", metadata: { dst_port: "3389", protocol: "tcp" } },
      { event_id: "net-2", timestamp: "2026-08-05T02:20:00Z", source: "network", source_host: "10.0.0.10", target_host: "10.0.0.20", raw_action: "tcp_connect:smb_admin_shares", mitre_technique_id: "T1021.002", metadata: { dst_port: "445", protocol: "tcp" } },
      { event_id: "net-3", timestamp: "2026-08-05T10:00:00Z", source: "network", source_host: "10.0.0.40", target_host: "10.0.0.30", raw_action: "tcp_connect:port_8080", metadata: { dst_port: "8080", protocol: "tcp" } },
      { event_id: "net-4", timestamp: "2026-08-05T10:00:00Z", source: "network", source_host: "10.0.0.40", target_host: "10.0.0.10", raw_action: "tcp_connect:port_5432", metadata: { dst_port: "5432", protocol: "tcp" } },
      { event_id: "auth-1", timestamp: "2026-08-05T02:16:00Z", source: "auth", source_host: "10.0.0.50", target_host: "10.0.0.10", user: "svc_admin", raw_action: "auth_attempt", mitre_technique_id: "T1078", metadata: { outcome: "success" } },
      { event_id: "auth-2", timestamp: "2026-08-05T02:17:00Z", source: "auth", source_host: "10.0.0.50", target_host: "10.0.0.20", user: "svc_admin", raw_action: "auth_attempt", metadata: { outcome: "failure" } },
      { event_id: "auth-3", timestamp: "2026-08-05T02:21:00Z", source: "auth", source_host: "10.0.0.10", target_host: "10.0.0.20", user: "svc_admin", raw_action: "auth_attempt", mitre_technique_id: "T1078", metadata: { outcome: "success" } },
      { event_id: "auth-4", timestamp: "2026-08-05T10:00:00Z", source: "auth", source_host: "10.0.0.40", target_host: "10.0.0.10", user: "alice", raw_action: "auth_attempt", mitre_technique_id: "T1078", metadata: { outcome: "success" } },
    ];
  }
}
