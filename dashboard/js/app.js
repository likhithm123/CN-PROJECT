import { initCharts, updateTrafficChart, updateThreatDonut } from "./charts.js";

let ws = null;
const threatCounts = {
  benign: 10,
  syn_flood: 0,
  port_scan: 0,
  flood: 0,
  zero_day: 0
};

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  connectWebSocket();
  setupSimulationButtons();
});

function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log("[WebSocket] Connected to NIDS Pipeline");
    const statusDot = document.getElementById("connectionStatus");
    if (statusDot) {
      statusDot.innerHTML = '<span class="pulse-dot"></span> LIVE ENGINE ACTIVE';
      statusDot.className = "status-badge";
    }
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      renderTelemetry(data.telemetry, data.stats);
    } catch (err) {
      console.error("Error processing telemetry packet:", err);
    }
  };

  ws.onclose = () => {
    console.warn("[WebSocket] Disconnected. Reconnecting in 2 seconds...");
    const statusDot = document.getElementById("connectionStatus");
    if (statusDot) {
      statusDot.innerHTML = '<span class="pulse-dot" style="background:#ff3366"></span> RECONNECTING...';
      statusDot.className = "status-badge";
      statusDot.style.color = "#ff3366";
      statusDot.style.borderColor = "rgba(255, 51, 102, 0.3)";
    }
    setTimeout(connectWebSocket, 2000);
  };
}

function renderTelemetry(telemetry, stats) {
  if (!telemetry) return;

  // 1. Update KPI Cards
  document.getElementById("valPps").innerText = telemetry.pps ? telemetry.pps.toLocaleString() : "0";
  document.getElementById("valFlows").innerText = telemetry.active_flows || "0";
  document.getElementById("valAlerts").innerText = (stats && stats.total_alerts) ? stats.total_alerts : "0";
  document.getElementById("valCritical").innerText = (stats && stats.critical_count) ? stats.critical_count : "0";
  document.getElementById("valThrottled").innerText = telemetry.active_mitigations ? telemetry.active_mitigations.length : "0";

  // Total Bytes / Bandwidth
  const kbps = Math.round((telemetry.bps || 0) / 1000);
  document.getElementById("valBandwidth").innerText = kbps > 1000 ? `${(kbps/1000).toFixed(2)} MB/s` : `${kbps} KB/s`;

  // 2. Update Charts
  updateTrafficChart(telemetry.pps, telemetry.bps);

  // 3. Update Live Traffic Table
  const flowsBody = document.getElementById("liveFlowsBody");
  if (flowsBody && telemetry.recent_flows) {
    flowsBody.innerHTML = "";
    telemetry.recent_flows.slice(0, 10).forEach(flow => {
      const row = document.createElement("tr");
      const badgeClass = getBadgeClass(flow.severity);
      row.innerHTML = `
        <td style="font-family: var(--font-mono)">${flow.src_ip}:${flow.src_port}</td>
        <td style="font-family: var(--font-mono)">${flow.dst_ip}:${flow.dst_port}</td>
        <td><span style="font-weight:600; color:var(--accent-cyan)">${flow.protocol}</span></td>
        <td>${flow.packets}</td>
        <td>${flow.pps}</td>
        <td>
          <span style="font-weight:700; color:${getRiskColor(flow.risk_score)}">${flow.risk_score}%</span>
        </td>
        <td><span class="badge ${badgeClass}">${flow.severity}</span></td>
      `;
      flowsBody.appendChild(row);
    });
  }

  // 4. Update Alerts Feed
  const alertsFeed = document.getElementById("alertsFeed");
  if (alertsFeed && telemetry.recent_alerts) {
    alertsFeed.innerHTML = "";
    if (telemetry.recent_alerts.length === 0) {
      alertsFeed.innerHTML = `<div style="color:var(--text-muted); font-size:0.85rem; padding:1rem; text-align:center;">No threat alerts detected. Network status normal.</div>`;
    }

    telemetry.recent_alerts.forEach(alert => {
      accumulateThreatStats(alert.attack_type);
      const div = document.createElement("div");
      div.className = `alert-item ${alert.severity}`;
      const timeStr = alert.timestamp ? alert.timestamp.split("T")[1].split(".")[0] : "";

      div.innerHTML = `
        <div class="alert-item-header">
          <span class="alert-type">${alert.attack_type}</span>
          <span class="alert-time">${timeStr}</span>
        </div>
        <div class="alert-details">
          <strong>${alert.source_ip}</strong> ➔ <strong>${alert.destination_ip}:${alert.destination_port}</strong> (${alert.protocol})
          <div style="font-size:0.7rem; color:var(--text-muted); margin-top:2px;">${alert.details || ""}</div>
        </div>
        <div class="alert-footer">
          <div>
            <span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
            <span style="margin-left: 0.5rem; font-size: 0.75rem; color: var(--accent-cyan); font-weight:600;">ACTION: ${alert.action}</span>
          </div>
          <div>
            <span style="font-size: 0.7rem; font-family: var(--font-mono); color: ${getRiskColor(alert.risk_score)}">${alert.risk_score}% Risk</span>
            <div class="alert-risk-bar">
              <div class="alert-risk-fill" style="width: ${Math.min(100, alert.risk_score)}%; background:${getRiskColor(alert.risk_score)}"></div>
            </div>
          </div>
        </div>
      `;
      alertsFeed.appendChild(div);
    });
  }

  // 5. Update Threat Distribution Donut
  updateThreatDonut(threatCounts);

  // 6. Update Active QoS Policies Table
  const qosBody = document.getElementById("qosPoliciesBody");
  if (qosBody && telemetry.active_mitigations) {
    qosBody.innerHTML = "";
    if (telemetry.active_mitigations.length === 0) {
      qosBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1rem;">All traffic operating at unrestricted standard QoS (100 Mbps, Priority 1).</td></tr>`;
    } else {
      telemetry.active_mitigations.forEach(p => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td style="font-family: var(--font-mono); font-weight:600;">${p.ip}</td>
          <td><span class="badge badge-${p.tier.toLowerCase()}">${p.tier}</span></td>
          <td style="color:var(--accent-cyan); font-weight:700;">${p.rate_limit_mbps} Mbps</td>
          <td>Tier ${p.priority}</td>
          <td style="font-size:0.75rem; color:var(--text-secondary);">${p.reason || "Mitigation rule"}</td>
          <td>
            <button class="btn btn-warning" style="padding:0.25rem 0.6rem; font-size:0.7rem;" onclick="window.overrideQoS('${p.ip}', 'NORMAL')">Release</button>
          </td>
        `;
        qosBody.appendChild(row);
      });
    }
  }
}

function accumulateThreatStats(attackType) {
  const at = (attackType || "").toLowerCase();
  if (at.includes("syn")) threatCounts.syn_flood++;
  else if (at.includes("scan")) threatCounts.port_scan++;
  else if (at.includes("flood") || at.includes("icmp") || at.includes("udp")) threatCounts.flood++;
  else if (at.includes("anomaly") || at.includes("zero")) threatCounts.zero_day++;
  else threatCounts.benign++;
}

function getBadgeClass(severity) {
  switch (severity) {
    case "CRITICAL": return "badge-critical";
    case "HIGH": return "badge-high";
    case "SUSPICIOUS": return "badge-suspicious";
    default: return "badge-normal";
  }
}

function getRiskColor(score) {
  if (score >= 80) return "#ff3366";
  if (score >= 65) return "#ff9900";
  if (score >= 35) return "#ffcc00";
  return "#00f59b";
}

function setupSimulationButtons() {
  const btnScan = document.getElementById("btnSimScan");
  const btnSyn = document.getElementById("btnSimSyn");
  const btnIcmp = document.getElementById("btnSimIcmp");
  const btnUdp = document.getElementById("btnSimUdp");
  const btnAnomaly = document.getElementById("btnSimAnomaly");
  const btnToggleTraffic = document.getElementById("btnToggleTraffic");

  if (btnScan) btnScan.addEventListener("click", () => triggerAttack("port_scan", "10.0.2.15"));
  if (btnSyn) btnSyn.addEventListener("click", () => triggerAttack("syn_flood", "10.0.2.18"));
  if (btnIcmp) btnIcmp.addEventListener("click", () => triggerAttack("icmp_flood", "10.0.2.25"));
  if (btnUdp) btnUdp.addEventListener("click", () => triggerAttack("udp_flood", "10.0.2.35"));
  if (btnAnomaly) btnAnomaly.addEventListener("click", () => triggerAttack("zero_day", "10.0.2.99"));

  if (btnToggleTraffic) {
    btnToggleTraffic.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/simulation/toggle_traffic", { method: "POST" });
        const data = await res.json();
        btnToggleTraffic.innerText = data.traffic_state === "STARTED" ? "Pause Benign Traffic" : "Resume Benign Traffic";
      } catch (err) {
        console.error("Traffic toggle error:", err);
      }
    });
  }
}

async function triggerAttack(attackType, attackerIp) {
  try {
    const res = await fetch("/api/simulation/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attack_type: attackType, attacker_ip: attackerIp })
    });
    const result = await res.json();
    console.log("Attack triggered:", result);
  } catch (err) {
    console.error("Error triggering attack:", err);
  }
}

window.overrideQoS = async function(ip, tier) {
  try {
    await fetch("/api/qos/override", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, tier })
    });
  } catch (err) {
    console.error("Error setting QoS override:", err);
  }
};

// =========================================================================
// Wireshark PCAP / PCAPNG Forensics Logic
// =========================================================================
function setupPcapHandlers() {
  const btnAnalyzeSample = document.getElementById("btnAnalyzeSample");
  const pcapSampleSelect = document.getElementById("pcapSampleSelect");
  const btnChoosePcap = document.getElementById("btnChoosePcap");
  const pcapFileInput = document.getElementById("pcapFileInput");
  const pcapFileName = document.getElementById("pcapFileName");
  const btnUploadPcap = document.getElementById("btnUploadPcap");

  if (btnAnalyzeSample && pcapSampleSelect) {
    btnAnalyzeSample.addEventListener("click", async () => {
      const selected = pcapSampleSelect.value;
      btnAnalyzeSample.disabled = true;
      btnAnalyzeSample.innerHTML = "<span>⏳</span> Analyzing...";
      try {
        const res = await fetch(`/api/pcap/analyze-sample?filename=${encodeURIComponent(selected)}`, { method: "POST" });
        const data = await res.json();
        renderPcapReport(data);
      } catch (err) {
        alert("Failed to analyze sample PCAP: " + err);
      } finally {
        btnAnalyzeSample.disabled = false;
        btnAnalyzeSample.innerHTML = "<span>⚡</span> Analyze Sample";
      }
    });
  }

  if (btnChoosePcap && pcapFileInput) {
    btnChoosePcap.addEventListener("click", () => pcapFileInput.click());
    pcapFileInput.addEventListener("change", () => {
      if (pcapFileInput.files && pcapFileInput.files.length > 0) {
        const f = pcapFileInput.files[0];
        pcapFileName.innerText = f.name;
        btnUploadPcap.style.display = "inline-flex";
      }
    });
  }

  if (btnUploadPcap && pcapFileInput) {
    btnUploadPcap.addEventListener("click", async () => {
      if (!pcapFileInput.files || pcapFileInput.files.length === 0) return;
      const file = pcapFileInput.files[0];
      const formData = new FormData();
      formData.append("file", file);

      btnUploadPcap.disabled = true;
      btnUploadPcap.innerHTML = "<span>⏳</span> Inspecting...";
      try {
        const res = await fetch("/api/pcap/upload", {
          method: "POST",
          body: formData
        });
        const data = await res.json();
        renderPcapReport(data);
      } catch (err) {
        alert("PCAP inspection failed: " + err);
      } finally {
        btnUploadPcap.disabled = false;
        btnUploadPcap.innerHTML = "<span>🚀</span> Upload & Analyze";
      }
    });
  }
}

function renderPcapReport(report) {
  const box = document.getElementById("pcapResultsBox");
  if (!box) return;
  box.style.display = "block";

  document.getElementById("pcapReportTitle").innerText = `Trace: ${report.filename} (${report.format})`;
  const badge = document.getElementById("pcapReportBadge");
  if (report.threats_detected_count > 0) {
    badge.className = "badge badge-danger";
    badge.innerText = `${report.threats_detected_count} THREAT(S) DETECTED`;
  } else {
    badge.className = "badge badge-success";
    badge.innerText = "NO THREATS DETECTED (BENIGN)";
  }

  const summary = document.getElementById("pcapStatsSummary");
  summary.innerHTML = `
    <div><strong>Packets:</strong> ${report.packets_analyzed}</div>
    <div><strong>Reconstructed Flows:</strong> ${report.flows_reconstructed}</div>
    <div><strong>DNS Packets:</strong> ${report.dns_packets_count}</div>
    <div><strong>Trace Duration:</strong> ${report.trace_duration_seconds}s</div>
    <div><strong>File Size:</strong> ${report.file_size_kb} KB</div>
  `;

  const tbody = document.getElementById("pcapThreatsBody");
  tbody.innerHTML = "";
  if (!report.threats || report.threats.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:1rem;">All traffic flows in this trace are classified as legitimate/benign.</td></tr>`;
    return;
  }

  report.threats.forEach(t => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td style="font-family:var(--font-mono); font-weight:600; color:var(--accent-cyan);">${t.source_ip}</td>
      <td style="font-family:var(--font-mono);">${t.destination_ip}:${t.destination_port}</td>
      <td><strong>${t.protocol}</strong></td>
      <td><span style="color:#ff3366; font-weight:600;">${t.attack_type}</span> ${t.rule_id ? `(${t.rule_id})` : ''}</td>
      <td><span style="font-size:0.75rem; color:var(--accent-purple);">${t.agreement_type}</span></td>
      <td><span style="font-weight:700; color:${getRiskColor(t.risk_score)}">${t.risk_score}%</span></td>
      <td><span class="badge ${getBadgeClass(t.severity)}">${t.severity}</span></td>
      <td><span style="font-size:0.75rem; color:#ffcc00; font-family:var(--font-mono);">${t.action}</span></td>
    `;
    tbody.appendChild(row);
  });
}

// Call setupPcapHandlers on load
document.addEventListener("DOMContentLoaded", () => {
  setupPcapHandlers();
});

