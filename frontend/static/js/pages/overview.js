import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  escapeHtml,
  fmtDateTime,
  fmtInt,
  fmtNumber,
  pageHead,
  pct,
  severityBadge,
  severityStrip,
  segmented,
  statCard,
  statusBadge,
  timeAgo,
  toast,
} from "../ui.js";
import {
  barChart,
  donutChart,
  severityColors,
  timelineChartId,
} from "../charts.js";

const RANGE_OPTIONS = [
  { value: "24h", label: "24H" },
  { value: "7d", label: "7D" },
  { value: "30d", label: "30D" },
  { value: "all", label: "ALL" },
];

const RANGE_LABEL = { "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", all: "All recorded traffic" };

export async function mount(container, ctx) {
  let range =
    localStorage.getItem("oppps.range") ||
    window.__opppsDefaults?.default_dashboard_range ||
    "7d";
  if (!RANGE_LABEL[range]) range = "7d";

  container.innerHTML = `${pageHead({
    title: "Security command center",
    description:
      "Live posture across ingested flow telemetry, model predictions, anomaly evidence and open response work.",
    actions: `${segmented("ovRange", RANGE_OPTIONS, range)}
      <button type="button" class="btn" id="ovRefresh">${icon("refresh")} Refresh</button>`,
  })}<div id="ovBody"></div>`;

  const body = container.querySelector("#ovBody");
  const alive = () => container.isConnected;

  container.querySelectorAll("#ovRange button").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.value === range) return;
      range = button.dataset.value;
      localStorage.setItem("oppps.range", range);
      container.querySelectorAll("#ovRange button").forEach((item) => {
        item.classList.toggle("active", item.dataset.value === range);
      });
      load();
    });
  });

  const refreshButton = container.querySelector("#ovRefresh");
  refreshButton.addEventListener("click", () => load(true));

  async function load(showToast = false) {
    body.innerHTML = loadingSkeleton();
    refreshButton.disabled = true;
    try {
      const data = await api.get("/api/dashboard/overview", { range });
      if (!alive()) return;
      render(data);
      if (showToast) {
        toast("Overview refreshed", "The latest stored telemetry is displayed.", "success");
      }
    } catch (error) {
      if (!alive()) return;
      body.innerHTML = `<div class="card card-pad"><div class="callout danger"><strong>Unable to load the overview.</strong><br />${escapeHtml(error.message)}</div></div>`;
    } finally {
      if (alive()) refreshButton.disabled = false;
    }
  }

  function loadingSkeleton() {
    return `<div class="stat-grid">${Array.from({ length: 6 })
      .map(() => '<div class="skeleton" style="height:106px;border-radius:12px"></div>')
      .join("")}</div>
      <div class="grid grid-main"><div class="skeleton" style="height:340px;border-radius:12px"></div><div class="skeleton" style="height:340px;border-radius:12px"></div></div>`;
  }

  function render(data) {
    const totals = data.totals || {};
    const severityCounts = data.severity_counts || totals.severity_counts || {};
    const models = data.active_models || [];
    const generated = fmtDateTime(data.generated_at);

    body.innerHTML = `
      <div class="stat-grid">
        ${statCard({
          label: "Total flows",
          value: fmtInt(totals.total_records),
          iconName: "layers",
          foot: `<strong>${fmtInt(totals.unique_sources)}</strong> unique sources`,
        })}
        ${statCard({
          label: "Analyzed",
          value: fmtInt(totals.analyzed),
          iconName: "cpu",
          foot: `<strong>${fmtInt(totals.unprocessed)}</strong> awaiting analysis`,
        })}
        ${statCard({
          label: "Predicted attacks",
          value: fmtInt(totals.attacks),
          iconName: "shield-alert",
          tone: "critical",
          foot: `<span class="text-critical">${pct(totals.attack_rate)}</span> of analyzed flows`,
        })}
        ${statCard({
          label: "Anomalies",
          value: fmtInt(totals.anomalies),
          iconName: "activity",
          tone: "warning",
          foot: `${pct(totals.detection_rate)} detection rate`,
        })}
        ${statCard({
          label: "Open incidents",
          value: fmtInt(totals.open_incidents),
          iconName: "alert-triangle",
          tone: "purple",
          foot: `<strong>${fmtInt(totals.incidents)}</strong> total · ${fmtInt(totals.resolved_incidents)} closed`,
        })}
        ${statCard({
          label: "Suspicious IPs",
          value: fmtInt(totals.suspicious_ips),
          iconName: "globe",
          foot: `<strong>${fmtInt(totals.new_suspicious_ips)}</strong> new in range`,
        })}
      </div>

      <div class="grid grid-main">
        <div class="card">
          <div class="card-head">
            <div><div class="card-title">Traffic & detection timeline</div><div class="card-sub">Ingested flows compared with predicted attacks and statistical anomalies</div></div>
            <span class="badge outline">${RANGE_LABEL[range]}</span>
          </div>
          <div class="card-body"><div class="chart-box" id="ovTimeline"></div></div>
        </div>

        <div class="card">
          <div class="card-head">
            <div><div class="card-title">Severity distribution</div><div class="card-sub">Operational triage severity across detections</div></div>
            <span class="badge outline">${fmtInt(totals.analyzed)} scored</span>
          </div>
          <div class="card-body">
            <div class="chart-box" id="ovSeverity"></div>
            ${severityStrip(severityCounts)}
          </div>
        </div>
      </div>

      <div class="grid grid-3 mt-16">
        <div class="card">
          <div class="card-head"><div><div class="card-title">Predicted attack classes</div><div class="card-sub">Supervised classifier output, excluding BENIGN</div></div></div>
          <div class="card-body"><div class="chart-box" id="ovAttacks"></div></div>
        </div>
        <div class="card">
          <div class="card-head"><div><div class="card-title">Protocol mix</div><div class="card-sub">Observed transport protocols</div></div></div>
          <div class="card-body"><div class="chart-box" id="ovProtocols"></div></div>
        </div>
        <div class="card">
          <div class="card-head"><div><div class="card-title">Highest-risk sources</div><div class="card-sub">Heuristic risk ranking, not reputation data</div></div></div>
          <div class="card-body" style="padding:0">
            <div class="table-wrap">${
              data.top_source_ips?.length
                ? `<table class="data"><thead><tr><th>Source</th><th>Risk</th><th>Events</th><th>Severity</th></tr></thead><tbody>${data.top_source_ips
                    .map(
                      (ip) => `<tr class="clickable" data-ip-search="${escapeHtml(ip.ip_address)}">
                        <td><span class="mono">${escapeHtml(ip.ip_address)}</span><br /><span class="dim" style="font-size:10px">${ip.is_private ? "private" : "public"} · ${escapeHtml((ip.classification || "").replace(/_/g, " "))}</span></td>
                        <td><div class="risk-line"><div class="risk-track"><div class="risk-fill ${Number(ip.risk_score) >= 75 ? "high" : Number(ip.risk_score) >= 50 ? "medium" : "low"}" style="width:${Math.min(100, Number(ip.risk_score) || 0)}%"></div></div><span class="mono" style="font-size:10px">${fmtNumber(ip.risk_score, 1)}</span></div></td>
                        <td class="num">${fmtInt(ip.event_count)}</td>
                        <td>${severityBadge(ip.max_severity)}</td>
                      </tr>`,
                    )
                    .join("")}</tbody></table>`
                : `<div class="empty-state">${icon("globe")}<strong>No suspicious sources</strong><span>Analyze traffic to populate IP tracking.</span></div>`
            }</div>
          </div>
        </div>
      </div>

      <div class="grid grid-main mt-16">
        <div class="card">
          <div class="card-head">
            <div><div class="card-title">Recent incidents</div><div class="card-sub">Newest detections escalated into the response queue</div></div>
            <button type="button" class="btn ghost sm" id="ovAllIncidents">View all ${icon("chevron-right")}</button>
          </div>
          <div class="incident-list" id="ovIncidents">
            ${
              data.recent_incidents?.length
                ? data.recent_incidents
                    .map(
                      (incident) => `<div class="incident-row" data-incident="${incident.id}">
                        <div class="sev-bar ${escapeHtml(incident.severity)}"></div>
                        <div class="incident-main">
                          <div class="incident-title">${escapeHtml(incident.title)}</div>
                          <div class="incident-meta">
                            <span class="mono">${escapeHtml(incident.incident_code)}</span>
                            <span>${escapeHtml(incident.source_ip || "unknown source")}</span>
                            <span>${timeAgo(incident.created_at)}</span>
                          </div>
                        </div>
                        <div class="row" style="gap:6px">${severityBadge(incident.severity)}${statusBadge(incident.status)}</div>
                      </div>`,
                    )
                    .join("")
                : `<div class="empty-state">${icon("shield-check")}<strong>No incidents in this range</strong><span>Escalation is driven by the configured severity threshold.</span></div>`
            }
          </div>
        </div>

        <div class="card">
          <div class="card-head"><div><div class="card-title">Active detection models</div><div class="card-sub">Currently serving predictions</div></div>${models.length ? '<span class="badge resolved">READY</span>' : '<span class="badge critical">MISSING</span>'}</div>
          <div class="card-body">
            ${
              models.length
                ? `<div class="stack">${models
                    .map((model) => {
                      const metrics = model.metrics || {};
                      const primary =
                        model.task_type === "classification"
                          ? `Weighted F1 ${fmtNumber(metrics.f1_weighted ?? metrics.f1, 4)}`
                          : `F1 ${fmtNumber(metrics.f1, 4)} · ROC-AUC ${fmtNumber(metrics.roc_auc, 4)}`;
                      return `<div class="status-tile">
                        <div class="row-between"><div class="s-label">${model.task_type === "classification" ? "SUPERVISED CLASSIFIER" : "ANOMALY DETECTOR"}</div><span class="badge outline">${escapeHtml(model.version)}</span></div>
                        <div class="s-value" style="font-family:Inter,sans-serif;font-size:14px">${escapeHtml(model.name)}</div>
                        <div class="s-note">${escapeHtml(model.algorithm)} · ${primary}</div>
                      </div>`;
                    })
                    .join("")}
                    <div class="callout info" style="font-size:10.5px">Model output is decision support, not proof of compromise. Review the explanation attached to each detection.</div></div>`
                : `<div class="empty-state">${icon("cpu")}<strong>No active models</strong><span>Open Model Performance and train or activate a model.</span></div>`
            }
          </div>
        </div>
      </div>

      <div class="row-between mt-16">
        <span class="dim" style="font-size:10.5px">Data generated ${escapeHtml(generated)} · All figures derive from stored flow and detection records.</span>
        <span class="row" style="gap:14px;font-size:10px;color:var(--dim)">
          <span class="legend-item"><span class="legend-dot" style="background:var(--primary)"></span>Flows</span>
          <span class="legend-item"><span class="legend-dot" style="background:var(--critical)"></span>Attacks</span>
          <span class="legend-item"><span class="legend-dot" style="background:var(--warning)"></span>Anomalies</span>
        </span>
      </div>`;

    timelineChartId("ovTimeline", data.timeline || [], { hourly: range === "24h", height: 286 });
    donutChart(
      "ovSeverity",
      Object.entries(severityCounts).map(([label, count]) => ({ label, count })),
      { height: 216, colors: severityColors },
    );
    barChart("ovAttacks", data.attack_distribution || [], {
      horizontal: true,
      height: 238,
      color: "#ef4444",
    });
    donutChart("ovProtocols", data.protocol_distribution || [], { height: 238 });

    body.querySelectorAll("[data-ip-search]").forEach((row) => {
      row.addEventListener("click", () => ctx.navigate("ips", { search: row.dataset.ipSearch }));
    });
    body.querySelectorAll("[data-incident]").forEach((row) => {
      row.addEventListener("click", () => ctx.navigate("incidents", { focus: row.dataset.incident }));
    });
    body.querySelector("#ovAllIncidents")?.addEventListener("click", () => ctx.navigate("incidents"));
  }

  await load();
  return () => {
    /* charts are destroyed by the router */
  };
}
