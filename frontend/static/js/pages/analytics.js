import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  badge,
  classificationBadge,
  downloadCsv,
  escapeHtml,
  fmtDateTime,
  fmtInt,
  fmtNumber,
  pageHead,
  pct,
  riskBar,
  segmented,
  severityBadge,
  statCard,
  toast,
} from "../ui.js";
import {
  barChart,
  donutChart,
  severityColors,
  timelineChartId,
} from "../charts.js";

const RANGES = [
  { value: "24h", label: "24H" },
  { value: "7d", label: "7D" },
  { value: "30d", label: "30D" },
  { value: "all", label: "ALL" },
];

const RANGE_LABEL = { "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", all: "All recorded traffic" };

const STATUS_COLORS = {
  NEW: "#3b82f6",
  INVESTIGATING: "#8b5cf6",
  RESOLVED: "#22c55e",
  FALSE_POSITIVE: "#64748b",
};

export async function mount(container, ctx) {
  let range =
    localStorage.getItem("oppps.range") ||
    window.__opppsDefaults?.default_dashboard_range ||
    "7d";
  if (!RANGE_LABEL[range]) range = "7d";
  let latest = null;
  const alive = () => container.isConnected;

  container.innerHTML = `${pageHead({
    title: "Security analytics",
    description:
      "Distribution and trend analysis across the selected window. Every series is computed from stored flow and detection records at request time.",
    actions: `${segmented("analyticsRange", RANGES, range)}
      <button type="button" class="btn" id="analyticsExport">${icon("download")} Export timeline</button>
      <button type="button" class="btn" id="analyticsRefresh">${icon("refresh")} Refresh</button>`,
  })}<div id="analyticsStats" class="stat-grid"></div><div id="analyticsBody"></div>`;

  const statsRoot = container.querySelector("#analyticsStats");
  const body = container.querySelector("#analyticsBody");
  const refreshButton = container.querySelector("#analyticsRefresh");
  const exportButton = container.querySelector("#analyticsExport");

  container.querySelectorAll("#analyticsRange button").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.value === range) return;
      range = button.dataset.value;
      localStorage.setItem("oppps.range", range);
      container.querySelectorAll("#analyticsRange button").forEach((item) => {
        item.classList.toggle("active", item.dataset.value === range);
      });
      load();
    });
  });

  async function load(showToast = false) {
    body.innerHTML = `<div class="grid grid-main"><div class="skeleton" style="height:340px;border-radius:12px"></div><div class="skeleton" style="height:340px;border-radius:12px"></div></div>`;
    refreshButton.disabled = true;
    try {
      const data = await api.get("/api/analytics", { range });
      if (!alive()) return;
      latest = data;
      render(data);
      if (showToast) toast("Analytics refreshed", "All series were recomputed.", "success");
    } catch (error) {
      if (!alive()) return;
      body.innerHTML = `<div class="card card-pad"><div class="callout danger"><strong>Unable to load analytics.</strong><br />${escapeHtml(error.message)}</div></div>`;
    } finally {
      if (alive()) refreshButton.disabled = false;
    }
  }

  function render(data) {
    const totals = data.totals || {};
    const severity = (data.severity_distribution || []).map((item) => ({ ...item }));
    statsRoot.innerHTML = [
      statCard({
        label: "Flows in range",
        value: fmtInt(totals.total_records),
        iconName: "layers",
        foot: `${fmtInt(totals.unique_sources)} unique sources`,
      }),
      statCard({
        label: "Analyzed",
        value: fmtInt(totals.analyzed),
        iconName: "cpu",
        foot: `${fmtInt(totals.unprocessed)} pending`,
      }),
      statCard({
        label: "Predicted attacks",
        value: fmtInt(totals.attacks),
        iconName: "shield-alert",
        tone: "critical",
        foot: `${pct(totals.attack_rate)} attack rate`,
      }),
      statCard({
        label: "Anomalies",
        value: fmtInt(totals.anomalies),
        iconName: "activity",
        tone: "warning",
        foot: `${pct(totals.detection_rate)} detection rate`,
      }),
      statCard({
        label: "Incidents",
        value: fmtInt(totals.incidents),
        iconName: "alert-triangle",
        tone: "purple",
        foot: `${fmtInt(totals.open_incidents)} open · ${fmtInt(totals.resolved_incidents)} closed`,
      }),
      statCard({
        label: "Suspicious IPs",
        value: fmtInt(totals.suspicious_ips),
        iconName: "globe",
        foot: `${fmtInt(totals.new_suspicious_ips)} new in range`,
      }),
    ].join("");

    body.innerHTML = `
      <div class="card">
        <div class="card-head">
          <div><div class="card-title">Traffic and detection trend</div><div class="card-sub">Aggregated by ${range === "24h" ? "hour" : "day"}</div></div>
          <span class="badge outline">${RANGE_LABEL[range]}</span>
        </div>
        <div class="card-body"><div class="chart-box" id="analyticsTimeline"></div></div>
      </div>

      <div class="grid grid-3 mt-16">
        <div class="card">
          <div class="card-head"><div><div class="card-title">Severity distribution</div><div class="card-sub">All detections in range</div></div></div>
          <div class="card-body"><div class="chart-box" id="analyticsSeverity"></div></div>
        </div>
        <div class="card">
          <div class="card-head"><div><div class="card-title">Attack classification</div><div class="card-sub">Supervised labels excluding BENIGN</div></div></div>
          <div class="card-body"><div class="chart-box" id="analyticsAttacks"></div></div>
        </div>
        <div class="card">
          <div class="card-head"><div><div class="card-title">Protocol distribution</div><div class="card-sub">Observed flow protocols</div></div></div>
          <div class="card-body"><div class="chart-box" id="analyticsProtocols"></div></div>
        </div>
      </div>

      <div class="grid grid-2 mt-16">
        <div class="card">
          <div class="card-head"><div><div class="card-title">Top destination ports</div><div class="card-sub">Ten most frequent destination ports</div></div></div>
          <div class="card-body"><div class="chart-box" id="analyticsPorts"></div></div>
        </div>
        <div class="card">
          <div class="card-head"><div><div class="card-title">Incident status</div><div class="card-sub">Current response queue, not filtered by range</div></div></div>
          <div class="card-body"><div class="chart-box" id="analyticsStatus"></div></div>
        </div>
      </div>

      <div class="card mt-16">
        <div class="card-head"><div><div class="card-title">Top source addresses</div><div class="card-sub">Ranked by heuristic risk indicator</div></div><span class="badge outline">TOP 10</span></div>
        <div class="table-wrap">${
          data.top_source_ips?.length
            ? `<table class="data"><thead><tr><th>Address</th><th>Exposure</th><th>Classification</th><th>Risk</th><th>Events</th><th>Incidents</th><th>Max severity</th></tr></thead><tbody>${data.top_source_ips
                .map(
                  (ip) => `<tr class="clickable" data-ip-search="${escapeHtml(ip.ip_address)}">
                    <td><span class="mono">${escapeHtml(ip.ip_address)}</span></td>
                    <td>${ip.is_private ? badge("PRIVATE", "private") : badge("PUBLIC", "public")}</td>
                    <td>${classificationBadge(ip.classification)}</td>
                    <td>${riskBar(ip.risk_score)}</td>
                    <td class="num">${fmtInt(ip.event_count)}</td>
                    <td class="num">${fmtInt(ip.incident_count)}</td>
                    <td>${severityBadge(ip.max_severity)}</td>
                  </tr>`,
                )
                .join("")}</tbody></table>`
            : `<div class="empty-state">${icon("globe")}<strong>No tracked source addresses</strong><span>Analyze traffic to populate IP intelligence.</span></div>`
        }</div>
      </div>

      <div class="row-between mt-16">
        <span class="dim" style="font-size:10.5px">Computed ${escapeHtml(fmtDateTime(new Date().toISOString()))} · Range: ${RANGE_LABEL[range]} · Observed payload volume: ${fmtNumber(totals.observed_bytes, 0)} bytes</span>
        <span class="dim" style="font-size:10.5px">Severity is a triage heuristic; anomaly flags are statistical, not proof of attack.</span>
      </div>`;

    timelineChartId("analyticsTimeline", data.timeline || [], { hourly: range === "24h", height: 300 });
    donutChart("analyticsSeverity", severity, { height: 240, colors: severityColors });
    barChart("analyticsAttacks", data.attack_distribution || [], {
      horizontal: true,
      height: 240,
      color: "#ef4444",
    });
    donutChart("analyticsProtocols", data.protocol_distribution || [], { height: 240 });
    barChart("analyticsPorts", data.top_destination_ports || [], {
      horizontal: true,
      height: 260,
      color: "#06b6d4",
    });
    donutChart("analyticsStatus", data.status_distribution || [], {
      height: 260,
      colors: STATUS_COLORS,
    });

    body.querySelectorAll("[data-ip-search]").forEach((row) => {
      row.addEventListener("click", () => ctx.navigate("ips", { search: row.dataset.ipSearch }));
    });
  }

  exportButton.addEventListener("click", () => {
    if (!latest?.timeline?.length) {
      toast("Nothing to export", "The timeline is empty for this range.", "warning");
      return;
    }
    downloadCsv(
      `oppps-timeline-${range}.csv`,
      latest.timeline.map((point) => ({
        bucket: point.bucket,
        total_flows: point.total,
        predicted_attacks: point.attacks,
        anomalies: point.anomalies,
        critical_severity: point.critical,
        high_severity: point.high,
      })),
    );
    toast("Export created", "The timeline was downloaded as CSV.", "success");
  });

  refreshButton.addEventListener("click", () => load(true));

  await load();
  return () => {
    /* charts destroyed by router */
  };
}
