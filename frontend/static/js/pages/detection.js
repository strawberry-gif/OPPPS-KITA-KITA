import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  badge,
  closeDrawer,
  debounce,
  escapeHtml,
  fmtDateTime,
  fmtInt,
  fmtNumber,
  kv,
  labelBadge,
  openDrawer,
  openModal,
  pageHead,
  ratioPct,
  renderPagination,
  segmented,
  setBusy,
  severityBadge,
  statCard,
  toast,
} from "../ui.js";

const LABELS = ["BENIGN", "DoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Infiltration", "ANOMALY"];

const state = {
  tab: "results",
  page: 1,
  page_size: 25,
  severity: "",
  predicted_label: "",
  anomaly: "",
  search: "",
  stats: null,
  canRun: false,
};

function explanationHtml(explanation, detection = null) {
  if (!explanation) return '<div class="callout warning">No explanation was stored for this detection.</div>';
  const signals = explanation.signals || [];
  return `<p class="muted" style="font-size:11.5px;line-height:1.6">${escapeHtml(explanation.summary || "")}</p>
    <div style="margin-top:10px">${signals
      .map(
        (signal) => `<div class="signal">
          <span class="signal-weight">+${fmtNumber(signal.weight, 1)}</span>
          <div><div class="signal-rule">${escapeHtml(signal.rule)}</div><div class="signal-detail">${escapeHtml(signal.detail)}</div></div>
        </div>`,
      )
      .join("") || '<div class="dim" style="font-size:11px">No heuristic signals contributed.</div>'}</div>
    <div class="divider"></div>
    <div class="kv-grid" style="grid-template-columns:repeat(2,minmax(0,1fr))">
      ${kv("Predicted label", escapeHtml(explanation.model?.predicted_label || detection?.predicted_label || "—"))}
      ${kv("Classifier confidence", fmtNumber(explanation.model?.confidence ?? detection?.confidence, 4))}
      ${kv("Attack probability", fmtNumber(explanation.model?.attack_probability ?? 0, 4))}
      ${kv("Anomaly flag", explanation.model?.is_anomaly ? "true" : "false")}
    </div>
    <div class="callout warning" style="margin-top:12px;font-size:10.5px">${(explanation.caveats || [])
      .map((item) => escapeHtml(item))
      .join("<br />")}</div>`;
}

export async function mount(container, ctx) {
  state.tab = "results";
  state.page = 1;
  state.page_size = 25;
  state.severity = "";
  state.predicted_label = "";
  state.anomaly = "";
  state.search = ctx.params.get("search") || "";
  state.canRun = ["admin", "analyst"].includes(ctx.user?.role);
  const alive = () => container.isConnected;

  container.innerHTML = `${pageHead({
    title: "Threat detection",
    description:
      "Model results, anomaly evidence and severity rationale for every analyzed flow. Scores are decision support, not confirmed compromise.",
    actions: `${segmented(
      "detectionTabs",
      [
        { value: "results", label: "Detection results" },
        { value: "predict", label: "Predict a flow" },
      ],
      state.tab,
    )}<button type="button" class="btn primary" id="detectionRun" ${state.canRun ? "" : "disabled"}>${icon("play")} Run detection</button>`,
  })}<div id="detectionStats" class="stat-grid"></div><div id="detectionContent"></div>`;

  const statsRoot = container.querySelector("#detectionStats");
  const content = container.querySelector("#detectionContent");
  const runButton = container.querySelector("#detectionRun");

  container.querySelectorAll("#detectionTabs button").forEach((button) => {
    button.addEventListener("click", () => {
      if (state.tab === button.dataset.value) return;
      state.tab = button.dataset.value;
      container.querySelectorAll("#detectionTabs button").forEach((item) => {
        item.classList.toggle("active", item.dataset.value === state.tab);
      });
      if (state.tab === "results") renderResultsTab();
      else renderPredictTab();
    });
  });

  async function loadStats() {
    try {
      const analytics = await api.get("/api/analytics", { range: "all" });
      if (!alive()) return;
      state.stats = analytics;
      renderStats(analytics);
    } catch (error) {
      if (!alive()) return;
      statsRoot.innerHTML = `<div class="callout danger">${escapeHtml(error.message)}</div>`;
    }
  }

  function renderStats(analytics) {
    const totals = analytics.totals || {};
    const severity = totals.severity_counts || {};
    statsRoot.innerHTML = [
      statCard({
        label: "Analyzed flows",
        value: fmtInt(totals.analyzed),
        iconName: "cpu",
        foot: `${fmtInt(totals.unprocessed)} still unprocessed`,
      }),
      statCard({
        label: "Predicted attacks",
        value: fmtInt(totals.attacks),
        iconName: "shield-alert",
        tone: "critical",
        foot: `${fmtNumber(totals.attack_rate, 2)}% attack rate`,
      }),
      statCard({
        label: "Anomalies",
        value: fmtInt(totals.anomalies),
        iconName: "activity",
        tone: "warning",
        foot: `${fmtNumber(totals.detection_rate, 2)}% detection rate`,
      }),
      statCard({
        label: "Critical severity",
        value: fmtInt(severity.CRITICAL),
        iconName: "alert-triangle",
        tone: "critical",
        foot: "Highest triage band",
      }),
      statCard({
        label: "High severity",
        value: fmtInt(severity.HIGH),
        iconName: "trending-up",
        tone: "warning",
        foot: "Escalated for review",
      }),
      statCard({
        label: "Model coverage",
        value: `${totals.total_records ? fmtNumber((totals.analyzed / totals.total_records) * 100, 1) : "0.0"}%`,
        iconName: "target",
        tone: "success",
        valueClass: "small",
        foot: `${fmtInt(totals.total_records)} total flows`,
      }),
    ].join("");
  }

  function renderResultsTab() {
    content.innerHTML = `<div class="card">
      <div class="card-head">
        <div><div class="card-title">Detection results</div><div class="card-sub">Each row is a stored model decision with an explainable severity score</div></div>
        <span class="badge outline" id="detectionCount">Loading…</span>
      </div>
      <div class="card-body">
        <div class="toolbar">
          <input class="input search" id="detectionSearch" value="${escapeHtml(state.search)}" placeholder="Search source or destination IP…" />
          <select class="select" id="detectionSeverity">
            <option value="">Any severity</option>
            ${["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
              .map((value) => `<option value="${value}" ${state.severity === value ? "selected" : ""}>${value}</option>`)
              .join("")}
          </select>
          <select class="select" id="detectionLabel">
            <option value="">Any prediction</option>
            ${LABELS.map(
              (value) => `<option value="${value}" ${state.predicted_label === value ? "selected" : ""}>${value}</option>`,
            ).join("")}
          </select>
          <select class="select" id="detectionAnomaly">
            <option value="">Anomaly: any</option>
            <option value="true" ${state.anomaly === "true" ? "selected" : ""}>Anomalies only</option>
            <option value="false" ${state.anomaly === "false" ? "selected" : ""}>Non-anomalies</option>
          </select>
          <select class="select" id="detectionPageSize">
            ${[25, 50, 100]
              .map((size) => `<option value="${size}" ${state.page_size === size ? "selected" : ""}>${size} / page</option>`)
              .join("")}
          </select>
        </div>
      </div>
      <div class="table-wrap" id="detectionTable"><div class="empty-state">${icon("clock")}<strong>Loading detections…</strong></div></div>
      <div class="pagination" id="detectionPagination"></div>
    </div>`;

    const search = content.querySelector("#detectionSearch");
    search.addEventListener(
      "input",
      debounce(() => {
        state.search = search.value.trim();
        state.page = 1;
        loadResults();
      }, 350),
    );
    content.querySelector("#detectionSeverity").addEventListener("change", (event) => {
      state.severity = event.target.value;
      state.page = 1;
      loadResults();
    });
    content.querySelector("#detectionLabel").addEventListener("change", (event) => {
      state.predicted_label = event.target.value;
      state.page = 1;
      loadResults();
    });
    content.querySelector("#detectionAnomaly").addEventListener("change", (event) => {
      state.anomaly = event.target.value;
      state.page = 1;
      loadResults();
    });
    content.querySelector("#detectionPageSize").addEventListener("change", (event) => {
      state.page_size = Number(event.target.value);
      state.page = 1;
      loadResults();
    });

    loadResults();
  }

  async function loadResults() {
    const table = content.querySelector("#detectionTable");
    if (table) table.innerHTML = `<div class="empty-state">${icon("clock")}<strong>Loading detections…</strong></div>`;
    try {
      const data = await api.get("/api/detection/results", {
        page: state.page,
        page_size: state.page_size,
        severity: state.severity || undefined,
        predicted_label: state.predicted_label || undefined,
        anomaly: state.anomaly || undefined,
        search: state.search || undefined,
      });
      if (!alive() || state.tab !== "results") return;
      const count = content.querySelector("#detectionCount");
      if (count) count.textContent = `${fmtInt(data.total)} results`;
      if (!data.items?.length) {
        table.innerHTML = `<div class="empty-state">${icon("shield-check")}<strong>No detections match</strong><span>Adjust filters or run detection on unprocessed flows.</span></div>`;
      } else {
        table.innerHTML = `<table class="data"><thead><tr>
          <th>Created</th><th>Source</th><th>Destination</th><th>Prediction</th><th>Confidence</th><th>Anomaly score</th><th>Severity</th><th>Model</th>
        </tr></thead><tbody>${data.items
          .map(
            (row) => `<tr class="clickable" data-detection="${row.id}">
              <td class="mono">${escapeHtml(fmtDateTime(row.created_at))}</td>
              <td class="mono">${escapeHtml(row.source_ip || "—")}</td>
              <td class="mono">${escapeHtml(row.destination_ip || "—")}</td>
              <td>${labelBadge(row.predicted_label, row.is_anomaly)}</td>
              <td class="num">${ratioPct(row.confidence, 2)}</td>
              <td class="num">${fmtNumber(row.anomaly_score, 4)}</td>
              <td>${severityBadge(row.severity)}</td>
              <td class="mono" style="font-size:10px">#${row.model_version_id ?? "—"}</td>
            </tr>`,
          )
          .join("")}</tbody></table>`;
        table.querySelectorAll("[data-detection]").forEach((row) => {
          row.addEventListener("click", () => openDetection(Number(row.dataset.detection)));
        });
      }
      renderPagination(content.querySelector("#detectionPagination"), data, (page) => {
        state.page = page;
        loadResults();
      });
    } catch (error) {
      if (!alive()) return;
      if (table) table.innerHTML = `<div class="empty-state">${icon("alert-circle")}<strong>Could not load detections</strong><span>${escapeHtml(error.message)}</span></div>`;
    }
  }

  async function openDetection(detectionId) {
    openDrawer({
      title: `Detection #${detectionId}`,
      subtitle: "Model decision and severity rationale",
      body: `<div class="empty-state">${icon("clock")}<strong>Loading detection…</strong></div>`,
    });
    try {
      const data = await api.get(`/api/detection/results/${detectionId}`);
      if (!alive()) return;
      const record = data.traffic_record || {};
      const features = record.features || {};
      openDrawer({
        title: `Detection #${data.id}`,
        subtitle: `${escapeHtml(record.src_ip || "unknown")} → ${escapeHtml(record.dst_ip || "unknown")}`,
        body: `
          <div class="drawer-section">
            <div class="drawer-section-title">Verdict</div>
            <div class="row" style="gap:8px;margin-bottom:12px">
              ${severityBadge(data.severity)}
              ${labelBadge(data.predicted_label, data.is_anomaly)}
              ${badge(`score ${fmtNumber(data.severity_score, 1)}/100`, "outline")}
            </div>
            <div class="kv-grid" style="grid-template-columns:repeat(2,minmax(0,1fr))">
              ${kv("Detection ID", `#${data.id}`)}
              ${kv("Traffic record", `#${data.traffic_record_id}`)}
              ${kv("Classifier confidence", ratioPct(data.confidence, 2))}
              ${kv("Anomaly score", fmtNumber(data.anomaly_score, 4))}
              ${kv("Model version", `#${data.model_version_id ?? "—"}`)}
              ${kv("Created", escapeHtml(fmtDateTime(data.created_at)))}
            </div>
          </div>
          <div class="drawer-section">
            <div class="drawer-section-title">Why this verdict</div>
            ${explanationHtml(data.explanation, data)}
          </div>
          <div class="drawer-section">
            <div class="drawer-section-title">Traffic context</div>
            <div class="kv-grid" style="grid-template-columns:repeat(2,minmax(0,1fr))">
              ${kv("Timestamp", escapeHtml(fmtDateTime(record.timestamp)))}
              ${kv("Protocol", escapeHtml(record.protocol || "—"))}
              ${kv("Destination port", String(record.dst_port ?? "—"))}
              ${kv("Ground-truth label", record.dataset_label ? escapeHtml(record.dataset_label) : "not provided")}
            </div>
            <div class="callout info" style="margin-top:10px;font-size:10.5px">The ground-truth label, when present, is dataset metadata and is not used by the prediction pipeline.</div>
          </div>
          <div class="drawer-section">
            <div class="drawer-section-title">Key features</div>
            <div class="table-wrap"><table class="data"><thead><tr><th>Feature</th><th style="text-align:right">Value</th></tr></thead><tbody>
              ${Object.keys(features)
                .sort()
                .map(
                  (key) =>
                    `<tr><td class="mono" style="font-size:11px">${escapeHtml(key)}</td><td class="num" style="text-align:right">${fmtNumber(features[key], 6)}</td></tr>`,
                )
                .join("") || '<tr><td class="empty-cell" colspan="2">No feature vector stored.</td></tr>'}
            </tbody></table></div>
          </div>`,
        footer: `<button type="button" class="btn" data-close>Close</button><button type="button" class="btn primary" data-flow>Open flow records ${icon("chevron-right")}</button>`,
      });
      document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", closeDrawer));
      document.querySelector("[data-flow]")?.addEventListener("click", () => {
        closeDrawer();
        ctx.navigate("traffic");
      });
    } catch (error) {
      if (!alive()) return;
      toast("Could not load detection", error.message, "error");
    }
  }

  function renderPredictTab() {
    content.innerHTML = `<div class="grid grid-main">
      <div class="card">
        <div class="card-head"><div><div class="card-title">Single-flow prediction</div><div class="card-sub">Runs the active classifier and anomaly model on operator-supplied values</div></div><span class="badge outline">NO PERSISTENCE</span></div>
        <div class="card-body">
          <div class="grid grid-3">
            <div class="field"><label for="predictSrc">Source IP (optional)</label><input class="input" id="predictSrc" placeholder="203.0.113.10" /></div>
            <div class="field"><label for="predictProtocol">Protocol</label><select class="select" id="predictProtocol"><option>TCP</option><option>UDP</option><option>ICMP</option></select></div>
            <div class="field"><label for="predictPort">Destination port</label><input class="input" id="predictPort" type="number" min="0" max="65535" placeholder="443" /></div>
          </div>
          <div class="divider"></div>
          <div class="drawer-section-title">Flow features</div>
          <div class="grid grid-3" id="predictFeatures">
            ${[
              ["flow_duration", "Flow duration (s)", "0.024"],
              ["packet_count", "Total packets", "12"],
              ["packet_length_mean", "Mean packet length (B)", "740"],
              ["flow_bytes_per_sec", "Flow bytes / second", "355000"],
              ["flow_packets_per_sec", "Flow packets / second", "500"],
              ["syn_count", "SYN flags", "1"],
              ["ack_count", "ACK flags", "10"],
              ["psh_count", "PSH flags", "2"],
              ["rst_count", "RST flags", "0"],
            ]
              .map(
                ([feature, label, placeholder]) => `<div class="field">
                  <label for="pf_${feature}">${label}</label>
                  <input class="input" id="pf_${feature}" data-feature="${feature}" type="number" step="any" min="0" placeholder="${placeholder}" />
                </div>`,
              )
              .join("")}
          </div>
          <div class="row-between mt-16">
            <span class="dim" style="font-size:10.5px">Blank fields are imputed with training medians by the model pipeline.</span>
            <button type="button" class="btn primary" id="predictButton">${icon("zap")} Predict</button>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><div><div class="card-title">Prediction result</div><div class="card-sub">Same model and severity rules used by batch detection</div></div></div>
        <div class="card-body" id="predictResult">
          <div class="empty-state">${icon("target")}<strong>No prediction yet</strong><span>Enter feature values and run a prediction.</span></div>
        </div>
      </div>
    </div>`;

    content.querySelector("#predictButton").addEventListener("click", async () => {
      const button = content.querySelector("#predictButton");
      const resultRoot = content.querySelector("#predictResult");
      const features = {};
      content.querySelectorAll("[data-feature]").forEach((input) => {
        if (input.value !== "") {
          const value = Number(input.value);
          if (Number.isFinite(value)) features[input.dataset.feature] = value;
        }
      });
      const dstPort = content.querySelector("#predictPort").value;
      if (dstPort !== "") features.destination_port = Number(dstPort);
      if (!Object.keys(features).length) {
        toast("No features supplied", "Provide at least one flow feature.", "warning");
        return;
      }
      setBusy(button, true, "Scoring…");
      try {
        const result = await api.post("/api/detection/predict", {
          src_ip: content.querySelector("#predictSrc").value.trim() || null,
          dst_port: dstPort === "" ? null : Number(dstPort),
          protocol: content.querySelector("#predictProtocol").value,
          features,
        });
        if (!alive()) return;
        resultRoot.innerHTML = `
          <div class="row" style="gap:8px">${severityBadge(result.severity)}${labelBadge(result.predicted_label, result.is_anomaly)}</div>
          <div class="grid grid-2 mt-16">
            ${[
              ["Severity score", `${fmtNumber(result.severity_score, 1)}/100`],
              ["Confidence", ratioPct(result.confidence, 2)],
              ["Anomaly", result.is_anomaly ? "yes" : "no"],
              ["Anomaly score", fmtNumber(result.anomaly_score, 4)],
            ]
              .map(
                ([label, value]) => `<div class="metric-tile"><div class="m-label">${label}</div><div class="m-value" style="font-size:15px">${value}</div></div>`,
              )
              .join("")}
          </div>
          <div class="divider"></div>
          ${explanationHtml(result.explanation, result)}
          <div class="callout info" style="margin-top:12px;font-size:10.5px">This is a transient inference. It is not stored and does not create an incident or IP record.</div>`;
      } catch (error) {
        if (!alive()) return;
        resultRoot.innerHTML = `<div class="callout danger"><strong>Prediction failed.</strong><br />${escapeHtml(error.message)}</div>`;
      } finally {
        if (alive()) setBusy(button, false);
      }
    });
  }

  runButton.addEventListener("click", async () => {
    if (!state.canRun) return;
    let imports = [];
    try {
      imports = await api.get("/api/traffic/imports");
    } catch {
      imports = [];
    }
    if (!alive()) return;
    openModal({
      title: "Run detection",
      subtitle: "Score unprocessed flows with the active models",
      width: "520px",
      body: `<div class="stack">
        <div class="field">
          <label for="runLimit">Maximum flows to process</label>
          <input class="input" id="runLimit" type="number" min="1" max="20000" value="2000" />
          <span class="dim" style="font-size:10.5px">Processing is sequential. 2,000 flows usually complete in a few seconds.</span>
        </div>
        <div class="field">
          <label for="runImport">Dataset import</label>
          <select class="select" id="runImport">
            <option value="">All unprocessed flows</option>
            ${imports
              .filter((item) => item.status === "completed")
              .map(
                (item) =>
                  `<option value="${item.id}">#${item.id} · ${escapeHtml(item.original_name)} (${fmtInt(item.accepted_rows)} rows)</option>`,
              )
              .join("")}
          </select>
        </div>
        <div class="callout info" style="font-size:10.5px">Only flows that do not yet have a detection result are processed. This action is audited.</div>
      </div>`,
      footer: `<button type="button" class="btn" data-cancel>Cancel</button><button type="button" class="btn primary" data-run>${icon("play")} Start detection</button>`,
      onMount(card) {
        card.querySelector("[data-cancel]").addEventListener("click", () => card.closest(".modal")?.querySelector("[data-modal-close]")?.click());
        card.querySelector("[data-run]").addEventListener("click", async () => {
          const button = card.querySelector("[data-run]");
          const limit = Number(card.querySelector("#runLimit").value) || 2000;
          const importId = card.querySelector("#runImport").value;
          setBusy(button, true, "Analyzing…");
          try {
            const result = await api.post("/api/detection/run", {
              limit,
              import_id: importId ? Number(importId) : null,
            });
            card.closest(".modal")?.querySelector("[data-modal-close]")?.click();
            toast(
              "Detection complete",
              `${fmtInt(result.processed)} flows processed · ${fmtInt(result.attacks)} attacks · ${fmtInt(result.incidents_created)} incidents.`,
              "success",
            );
            await loadStats();
            if (state.tab === "results") await loadResults();
          } catch (error) {
            toast("Detection failed", error.message, "error");
            setBusy(button, false);
          }
        });
      },
    });
  });

  await loadStats();
  if (alive()) renderResultsTab();

  return () => {
    /* no background work */
  };
}
