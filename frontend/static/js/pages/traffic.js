import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  badge,
  closeDrawer,
  debounce,
  emptyState,
  escapeHtml,
  fmtDateTime,
  fmtInt,
  fmtNumber,
  kv,
  labelBadge,
  openDrawer,
  pageHead,
  renderPagination,
  segmented,
  setBusy,
  severityBadge,
  statCard,
  toast,
} from "../ui.js";

const PAGE_SIZES = [25, 50, 100];

const state = {
  tab: "records",
  stats: null,
  schema: null,
  records: { page: 1, page_size: 25, search: "", protocol: "", label: "", severity: "", anomaly: "" },
  imports: [],
  selectedFile: null,
  headers: [],
  mapping: {},
  labelColumn: "",
  busy: false,
};

function normalize(value) {
  return String(value || "")
    .replace(/\uFEFF/g, "")
    .trim()
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/[^a-z0-9 ]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function parseCsvLine(line) {
  const cells = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quoted) {
      if (char === '"') {
        if (line[index + 1] === '"') {
          current += '"';
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        current += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      cells.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  cells.push(current);
  return cells.map((cell) => cell.trim()).filter((cell, index, all) => cell !== "" || index < all.length - 1);
}

async function readHeader(file) {
  const slice = file.slice(0, 128 * 1024);
  const text = await slice.text();
  const line = text.split(/\r?\n/)[0] || "";
  return parseCsvLine(line.replace(/^\uFEFF/, "")).filter((value) => value !== "");
}

function buildAutoMapping(headers, schema) {
  const lookup = new Map();
  const add = (alias, canonical) => {
    const key = normalize(alias);
    if (key && !lookup.has(key)) lookup.set(key, canonical);
  };
  (schema?.canonical_features || []).forEach((canonical) => add(canonical, canonical));
  Object.entries(schema?.aliases || {}).forEach(([canonical, aliases]) => {
    (aliases || []).forEach((alias) => add(alias, canonical));
  });
  const mapping = {};
  headers.forEach((header) => {
    const canonical = lookup.get(normalize(header));
    if (canonical && !Object.values(mapping).includes(canonical)) {
      mapping[header] = canonical;
    }
  });
  return mapping;
}

function guessLabelColumn(headers) {
  const candidates = ["label", "class", "attack", "attack type", "category", "target"];
  return headers.find((header) => candidates.includes(normalize(header))) || "";
}

export async function mount(container, ctx) {
  const canImport = ["admin", "analyst"].includes(ctx.user?.role);
  const alive = () => container.isConnected;
  state.tab = "records";
  state.records = { page: 1, page_size: 25, search: "", protocol: "", label: "", severity: "", anomaly: "" };
  state.selectedFile = null;
  state.headers = [];
  state.mapping = {};
  state.labelColumn = "";

  container.innerHTML = `${pageHead({
    title: "Network traffic",
    description:
      "Inspect every stored flow, distinguish dataset ground truth from model predictions, and import new CSV telemetry with an explicit feature mapping.",
    actions: `${segmented(
      "trafficTabs",
      [
        { value: "records", label: "Flow records" },
        { value: "import", label: "Import dataset" },
      ],
      state.tab,
    )}<button type="button" class="btn" id="trafficRefresh">${icon("refresh")} Refresh</button>`,
  })}<div id="trafficStats" class="stat-grid"></div><div id="trafficContent"></div>`;

  const statsRoot = container.querySelector("#trafficStats");
  const content = container.querySelector("#trafficContent");
  const refreshButton = container.querySelector("#trafficRefresh");

  container.querySelectorAll("#trafficTabs button").forEach((button) => {
    button.addEventListener("click", () => {
      if (state.tab === button.dataset.value) return;
      state.tab = button.dataset.value;
      container.querySelectorAll("#trafficTabs button").forEach((item) => {
        item.classList.toggle("active", item.dataset.value === state.tab);
      });
      if (state.tab === "records") renderRecordsTab();
      else renderImportTab();
    });
  });

  async function loadStats() {
    try {
      const stats = await api.get("/api/traffic/stats");
      state.stats = stats;
      if (!alive()) return;
      renderStats(stats);
    } catch (error) {
      if (!alive()) return;
      statsRoot.innerHTML = `<div class="callout danger">${escapeHtml(error.message)}</div>`;
    }
  }

  function renderStats(stats) {
    statsRoot.innerHTML = [
      statCard({
        label: "Total flow records",
        value: fmtInt(stats.total_records),
        iconName: "layers",
        foot: "Stored in PostgreSQL",
      }),
      statCard({
        label: "Analyzed",
        value: fmtInt(stats.analyzed),
        iconName: "cpu",
        tone: "success",
        foot: `${stats.total_records ? fmtNumber((stats.analyzed / stats.total_records) * 100, 1) : "0.0"}% coverage`,
      }),
      statCard({
        label: "Awaiting analysis",
        value: fmtInt(stats.unprocessed),
        iconName: "clock",
        tone: stats.unprocessed ? "warning" : "",
        foot: stats.unprocessed ? "Run Threat Detection" : "Pipeline is caught up",
      }),
      statCard({
        label: "Capture window",
        value: stats.earliest ? fmtDateTime(stats.earliest).split(",")[0] : "No data",
        iconName: "calendar",
        valueClass: "small",
        foot: stats.latest ? `Latest ${fmtDateTime(stats.latest)}` : "Import a dataset to begin",
      }),
    ].join("");
  }

  function renderRecordsTab() {
    content.innerHTML = `<div class="card">
      <div class="card-head">
        <div><div class="card-title">Flow records</div><div class="card-sub">Ground-truth labels, model predictions and heuristic severity are shown in separate columns</div></div>
        <span class="badge outline" id="trafficRecordCount">Loading…</span>
      </div>
      <div class="card-body">
        <div class="toolbar">
          <input class="input search" id="trafficSearch" placeholder="Search source or destination IP…" value="${escapeHtml(state.records.search)}" />
          <select class="select" id="trafficProtocol">
            <option value="">All protocols</option>
            ${["TCP", "UDP", "ICMP", "OTHER"]
              .map((value) => `<option value="${value}" ${state.records.protocol === value ? "selected" : ""}>${value}</option>`)
              .join("")}
          </select>
          <select class="select" id="trafficLabel">
            <option value="">Any ground truth</option>
            ${[
              ["BENIGN", "BENIGN only"],
              ["ATTACK", "Attack (any)"],
              ["DoS", "DoS"],
              ["PortScan", "PortScan"],
              ["BruteForce", "BruteForce"],
              ["WebAttack", "WebAttack"],
              ["Botnet", "Botnet"],
              ["Infiltration", "Infiltration"],
            ]
              .map(([value, label]) => `<option value="${value}" ${state.records.label === value ? "selected" : ""}>${label}</option>`)
              .join("")}
          </select>
          <select class="select" id="trafficSeverity">
            <option value="">Any severity</option>
            ${["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
              .map((value) => `<option value="${value}" ${state.records.severity === value ? "selected" : ""}>${value}</option>`)
              .join("")}
          </select>
          <select class="select" id="trafficAnomaly">
            <option value="">Anomaly: any</option>
            <option value="true" ${state.records.anomaly === "true" ? "selected" : ""}>Anomalies only</option>
            <option value="false" ${state.records.anomaly === "false" ? "selected" : ""}>Non-anomalies</option>
          </select>
          <select class="select" id="trafficPageSize">
            ${PAGE_SIZES.map((size) => `<option value="${size}" ${state.records.page_size === size ? "selected" : ""}>${size} / page</option>`).join("")}
          </select>
        </div>
      </div>
      <div class="table-wrap" id="trafficTable"><div class="empty-state">${icon("clock")}<strong>Loading flows…</strong></div></div>
      <div class="pagination" id="trafficPagination"></div>
    </div>`;

    const searchInput = content.querySelector("#trafficSearch");
    searchInput.addEventListener(
      "input",
      debounce(() => {
        state.records.search = searchInput.value.trim();
        state.records.page = 1;
        loadRecords();
      }, 350),
    );
    content.querySelector("#trafficProtocol").addEventListener("change", (event) => {
      state.records.protocol = event.target.value;
      state.records.page = 1;
      loadRecords();
    });
    content.querySelector("#trafficLabel").addEventListener("change", (event) => {
      state.records.label = event.target.value;
      state.records.page = 1;
      loadRecords();
    });
    content.querySelector("#trafficSeverity").addEventListener("change", (event) => {
      state.records.severity = event.target.value;
      state.records.page = 1;
      loadRecords();
    });
    content.querySelector("#trafficAnomaly").addEventListener("change", (event) => {
      state.records.anomaly = event.target.value;
      state.records.page = 1;
      loadRecords();
    });
    content.querySelector("#trafficPageSize").addEventListener("change", (event) => {
      state.records.page_size = Number(event.target.value);
      state.records.page = 1;
      loadRecords();
    });

    loadRecords();
  }

  async function loadRecords() {
    const table = content.querySelector("#trafficTable");
    if (table) table.innerHTML = `<div class="empty-state">${icon("clock")}<strong>Loading flows…</strong></div>`;
    try {
      const data = await api.get("/api/traffic/records", {
        page: state.records.page,
        page_size: state.records.page_size,
        search: state.records.search || undefined,
        protocol: state.records.protocol || undefined,
        label: state.records.label || undefined,
        severity: state.records.severity || undefined,
        anomaly: state.records.anomaly || undefined,
      });
      if (!alive() || state.tab !== "records") return;
      renderRecordTable(data);
    } catch (error) {
      if (!alive()) return;
      if (table) table.innerHTML = `<div class="empty-state">${icon("alert-circle")}<strong>Could not load flows</strong><span>${escapeHtml(error.message)}</span></div>`;
    }
  }

  function renderRecordTable(data) {
    const table = content.querySelector("#trafficTable");
    const pagination = content.querySelector("#trafficPagination");
    const count = content.querySelector("#trafficRecordCount");
    if (count) count.textContent = `${fmtInt(data.total)} records`;
    if (!table) return;
    if (!data.items?.length) {
      table.innerHTML = `<div class="empty-state">${icon("inbox")}<strong>No flows match these filters</strong><span>Adjust the filters or import a dataset.</span></div>`;
      renderPagination(pagination, data, (page) => {
        state.records.page = page;
        loadRecords();
      });
      return;
    }
    table.innerHTML = `<table class="data"><thead><tr>
      <th>Timestamp</th><th>Source</th><th>Destination</th><th>Proto</th><th>Packets</th><th>Duration</th><th>Ground truth</th><th>Prediction</th><th>Severity</th>
    </tr></thead><tbody>${data.items
      .map(
        (row) => `<tr class="clickable" data-record="${row.id}">
          <td class="mono">${escapeHtml(fmtDateTime(row.timestamp))}</td>
          <td class="mono">${escapeHtml(row.src_ip || "—")}</td>
          <td class="mono">${escapeHtml(row.dst_ip || "—")}${row.dst_port ? `<span class="dim">:${row.dst_port}</span>` : ""}</td>
          <td>${badge(row.protocol || "OTHER", "outline")}</td>
          <td class="num">${fmtInt(row.packet_count)}</td>
          <td class="num">${fmtNumber(row.flow_duration, 3)}s</td>
          <td>${row.dataset_label ? badge(row.dataset_label, row.dataset_label === "BENIGN" ? "benign" : "attack") : '<span class="dim">not provided</span>'}</td>
          <td>${labelBadge(row.predicted_label, row.is_anomaly)}</td>
          <td>${severityBadge(row.severity)}</td>
        </tr>`,
      )
      .join("")}</tbody></table>`;
    table.querySelectorAll("[data-record]").forEach((row) => {
      row.addEventListener("click", () => openRecord(Number(row.dataset.record)));
    });
    renderPagination(pagination, data, (page) => {
      state.records.page = page;
      loadRecords();
    });
  }

  async function openRecord(recordId) {
    openDrawer({
      title: `Flow record #${recordId}`,
      subtitle: "Stored flow metadata and model decision",
      body: `<div class="empty-state">${icon("clock")}<strong>Loading record…</strong></div>`,
    });
    try {
      const data = await api.get(`/api/traffic/records/${recordId}`);
      if (!alive()) return;
      const detection = data.detection;
      const explanation = detection?.explanation || {};
      const features = data.features || {};
      openDrawer({
        title: `Flow record #${data.id}`,
        subtitle: `${escapeHtml(data.src_ip || "unknown")} → ${escapeHtml(data.dst_ip || "unknown")}${data.dst_port ? `:${data.dst_port}` : ""}`,
        body: `
          <div class="drawer-section">
            <div class="drawer-section-title">Verdict</div>
            <div class="row" style="gap:8px;margin-bottom:12px">
              ${severityBadge(data.severity)}
              ${labelBadge(data.predicted_label, data.is_anomaly)}
              ${data.is_anomaly ? badge("ANOMALY", "anomaly") : ""}
            </div>
            <div class="callout info" style="font-size:11px">
              <strong>Ground truth:</strong> ${data.dataset_label ? escapeHtml(data.dataset_label) : "not provided by the dataset"}.
              This value is stored separately and is never used by the model at prediction time.<br />
              <strong>Model prediction:</strong> ${escapeHtml(data.predicted_label || "not analyzed")}
              ${detection ? `with confidence ${fmtNumber(detection.confidence, 4)}` : ""}.
              <strong>Anomaly score:</strong> ${detection ? fmtNumber(detection.anomaly_score, 4) : "—"}.
            </div>
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Flow metadata</div>
            <div class="kv-grid" style="grid-template-columns:repeat(2,minmax(0,1fr))">
              ${kv("Timestamp", escapeHtml(fmtDateTime(data.timestamp)))}
              ${kv("Protocol", escapeHtml(data.protocol || "—"))}
              ${kv("Source", `<span class="mono">${escapeHtml(data.src_ip || "—")}${data.src_port ? `:${data.src_port}` : ""}</span>`)}
              ${kv("Destination", `<span class="mono">${escapeHtml(data.dst_ip || "—")}${data.dst_port ? `:${data.dst_port}` : ""}</span>`)}
              ${kv("Packets", fmtInt(data.packet_count))}
              ${kv("Duration", `${fmtNumber(data.flow_duration, 4)} s`)}
              ${kv("Mean packet length", `${fmtNumber(data.packet_length, 2)} B`)}
              ${kv("Source", escapeHtml(data.source || "—"))}
            </div>
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Detection explanation</div>
            ${
              detection
                ? `<p class="muted" style="font-size:11.5px;line-height:1.6">${escapeHtml(explanation.summary || "No summary was recorded.")}</p>
                  <div style="margin-top:10px">${(explanation.signals || [])
                    .map(
                      (signal) => `<div class="signal">
                        <span class="signal-weight">+${fmtNumber(signal.weight, 1)}</span>
                        <div><div class="signal-rule">${escapeHtml(signal.rule)}</div><div class="signal-detail">${escapeHtml(signal.detail)}</div></div>
                      </div>`,
                    )
                    .join("") || '<div class="dim" style="font-size:11px">No heuristic signals contributed.</div>'}</div>
                  <div class="divider"></div>
                  <div class="kv-grid" style="grid-template-columns:repeat(2,minmax(0,1fr))">
                    ${kv("Predicted label", escapeHtml(explanation.model?.predicted_label || data.predicted_label || "—"))}
                    ${kv("Confidence", fmtNumber(explanation.model?.confidence ?? detection.confidence, 4))}
                    ${kv("Attack probability", fmtNumber(explanation.model?.attack_probability ?? 0, 4))}
                    ${kv("Anomaly flag", explanation.model?.is_anomaly ? "true" : "false")}
                  </div>
                  <div class="callout warning" style="margin-top:12px;font-size:10.5px">${(explanation.caveats || []).map((item) => escapeHtml(item)).join("<br />")}</div>`
                : '<div class="callout warning">This flow has not been analyzed yet. Run detection to generate a prediction.</div>'
            }
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Canonical model features</div>
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
        footer: `<button type="button" class="btn" data-close>Close</button><button type="button" class="btn primary" data-open-detection>Open detection view ${icon("chevron-right")}</button>`,
      });
      document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", closeDrawer));
      document.querySelector("[data-open-detection]")?.addEventListener("click", () => {
        closeDrawer();
        ctx.navigate("detection", { search: data.src_ip || "" });
      });
    } catch (error) {
      if (!alive()) return;
      toast("Could not load flow", error.message, "error");
    }
  }

  function renderImportTab() {
    content.innerHTML = `<div class="stack">
      <div class="card">
        <div class="card-head"><div><div class="card-title">Import a traffic dataset</div><div class="card-sub">CSV only · maximum ${fmtInt(state.schema?.max_rows || 20000)} rows and ${fmtInt(state.schema?.max_upload_mb || 50)} MB</div></div><span class="badge outline">${canImport ? "ANALYST ACCESS" : "READ ONLY"}</span></div>
        <div class="card-body">
          <label class="dropzone" id="trafficDropzone" for="trafficFile">
            ${icon("upload")}
            <strong>Drop a CSV file here or click to browse</strong>
            <span>Automatic feature detection runs first; you can override the mapping below before import.</span>
          </label>
          <input type="file" id="trafficFile" accept=".csv,text/csv" style="display:none" ${canImport ? "" : "disabled"} />
          <div id="trafficFileInfo" class="row" style="margin-top:10px"></div>
          <div id="trafficMappingPanel" class="mt-16"></div>

          <div class="row-between mt-16">
            <label class="checkbox"><input type="checkbox" id="trafficAnalyze" checked /> Run detection immediately after import</label>
            <button type="button" class="btn primary" id="trafficImportButton" disabled>${icon("upload")} Import dataset</button>
          </div>

          <div class="callout info mt-16" style="font-size:10.5px">
            <strong>Feature mapping.</strong> At least three canonical flow features must be available. Ground-truth labels are optional and are stored separately from predictions. The <span class="mono">Flow Duration</span> column used by CICIDS-style exports is automatically treated as microseconds and converted to seconds.
          </div>
        </div>
      </div>

      <div id="trafficImportResult"></div>

      <div class="card">
        <div class="card-head"><div><div class="card-title">Import history</div><div class="card-sub">Most recent dataset imports, including rejected rows and mapping metadata</div></div><span class="badge outline" id="trafficImportCount">—</span></div>
        <div class="table-wrap" id="trafficImportHistory"><div class="empty-state">${icon("clock")}<strong>Loading imports…</strong></div></div>
      </div>
    </div>`;

    const fileInput = content.querySelector("#trafficFile");
    const dropzone = content.querySelector("#trafficDropzone");
    const importButton = content.querySelector("#trafficImportButton");
    const analyze = content.querySelector("#trafficAnalyze");

    if (!canImport) {
      dropzone.style.opacity = "0.55";
      dropzone.style.cursor = "not-allowed";
      importButton.disabled = true;
      importButton.textContent = "Analyst role required";
    }

    dropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropzone.classList.add("drag");
    });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
    dropzone.addEventListener("drop", (event) => {
      event.preventDefault();
      dropzone.classList.remove("drag");
      if (!canImport) return;
      const file = event.dataTransfer?.files?.[0];
      if (file) selectFile(file);
    });
    fileInput.addEventListener("change", () => {
      if (fileInput.files?.[0]) selectFile(fileInput.files[0]);
    });

    async function selectFile(file) {
      state.selectedFile = file;
      const info = content.querySelector("#trafficFileInfo");
      const maxBytes = (state.schema?.max_upload_mb || 50) * 1024 * 1024;
      if (!file.name.toLowerCase().endsWith(".csv")) {
        state.selectedFile = null;
        info.innerHTML = `<div class="callout danger">Only .csv files are accepted.</div>`;
        importButton.disabled = true;
        return;
      }
      if (file.size > maxBytes) {
        state.selectedFile = null;
        info.innerHTML = `<div class="callout danger">The file exceeds the ${fmtInt(state.schema?.max_upload_mb || 50)} MB upload limit.</div>`;
        importButton.disabled = true;
        return;
      }
      info.innerHTML = `<span class="file-pill">${icon("file-text")} ${escapeHtml(file.name)} · ${(file.size / 1024).toFixed(1)} KB</span>`;
      try {
        state.headers = await readHeader(file);
      } catch {
        state.headers = [];
      }
      if (!alive()) return;
      state.mapping = buildAutoMapping(state.headers, state.schema);
      state.labelColumn = guessLabelColumn(state.headers);
      renderMappingPanel();
      importButton.disabled = !canImport;
    }

    function renderMappingPanel() {
      const panel = content.querySelector("#trafficMappingPanel");
      if (!state.selectedFile || !state.headers.length) {
        panel.innerHTML = "";
        importButton.disabled = true;
        return;
      }
      const canonical = state.schema?.canonical_features || [];
      const mappedCount = Object.keys(state.mapping).length;
      panel.innerHTML = `<div class="divider"></div>
        <div class="row-between">
          <div><div class="card-title">Column mapping</div><div class="card-sub">${state.headers.length} columns detected · ${mappedCount} canonical features mapped</div></div>
          <div class="row">
            <button type="button" class="btn sm" id="trafficAutoMap">${icon("rotate-ccw")} Auto-detect</button>
            <button type="button" class="btn sm" id="trafficClearMap">Clear</button>
          </div>
        </div>
        <div class="grid grid-2 mt-16">
          <div class="field">
            <label for="trafficLabelColumn">Ground-truth label column</label>
            <select class="select" id="trafficLabelColumn">
              <option value="">Auto-detect or none</option>
              ${state.headers
                .map((header) => `<option value="${escapeHtml(header)}" ${header === state.labelColumn ? "selected" : ""}>${escapeHtml(header)}</option>`)
                .join("")}
            </select>
          </div>
          <div class="field">
            <label>Mapping status</label>
            <div class="callout ${mappedCount >= 3 ? "info" : "warning"}" style="padding:8px 10px;font-size:10.5px">
              ${mappedCount >= 3 ? `${mappedCount} features mapped — ready to import.` : `${mappedCount} of 21 features mapped. At least three are required; the server can still auto-detect unmapped columns.`}
            </div>
          </div>
        </div>
        <div class="grid grid-3 mt-16" style="max-height:320px;overflow-y:auto;padding-right:4px">
          ${canonical
            .map((feature) => {
              const selected = Object.keys(state.mapping).find((source) => state.mapping[source] === feature) || "";
              return `<div class="field">
                <label class="mono" style="font-size:10px">${escapeHtml(feature)}</label>
                <select class="select" data-feature="${escapeHtml(feature)}" style="height:32px;font-size:11px">
                  <option value="">— ignore —</option>
                  ${state.headers
                    .map((header) => `<option value="${escapeHtml(header)}" ${header === selected ? "selected" : ""}>${escapeHtml(header)}</option>`)
                    .join("")}
                </select>
              </div>`;
            })
            .join("")}
        </div>`;

      panel.querySelector("#trafficLabelColumn").addEventListener("change", (event) => {
        state.labelColumn = event.target.value;
      });
      panel.querySelector("#trafficAutoMap").addEventListener("click", () => {
        state.mapping = buildAutoMapping(state.headers, state.schema);
        state.labelColumn = guessLabelColumn(state.headers);
        renderMappingPanel();
      });
      panel.querySelector("#trafficClearMap").addEventListener("click", () => {
        state.mapping = {};
        renderMappingPanel();
      });
      panel.querySelectorAll("[data-feature]").forEach((select) => {
        select.addEventListener("change", () => {
          const feature = select.dataset.feature;
          Object.keys(state.mapping).forEach((source) => {
            if (state.mapping[source] === feature) delete state.mapping[source];
          });
          if (select.value) state.mapping[select.value] = feature;
          renderMappingPanel();
        });
      });
    }

    importButton.addEventListener("click", async () => {
      if (!state.selectedFile || state.busy) return;
      state.busy = true;
      setBusy(importButton, true, "Importing…");
      const resultRoot = content.querySelector("#trafficImportResult");
      resultRoot.innerHTML = `<div class="card"><div class="card-body"><div class="row"><span class="spinner" style="border-color:rgba(59,130,246,.3);border-top-color:#3b82f6"></span><span class="muted">Parsing rows, storing flows and running detection…</span></div></div></div>`;
      try {
        const form = new FormData();
        form.append("file", state.selectedFile, state.selectedFile.name);
        if (Object.keys(state.mapping).length) {
          const scales = {};
          Object.entries(state.mapping).forEach(([source, canonical]) => {
            if (canonical === "flow_duration" && normalize(source) === "flow duration") scales[source] = 0.000001;
          });
          form.append("mapping", JSON.stringify({ column_map: state.mapping, scales }));
        }
        if (state.labelColumn) form.append("label_column", state.labelColumn);
        form.append("analyze", analyze.checked ? "true" : "false");
        const result = await api.request("/api/traffic/import", { method: "POST", body: form });
        if (!alive()) return;
        renderImportResult(result);
        toast("Dataset imported", `${fmtInt(result.analysis?.accepted)} flows accepted.`, "success");
        state.selectedFile = null;
        state.headers = [];
        state.mapping = {};
        content.querySelector("#trafficFileInfo").innerHTML = "";
        content.querySelector("#trafficMappingPanel").innerHTML = "";
        importButton.disabled = true;
        const fileField = content.querySelector("#trafficFile");
        if (fileField) fileField.value = "";
        await loadStats();
        await loadImports();
      } catch (error) {
        if (!alive()) return;
        resultRoot.innerHTML = `<div class="card card-pad"><div class="callout danger"><strong>Import failed.</strong><br />${escapeHtml(error.message)}</div></div>`;
        toast("Import failed", error.message, "error");
        importButton.disabled = false;
      } finally {
        state.busy = false;
        setBusy(importButton, false);
        if (state.selectedFile && alive()) importButton.disabled = false;
      }
    });

    loadImports();
  }

  function renderImportResult(result) {
    const root = content.querySelector("#trafficImportResult");
    if (!root) return;
    const analysis = result.analysis || {};
    const detection = analysis.detection;
    const warnings = result.warnings || [];
    const labels = analysis.label_distribution || {};
    const protocols = analysis.protocol_distribution || {};
    root.innerHTML = `<div class="card">
      <div class="card-head"><div><div class="card-title">Import complete</div><div class="card-sub">${escapeHtml(result.dataset?.original_name || "Dataset")} · ${fmtInt(result.dataset?.accepted_rows)} accepted rows</div></div>${badge("COMPLETED", "resolved")}</div>
      <div class="card-body">
        <div class="grid grid-4">
          ${[
            ["Source rows", fmtInt(analysis.source_rows)],
            ["Accepted", fmtInt(analysis.accepted)],
            ["Rejected", fmtInt(analysis.rejected)],
            ["Mapped features", fmtInt(Object.keys(result.detected_columns || {}).length)],
          ]
            .map(
              ([label, value]) => `<div class="metric-tile"><div class="m-label">${label}</div><div class="m-value">${value}</div></div>`,
            )
            .join("")}
        </div>

        ${
          warnings.length
            ? `<div class="callout warning mt-16"><strong>Warnings</strong><br />${warnings.map((item) => escapeHtml(item)).join("<br />")}</div>`
            : ""
        }

        <div class="grid grid-2 mt-16">
          <div>
            <div class="drawer-section-title">Ground-truth labels in the file</div>
            ${
              Object.keys(labels).length
                ? `<div class="row">${Object.entries(labels)
                    .map(([label, count]) => `<span class="badge ${label === "BENIGN" ? "benign" : "attack"}">${escapeHtml(label)} · ${fmtInt(count)}</span>`)
                    .join("")}</div>`
                : '<div class="dim" style="font-size:11px">No label column was detected. Supervised evaluation is unavailable for this import.</div>'
            }
            <div class="drawer-section-title mt-16">Detected protocol mix</div>
            <div class="row">${Object.entries(protocols)
              .map(([protocol, count]) => `<span class="badge outline">${escapeHtml(protocol)} · ${fmtInt(count)}</span>`)
              .join("")}</div>
          </div>
          <div>
            <div class="drawer-section-title">Detection outcome</div>
            ${
              detection
                ? `<div class="grid grid-2">
                    ${[
                      ["Processed", fmtInt(detection.processed)],
                      ["Predicted attacks", fmtInt(detection.attacks)],
                      ["Anomalies", fmtInt(detection.anomalies)],
                      ["Incidents created", fmtInt(detection.incidents_created)],
                    ]
                      .map(
                        ([label, value]) => `<div class="status-tile"><div class="s-label">${label}</div><div class="s-value">${value}</div></div>`,
                      )
                      .join("")}
                  </div>
                  <div class="dim" style="font-size:10.5px;margin-top:8px">Scored in ${fmtNumber(detection.duration_seconds, 2)}s by ${escapeHtml(detection.model)} + ${escapeHtml(detection.anomaly_model)}.</div>`
                : '<div class="callout warning">Detection did not run for this import.</div>'
            }
          </div>
        </div>

        <div class="divider"></div>
        <div class="drawer-section-title">Detected column mapping</div>
        <div class="table-wrap"><table class="data"><thead><tr><th>Source column</th><th>Canonical feature</th></tr></thead><tbody>
          ${Object.entries(result.detected_columns || {})
            .map(
              ([source, target]) =>
                `<tr><td class="mono">${escapeHtml(source)}</td><td class="mono" style="color:#93c5fd">${escapeHtml(target)}</td></tr>`,
            )
            .join("") || '<tr><td class="empty-cell" colspan="2">No canonical features were mapped.</td></tr>'}
        </tbody></table></div>
        <div class="callout info" style="font-size:10.5px;margin-top:12px">Rows are now available in Flow Records. Dataset labels are ground truth from the file; predictions are generated independently by the active models.</div>
      </div>
    </div>`;
  }

  async function loadImports() {
    const history = content.querySelector("#trafficImportHistory");
    if (!history) return;
    try {
      const data = await api.get("/api/traffic/imports");
      if (!alive()) return;
      state.imports = data || [];
      const count = content.querySelector("#trafficImportCount");
      if (count) count.textContent = `${fmtInt(state.imports.length)} imports`;
      if (!state.imports.length) {
        history.innerHTML = `<div class="empty-state">${icon("file-text")}<strong>No imports yet</strong><span>Upload a CSV to create the first dataset import.</span></div>`;
        return;
      }
      history.innerHTML = `<table class="data"><thead><tr><th>Dataset</th><th>Rows</th><th>Accepted</th><th>Rejected</th><th>Status</th><th>Label column</th><th>Imported</th></tr></thead><tbody>${state.imports
        .map(
          (row) => `<tr>
            <td><div style="max-width:240px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(row.original_name)}</div><div class="dim mono" style="font-size:9.5px">${escapeHtml(row.sha256.slice(0, 16))}…</div></td>
            <td class="num">${fmtInt(row.row_count)}</td>
            <td class="num text-success">${fmtInt(row.accepted_rows)}</td>
            <td class="num ${row.rejected_rows ? "text-critical" : ""}">${fmtInt(row.rejected_rows)}</td>
            <td>${badge(
              row.status.toUpperCase(),
              row.status === "completed" ? "resolved" : row.status === "failed" ? "critical" : "new",
            )}</td>
            <td class="mono" style="font-size:10.5px">${escapeHtml(row.label_column || "—")}</td>
            <td class="mono">${escapeHtml(fmtDateTime(row.created_at))}</td>
          </tr>`,
        )
        .join("")}</tbody></table>`;
    } catch (error) {
      if (!alive()) return;
      history.innerHTML = `<div class="empty-state">${icon("alert-circle")}<strong>Import history unavailable</strong><span>${escapeHtml(error.message)}</span></div>`;
    }
  }

  async function ensureSchema() {
    if (state.schema) return;
    try {
      state.schema = await api.get("/api/traffic/schema");
    } catch {
      state.schema = { canonical_features: [], aliases: {}, max_rows: 20000, max_upload_mb: 50 };
    }
  }

  refreshButton.addEventListener("click", async () => {
    refreshButton.disabled = true;
    try {
      await loadStats();
      if (state.tab === "records") await loadRecords();
      else {
        await loadImports();
        toast("Import view refreshed", "Import history is up to date.", "success");
      }
    } finally {
      refreshButton.disabled = false;
    }
  });

  await loadStats();
  await ensureSchema();
  if (alive()) renderRecordsTab();

  return () => {
    /* no background timers */
  };
}
