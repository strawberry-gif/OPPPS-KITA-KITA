import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  badge,
  escapeHtml,
  fmtDateTime,
  fmtInt,
  fmtNumber,
  pageHead,
  setBusy,
  severityBadge,
  statCard,
  timeAgo,
  toast,
} from "../ui.js";

export async function mount(container, ctx) {
  const canOperate = ["admin", "analyst"].includes(ctx.user?.role);
  let pollTimer = null;
  let lastStatus = null;
  let interfaces = [];
  let liveTotal = 0;
  let busy = false;

  container.innerHTML = `${pageHead({
    title: "Live network monitoring",
    description:
      "Optional passive flow capture. Packets are aggregated into metadata-only flow records; payloads are never stored.",
    actions: `<span id="monStatusBadge">${badge("Checking", "outline")}</span><button type="button" class="btn" id="monRefresh">${icon("refresh")} Refresh</button>`,
  })}
  <div id="monStatusTiles" class="stat-grid"></div>
  <div class="grid grid-main">
    <div class="card">
      <div class="card-head"><div><div class="card-title">Capture control</div><div class="card-sub">Requires Npcap and an elevated (Administrator) server process on Windows</div></div></div>
      <div class="card-body">
        <div class="grid grid-2">
          <div class="field">
            <label for="monInterface">Network interface</label>
            <select class="select" id="monInterface"><option value="">Auto-detect default interface</option></select>
          </div>
          <div class="field">
            <label for="monBpf">BPF filter (optional)</label>
            <input class="input" id="monBpf" placeholder="tcp port 443 or host 10.0.0.5" maxlength="200" />
          </div>
        </div>
        <div class="row mt-16">
          <button type="button" class="btn primary" id="monStart">${icon("play")} Start capture</button>
          <button type="button" class="btn danger" id="monStop">${icon("square")} Stop capture</button>
          <span class="spacer"></span>
          <span class="dim" style="font-size:10.5px">Flush interval: <span id="monFlush">—</span>s</span>
        </div>
        <div id="monControlNote" class="callout mt-16"></div>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><div><div class="card-title">Engine detail</div><div class="card-sub">State of the passive sniffer</div></div></div>
      <div class="card-body" id="monEngine"></div>
    </div>
  </div>

  <div class="card mt-16">
    <div class="card-head">
      <div><div class="card-title">Recent captured flows</div><div class="card-sub">Metadata aggregated from live packets and analyzed on flush</div></div>
      <span class="badge outline" id="monLiveCount">—</span>
    </div>
    <div class="table-wrap" id="monFeed"></div>
  </div>

  <div class="grid grid-2 mt-16">
    <div class="callout info">
      <strong>How passive capture works.</strong> Packets are grouped into bidirectional flows in memory. Every flush interval the flows are written to PostgreSQL and the detection pipeline scores them. Only packet metadata (addresses, ports, flags, byte and packet counters) is retained.
    </div>
    <div class="callout warning">
      <strong>Operational requirements.</strong> Passive capture needs Npcap, an elevated process, and a host interface that actually sees the traffic. If capture is unavailable, the CSV import pipeline remains fully functional and uses the same detection engine.
    </div>
  </div>`;

  const tiles = container.querySelector("#monStatusTiles");
  const engine = container.querySelector("#monEngine");
  const controlNote = container.querySelector("#monControlNote");
  const statusBadge = container.querySelector("#monStatusBadge");
  const interfaceSelect = container.querySelector("#monInterface");
  const bpfInput = container.querySelector("#monBpf");
  const startButton = container.querySelector("#monStart");
  const stopButton = container.querySelector("#monStop");
  const refreshButton = container.querySelector("#monRefresh");
  const feed = container.querySelector("#monFeed");
  const liveCount = container.querySelector("#monLiveCount");
  const alive = () => container.isConnected;

  startButton.disabled = !canOperate;
  stopButton.disabled = !canOperate;
  if (!canOperate) {
    controlNote.className = "callout warning mt-16";
    controlNote.innerHTML =
      "<strong>Read-only role.</strong> Starting or stopping passive capture requires the analyst or administrator role.";
  }

  function renderTiles(status) {
    const running = Boolean(status?.running);
    const available = Boolean(status?.available);
    tiles.innerHTML = [
      statCard({
        label: "Capture engine",
        value: available ? "Available" : "Unavailable",
        iconName: "radio",
        tone: available ? "success" : "critical",
        valueClass: "small",
        foot: status?.scapy_available ? "Scapy detected" : "Scapy not installed",
      }),
      statCard({
        label: "Capture state",
        value: running ? "Running" : "Stopped",
        iconName: running ? "activity" : "square",
        tone: running ? "success" : "",
        valueClass: "small",
        foot: running ? `Started ${timeAgo(status.started_at)}` : "Idle",
      }),
      statCard({
        label: "Packets observed",
        value: fmtInt(status?.packets_seen),
        iconName: "zap",
        foot: `${fmtInt(status?.flows_buffered)} flows buffered`,
      }),
      statCard({
        label: "Flows flushed",
        value: fmtInt(status?.flows_flushed),
        iconName: "layers",
        tone: "purple",
        foot: `${fmtInt(status?.records_created)} records created`,
      }),
    ].join("");
  }

  function renderEngine(status) {
    if (!status) {
      engine.innerHTML = '<div class="callout danger">Capture status is unavailable.</div>';
      return;
    }
    const rows = [
      ["Availability", status.available ? badge("READY", "resolved") : badge("DISABLED", "critical")],
      ["Scapy", status.scapy_available ? badge("LOADED", "resolved") : badge("MISSING", "critical")],
      ["Interface", status.interface ? `<span class="mono">${escapeHtml(status.interface)}</span>` : '<span class="dim">auto / default</span>'],
      ["BPF filter", status.bpf_filter ? `<span class="mono">${escapeHtml(status.bpf_filter)}</span>` : '<span class="dim">none</span>'],
      ["Started", status.started_at ? escapeHtml(fmtDateTime(status.started_at)) : '<span class="dim">—</span>'],
      ["Last flush", status.last_flush_at ? escapeHtml(fmtDateTime(status.last_flush_at)) : '<span class="dim">—</span>'],
      ["Flush interval", `${fmtNumber(status.flush_seconds, 0)} s`],
      ["Last error", status.last_error ? `<span class="text-critical">${escapeHtml(status.last_error)}</span>` : '<span class="dim">none reported</span>'],
    ];
    engine.innerHTML = `<div class="kv-grid" style="grid-template-columns:repeat(2,minmax(0,1fr))">${rows
      .map(
        ([label, value]) =>
          `<div class="kv"><div class="k">${label}</div><div class="v">${value}</div></div>`,
      )
      .join("")}</div>
      <div class="divider"></div>
      <div class="callout ${status.available ? "info" : "warning"}" style="font-size:10.5px">${escapeHtml(
        status.permissions_note || "Passive capture runs locally on the server host.",
      )}${status.scapy_error ? `<br /><strong>Scapy detail:</strong> ${escapeHtml(status.scapy_error)}` : ""}</div>`;
  }

  function applyStatus(status) {
    lastStatus = status;
    renderTiles(status);
    renderEngine(status);
    statusBadge.innerHTML = status.running
      ? badge("CAPTURING", "resolved")
      : status.available
        ? badge("IDLE", "outline")
        : badge("UNAVAILABLE", "critical");
    container.querySelector("#monFlush").textContent = fmtNumber(status.flush_seconds, 0);
    startButton.disabled = !canOperate || busy || status.running || !status.available;
    stopButton.disabled = !canOperate || busy || !status.running;
    if (!canOperate) return;
    if (!status.scapy_available) {
      controlNote.className = "callout warning mt-16";
      controlNote.innerHTML = `<strong>Scapy is not available.</strong> ${escapeHtml(status.scapy_error || "Install scapy and Npcap to enable passive capture.")}`;
    } else if (!status.available) {
      controlNote.className = "callout warning mt-16";
      controlNote.innerHTML =
        "<strong>Live capture is disabled by configuration.</strong> Set <span class=\"mono\">LIVE_CAPTURE_ENABLED=true</span> to enable it.";
    } else if (status.running) {
      controlNote.className = "callout info mt-16";
      controlNote.innerHTML =
        "<strong>Capture is active.</strong> Keep this page open to observe flush activity. Stopping capture flushes any buffered flows.";
    } else {
      controlNote.className = "callout info mt-16";
      controlNote.innerHTML =
        "<strong>Ready to capture.</strong> Leave the interface on auto-detect unless the host has multiple adapters. Use a BPF filter to limit volume.";
    }
  }

  function renderInterfaces(payload) {
    interfaces = payload?.interfaces || [];
    interfaceSelect.innerHTML = `<option value="">Auto-detect default interface</option>${interfaces
      .map((item) => {
        const detail = [item.description, ...(item.addresses || [])].filter(Boolean).join(" · ");
        return `<option value="${escapeHtml(item.name)}">${escapeHtml(item.name)}${detail ? ` — ${escapeHtml(detail)}` : ""}</option>`;
      })
      .join("")}`;
  }

  function renderFeed(payload) {
    const items = payload?.items || [];
    liveTotal = Number(payload?.total) || 0;
    liveCount.textContent = `${fmtInt(liveTotal)} stored`;
    if (!items.length) {
      feed.innerHTML = `<div class="empty-state">${icon("wifi")}<strong>No live flows captured yet</strong><span>Start passive capture, or import a CSV from Traffic Analysis.</span></div>`;
      return;
    }
    feed.innerHTML = `<table class="data"><thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Duration</th><th>Prediction</th><th>Severity</th></tr></thead><tbody>${items
      .map(
        (row) => `<tr>
          <td class="mono">${escapeHtml(fmtDateTime(row.timestamp))}</td>
          <td class="mono">${escapeHtml(row.src_ip || "—")}</td>
          <td class="mono">${escapeHtml(row.dst_ip || "—")}${row.dst_port ? `:${row.dst_port}` : ""}</td>
          <td>${badge(row.protocol || "OTHER", "outline")}</td>
          <td class="num">${fmtInt(row.packet_count)}</td>
          <td class="num">${fmtNumber(row.flow_duration, 3)}s</td>
          <td>${row.predicted_label ? badge(row.predicted_label, row.predicted_label === "BENIGN" ? "benign" : "attack") : '<span class="dim">pending</span>'}</td>
          <td>${severityBadge(row.severity)}</td>
        </tr>`,
      )
      .join("")}</tbody></table>`;
  }

  async function loadAll() {
    refreshButton.disabled = true;
    try {
      const [statusResult, interfacesResult, feedResult] = await Promise.allSettled([
        api.get("/api/monitoring/status"),
        api.get("/api/monitoring/interfaces"),
        api.get("/api/traffic/records", { source: "live", page: 1, page_size: 8 }),
      ]);
      if (!alive()) return;
      if (statusResult.status === "fulfilled") applyStatus(statusResult.value);
      else {
        tiles.innerHTML = `<div class="callout danger">${escapeHtml(statusResult.reason?.message || "Unable to read capture status.")}</div>`;
        engine.innerHTML = "";
      }
      if (interfacesResult.status === "fulfilled") renderInterfaces(interfacesResult.value);
      if (feedResult.status === "fulfilled") renderFeed(feedResult.value);
      else {
        feed.innerHTML = `<div class="empty-state">${icon("alert-circle")}<strong>Capture feed unavailable</strong><span>${escapeHtml(feedResult.reason?.message || "Unable to query live flows.")}</span></div>`;
      }
    } finally {
      if (alive()) refreshButton.disabled = false;
    }
  }

  async function poll() {
    try {
      const status = await api.get("/api/monitoring/status");
      if (!alive()) return;
      applyStatus(status);
    } catch {
      /* transient polling failure; next tick retries */
    }
  }

  startButton.addEventListener("click", async () => {
    if (!canOperate || busy) return;
    busy = true;
    setBusy(startButton, true, "Starting…");
    try {
      await api.post("/api/monitoring/start", undefined, {
        interface: interfaceSelect.value || undefined,
        bpf_filter: bpfInput.value.trim() || undefined,
      });
      toast("Capture started", "Passive metadata collection is active.", "success");
      await poll();
      const feedResult = await api.get("/api/traffic/records", { source: "live", page: 1, page_size: 8 });
      if (alive()) renderFeed(feedResult);
    } catch (error) {
      toast("Could not start capture", error.message, "error");
    } finally {
      busy = false;
      setBusy(startButton, false);
      if (lastStatus && alive()) applyStatus(lastStatus);
    }
  });

  stopButton.addEventListener("click", async () => {
    if (!canOperate || busy) return;
    busy = true;
    setBusy(stopButton, true, "Stopping…");
    try {
      const status = await api.post("/api/monitoring/stop");
      if (alive()) applyStatus(status);
      toast("Capture stopped", "Buffered flows were flushed and analyzed.", "success");
    } catch (error) {
      toast("Could not stop capture", error.message, "error");
    } finally {
      busy = false;
      setBusy(stopButton, false);
      if (lastStatus && alive()) applyStatus(lastStatus);
    }
  });

  refreshButton.addEventListener("click", loadAll);

  await loadAll();
  pollTimer = window.setInterval(poll, 5000);

  return () => {
    if (pollTimer) window.clearInterval(pollTimer);
  };
}
