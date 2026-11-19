import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  badge,
  classificationBadge,
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
  riskBar,
  setBusy,
  severityBadge,
  statCard,
  timeAgo,
  toast,
} from "../ui.js";

const CLASSIFICATIONS = ["OBSERVED", "WATCHLIST", "SUSPICIOUS", "HIGH_RISK", "MONITORED_DESTINATION"];

const state = {
  page: 1,
  page_size: 25,
  search: "",
  direction: "",
  classification: "",
  min_risk: "",
  private: "",
};

export async function mount(container, ctx) {
  const canEdit = ["admin", "analyst"].includes(ctx.user?.role);
  state.page = 1;
  state.page_size = 25;
  state.search = ctx.params.get("search") || "";
  state.direction = "";
  state.classification = "";
  state.min_risk = "";
  state.private = "";
  const alive = () => container.isConnected;

  container.innerHTML = `${pageHead({
    title: "Suspicious IP intelligence",
    description:
      "Source and destination addresses observed in tracked events. Risk is a transparent heuristic built from severity, anomaly frequency, event volume and recency.",
    actions: `<button type="button" class="btn" id="ipsRefresh">${icon("refresh")} Refresh</button>`,
  })}<div id="ipsStats" class="stat-grid"></div>
  <div class="card">
    <div class="card-head">
      <div><div class="card-title">Tracked addresses</div><div class="card-sub">Risk scores are operational indicators, not reputation feeds or probabilities</div></div>
      <span class="badge outline" id="ipsCount">Loading…</span>
    </div>
    <div class="card-body">
      <div class="toolbar">
        <input class="input search" id="ipsSearch" value="${escapeHtml(state.search)}" placeholder="Search IP address…" />
        <select class="select" id="ipsDirection">
          <option value="">Any direction</option>
          <option value="source">Source</option>
          <option value="destination">Destination</option>
          <option value="both">Both</option>
        </select>
        <select class="select" id="ipsClassification">
          <option value="">Any classification</option>
          ${CLASSIFICATIONS.map((value) => `<option value="${value}">${value.replace(/_/g, " ")}</option>`).join("")}
        </select>
        <select class="select" id="ipsRisk">
          <option value="">Any risk</option>
          <option value="75">Risk ≥ 75</option>
          <option value="50">Risk ≥ 50</option>
          <option value="25">Risk ≥ 25</option>
        </select>
        <select class="select" id="ipsPrivate">
          <option value="">Any exposure</option>
          <option value="false">Public only</option>
          <option value="true">Private only</option>
        </select>
        <select class="select" id="ipsPageSize">
          ${[25, 50, 100].map((size) => `<option value="${size}">${size} / page</option>`).join("")}
        </select>
      </div>
    </div>
    <div class="table-wrap" id="ipsTable"><div class="empty-state">${icon("clock")}<strong>Loading addresses…</strong></div></div>
    <div class="pagination" id="ipsPagination"></div>
  </div>`;

  const statsRoot = container.querySelector("#ipsStats");
  const tableRoot = container.querySelector("#ipsTable");
  const refreshButton = container.querySelector("#ipsRefresh");

  const searchInput = container.querySelector("#ipsSearch");
  searchInput.addEventListener(
    "input",
    debounce(() => {
      state.search = searchInput.value.trim();
      state.page = 1;
      loadTable();
    }, 350),
  );
  const bindSelect = (id, key, numeric = false) => {
    container.querySelector(id).addEventListener("change", (event) => {
      state[key] = numeric ? event.target.value : event.target.value;
      state.page = 1;
      loadTable();
    });
  };
  bindSelect("#ipsDirection", "direction");
  bindSelect("#ipsClassification", "classification");
  bindSelect("#ipsRisk", "min_risk");
  bindSelect("#ipsPrivate", "private");
  container.querySelector("#ipsPageSize").addEventListener("change", (event) => {
    state.page_size = Number(event.target.value);
    state.page = 1;
    loadTable();
  });

  async function loadStats() {
    const queries = [
      { key: "total", params: {} },
      { key: "high", params: { min_risk: 75 } },
      { key: "suspicious", params: { classification: "SUSPICIOUS" } },
      { key: "watchlist", params: { classification: "WATCHLIST" } },
      { key: "public", params: { private: false } },
      { key: "private", params: { private: true } },
    ];
    try {
      const results = await Promise.all(
        queries.map((query) => api.get("/api/ips", { page: 1, page_size: 1, ...query.params })),
      );
      if (!alive()) return;
      const totals = Object.fromEntries(results.map((data, index) => [queries[index].key, Number(data.total) || 0]));
      statsRoot.innerHTML = [
        statCard({
          label: "Tracked IPs",
          value: fmtInt(totals.total),
          iconName: "globe",
          foot: "Appearing in tracked events",
        }),
        statCard({
          label: "High risk",
          value: fmtInt(totals.high),
          iconName: "shield-alert",
          tone: "critical",
          foot: "Heuristic risk ≥ 75",
        }),
        statCard({
          label: "Suspicious class",
          value: fmtInt(totals.suspicious),
          iconName: "alert-triangle",
          tone: "warning",
          foot: "Risk between 50 and 74.9",
        }),
        statCard({
          label: "Watchlist",
          value: fmtInt(totals.watchlist),
          iconName: "eye",
          tone: "purple",
          foot: "Risk between 25 and 49.9",
        }),
        statCard({
          label: "Public exposure",
          value: fmtInt(totals.public),
          iconName: "wifi",
          foot: "Routable, non-private addresses",
        }),
        statCard({
          label: "Internal addresses",
          value: fmtInt(totals.private),
          iconName: "server",
          tone: "success",
          foot: "Private or reserved ranges",
        }),
      ].join("");
    } catch (error) {
      if (!alive()) return;
      statsRoot.innerHTML = `<div class="callout danger">${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadTable() {
    tableRoot.innerHTML = `<div class="empty-state">${icon("clock")}<strong>Loading addresses…</strong></div>`;
    try {
      const data = await api.get("/api/ips", {
        page: state.page,
        page_size: state.page_size,
        search: state.search || undefined,
        direction: state.direction || undefined,
        classification: state.classification || undefined,
        min_risk: state.min_risk || undefined,
        private: state.private || undefined,
      });
      if (!alive()) return;
      const count = container.querySelector("#ipsCount");
      if (count) count.textContent = `${fmtInt(data.total)} addresses`;
      if (!data.items?.length) {
        tableRoot.innerHTML = `<div class="empty-state">${icon("globe")}<strong>No tracked addresses match</strong><span>Adjust filters or analyze more traffic.</span></div>`;
      } else {
        tableRoot.innerHTML = `<table class="data"><thead><tr>
          <th>Address</th><th>Direction</th><th>Exposure</th><th>Classification</th><th>Risk</th><th>Events</th><th>Anomalies</th><th>Incidents</th><th>Max severity</th><th>Top prediction</th><th>Last seen</th>
        </tr></thead><tbody>${data.items
          .map(
            (row) => `<tr class="clickable" data-ip="${row.id}">
              <td><div class="ip-cell"><span class="mono">${escapeHtml(row.ip_address)}</span></div></td>
              <td>${badge(row.direction, "outline")}</td>
              <td>${row.is_private ? badge("PRIVATE", "private") : badge("PUBLIC", "public")}</td>
              <td>${classificationBadge(row.classification)}</td>
              <td>${riskBar(row.risk_score)}</td>
              <td class="num">${fmtInt(row.event_count)}</td>
              <td class="num">${fmtInt(row.anomaly_count)}</td>
              <td class="num">${fmtInt(row.incident_count)}</td>
              <td>${severityBadge(row.max_severity)}</td>
              <td>${row.top_prediction ? labelBadge(row.top_prediction) : '<span class="dim">—</span>'}</td>
              <td class="mono">${escapeHtml(timeAgo(row.last_seen))}</td>
            </tr>`,
          )
          .join("")}</tbody></table>`;
        tableRoot.querySelectorAll("[data-ip]").forEach((row) => {
          row.addEventListener("click", () => openIp(Number(row.dataset.ip)));
        });
      }
      renderPagination(container.querySelector("#ipsPagination"), data, (page) => {
        state.page = page;
        loadTable();
      });
    } catch (error) {
      if (!alive()) return;
      tableRoot.innerHTML = `<div class="empty-state">${icon("alert-circle")}<strong>Could not load addresses</strong><span>${escapeHtml(error.message)}</span></div>`;
    }
  }

  async function openIp(ipId) {
    openDrawer({
      title: "IP intelligence",
      subtitle: "Tracked address detail",
      body: `<div class="empty-state">${icon("clock")}<strong>Loading address…</strong></div>`,
    });
    try {
      const data = await api.get(`/api/ips/${ipId}`);
      if (!alive()) return;
      const editable = canEdit && data.direction !== "destination";
      openDrawer({
        title: `<span class="mono">${escapeHtml(data.ip_address)}</span>`,
        subtitle: `${data.is_private ? "Private" : "Public"} address · ${data.direction} direction`,
        body: `
          <div class="drawer-section">
            <div class="row" style="gap:8px;margin-bottom:12px">${classificationBadge(data.classification)}${severityBadge(data.max_severity)}${data.is_private ? badge("PRIVATE", "private") : badge("PUBLIC", "public")}</div>
            <div class="row-between"><span class="muted" style="font-size:11px">Risk indicator</span><span class="mono" style="font-size:13px">${fmtNumber(data.risk_score, 1)} / 100</span></div>
            <div class="mt-12">${riskBar(data.risk_score)}</div>
            <div class="callout info mt-16" style="font-size:10.5px">${escapeHtml(data.risk_model)}</div>
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Observed activity</div>
            <div class="kv-grid" style="grid-template-columns:repeat(2,minmax(0,1fr))">
              ${kv("Events", fmtInt(data.event_count))}
              ${kv("Anomalies", fmtInt(data.anomaly_count))}
              ${kv("Incidents", fmtInt(data.incident_count))}
              ${kv("Top prediction", data.top_prediction ? escapeHtml(data.top_prediction) : "—")}
              ${kv("First seen", escapeHtml(fmtDateTime(data.first_seen)))}
              ${kv("Last seen", escapeHtml(fmtDateTime(data.last_seen)))}
            </div>
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Related incidents</div>
            ${
              data.related_incidents?.length
                ? `<div style="border:1px solid var(--border-soft);border-radius:8px;overflow:hidden">${data.related_incidents
                    .map(
                      (incident) => `<div class="incident-row" data-related-incident="${incident.id}" style="padding:10px 12px">
                        <div class="sev-bar ${escapeHtml(incident.severity)}"></div>
                        <div class="incident-main"><div class="incident-title">${escapeHtml(incident.title)}</div><div class="incident-meta"><span class="mono">${escapeHtml(incident.incident_code)}</span><span>${timeAgo(incident.created_at)}</span></div></div>
                        ${severityBadge(incident.severity)}
                      </div>`,
                    )
                    .join("")}</div>`
                : '<div class="dim" style="font-size:11px">No incidents are linked to this source address.</div>'
            }
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Recent activity</div>
            ${
              data.recent_activity?.length
                ? `<div class="table-wrap"><table class="data"><thead><tr><th>Time</th><th>Destination</th><th>Prediction</th><th>Severity</th></tr></thead><tbody>${data.recent_activity
                    .map(
                      (item) => `<tr>
                        <td class="mono">${escapeHtml(fmtDateTime(item.timestamp))}</td>
                        <td class="mono">${escapeHtml(item.dst_ip || "—")}${item.dst_port ? `:${item.dst_port}` : ""}</td>
                        <td>${labelBadge(item.predicted_label, item.is_anomaly)}</td>
                        <td>${severityBadge(item.severity)}</td>
                      </tr>`,
                    )
                    .join("")}</tbody></table></div>`
                : '<div class="dim" style="font-size:11px">No recent flow activity.</div>'
            }
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Analyst notes</div>
            ${
              canEdit
                ? `<div class="stack">
                    <div class="field"><label for="ipClassification">Classification</label>
                      <select class="select" id="ipClassification" ${editable ? "" : "disabled"}>
                        ${CLASSIFICATIONS.map(
                          (value) => `<option value="${value}" ${value === data.classification ? "selected" : ""}>${value.replace(/_/g, " ")}</option>`,
                        ).join("")}
                      </select>
                      ${editable ? "" : '<span class="dim" style="font-size:10px">Destination-direction addresses are managed by the pipeline.</span>'}
                    </div>
                    <div class="field"><label for="ipNotes">Notes</label><textarea class="textarea" id="ipNotes" maxlength="5000" placeholder="Investigation context, blocklist ticket reference, false-positive rationale…">${escapeHtml(data.notes || "")}</textarea></div>
                  </div>`
                : `<div class="callout">${data.notes ? escapeHtml(data.notes) : "No analyst notes recorded."}</div>`
            }
          </div>`,
        footer: canEdit
          ? `<button type="button" class="btn" data-close>Close</button><button type="button" class="btn primary" data-save>${icon("check")} Save changes</button>`
          : `<button type="button" class="btn" data-close>Close</button>`,
      });

      document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", closeDrawer));
      document.querySelectorAll("[data-related-incident]").forEach((row) => {
        row.addEventListener("click", () => {
          closeDrawer();
          ctx.navigate("incidents", { focus: row.dataset.relatedIncident });
        });
      });
      document.querySelector("[data-save]")?.addEventListener("click", async (event) => {
        const button = event.currentTarget;
        setBusy(button, true, "Saving…");
        try {
          const payload = { notes: document.querySelector("#ipNotes").value };
          if (editable) payload.classification = document.querySelector("#ipClassification").value;
          await api.patch(`/api/ips/${ipId}`, payload);
          toast("IP record updated", "Classification and notes were saved.", "success");
          closeDrawer();
          await Promise.all([loadTable(), loadStats()]);
        } catch (error) {
          toast("Could not save", error.message, "error");
          setBusy(button, false);
        }
      });
    } catch (error) {
      if (!alive()) return;
      toast("Could not load address", error.message, "error");
    }
  }

  refreshButton.addEventListener("click", async () => {
    refreshButton.disabled = true;
    try {
      await Promise.all([loadStats(), loadTable()]);
    } finally {
      refreshButton.disabled = false;
    }
  });

  await Promise.all([loadStats(), loadTable()]);

  return () => {
    /* no background work */
  };
}
