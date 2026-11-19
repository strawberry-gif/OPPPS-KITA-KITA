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
  kv,
  labelBadge,
  openDrawer,
  pageHead,
  renderPagination,
  setBusy,
  severityBadge,
  statCard,
  statusBadge,
  timeAgo,
  toast,
} from "../ui.js";

const STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];

const state = {
  page: 1,
  page_size: 25,
  status: "",
  severity: "",
  search: "",
  requireNotes: false,
};

export async function mount(container, ctx) {
  const canEdit = ["admin", "analyst"].includes(ctx.user?.role);
  state.page = 1;
  state.page_size = 25;
  state.status = "";
  state.severity = "";
  state.search = "";
  const alive = () => container.isConnected;
  let focusId = ctx.params.get("focus");

  container.innerHTML = `${pageHead({
    title: "Security incidents",
    description:
      "Response queue generated from detections that crossed the configured severity threshold. Triage, assign, annotate and close.",
    actions: `<button type="button" class="btn" id="incidentsRefresh">${icon("refresh")} Refresh</button>`,
  })}<div id="incidentStats" class="stat-grid"></div>
  <div class="card">
    <div class="card-head">
      <div><div class="card-title">Incident queue</div><div class="card-sub">Incidents are derived from model output and heuristic rules; they are not confirmed compromises</div></div>
      <span class="badge outline" id="incidentCount">Loading…</span>
    </div>
    <div class="card-body">
      <div class="toolbar">
        <input class="input search" id="incidentSearch" value="${escapeHtml(state.search)}" placeholder="Search code, title, source IP or notes…" />
        <select class="select" id="incidentStatus">
          <option value="">Any status</option>
          ${STATUSES.map((value) => `<option value="${value}">${value.replace(/_/g, " ")}</option>`).join("")}
        </select>
        <select class="select" id="incidentSeverity">
          <option value="">Any severity</option>
          ${SEVERITIES.map((value) => `<option value="${value}">${value}</option>`).join("")}
        </select>
        <select class="select" id="incidentPageSize">
          ${[25, 50, 100].map((size) => `<option value="${size}">${size} / page</option>`).join("")}
        </select>
      </div>
    </div>
    <div class="table-wrap" id="incidentTable"><div class="empty-state">${icon("clock")}<strong>Loading incidents…</strong></div></div>
    <div class="pagination" id="incidentPagination"></div>
  </div>`;

  const statsRoot = container.querySelector("#incidentStats");
  const tableRoot = container.querySelector("#incidentTable");
  const refreshButton = container.querySelector("#incidentsRefresh");

  const searchInput = container.querySelector("#incidentSearch");
  searchInput.addEventListener(
    "input",
    debounce(() => {
      state.search = searchInput.value.trim();
      state.page = 1;
      loadTable();
    }, 350),
  );
  container.querySelector("#incidentStatus").addEventListener("change", (event) => {
    state.status = event.target.value;
    state.page = 1;
    loadTable();
  });
  container.querySelector("#incidentSeverity").addEventListener("change", (event) => {
    state.severity = event.target.value;
    state.page = 1;
    loadTable();
  });
  container.querySelector("#incidentPageSize").addEventListener("change", (event) => {
    state.page_size = Number(event.target.value);
    state.page = 1;
    loadTable();
  });

  async function loadSettingsHint() {
    try {
      const settings = await api.get("/api/settings");
      if (!alive()) return;
      state.requireNotes = String(settings.values?.analyst_note_required_on_close || "false") === "true";
    } catch {
      state.requireNotes = false;
    }
  }

  async function loadStats() {
    try {
      const [total, newCount, investigating, resolved, falsePositive] = await Promise.all([
        api.get("/api/incidents", { page: 1, page_size: 1 }),
        api.get("/api/incidents", { page: 1, page_size: 1, status: "NEW" }),
        api.get("/api/incidents", { page: 1, page_size: 1, status: "INVESTIGATING" }),
        api.get("/api/incidents", { page: 1, page_size: 1, status: "RESOLVED" }),
        api.get("/api/incidents", { page: 1, page_size: 1, status: "FALSE_POSITIVE" }),
      ]);
      if (!alive()) return;
      const counts = {
        total: Number(total.total) || 0,
        new: Number(newCount.total) || 0,
        investigating: Number(investigating.total) || 0,
        resolved: Number(resolved.total) || 0,
        falsePositive: Number(falsePositive.total) || 0,
      };
      statsRoot.innerHTML = [
        statCard({
          label: "Total incidents",
          value: fmtInt(counts.total),
          iconName: "alert-triangle",
          foot: "All recorded response items",
        }),
        statCard({
          label: "New",
          value: fmtInt(counts.new),
          iconName: "inbox",
          tone: "purple",
          foot: "Awaiting first review",
        }),
        statCard({
          label: "Investigating",
          value: fmtInt(counts.investigating),
          iconName: "search",
          tone: "warning",
          foot: "Active analyst work",
        }),
        statCard({
          label: "Resolved",
          value: fmtInt(counts.resolved),
          iconName: "shield-check",
          tone: "success",
          foot: "Confirmed and closed",
        }),
        statCard({
          label: "False positive",
          value: fmtInt(counts.falsePositive),
          iconName: "x",
          foot: "Dismissed after review",
        }),
        statCard({
          label: "Open workload",
          value: fmtInt(counts.new + counts.investigating),
          iconName: "activity",
          tone: counts.new + counts.investigating ? "critical" : "success",
          foot: "New + investigating",
        }),
      ].join("");
    } catch (error) {
      if (!alive()) return;
      statsRoot.innerHTML = `<div class="callout danger">${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadTable() {
    tableRoot.innerHTML = `<div class="empty-state">${icon("clock")}<strong>Loading incidents…</strong></div>`;
    try {
      const data = await api.get("/api/incidents", {
        page: state.page,
        page_size: state.page_size,
        status: state.status || undefined,
        severity: state.severity || undefined,
        search: state.search || undefined,
      });
      if (!alive()) return;
      const count = container.querySelector("#incidentCount");
      if (count) count.textContent = `${fmtInt(data.total)} incidents`;
      if (!data.items?.length) {
        tableRoot.innerHTML = `<div class="empty-state">${icon("shield-check")}<strong>No incidents match</strong><span>Adjust filters or lower the incident severity threshold in Settings.</span></div>`;
      } else {
        tableRoot.innerHTML = `<table class="data"><thead><tr>
          <th>Code</th><th>Title</th><th>Severity</th><th>Status</th><th>Source</th><th>Assignee</th><th>Created</th><th>Updated</th>
        </tr></thead><tbody>${data.items
          .map(
            (row) => `<tr class="clickable" data-incident="${row.id}">
              <td class="mono">${escapeHtml(row.incident_code)}</td>
              <td><div style="max-width:380px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(row.title)}</div></td>
              <td>${severityBadge(row.severity)}</td>
              <td>${statusBadge(row.status)}</td>
              <td class="mono">${escapeHtml(row.source_ip || "—")}</td>
              <td>${escapeHtml(row.assignee_name || "Unassigned")}</td>
              <td class="mono">${escapeHtml(fmtDateTime(row.created_at))}</td>
              <td class="mono">${escapeHtml(timeAgo(row.updated_at))}</td>
            </tr>`,
          )
          .join("")}</tbody></table>`;
        tableRoot.querySelectorAll("[data-incident]").forEach((row) => {
          row.addEventListener("click", () => openIncident(Number(row.dataset.incident)));
        });
      }
      renderPagination(container.querySelector("#incidentPagination"), data, (page) => {
        state.page = page;
        loadTable();
      });
      if (focusId) {
        const id = Number(focusId);
        focusId = null;
        if (Number.isFinite(id)) openIncident(id);
      }
    } catch (error) {
      if (!alive()) return;
      tableRoot.innerHTML = `<div class="empty-state">${icon("alert-circle")}<strong>Could not load incidents</strong><span>${escapeHtml(error.message)}</span></div>`;
    }
  }

  async function openIncident(incidentId) {
    openDrawer({
      title: `Incident #${incidentId}`,
      subtitle: "Response detail",
      body: `<div class="empty-state">${icon("clock")}<strong>Loading incident…</strong></div>`,
    });
    try {
      const [data, assignees] = await Promise.all([
        api.get(`/api/incidents/${incidentId}`),
        canEdit ? api.get("/api/users/assignees").catch(() => []) : Promise.resolve([]),
      ]);
      if (!alive()) return;
      const openStatuses = ["NEW", "INVESTIGATING"];
      openDrawer({
        title: escapeHtml(data.title),
        subtitle: `<span class="mono">${escapeHtml(data.incident_code)}</span> · ${escapeHtml(data.source_ip || "unknown source")}`,
        body: `
          <div class="drawer-section">
            <div class="row" style="gap:8px;margin-bottom:12px">${severityBadge(data.severity)}${statusBadge(data.status)}${badge(openStatuses.includes(data.status) ? "OPEN" : "CLOSED", openStatuses.includes(data.status) ? "new" : "resolved")}</div>
            <p class="muted" style="font-size:11.5px;line-height:1.6">${escapeHtml(data.description)}</p>
            <div class="callout warning" style="margin-top:10px;font-size:10.5px">${escapeHtml(data.detection_explanation || "No detection explanation stored.")}</div>
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Incident metadata</div>
            <div class="kv-grid" style="grid-template-columns:repeat(2,minmax(0,1fr))">
              ${kv("Source IP", `<span class="mono">${escapeHtml(data.source_ip || "—")}</span>`)}
              ${kv("Destination IP", `<span class="mono">${escapeHtml(data.destination_ip || "—")}</span>`)}
              ${kv("Traffic record", data.traffic_record_id ? `#${data.traffic_record_id}` : "—")}
              ${kv("Detection result", data.detection_result_id ? `#${data.detection_result_id}` : "—")}
              ${kv("Assignee", escapeHtml(data.assignee_name || "Unassigned"))}
              ${kv("Created", escapeHtml(fmtDateTime(data.created_at)))}
              ${kv("Updated", escapeHtml(fmtDateTime(data.updated_at)))}
              ${kv("Resolved", data.resolved_at ? escapeHtml(fmtDateTime(data.resolved_at)) : "—")}
            </div>
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Related flows from this source</div>
            ${
              data.related_records?.length
                ? `<div class="table-wrap"><table class="data"><thead><tr><th>Time</th><th>Destination</th><th>Prediction</th><th>Severity</th></tr></thead><tbody>${data.related_records
                    .map(
                      (record) => `<tr>
                        <td class="mono">${escapeHtml(fmtDateTime(record.timestamp))}</td>
                        <td class="mono">${escapeHtml(record.destination_ip || "—")}${record.destination_port ? `:${record.destination_port}` : ""}</td>
                        <td>${labelBadge(record.predicted_label)}</td>
                        <td>${severityBadge(record.severity)}</td>
                      </tr>`,
                    )
                    .join("")}</tbody></table></div>`
                : '<div class="dim" style="font-size:11px">No related flow records.</div>'
            }
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Activity log</div>
            ${
              data.activity_log?.length
                ? `<div class="stack" style="gap:8px">${data.activity_log
                    .map(
                      (entry) => `<div class="row-between" style="font-size:10.5px;border-bottom:1px solid var(--border-soft);padding-bottom:7px">
                        <div><span class="mono" style="color:#93c5fd">${escapeHtml(entry.action)}</span><span class="dim"> · user ${entry.user_id ?? "system"}</span></div>
                        <span class="dim">${escapeHtml(timeAgo(entry.created_at))}</span>
                      </div>`,
                    )
                    .join("")}</div>`
                : '<div class="dim" style="font-size:11px">No audit entries yet.</div>'
            }
          </div>

          <div class="drawer-section">
            <div class="drawer-section-title">Triage</div>
            ${
              canEdit
                ? `<div class="stack">
                    <div class="grid grid-2">
                      <div class="field"><label for="incidentStatusField">Status</label><select class="select" id="incidentStatusField">${STATUSES.map(
                        (value) => `<option value="${value}" ${value === data.status ? "selected" : ""}>${value.replace(/_/g, " ")}</option>`,
                      ).join("")}</select></div>
                      <div class="field"><label for="incidentAssignee">Assignee</label><select class="select" id="incidentAssignee"><option value="0">Unassigned</option>${assignees
                        .map(
                          (person) => `<option value="${person.id}" ${person.id === data.assigned_to ? "selected" : ""}>${escapeHtml(person.full_name || person.email)}</option>`,
                        )
                        .join("")}</select></div>
                    </div>
                    <div class="field"><label for="incidentNotes">Investigation notes</label><textarea class="textarea" id="incidentNotes" maxlength="10000" placeholder="Scope, evidence, containment steps, false-positive rationale…">${escapeHtml(data.investigation_notes || "")}</textarea>
                      ${state.requireNotes ? '<span class="dim" style="font-size:10px">Notes are required by policy before an incident can be closed.</span>' : ""}
                    </div>
                  </div>`
                : `<div class="callout">${data.investigation_notes ? escapeHtml(data.investigation_notes) : "No investigation notes recorded."}</div>`
            }
          </div>`,
        footer: canEdit
          ? `<button type="button" class="btn" data-close>Close</button><button type="button" class="btn primary" data-save>${icon("check")} Save triage</button>`
          : `<button type="button" class="btn" data-close>Close</button>`,
      });

      document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", closeDrawer));
      document.querySelector("[data-save]")?.addEventListener("click", async (event) => {
        const button = event.currentTarget;
        const status = document.querySelector("#incidentStatusField").value;
        const assignee = document.querySelector("#incidentAssignee").value;
        const notes = document.querySelector("#incidentNotes").value;
        setBusy(button, true, "Saving…");
        try {
          await api.patch(`/api/incidents/${incidentId}`, {
            status,
            assigned_to: Number(assignee) || 0,
            investigation_notes: notes,
          });
          toast("Incident updated", `${data.incident_code} saved.`, "success");
          closeDrawer();
          await Promise.all([loadTable(), loadStats()]);
        } catch (error) {
          toast("Could not update incident", error.message, "error");
          setBusy(button, false);
        }
      });
    } catch (error) {
      if (!alive()) return;
      toast("Could not load incident", error.message, "error");
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

  await Promise.all([loadSettingsHint(), loadStats(), loadTable()]);

  return () => {
    /* no background work */
  };
}
