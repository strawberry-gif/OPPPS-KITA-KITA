import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  badge,
  confirmDialog,
  escapeHtml,
  fmtDateTime,
  fmtInt,
  kv,
  openModal,
  pageHead,
  roleLabel,
  setBusy,
  statCard,
  toast,
} from "../ui.js";

const SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

const RANGES = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "all", label: "All recorded traffic" },
];

const SETTING_FIELDS = {
  incident_min_severity: {
    label: "Minimum severity for automatic incidents",
    help: "A detection at or above this heuristic severity opens a security incident automatically.",
  },
  default_dashboard_range: {
    label: "Default dashboard range",
    help: "Initial time window for the overview and analytics views when an operator has no saved preference.",
  },
  analyst_note_required_on_close: {
    label: "Require investigation notes when closing",
    help: "When enabled, resolving or closing an incident requires a written investigation note.",
  },
};

function statusTone(ok) {
  return ok ? "resolved" : "critical";
}

function detailText(detail) {
  if (detail === null || detail === undefined) return "—";
  if (typeof detail === "string") return detail;
  try {
    return JSON.stringify(detail);
  } catch {
    return String(detail);
  }
}

export async function mount(container, ctx) {
  const isAdmin = ctx.user?.role === "admin";
  const alive = () => container.isConnected;

  let settings = { values: {}, descriptions: {} };
  let users = [];
  let auditRows = [];
  let health = null;
  let loaded = false;

  container.innerHTML = `${pageHead({
    title: "Settings & administration",
    description:
      "Detection policy, account security, operator access and the audit trail. Changes are applied immediately and recorded for accountability.",
    actions: `<button type="button" class="btn" id="settingsRefresh">${icon("refresh")} Refresh</button>`,
  })}<div id="settingsStats" class="stat-grid"></div><div id="settingsBody"></div>`;

  const statsRoot = container.querySelector("#settingsStats");
  const body = container.querySelector("#settingsBody");
  const refreshButton = container.querySelector("#settingsRefresh");

  function renderStats() {
    const databaseOk = health?.database === "connected";
    const modelsReady = Boolean(health?.models_ready);
    const capture = health?.live_capture_running
      ? "Running"
      : health?.live_capture_available
        ? "Available"
        : "Unavailable";
    statsRoot.innerHTML = [
      statCard({
        label: "Signed in as",
        value: escapeHtml(ctx.user?.full_name || ctx.user?.email || "Unknown"),
        iconName: "user",
        valueClass: "small",
        foot: escapeHtml(roleLabel(ctx.user?.role || "")),
      }),
      statCard({
        label: "Account status",
        value: ctx.user?.is_active === false ? "Disabled" : "Active",
        iconName: "shield-check",
        tone: ctx.user?.is_active === false ? "critical" : "success",
        valueClass: "small",
        foot: ctx.user?.last_login_at
          ? `Last login ${escapeHtml(fmtDateTime(ctx.user.last_login_at))}`
          : "First session",
      }),
      statCard({
        label: "Database",
        value: databaseOk ? "Connected" : "Unavailable",
        iconName: "database",
        tone: databaseOk ? "success" : "critical",
        valueClass: "small",
        foot: "PostgreSQL · SQLAlchemy",
      }),
      statCard({
        label: "Detection engine",
        value: modelsReady ? "Ready" : "Not ready",
        iconName: "cpu",
        tone: modelsReady ? "success" : "warning",
        valueClass: "small",
        foot: health?.active_classifier
          ? escapeHtml(health.active_classifier.name)
          : "No active classifier",
      }),
      statCard({
        label: "Live capture",
        value: capture,
        iconName: "radio",
        tone: health?.live_capture_running ? "success" : health?.live_capture_available ? "warning" : "",
        valueClass: "small",
        foot: "Optional passive sensor",
      }),
      statCard({
        label: "Application",
        value: escapeHtml(health?.version || "1.0.0"),
        iconName: "server",
        valueClass: "small",
        foot: health?.server_time
          ? `Server time ${escapeHtml(fmtDateTime(health.server_time))}`
          : "OPPPS KITA-KITA",
      }),
    ].join("");
  }

  function optionsMarkup(options, selected) {
    return options
      .map(
        (option) =>
          `<option value="${escapeHtml(option.value)}" ${option.value === selected ? "selected" : ""}>${escapeHtml(option.label)}</option>`,
      )
      .join("");
  }

  function policyCard() {
    const values = settings.values || {};
    const noteRequired = String(values.analyst_note_required_on_close || "false").toLowerCase() === "true";
    return `<div class="card">
      <div class="card-head">
        <div><div class="card-title">Detection policy</div><div class="card-sub">Applied by the detection and incident services</div></div>
        ${isAdmin ? badge("ADMIN", "investigating") : badge("READ ONLY", "outline")}
      </div>
      <div class="card-body">
        ${
          isAdmin
            ? ""
            : `<div class="callout info mb-16" style="font-size:10.5px">Only administrators can change detection policy. The current values are shown for reference.</div>`
        }
        <form id="policyForm" class="stack" novalidate>
          <div class="field">
            <label for="incidentMinSeverity">${escapeHtml(SETTING_FIELDS.incident_min_severity.label)}</label>
            <select class="select" id="incidentMinSeverity" name="incident_min_severity" ${isAdmin ? "" : "disabled"}>
              ${optionsMarkup(
                SEVERITIES.map((value) => ({ value, label: value.charAt(0) + value.slice(1).toLowerCase() })),
                values.incident_min_severity || "HIGH",
              )}
            </select>
            <span class="hint">${escapeHtml(SETTING_FIELDS.incident_min_severity.help)}</span>
          </div>

          <div class="field">
            <label for="defaultDashboardRange">${escapeHtml(SETTING_FIELDS.default_dashboard_range.label)}</label>
            <select class="select" id="defaultDashboardRange" name="default_dashboard_range" ${isAdmin ? "" : "disabled"}>
              ${optionsMarkup(RANGES, values.default_dashboard_range || "7d")}
            </select>
            <span class="hint">${escapeHtml(SETTING_FIELDS.default_dashboard_range.help)}</span>
          </div>

          <label class="switch-row ${isAdmin ? "" : "disabled"}">
            <span>
              <span class="switch-title">${escapeHtml(SETTING_FIELDS.analyst_note_required_on_close.label)}</span>
              <span class="hint">${escapeHtml(SETTING_FIELDS.analyst_note_required_on_close.help)}</span>
            </span>
            <span class="switch">
              <input type="checkbox" id="noteRequired" ${noteRequired ? "checked" : ""} ${isAdmin ? "" : "disabled"} />
              <span class="track" aria-hidden="true"><span class="thumb"></span></span>
            </span>
          </label>

          ${
            isAdmin
              ? `<div class="row-between">
                  <span class="dim" style="font-size:10.5px">Saving is audited with your account and source address.</span>
                  <div class="row">
                    <button type="button" class="btn" id="policyReset">Reset</button>
                    <button type="submit" class="btn primary" id="policySave">${icon("check")} Save policy</button>
                  </div>
                </div>`
              : ""
          }
        </form>
      </div>
    </div>`;
  }

  function systemCard() {
    const classifier = health?.active_classifier;
    const anomaly = health?.active_anomaly_model;
    return `<div class="card">
      <div class="card-head">
        <div><div class="card-title">System status</div><div class="card-sub">Live service health</div></div>
        <span class="health-chip ${health?.status === "ok" ? "" : "degraded"}"><span class="dot"></span>${escapeHtml(health?.status === "ok" ? "Operational" : "Degraded")}</span>
      </div>
      <div class="card-body">
        <div class="health-list">
          <div class="health-row">
            <span class="health-icon ${health?.database === "connected" ? "ok" : "bad"}">${icon("database")}</span>
            <div><strong>PostgreSQL database</strong><span>${escapeHtml(health?.database || "unavailable")}</span></div>
            ${badge(health?.database === "connected" ? "CONNECTED" : "UNAVAILABLE", statusTone(health?.database === "connected"))}
          </div>
          <div class="health-row">
            <span class="health-icon ${classifier ? "ok" : "warn"}">${icon("cpu")}</span>
            <div><strong>Supervised classifier</strong><span>${classifier ? escapeHtml(classifier.name) : "No active classifier"}</span></div>
            ${classifier ? badge("LOADED", "resolved") : badge("MISSING", "medium")}
          </div>
          <div class="health-row">
            <span class="health-icon ${anomaly ? "ok" : "warn"}">${icon("activity")}</span>
            <div><strong>Anomaly detector</strong><span>${anomaly ? escapeHtml(anomaly.name) : "No active anomaly model"}</span></div>
            ${anomaly ? badge("LOADED", "resolved") : badge("MISSING", "medium")}
          </div>
          <div class="health-row">
            <span class="health-icon ${health?.live_capture_available ? "ok" : ""}">${icon("radio")}</span>
            <div><strong>Passive live capture</strong><span>Optional Scapy sensor</span></div>
            ${badge(
              health?.live_capture_running ? "RUNNING" : health?.live_capture_available ? "AVAILABLE" : "UNAVAILABLE",
              health?.live_capture_running ? "resolved" : health?.live_capture_available ? "new" : "outline",
            )}
          </div>
        </div>
        <div class="divider"></div>
        <div class="kv-grid">
          ${kv("Classifier version", `<span class="mono" style="font-size:10.5px">${escapeHtml(classifier?.version || "—")}</span>`)}
          ${kv("Anomaly version", `<span class="mono" style="font-size:10.5px">${escapeHtml(anomaly?.version || "—")}</span>`)}
          ${kv("Server time", escapeHtml(fmtDateTime(health?.server_time)))}
          ${kv("API documentation", `<a class="link" href="/api/docs" target="_blank" rel="noopener noreferrer">Open Swagger UI</a>`)}
        </div>
        <div class="callout info mt-16" style="font-size:10.5px">Health is sampled when this page loads. The top bar refreshes it every 30 seconds.</div>
      </div>
    </div>`;
  }

  function accountCard() {
    return `<div class="card">
      <div class="card-head"><div><div class="card-title">Your account</div><div class="card-sub">Identity and session</div></div>${badge(roleLabel(ctx.user?.role || ""), "outline")}</div>
      <div class="card-body">
        <div class="kv-grid">
          ${kv("Full name", escapeHtml(ctx.user?.full_name || "—"))}
          ${kv("Email address", `<span class="mono" style="font-size:10.5px">${escapeHtml(ctx.user?.email || "—")}</span>`)}
          ${kv("Role", escapeHtml(roleLabel(ctx.user?.role || "")))}
          ${kv("Account created", escapeHtml(fmtDateTime(ctx.user?.created_at)))}
          ${kv("Last login", escapeHtml(fmtDateTime(ctx.user?.last_login_at)))}
          ${kv("User ID", `<span class="mono">#${escapeHtml(ctx.user?.id ?? "—")}</span>`)}
        </div>
      </div>
    </div>`;
  }

  function passwordCard() {
    return `<div class="card">
      <div class="card-head"><div><div class="card-title">Change password</div><div class="card-sub">Minimum 10 characters</div></div><span class="stat-icon">${icon("key")}</span></div>
      <div class="card-body">
        <form id="passwordForm" class="stack" novalidate>
          <div class="field">
            <label for="currentPassword">Current password</label>
            <input class="input" type="password" id="currentPassword" autocomplete="current-password" required />
          </div>
          <div class="grid grid-2">
            <div class="field">
              <label for="newPassword">New password</label>
              <input class="input" type="password" id="newPassword" autocomplete="new-password" minlength="10" required />
            </div>
            <div class="field">
              <label for="confirmPassword">Confirm new password</label>
              <input class="input" type="password" id="confirmPassword" autocomplete="new-password" minlength="10" required />
            </div>
          </div>
          <div class="row-between">
            <span class="dim" style="font-size:10.5px">Existing sessions stay valid until their token expires.</span>
            <button type="submit" class="btn primary" id="passwordSave">${icon("lock")} Update password</button>
          </div>
        </form>
      </div>
    </div>`;
  }

  function usersCard() {
    if (!isAdmin) {
      return `<div class="card">
        <div class="card-head"><div><div class="card-title">Operator access</div><div class="card-sub">Role-based access control</div></div></div>
        <div class="card-body"><div class="callout info" style="font-size:11px">User administration requires the administrator role. Contact an administrator to change roles or deactivate accounts.</div></div>
      </div>`;
    }
    const rows = users
      .map((user) => {
        const isSelf = user.id === ctx.user?.id;
        return `<tr>
          <td><div class="user-cell"><span class="avatar sm">${escapeHtml((user.full_name || user.email || "?").slice(0, 2).toUpperCase())}</span><div><div style="color:#e2e8f0;font-weight:550">${escapeHtml(user.full_name || user.email)}${isSelf ? ' <span class="dim" style="font-size:9px">(you)</span>' : ""}</div><div class="dim" style="font-size:9.5px">${escapeHtml(user.email)}</div></div></div></td>
          <td>${badge(roleLabel(user.role), user.role === "admin" ? "investigating" : user.role === "analyst" ? "new" : "outline")}</td>
          <td>${user.is_active ? badge("ACTIVE", "resolved") : badge("DISABLED", "critical")}</td>
          <td class="mono" style="font-size:10px">${escapeHtml(fmtDateTime(user.last_login_at))}</td>
          <td class="mono" style="font-size:10px">${escapeHtml(fmtDateTime(user.created_at))}</td>
          <td><button type="button" class="btn sm" data-edit-user="${user.id}">${icon("edit")} Edit</button></td>
        </tr>`;
      })
      .join("");
    return `<div class="card">
      <div class="card-head"><div><div class="card-title">Operator access</div><div class="card-sub">${fmtInt(users.length)} account${users.length === 1 ? "" : "s"} · administrators manage roles and status</div></div><button type="button" class="btn primary sm" id="addUser">${icon("user-plus")} Add user</button></div>
      <div class="table-wrap">${
        users.length
          ? `<table class="data"><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last login</th><th>Created</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table>`
          : `<div class="empty-state">${icon("user")}<strong>No users found</strong><span>Create the first operator account.</span></div>`
      }</div>
    </div>`;
  }

  function auditCard() {
    if (!isAdmin) return "";
    const userMap = new Map(users.map((user) => [user.id, user]));
    const rows = auditRows
      .map((row) => {
        const actor = row.user_id ? userMap.get(row.user_id) : null;
        return `<tr>
          <td class="mono" style="font-size:10px;white-space:nowrap">${escapeHtml(fmtDateTime(row.created_at))}</td>
          <td>${actor ? `<div style="font-size:11px">${escapeHtml(actor.full_name || actor.email)}</div><div class="dim" style="font-size:9px">${escapeHtml(actor.email)}</div>` : `<span class="dim">${row.user_id ? `user #${escapeHtml(row.user_id)}` : "system"}</span>`}</td>
          <td><span class="mono" style="font-size:10.5px;color:#bfdbfe">${escapeHtml(row.action)}</span></td>
          <td>${escapeHtml(row.entity_type || "—")}${row.entity_id ? `<div class="dim" style="font-size:9px">${escapeHtml(row.entity_id)}</div>` : ""}</td>
          <td><span class="audit-detail" title="${escapeHtml(detailText(row.detail))}">${escapeHtml(detailText(row.detail))}</span></td>
          <td class="mono" style="font-size:10px">${escapeHtml(row.ip_address || "—")}</td>
        </tr>`;
      })
      .join("");
    return `<div class="card mt-16">
      <div class="card-head"><div><div class="card-title">Audit trail</div><div class="card-sub">Most recent ${fmtInt(auditRows.length)} recorded actions</div></div><span class="badge outline">IMMUTABLE LOG</span></div>
      <div class="table-wrap">${
        auditRows.length
          ? `<table class="data"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Entity</th><th>Detail</th><th>Source IP</th></tr></thead><tbody>${rows}</tbody></table>`
          : `<div class="empty-state">${icon("terminal")}<strong>No audit events yet</strong><span>Sign-ins and administrative changes appear here.</span></div>`
      }</div>
    </div>`;
  }

  function render() {
    renderStats();
    body.innerHTML = `
      <div class="grid grid-main">
        ${policyCard()}
        ${systemCard()}
      </div>
      <div class="grid grid-2 mt-16">
        ${accountCard()}
        ${passwordCard()}
      </div>
      <div class="mt-16">${usersCard()}</div>
      ${auditCard()}
      <div class="row-between mt-16">
        <span class="dim" style="font-size:10.5px">OPPPS KITA-KITA · Cyber Threat Detection Platform</span>
        <span class="dim" style="font-size:10.5px">Role: ${escapeHtml(roleLabel(ctx.user?.role || ""))} · Session secured with JWT</span>
      </div>`;
    bind();
  }

  function bind() {
    const policyForm = body.querySelector("#policyForm");
    if (policyForm && isAdmin) {
      policyForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = policyForm.querySelector("#policySave");
        const values = {
          incident_min_severity: body.querySelector("#incidentMinSeverity").value,
          default_dashboard_range: body.querySelector("#defaultDashboardRange").value,
          analyst_note_required_on_close: body.querySelector("#noteRequired").checked ? "true" : "false",
        };
        setBusy(button, true, "Saving…");
        try {
          const updated = await api.put("/api/settings", { values });
          if (!alive()) return;
          settings = updated;
          localStorage.setItem("oppps.range", values.default_dashboard_range);
          window.__opppsDefaults = { ...(window.__opppsDefaults || {}), ...values };
          toast("Detection policy saved", "New settings apply to subsequent detections and sessions.", "success");
          render();
        } catch (error) {
          if (!alive()) return;
          toast("Could not save policy", error.message, "error");
          setBusy(button, false);
        }
      });
      body.querySelector("#policyReset")?.addEventListener("click", () => {
        const values = settings.values || {};
        body.querySelector("#incidentMinSeverity").value = values.incident_min_severity || "HIGH";
        body.querySelector("#defaultDashboardRange").value = values.default_dashboard_range || "7d";
        body.querySelector("#noteRequired").checked =
          String(values.analyst_note_required_on_close || "false").toLowerCase() === "true";
        toast("Form reset", "Unsaved changes were discarded.", "info");
      });
    }

    body.querySelector("#passwordForm")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = body.querySelector("#passwordSave");
      const currentPassword = body.querySelector("#currentPassword").value;
      const newPassword = body.querySelector("#newPassword").value;
      const confirmPassword = body.querySelector("#confirmPassword").value;
      if (!currentPassword) {
        toast("Current password required", "Enter your existing password to continue.", "warning");
        return;
      }
      if (newPassword.length < 10) {
        toast("Password too short", "Use at least 10 characters.", "warning");
        return;
      }
      if (newPassword !== confirmPassword) {
        toast("Passwords do not match", "Re-enter the new password in both fields.", "warning");
        return;
      }
      setBusy(button, true, "Updating…");
      try {
        await api.post("/api/auth/change-password", {
          current_password: currentPassword,
          new_password: newPassword,
        });
        if (!alive()) return;
        toast("Password updated", "Use the new password on your next sign-in.", "success");
        body.querySelector("#currentPassword").value = "";
        body.querySelector("#newPassword").value = "";
        body.querySelector("#confirmPassword").value = "";
      } catch (error) {
        if (!alive()) return;
        toast("Could not update password", error.message, "error");
      } finally {
        if (alive()) setBusy(button, false);
      }
    });

    body.querySelector("#addUser")?.addEventListener("click", openCreateUser);
    body.querySelectorAll("[data-edit-user]").forEach((button) => {
      button.addEventListener("click", () => {
        const user = users.find((item) => item.id === Number(button.dataset.editUser));
        if (user) openEditUser(user);
      });
    });
  }

  function openCreateUser() {
    openModal({
      title: "Add operator account",
      subtitle: "The new user can sign in immediately with the password you set",
      width: "520px",
      body: `<div class="stack">
        <div class="field"><label for="newUserName">Full name</label><input class="input" id="newUserName" maxlength="160" placeholder="Jane Analyst" /></div>
        <div class="field"><label for="newUserEmail">Email address</label><input class="input" id="newUserEmail" type="email" autocomplete="off" placeholder="jane@oppps.local" /></div>
        <div class="grid grid-2">
          <div class="field"><label for="newUserRole">Role</label><select class="select" id="newUserRole"><option value="analyst">Security Analyst</option><option value="viewer">Read-only Viewer</option><option value="admin">Administrator</option></select></div>
          <div class="field"><label for="newUserPassword">Initial password</label><input class="input" id="newUserPassword" type="password" minlength="10" autocomplete="new-password" /></div>
        </div>
        <div class="callout info" style="font-size:10.5px">Passwords must contain at least 10 characters and are stored as bcrypt hashes. The user should change it after first sign-in.</div>
      </div>`,
      footer: `<button type="button" class="btn" data-cancel>Cancel</button><button type="button" class="btn primary" data-create>${icon("user-plus")} Create account</button>`,
      onMount(card, close) {
        card.querySelector("[data-cancel]").addEventListener("click", close);
        card.querySelector("[data-create]").addEventListener("click", async () => {
          const button = card.querySelector("[data-create]");
          const fullName = card.querySelector("#newUserName").value.trim();
          const email = card.querySelector("#newUserEmail").value.trim();
          const password = card.querySelector("#newUserPassword").value;
          const role = card.querySelector("#newUserRole").value;
          if (!fullName) {
            toast("Name required", "Enter the operator's full name.", "warning");
            return;
          }
          if (!email) {
            toast("Email required", "Enter a valid email address.", "warning");
            return;
          }
          if (password.length < 10) {
            toast("Password too short", "Use at least 10 characters.", "warning");
            return;
          }
          setBusy(button, true, "Creating…");
          try {
            await api.post("/api/users", { full_name: fullName, email, password, role });
            close();
            toast("User created", `${fullName} can now sign in.`, "success");
            await loadUsers();
            if (!alive()) return;
            render();
          } catch (error) {
            if (!alive()) return;
            toast("Could not create user", error.message, "error");
            setBusy(button, false);
          }
        });
      },
    });
  }

  function openEditUser(user) {
    const isSelf = user.id === ctx.user?.id;
    openModal({
      title: `Edit ${user.full_name || user.email}`,
      subtitle: "Role and account status changes are audited",
      width: "480px",
      body: `<div class="stack">
        <div class="kv-grid">
          ${kv("Email", `<span class="mono" style="font-size:10.5px">${escapeHtml(user.email)}</span>`)}
          ${kv("Created", escapeHtml(fmtDateTime(user.created_at)))}
        </div>
        <div class="field">
          <label for="editUserRole">Role</label>
          <select class="select" id="editUserRole" ${isSelf ? "disabled" : ""}>
            <option value="admin" ${user.role === "admin" ? "selected" : ""}>Administrator</option>
            <option value="analyst" ${user.role === "analyst" ? "selected" : ""}>Security Analyst</option>
            <option value="viewer" ${user.role === "viewer" ? "selected" : ""}>Read-only Viewer</option>
          </select>
          ${isSelf ? '<span class="hint">You cannot remove your own administrator role.</span>' : ""}
        </div>
        <label class="switch-row ${isSelf ? "disabled" : ""}">
          <span><span class="switch-title">Account active</span><span class="hint">${isSelf ? "You cannot deactivate your own account." : "Disabled accounts cannot sign in or use the API."}</span></span>
          <span class="switch"><input type="checkbox" id="editUserActive" ${user.is_active ? "checked" : ""} ${isSelf ? "disabled" : ""} /><span class="track" aria-hidden="true"><span class="thumb"></span></span></span>
        </label>
      </div>`,
      footer: `<button type="button" class="btn" data-cancel>Cancel</button><button type="button" class="btn primary" data-save>${icon("check")} Save changes</button>`,
      onMount(card, close) {
        card.querySelector("[data-cancel]").addEventListener("click", close);
        card.querySelector("[data-save]").addEventListener("click", async () => {
          const button = card.querySelector("[data-save]");
          const payload = {};
          const role = card.querySelector("#editUserRole").value;
          const isActive = card.querySelector("#editUserActive").checked;
          if (!isSelf && role !== user.role) payload.role = role;
          if (!isSelf && isActive !== user.is_active) payload.is_active = isActive;
          if (!Object.keys(payload).length) {
            close();
            toast("No changes", "The account already matches the selected values.", "info");
            return;
          }
          if (payload.is_active === false) {
            const confirmed = await confirmDialog({
              title: "Disable account",
              message: `${user.full_name || user.email} will no longer be able to sign in or call the API.`,
              confirmText: "Disable account",
              danger: true,
            });
            if (!confirmed) return;
          }
          setBusy(button, true, "Saving…");
          try {
            await api.patch(`/api/users/${user.id}`, payload);
            close();
            toast("Account updated", "The change is now in effect.", "success");
            await loadUsers();
            if (!alive()) return;
            render();
          } catch (error) {
            if (!alive()) return;
            toast("Could not update account", error.message, "error");
            setBusy(button, false);
          }
        });
      },
    });
  }

  async function loadUsers() {
    if (!isAdmin) return;
    users = (await api.get("/api/users")) || [];
  }

  async function loadAudit() {
    if (!isAdmin) return;
    auditRows = (await api.get("/api/settings/audit", { limit: 100 })) || [];
  }

  async function load() {
    refreshButton.disabled = true;
    if (!loaded) {
      body.innerHTML = `<div class="grid grid-main"><div class="skeleton" style="height:420px;border-radius:12px"></div><div class="skeleton" style="height:420px;border-radius:12px"></div></div>`;
      statsRoot.innerHTML = Array.from({ length: 6 })
        .map(() => '<div class="skeleton" style="height:106px;border-radius:12px"></div>')
        .join("");
    }
    try {
      const requests = [api.get("/api/settings"), api.get("/api/dashboard/health")];
      if (isAdmin) {
        requests.push(api.get("/api/users"), api.get("/api/settings/audit", { limit: 100 }));
      }
      const [settingsData, healthData, usersData, auditData] = await Promise.all(requests);
      if (!alive()) return;
      settings = settingsData || { values: {}, descriptions: {} };
      health = healthData || null;
      if (isAdmin) {
        users = usersData || [];
        auditRows = auditData || [];
      }
      loaded = true;
      render();
    } catch (error) {
      if (!alive()) return;
      body.innerHTML = `<div class="card card-pad"><div class="callout danger"><strong>Unable to load settings.</strong><br />${escapeHtml(error.message)}</div></div>`;
      statsRoot.innerHTML = "";
    } finally {
      if (alive()) refreshButton.disabled = false;
    }
  }

  refreshButton.addEventListener("click", load);
  await load();

  return () => {
    /* no background work */
  };
}
