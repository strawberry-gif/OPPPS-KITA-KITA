import { icon } from "./icons.js";

const HTML_ESCAPES = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]);
}

export function titleCase(value) {
  const text = String(value ?? "").replace(/_/g, " ").toLowerCase();
  return text.replace(/\b\w/g, (char) => char.toUpperCase());
}

const intFormatter = new Intl.NumberFormat("en-US");
const compactFormatter = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 1,
});

export function fmtInt(value) {
  const number = Number(value);
  return intFormatter.format(Number.isFinite(number) ? number : 0);
}

export function fmtNumber(value, digits = 0) {
  const number = Number(value);
  return new Intl.NumberFormat("en-US", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(Number.isFinite(number) ? number : 0);
}

export function fmtCompact(value) {
  const number = Number(value);
  return compactFormatter.format(Number.isFinite(number) ? number : 0);
}

export function ratioPct(value, digits = 1) {
  const number = Number(value);
  return `${fmtNumber((Number.isFinite(number) ? number : 0) * 100, digits)}%`;
}

export function pct(value, digits = 1) {
  const number = Number(value);
  return `${fmtNumber(Number.isFinite(number) ? number : 0, digits)}%`;
}

export function fmtBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${fmtNumber(value, 0)} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let scaled = value / 1024;
  let index = 0;
  while (scaled >= 1024 && index < units.length - 1) {
    scaled /= 1024;
    index += 1;
  }
  return `${fmtNumber(scaled, scaled >= 100 ? 0 : 1)} ${units[index]}`;
}

export function fmtDuration(seconds) {
  const value = Number(seconds) || 0;
  if (value < 1) return `${fmtNumber(value * 1000, 0)} ms`;
  if (value < 60) return `${fmtNumber(value, 2)} s`;
  if (value < 3600) {
    const minutes = Math.floor(value / 60);
    const rest = Math.round(value % 60);
    return `${minutes}m ${rest}s`;
  }
  const hours = Math.floor(value / 3600);
  const minutes = Math.round((value % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

const dateTimeFormatter = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const dateFormatter = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
});
const timeFormatter = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

export function fmtDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return dateTimeFormatter.format(date);
}

export function fmtDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return dateFormatter.format(date);
}

export function fmtTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return timeFormatter.format(date);
}

export function timeAgo(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 45) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  if (seconds < 86400 * 30) return `${Math.round(seconds / 86400)}d ago`;
  return fmtDate(value);
}

export function truncate(value, length = 48) {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

export function badge(text, tone = "outline") {
  return `<span class="badge ${escapeHtml(tone)}">${escapeHtml(text)}</span>`;
}

export function severityBadge(severity) {
  if (!severity) return '<span class="dim">—</span>';
  const tones = {
    CRITICAL: "critical",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    INFORMATIONAL: "info",
  };
  return badge(titleCase(severity), tones[severity] || "info");
}

export function statusBadge(status) {
  if (!status) return '<span class="dim">—</span>';
  return badge(
    String(status).replace(/_/g, " "),
    String(status).toLowerCase(),
  );
}

export function classificationBadge(classification) {
  if (!classification) return '<span class="dim">—</span>';
  const tones = {
    HIGH_RISK: "critical",
    SUSPICIOUS: "high",
    WATCHLIST: "medium",
    OBSERVED: "outline",
    MONITORED_DESTINATION: "private",
  };
  return badge(classification.replace(/_/g, " "), tones[classification] || "outline");
}

export function labelBadge(label, isAnomaly = null) {
  if (!label) return '<span class="dim">—</span>';
  const tone = label === "BENIGN" ? "benign" : label === "ANOMALY" ? "anomaly" : "attack";
  const suffix = isAnomaly ? ` <span class="dot"></span>` : "";
  return `<span class="badge ${tone}">${escapeHtml(label)}${suffix}</span>`;
}

export function severityColor(severity) {
  return (
    {
      CRITICAL: "#ef4444",
      HIGH: "#fb7185",
      MEDIUM: "#f59e0b",
      LOW: "#38bdf8",
      INFORMATIONAL: "#64748b",
    }[severity] || "#64748b"
  );
}

export function riskBar(score) {
  const value = Math.max(0, Math.min(100, Number(score) || 0));
  const tone = value >= 75 ? "high" : value >= 50 ? "medium" : "low";
  return `<div class="risk-line"><div class="risk-track"><div class="risk-fill ${tone}" style="width:${value}%"></div></div><span class="mono" style="font-size:11px;color:var(--muted)">${fmtNumber(value, 1)}</span></div>`;
}

export function statCard({ label, value, iconName = "activity", tone = "", foot = "", valueClass = "" }) {
  return `<div class="stat-card">
    <div class="stat-top">
      <div class="stat-label">${escapeHtml(label)}</div>
      <div class="stat-icon ${tone}">${icon(iconName)}</div>
    </div>
    <div class="stat-value ${valueClass}">${value}</div>
    ${foot ? `<div class="stat-foot">${foot}</div>` : ""}
  </div>`;
}

export function metricTile(label, value, note = "") {
  return `<div class="metric-tile">
    <div class="m-label">${escapeHtml(label)}</div>
    <div class="m-value">${value}</div>
    ${note ? `<div class="m-note">${escapeHtml(note)}</div>` : ""}
  </div>`;
}

export function kv(label, value) {
  return `<div class="kv"><div class="k">${escapeHtml(label)}</div><div class="v">${value}</div></div>`;
}

export function emptyState(iconName, title, subtitle = "") {
  return `<div class="empty-state">${icon(iconName)}<strong>${escapeHtml(title)}</strong>${subtitle ? `<span>${escapeHtml(subtitle)}</span>` : ""}</div>`;
}

export function loadingBlock(height = 260) {
  return `<div class="skeleton loading-block" style="height:${height}px"></div>`;
}

export function pageHead({ title, description, actions = "" }) {
  return `<div class="page-head">
    <div><h1>${escapeHtml(title)}</h1>${description ? `<p>${escapeHtml(description)}</p>` : ""}</div>
    ${actions ? `<div class="page-actions">${actions}</div>` : ""}
  </div>`;
}

export function segmented(id, options, active) {
  return `<div class="segmented" id="${escapeHtml(id)}">${options
    .map(
      (option) =>
        `<button type="button" data-value="${escapeHtml(option.value)}" class="${option.value === active ? "active" : ""}">${escapeHtml(option.label)}</button>`,
    )
    .join("")}</div>`;
}

export function severityStrip(counts) {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
  const tone = {
    CRITICAL: "critical",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    INFORMATIONAL: "info",
  };
  return `<div class="severity-strip">${order
    .map(
      (level) => `<div class="severity-mini ${tone[level]}">
        <div class="label">${level === "INFORMATIONAL" ? "INFO" : level}</div>
        <div class="value">${fmtInt(counts?.[level] ?? 0)}</div>
      </div>`,
    )
    .join("")}</div>`;
}

export function toast(title, message = "", type = "info") {
  const stack = document.getElementById("toastStack");
  if (!stack) return;
  const iconName =
    type === "success"
      ? "check-circle"
      : type === "error"
        ? "alert-circle"
        : type === "warning"
          ? "alert-triangle"
          : "info";
  const element = document.createElement("div");
  element.className = `toast ${type}`;
  element.innerHTML = `<div>${icon(iconName)}</div><div><strong>${escapeHtml(title)}</strong>${
    message ? `<span>${escapeHtml(message)}</span>` : ""
  }</div>`;
  stack.appendChild(element);
  window.setTimeout(() => {
    element.style.transition = "opacity .2s ease";
    element.style.opacity = "0";
    window.setTimeout(() => element.remove(), 220);
  }, 5200);
}

let drawerCloseTimer = null;

export function openDrawer({ title, subtitle = "", body = "", footer = "" }) {
  const drawer = document.getElementById("drawer");
  const overlay = document.getElementById("drawerOverlay");
  if (!drawer || !overlay) return;
  if (drawerCloseTimer) {
    window.clearTimeout(drawerCloseTimer);
    drawerCloseTimer = null;
  }
  drawer.innerHTML = `<div class="drawer-head">
      <div><h3>${title}</h3>${subtitle ? `<div class="card-sub">${subtitle}</div>` : ""}</div>
      <button type="button" class="icon-button" data-drawer-close aria-label="Close panel">${icon("x")}</button>
    </div>
    <div class="drawer-body">${body}</div>
    ${footer ? `<div class="drawer-foot">${footer}</div>` : ""}`;
  drawer.classList.add("open");
  overlay.classList.add("open");
  document.body.classList.add("no-scroll");
  overlay.onclick = closeDrawer;
  drawer.querySelectorAll("[data-drawer-close]").forEach((button) => {
    button.addEventListener("click", closeDrawer);
  });
}

export function closeDrawer() {
  const drawer = document.getElementById("drawer");
  const overlay = document.getElementById("drawerOverlay");
  if (!drawer) return;
  drawer.classList.remove("open");
  overlay?.classList.remove("open");
  document.body.classList.remove("no-scroll");
  drawerCloseTimer = window.setTimeout(() => {
    if (!drawer.classList.contains("open")) drawer.innerHTML = "";
  }, 260);
}

export function openModal({ title, subtitle = "", body = "", footer = "", width = "620px", onMount = null }) {
  const overlay = document.createElement("div");
  overlay.className = "overlay open";
  overlay.setAttribute("data-modal-backdrop", "");
  const modal = document.createElement("div");
  modal.className = "modal open";
  modal.innerHTML = `<div class="modal-card" style="width:min(${width}, 96vw)">
      <div class="modal-head">
        <div><div class="card-title">${title}</div>${subtitle ? `<div class="card-sub">${subtitle}</div>` : ""}</div>
        <button type="button" class="icon-button" data-modal-close aria-label="Close dialog">${icon("x")}</button>
      </div>
      <div class="modal-body">${body}</div>
      ${footer ? `<div class="modal-body" style="padding-top:0;display:flex;justify-content:flex-end;gap:8px">${footer}</div>` : ""}
    </div>`;
  document.body.appendChild(overlay);
  document.body.appendChild(modal);
  document.body.classList.add("no-scroll");

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    overlay.classList.remove("open");
    modal.classList.remove("open");
    document.body.classList.remove("no-scroll");
    document.removeEventListener("keydown", onKey);
    window.setTimeout(() => {
      overlay.remove();
      modal.remove();
    }, 200);
  };
  const onKey = (event) => {
    if (event.key === "Escape") close();
  };
  overlay.addEventListener("click", close);
  modal.querySelectorAll("[data-modal-close]").forEach((button) => {
    button.addEventListener("click", close);
  });
  document.addEventListener("keydown", onKey);
  if (typeof onMount === "function") onMount(modal.querySelector(".modal-card"), close);
  return { close, element: modal };
}

export function confirmDialog({ title, message, confirmText = "Confirm", danger = false }) {
  return new Promise((resolve) => {
    const modal = openModal({
      title: escapeHtml(title),
      body: `<div class="callout ${danger ? "danger" : "info"}">${escapeHtml(message)}</div>`,
      width: "440px",
      footer: `<button type="button" class="btn" data-cancel>Cancel</button>
        <button type="button" class="btn ${danger ? "danger" : "primary"}" data-confirm>${escapeHtml(confirmText)}</button>`,
      onMount(card, close) {
        card.querySelector("[data-cancel]").addEventListener("click", () => {
          close();
          resolve(false);
        });
        card.querySelector("[data-confirm]").addEventListener("click", () => {
          close();
          resolve(true);
        });
      },
    });
    modal.element.addEventListener("click", (event) => {
      if (event.target.closest("[data-modal-close]") || event.target.classList.contains("overlay")) {
        resolve(false);
      }
    });
  });
}

export function renderPagination(element, meta, onPage) {
  if (!element) return;
  const page = Math.max(1, Number(meta.page) || 1);
  const pages = Math.max(1, Number(meta.pages) || 1);
  const total = Math.max(0, Number(meta.total) || 0);
  const pageSize = Number(meta.page_size || meta.pageSize) || 25;
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);
  const first = Math.max(1, Math.min(page - 2, pages - 4));
  const last = Math.min(pages, first + 4);
  const numbers = [];
  for (let index = first; index <= last; index += 1) numbers.push(index);

  element.innerHTML = `<span>Showing <strong style="color:var(--muted)">${fmtInt(start)}–${fmtInt(end)}</strong> of ${fmtInt(total)}</span>
    <div class="page-buttons">
      <button type="button" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""} aria-label="Previous page">${icon("chevron-left")}</button>
      ${numbers
        .map(
          (number) =>
            `<button type="button" data-page="${number}" class="${number === page ? "active" : ""}">${number}</button>`,
        )
        .join("")}
      <button type="button" data-page="${page + 1}" ${page >= pages ? "disabled" : ""} aria-label="Next page">${icon("chevron-right")}</button>
    </div>`;
  element.querySelectorAll("[data-page]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = Number(button.dataset.page);
      const disabled = button.hasAttribute("disabled");
      if (!disabled && target >= 1 && target <= pages && target !== page) onPage(target);
    });
  });
}

export function debounce(callback, delay = 300) {
  let timer = null;
  return (...args) => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => callback(...args), delay);
  };
}

export function setBusy(button, busy, label = "Working…") {
  if (!button) return;
  if (busy) {
    if (!button.dataset.originalHtml) button.dataset.originalHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span class="spinner"></span>${escapeHtml(label)}`;
  } else {
    button.disabled = false;
    if (button.dataset.originalHtml) {
      button.innerHTML = button.dataset.originalHtml;
      delete button.dataset.originalHtml;
    }
  }
}

export function downloadCsv(filename, rows, columns = null) {
  const list = Array.isArray(rows) ? rows : [];
  if (!list.length) {
    toast("Nothing to export", "The current dataset is empty.", "warning");
    return;
  }
  const keys = columns || Object.keys(list[0]);
  const cell = (value) => {
    const text = value === null || value === undefined ? "" : String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const content = [keys.map(cell).join(",")]
    .concat(list.map((row) => keys.map((key) => cell(row[key])).join(",")))
    .join("\r\n");
  const blob = new Blob([`\uFEFF${content}`], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}

export function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard
      .writeText(text)
      .then(() => toast("Copied", "The value was copied to the clipboard.", "success"))
      .catch(() => toast("Copy failed", "Clipboard access was denied.", "error"));
  } else {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand("copy");
      toast("Copied", "The value was copied to the clipboard.", "success");
    } catch {
      toast("Copy failed", "This browser blocked clipboard access.", "error");
    }
    area.remove();
  }
}

export function initials(name) {
  const text = String(name || "?").trim();
  const parts = text.split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
}

export function roleLabel(role) {
  return { admin: "Administrator", analyst: "Security Analyst", viewer: "Read-only Viewer" }[role] || titleCase(role);
}
