import { api, auth, logout } from "./api.js";
import { closeDrawer, initials, roleLabel, toast } from "./ui.js";
import { destroyAllCharts } from "./charts.js";
import { icon } from "./icons.js";
import * as overview from "./pages/overview.js";
import * as monitor from "./pages/monitor.js";
import * as traffic from "./pages/traffic.js";
import * as detection from "./pages/detection.js";
import * as ips from "./pages/ips.js";
import * as incidents from "./pages/incidents.js";
import * as analytics from "./pages/analytics.js";
import * as models from "./pages/models.js";
import * as settings from "./pages/settings.js";

const ROUTES = {
  overview: {
    label: "Overview",
    kicker: "Command center",
    title: "Security overview",
    icon: "grid",
    page: overview,
  },
  monitor: {
    label: "Network Monitoring",
    kicker: "Operations",
    title: "Live network monitoring",
    icon: "radio",
    page: monitor,
  },
  traffic: {
    label: "Traffic Analysis",
    kicker: "Operations",
    title: "Network traffic",
    icon: "network",
    page: traffic,
  },
  detection: {
    label: "Threat Detection",
    kicker: "Operations",
    title: "Threat detection",
    icon: "shield-alert",
    page: detection,
  },
  ips: {
    label: "Suspicious IPs",
    kicker: "Response",
    title: "Suspicious IP intelligence",
    icon: "globe",
    page: ips,
  },
  incidents: {
    label: "Security Incidents",
    kicker: "Response",
    title: "Security incidents",
    icon: "alert-triangle",
    page: incidents,
    badge: true,
  },
  analytics: {
    label: "Analytics",
    kicker: "Intelligence",
    title: "Security analytics",
    icon: "bar-chart",
    page: analytics,
  },
  models: {
    label: "Model Performance",
    kicker: "Intelligence",
    title: "Model performance",
    icon: "cpu",
    page: models,
  },
  settings: {
    label: "Settings",
    kicker: "System",
    title: "Settings & administration",
    icon: "sliders",
    page: settings,
  },
};

const NAV_GROUPS = [
  { label: "Operations", items: ["overview", "monitor", "traffic", "detection"] },
  { label: "Response", items: ["ips", "incidents"] },
  { label: "Intelligence", items: ["analytics", "models"] },
  { label: "System", items: ["settings"] },
];

const view = document.getElementById("view");
const pageTitle = document.getElementById("pageTitle");
const pageKicker = document.getElementById("pageKicker");
const navRoot = document.getElementById("navRoot");
const sidebar = document.getElementById("sidebar");
const sidebarOverlay = document.getElementById("sidebarOverlay");
const menuToggle = document.getElementById("menuToggle");
const logoutButton = document.getElementById("logoutButton");
const clock = document.getElementById("clock");
const healthChip = document.getElementById("healthChip");
const healthChipText = document.getElementById("healthChipText");
const sideStatus = document.getElementById("sideStatus");
const sideStatusText = document.getElementById("sideStatusText");

let currentUser = null;
let renderToken = 0;
let currentCleanup = null;
let clockTimer = null;
let healthTimer = null;
let badgeTimer = null;

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, queryString] = raw.split("?");
  const id = (path || "overview").replace(/\/+$/, "") || "overview";
  const params = new URLSearchParams(queryString || "");
  return { id, params };
}

function navigate(id, params = null) {
  const query = params ? `?${new URLSearchParams(params).toString()}` : "";
  location.hash = `#/${id}${query}`;
}

function closeSidebar() {
  sidebar?.classList.remove("open");
  sidebarOverlay?.classList.remove("open");
}

function bindChrome() {
  menuToggle.innerHTML = icon("menu");
  logoutButton.innerHTML = icon("log-out");
  menuToggle.addEventListener("click", () => {
    sidebar.classList.toggle("open");
    sidebarOverlay.classList.toggle("open");
  });
  sidebarOverlay.addEventListener("click", closeSidebar);
  logoutButton.addEventListener("click", () => {
    auth.clear();
    location.replace("/login");
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeSidebar();
      closeDrawer();
    }
  });
}

function renderNavigation() {
  navRoot.innerHTML = NAV_GROUPS.map(
    (group) => `<div class="nav-label">${group.label}</div>${group.items
      .map((id) => {
        const route = ROUTES[id];
        return `<a class="nav-link" href="#/${id}" data-route="${id}">
          ${icon(route.icon)}
          <span>${route.label}</span>
          ${route.badge ? '<span class="nav-badge hidden" id="navIncidentBadge">0</span>' : ""}
        </a>`;
      })
      .join("")}`,
  ).join("");
  navRoot.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", closeSidebar);
  });
}

function fillUser() {
  if (!currentUser) return;
  const name = currentUser.full_name || currentUser.email;
  document.getElementById("userAvatar").textContent = initials(name);
  document.getElementById("userName").textContent = name;
  document.getElementById("userRole").textContent = roleLabel(currentUser.role);
}

function setActiveNav(routeId) {
  navRoot.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.toggle("active", link.dataset.route === routeId);
  });
}

function startClock() {
  const format = () => {
    const now = new Date();
    const date = now.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
    const time = now.toLocaleTimeString("en-GB", { hour12: false });
    clock.textContent = `${date} · ${time}`;
  };
  format();
  clockTimer = window.setInterval(format, 1000);
}

function setHealth(health) {
  if (!health) {
    healthChip.className = "health-chip down";
    healthChipText.textContent = "API offline";
    sideStatus.className = "side-status degraded";
    sideStatusText.textContent = "API server unreachable";
    return;
  }
  const healthy = health.database === "connected";
  const ready = Boolean(health.models_ready);
  healthChip.className = `health-chip ${healthy && ready ? "" : "degraded"}`;
  healthChipText.textContent = healthy
    ? ready
      ? "All systems operational"
      : "Models unavailable"
    : "Database unavailable";
  sideStatus.className = `side-status ${healthy ? "" : "degraded"}`;
  sideStatusText.textContent = healthy
    ? ready
      ? "Detection engine online"
      : "Detection engine not ready"
    : "Database connection lost";
}

async function refreshHealth() {
  try {
    const health = await api.get("/api/dashboard/health");
    setHealth(health);
    window.__opppsHealth = health;
  } catch {
    setHealth(null);
  }
}

async function refreshIncidentBadge() {
  const badge = document.getElementById("navIncidentBadge");
  if (!badge) return;
  try {
    const data = await api.get("/api/incidents", { page: 1, page_size: 1, status: "NEW" });
    const total = Number(data.total) || 0;
    badge.textContent = total > 99 ? "99+" : String(total);
    badge.classList.toggle("hidden", total === 0);
  } catch {
    badge.classList.add("hidden");
  }
}

function loadingView() {
  return `<div class="stack">
    <div class="skeleton" style="height:76px;border-radius:12px"></div>
    <div class="stat-grid">
      ${Array.from({ length: 6 })
        .map(() => '<div class="skeleton" style="height:106px;border-radius:12px"></div>')
        .join("")}
    </div>
    <div class="grid grid-main">
      <div class="skeleton" style="height:330px;border-radius:12px"></div>
      <div class="skeleton" style="height:330px;border-radius:12px"></div>
    </div>
  </div>`;
}

function errorView(error) {
  return `<div class="card card-pad" style="max-width:640px;margin:48px auto;text-align:center">
    <div class="stat-icon critical" style="margin:0 auto 14px;width:40px;height:40px;border-radius:10px">${icon("alert-triangle")}</div>
    <h2 style="font-size:17px">This view could not be loaded</h2>
    <p class="muted" style="font-size:12.5px;margin-top:8px">${error?.message ? String(error.message).replace(/</g, "&lt;") : "An unexpected error occurred."}</p>
    <div class="row" style="justify-content:center;margin-top:18px">
      <button type="button" class="btn primary" id="retryRoute">${icon("refresh")} Retry</button>
      <button type="button" class="btn" id="openOverview">Go to overview</button>
    </div>
  </div>`;
}

async function renderRoute() {
  const token = ++renderToken;
  const { id, params } = parseHash();
  const routeId = ROUTES[id] ? id : "overview";
  const route = ROUTES[routeId];

  if (location.hash.replace(/^#\/?/, "").split("?")[0] !== routeId) {
    history.replaceState(null, "", `#/${routeId}${params.toString() ? `?${params}` : ""}`);
  }

  setActiveNav(routeId);
  pageTitle.textContent = route.title;
  pageKicker.textContent = route.kicker;

  if (typeof currentCleanup === "function") {
    try {
      currentCleanup();
    } catch {
      /* ignore cleanup failures */
    }
    currentCleanup = null;
  }
  destroyAllCharts();
  closeDrawer();
  closeSidebar();

  const pageRoot = document.createElement("div");
  view.replaceChildren(pageRoot);
  pageRoot.innerHTML = loadingView();

  try {
    const cleanup = await route.page.mount(pageRoot, {
      user: currentUser,
      params,
      navigate,
      refreshHealth,
    });
    if (token !== renderToken) return;
    if (typeof cleanup === "function") currentCleanup = cleanup;
  } catch (error) {
    if (token !== renderToken) return;
    if (error?.status === 401) return;
    pageRoot.innerHTML = errorView(error);
    pageRoot.querySelector("#retryRoute")?.addEventListener("click", renderRoute);
    pageRoot.querySelector("#openOverview")?.addEventListener("click", () => navigate("overview"));
    if (error?.status !== 403) {
      toast("Failed to load page", error?.message || "Unexpected error", "error");
    }
  }
}

async function boot() {
  if (!auth.isAuthenticated) {
    location.replace("/login");
    return;
  }
  try {
    currentUser = await api.get("/api/auth/me");
    auth.setUser(currentUser);
  } catch {
    auth.clear();
    location.replace("/login");
    return;
  }

  bindChrome();
  renderNavigation();
  fillUser();
  startClock();
  await refreshHealth();
  try {
    const appSettings = await api.get("/api/settings");
    window.__opppsDefaults = appSettings?.values || {};
  } catch {
    window.__opppsDefaults = {};
  }
  refreshIncidentBadge();

  healthTimer = window.setInterval(refreshHealth, 30000);
  badgeTimer = window.setInterval(refreshIncidentBadge, 60000);

  if (!location.hash) history.replaceState(null, "", "#/overview");
  await renderRoute();

  window.addEventListener("hashchange", renderRoute);
  window.addEventListener("beforeunload", () => {
    if (clockTimer) window.clearInterval(clockTimer);
    if (healthTimer) window.clearInterval(healthTimer);
    if (badgeTimer) window.clearInterval(badgeTimer);
  });
}

boot();
