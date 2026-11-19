import { emptyState, fmtInt } from "./ui.js";

export const PALETTE = {
  primary: "#3b82f6",
  primarySoft: "rgba(59, 130, 246, 0.16)",
  success: "#22c55e",
  warning: "#f59e0b",
  critical: "#ef4444",
  high: "#fb7185",
  purple: "#8b5cf6",
  cyan: "#06b6d4",
  muted: "#94a3b8",
  dim: "#64748b",
  grid: "rgba(36, 49, 74, 0.55)",
  bg: "#172033",
};

const CATEGORY_COLORS = [
  "#3b82f6",
  "#22c55e",
  "#f59e0b",
  "#ef4444",
  "#8b5cf6",
  "#06b6d4",
  "#fb7185",
  "#84cc16",
  "#f97316",
  "#a78bfa",
  "#14b8a6",
  "#eab308",
];

const registry = new Map();
let defaultsApplied = false;

function applyDefaults() {
  if (defaultsApplied || !window.Chart) return;
  const Chart = window.Chart;
  Chart.defaults.color = "#94a3b8";
  Chart.defaults.font.family = '"Inter", sans-serif';
  Chart.defaults.font.size = 11;
  Chart.defaults.borderColor = PALETTE.grid;
  Chart.defaults.animation.duration = 650;
  defaultsApplied = true;
}

function baseOptions(height) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    layout: { padding: { top: 4, right: 4, bottom: 0, left: 0 } },
    plugins: {
      legend: {
        display: true,
        position: "bottom",
        align: "start",
        labels: {
          usePointStyle: true,
          pointStyle: "rectRounded",
          boxWidth: 7,
          boxHeight: 7,
          padding: 14,
          color: "#94a3b8",
          font: { size: 10.5 },
        },
      },
      tooltip: {
        backgroundColor: "#0f172a",
        borderColor: "#2b3b57",
        borderWidth: 1,
        titleColor: "#f8fafc",
        bodyColor: "#cbd5e1",
        titleFont: { size: 11, weight: "600" },
        bodyFont: { size: 11 },
        padding: 10,
        cornerRadius: 7,
        displayColors: true,
        boxPadding: 4,
        callbacks: {
          label(context) {
            const label = context.dataset?.label || context.label || "";
            return ` ${label}: ${fmtInt(context.parsed?.y ?? context.parsed?.x ?? context.parsed)}`;
          },
        },
      },
    },
    scales: {
      x: {
        grid: { display: false, drawBorder: false },
        ticks: { color: "#64748b", maxRotation: 0, autoSkip: true, maxTicksLimit: 9, font: { size: 10 } },
        border: { display: false },
      },
      y: {
        beginAtZero: true,
        grid: { color: PALETTE.grid, drawBorder: false },
        ticks: {
          color: "#64748b",
          precision: 0,
          maxTicksLimit: 6,
          font: { size: 10 },
          callback: (value) => fmtInt(value),
        },
        border: { display: false },
      },
    },
  };
}

function chartHost(canvasId) {
  return document.getElementById(canvasId);
}

function showEmpty(host, iconName, title, message, height = 220) {
  if (!host) return;
  host.style.height = "auto";
  host.style.minHeight = `${height}px`;
  host.innerHTML = emptyState(iconName, title, message);
}

function canvasFor(canvasId, height) {
  const host = chartHost(canvasId);
  if (!host) return null;
  if (host.tagName === "CANVAS") {
    const parent = host.parentElement;
    if (parent) {
      parent.style.height = `${height}px`;
      parent.style.minHeight = `${height}px`;
    }
    return host;
  }
  let canvas = host.querySelector("canvas");
  if (!canvas) {
    canvas = document.createElement("canvas");
    canvas.setAttribute("role", "img");
    host.replaceChildren(canvas);
  }
  host.style.height = `${height}px`;
  host.style.minHeight = `${height}px`;
  return canvas;
}

export function destroyChart(canvasId) {
  const existing = registry.get(canvasId);
  if (existing) {
    existing.destroy();
    registry.delete(canvasId);
  }
}

export function destroyAllCharts() {
  registry.forEach((chart) => chart.destroy());
  registry.clear();
}

export function createChart(canvasId, config, height = 260) {
  if (!window.Chart) {
    showEmpty(
      chartHost(canvasId),
      "bar-chart",
      "Chart unavailable",
      "Chart.js could not be loaded from the local vendor bundle.",
      height,
    );
    return null;
  }
  applyDefaults();
  const canvas = canvasFor(canvasId, height);
  if (!canvas) return null;
  destroyChart(canvasId);
  const chart = new window.Chart(canvas.getContext("2d"), config);
  registry.set(canvasId, chart);
  return chart;
}

function gradient(context, colorTop, colorBottom) {
  const chart = context.chart;
  const { ctx, chartArea } = chart;
  if (!chartArea) return colorTop;
  const fill = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
  fill.addColorStop(0, colorTop);
  fill.addColorStop(1, colorBottom);
  return fill;
}

function bucketLabels(points, hourly) {
  return points.map((point) => {
    const date = new Date(point.bucket);
    if (Number.isNaN(date.getTime())) return point.bucket;
    if (hourly) {
      return date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
    }
    return date.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
  });
}

export function timelineChartId(canvasId, points, { hourly = false, height = 280, showTotal = true } = {}) {
  const total = (points || []).reduce((sum, point) => sum + (point.total || 0), 0);
  if (!points || !points.length || total === 0) {
    showEmpty(
      chartHost(canvasId),
      "activity",
      "No traffic in this range",
      "Import a dataset or start passive capture to populate the timeline.",
      260,
    );
    return null;
  }
  const labels = bucketLabels(points, hourly);
  const datasets = [];
  if (showTotal) {
    datasets.push({
      label: "Total flows",
      data: points.map((point) => point.total || 0),
      borderColor: PALETTE.primary,
      backgroundColor(context) {
        const { ctx, chartArea } = context.chart;
        if (!chartArea) return PALETTE.primarySoft;
        const fill = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
        fill.addColorStop(0, "rgba(59, 130, 246, 0.28)");
        fill.addColorStop(1, "rgba(59, 130, 246, 0.01)");
        return fill;
      },
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 4,
      pointHoverBackgroundColor: PALETTE.primary,
      pointHoverBorderColor: "#0b1120",
      pointHoverBorderWidth: 2,
      fill: true,
      tension: 0.35,
      order: 3,
    });
  }
  datasets.push(
    {
      label: "Predicted attacks",
      data: points.map((point) => point.attacks || 0),
      borderColor: PALETTE.critical,
      backgroundColor: "rgba(239, 68, 68, 0.1)",
      borderWidth: 1.8,
      pointRadius: 0,
      pointHoverRadius: 4,
      fill: false,
      tension: 0.35,
      order: 1,
    },
    {
      label: "Anomalies",
      data: points.map((point) => point.anomalies || 0),
      borderColor: PALETTE.warning,
      backgroundColor: "rgba(245, 158, 11, 0.08)",
      borderWidth: 1.6,
      pointRadius: 0,
      pointHoverRadius: 4,
      borderDash: [4, 3],
      fill: false,
      tension: 0.35,
      order: 2,
    },
  );
  const options = baseOptions(height);
  options.plugins.tooltip.callbacks.label = (context) => ` ${context.dataset.label}: ${fmtInt(context.parsed.y)}`;
  return createChart(
    canvasId,
    { type: "line", data: { labels, datasets }, options },
    height,
  );
}

export function donutChart(canvasId, items, { height = 230, colors = null, cutout = "68%" } = {}) {
  const filtered = (items || []).filter((item) => Number(item.count) > 0);
  const total = filtered.reduce((sum, item) => sum + Number(item.count), 0);
  if (!filtered.length || total === 0) {
    showEmpty(chartHost(canvasId), "inbox", "No data", "Nothing to chart for the selected range.", 220);
    return null;
  }
  const options = baseOptions(height);
  options.scales = {};
  options.cutout = cutout;
  options.plugins.tooltip.callbacks.label = (context) => {
    const value = Number(context.parsed) || 0;
    const share = total ? (value / total) * 100 : 0;
    return ` ${context.label}: ${fmtInt(value)} (${share.toFixed(1)}%)`;
  };
  options.plugins.legend.labels.padding = 10;
  return createChart(
    canvasId,
    {
      type: "doughnut",
      data: {
        labels: filtered.map((item) => item.label),
        datasets: [
          {
            data: filtered.map((item) => Number(item.count)),
            backgroundColor: filtered.map(
              (item, index) => colors?.[item.label] || CATEGORY_COLORS[index % CATEGORY_COLORS.length],
            ),
            borderColor: "#172033",
            borderWidth: 2,
            hoverOffset: 4,
          },
        ],
      },
      options,
    },
    height,
  );
}

export function barChart(canvasId, items, { horizontal = false, height = 250, color = PALETTE.primary, colors = null, maxBarThickness = 26 } = {}) {
  const filtered = (items || []).filter((item) => Number(item.count) > 0);
  if (!filtered.length) {
    showEmpty(
      chartHost(canvasId),
      "bar-chart",
      "No data",
      "No observations were recorded for this range.",
      230,
    );
    return null;
  }
  const options = baseOptions(height);
  if (horizontal) {
    options.indexAxis = "y";
    options.scales = {
      x: {
        beginAtZero: true,
        grid: { color: PALETTE.grid, drawBorder: false },
        ticks: { color: "#64748b", precision: 0, font: { size: 10 }, callback: (value) => fmtInt(value) },
        border: { display: false },
      },
      y: {
        grid: { display: false, drawBorder: false },
        ticks: { color: "#94a3b8", font: { size: 10.5 }, autoSkip: false },
        border: { display: false },
      },
    };
    options.plugins.legend.display = false;
  } else {
    options.plugins.legend.display = false;
  }
  options.plugins.tooltip.callbacks.label = (context) => {
    const value = horizontal ? context.parsed.x : context.parsed.y;
    return ` ${fmtInt(value)}`;
  };
  return createChart(
    canvasId,
    {
      type: "bar",
      data: {
        labels: filtered.map((item) => item.label),
        datasets: [
          {
            data: filtered.map((item) => Number(item.count)),
            backgroundColor: filtered.map(
              (item, index) =>
                colors?.[item.label] ||
                (Array.isArray(colors) ? colors[index % colors.length] : color),
            ),
            borderRadius: 4,
            maxBarThickness,
          },
        ],
      },
      options,
    },
    height,
  );
}

export const severityColors = {
  CRITICAL: "#ef4444",
  HIGH: "#fb7185",
  MEDIUM: "#f59e0b",
  LOW: "#38bdf8",
  INFORMATIONAL: "#64748b",
};
