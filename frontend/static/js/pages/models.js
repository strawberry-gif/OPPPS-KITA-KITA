import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  badge,
  confirmDialog,
  emptyState,
  escapeHtml,
  fmtDateTime,
  fmtInt,
  fmtNumber,
  kv,
  metricTile,
  openModal,
  pageHead,
  ratioPct,
  setBusy,
  statCard,
  toast,
} from "../ui.js";
import { barChart } from "../charts.js";

const metric = (value) => (value === undefined || value === null ? "—" : fmtNumber(value, 4));

function confusionMatrix(labels, matrix, note) {
  if (!Array.isArray(matrix) || !Array.isArray(labels)) {
    return '<div class="dim" style="font-size:11px">No confusion matrix available.</div>';
  }
  const size = labels.length;
  return `<div class="confusion">
    <div class="confusion-grid" style="--n:${size}">
      <div class="confusion-cell head"></div>
      ${labels.map((label) => `<div class="confusion-cell head" title="${escapeHtml(label)}">${escapeHtml(label)}</div>`).join("")}
      ${matrix
        .map(
          (row, rowIndex) =>
            `<div class="confusion-cell head" title="${escapeHtml(labels[rowIndex])}" style="text-align:right;padding-right:7px">${escapeHtml(labels[rowIndex])}</div>` +
            row
              .map(
                (value, columnIndex) =>
                  `<div class="confusion-cell ${rowIndex === columnIndex ? "diag" : ""}" title="Actual ${escapeHtml(labels[rowIndex])} → predicted ${escapeHtml(labels[columnIndex])}">${fmtInt(value)}</div>`,
              )
              .join(""),
        )
        .join("")}
    </div>
    ${note ? `<div class="dim" style="font-size:10px;margin-top:8px;font-family:Inter,sans-serif">${escapeHtml(note)}</div>` : ""}
  </div>`;
}

function featureBars(topFeatures) {
  if (!topFeatures?.length) return '<div class="dim" style="font-size:11px">No feature importance data.</div>';
  const max = Math.max(...topFeatures.map((item) => Number(item.importance) || 0), 0.0001);
  return topFeatures
    .slice(0, 8)
    .map(
      (item) => `<div class="feature-bar">
        <span class="name mono">${escapeHtml(item.feature)}</span>
        <div class="bar"><div class="fill" style="width:${Math.max(2, ((Number(item.importance) || 0) / max) * 100)}%"></div></div>
        <span class="val">${fmtNumber(item.importance, 3)}</span>
      </div>`,
    )
    .join("");
}

export async function mount(container, ctx) {
  const isAdmin = ctx.user?.role === "admin";
  const alive = () => container.isConnected;
  let latestRun = null;
  let models = [];

  container.innerHTML = `${pageHead({
    title: "Model performance",
    description:
      "Held-out evaluation for the supervised classifiers and the Isolation Forest anomaly detector, with the exact artifacts and versions currently serving predictions.",
    actions: `<button type="button" class="btn" id="modelsRefresh">${icon("refresh")} Refresh</button>${
      isAdmin ? `<button type="button" class="btn primary" id="modelsTrain">${icon("cpu")} Train models</button>` : ""
    }`,
  })}<div id="modelsStats" class="stat-grid"></div><div id="modelsBody"></div>`;

  const statsRoot = container.querySelector("#modelsStats");
  const body = container.querySelector("#modelsBody");
  const refreshButton = container.querySelector("#modelsRefresh");

  async function load() {
    body.innerHTML = '<div class="skeleton" style="height:420px;border-radius:12px"></div>';
    try {
      const [modelsData, comparison] = await Promise.all([
        api.get("/api/models"),
        api.get("/api/models/comparison"),
      ]);
      if (!alive()) return;
      models = modelsData || [];
      latestRun = comparison?.latest_run || null;
      render();
    } catch (error) {
      if (!alive()) return;
      body.innerHTML = `<div class="card card-pad"><div class="callout danger"><strong>Unable to load model data.</strong><br />${escapeHtml(error.message)}</div></div>`;
      statsRoot.innerHTML = "";
    }
  }

  function render() {
    if (!latestRun) {
      statsRoot.innerHTML = "";
      body.innerHTML = `<div class="card card-pad">${emptyState(
        "cpu",
        "No training report found",
        "Train the models to generate evaluation metrics and model versions.",
      )}</div>`;
      return;
    }
    const comparison = latestRun.comparison || {};
    const classifierName = latestRun.selected_classifier || "—";
    const classifierMetrics =
      latestRun.classifier_metrics?.[classifierName]?.per_class?.accuracy ??
      latestRun.classifier_metrics?.[classifierName]?.accuracy ??
      comparison[classifierName]?.accuracy;
    const selected = latestRun.classifier_metrics?.[classifierName] || {};
    const anomaly = latestRun.anomaly_metrics || {};

    statsRoot.innerHTML = [
      statCard({
        label: "Selected classifier",
        value: escapeHtml(classifierName),
        iconName: "cpu",
        tone: "success",
        valueClass: "small",
        foot: "Highest weighted F1 on holdout",
      }),
      statCard({
        label: "Accuracy",
        value: metric(classifierMetrics),
        iconName: "target",
        foot: "Held-out test split",
      }),
      statCard({
        label: "Weighted F1",
        value: metric(selected.f1_weighted ?? comparison[classifierName]?.f1),
        iconName: "bar-chart",
        foot: "Weighted by class support",
      }),
      statCard({
        label: "Test rows",
        value: fmtInt(latestRun.test_rows),
        iconName: "layers",
        foot: `${fmtInt(latestRun.train_rows)} training rows`,
      }),
      statCard({
        label: "Training time",
        value: `${fmtNumber(latestRun.duration_seconds, 2)}s`,
        iconName: "clock",
        valueClass: "small",
        foot: "CPU only · no GPU required",
      }),
      statCard({
        label: "Trained",
        value: fmtDateTime(latestRun.trained_at).split(",")[0],
        iconName: "calendar",
        valueClass: "small",
        foot: escapeHtml(latestRun.version || ""),
      }),
    ].join("");

    const comparisonRows = Object.entries(comparison)
      .map(([algorithm, values]) => {
        const isSelected = algorithm === classifierName;
        const isAnomaly = algorithm === "IsolationForest";
        return `<tr>
          <td><span style="color:#e2e8f0;font-weight:550">${escapeHtml(algorithm)}</span><div class="dim" style="font-size:9.5px">${isAnomaly ? "Unsupervised anomaly detector" : "Supervised classifier"}</div></td>
          <td class="num">${metric(values.accuracy)}</td>
          <td class="num">${metric(values.precision)}</td>
          <td class="num">${metric(values.recall)}</td>
          <td class="num">${metric(values.f1)}</td>
          <td class="num">${metric(values.f1_macro)}</td>
          <td class="num">${metric(values.roc_auc)}</td>
          <td>${isSelected ? badge("SELECTED", "resolved") : isAnomaly ? badge("ANOMALY", "new") : badge("COMPARED", "outline")}</td>
        </tr>`;
      })
      .join("");

    const activeModels = models.filter((model) => model.is_active);
    const perClass = selected.per_class || {};
    const classRows = Object.entries(perClass)
      .filter(([label]) => !["accuracy", "macro avg", "weighted avg"].includes(label))
      .map(
        ([label, values]) => `<tr>
          <td>${badge(label, label === "BENIGN" ? "benign" : "attack")}</td>
          <td class="num">${metric(values.precision)}</td>
          <td class="num">${metric(values.recall)}</td>
          <td class="num">${metric(values["f1-score"])}</td>
          <td class="num">${fmtInt(values.support)}</td>
        </tr>`,
      )
      .join("");

    body.innerHTML = `
      <div class="grid grid-main">
        <div class="card">
          <div class="card-head"><div><div class="card-title">Latest training run</div><div class="card-sub">Reproducible evaluation metadata</div></div><span class="badge outline">${escapeHtml(latestRun.run_id?.slice(0, 12) || "run")}</span></div>
          <div class="card-body">
            <div class="kv-grid">
              ${kv("Dataset", `<span class="mono" style="font-size:10.5px">${escapeHtml(latestRun.dataset)}</span>`)}
              ${kv("Dataset rows", fmtInt(latestRun.dataset_rows))}
              ${kv("Train / test split", `${fmtInt(latestRun.train_rows)} / ${fmtInt(latestRun.test_rows)}`)}
              ${kv("Selected classifier", escapeHtml(classifierName))}
              ${kv("Random state", "42 (split before fitting)")}
              ${kv("Version", `<span class="mono">${escapeHtml(latestRun.version || "—")}</span>`)}
            </div>
            <div class="divider"></div>
            <div class="drawer-section-title">Dataset label distribution</div>
            <div class="row">${Object.entries(latestRun.label_distribution || {})
              .map(([label, count]) => `<span class="badge ${label === "BENIGN" ? "benign" : "attack"}">${escapeHtml(label)} · ${fmtInt(count)}</span>`)
              .join("")}</div>
            <div class="callout warning mt-16" style="font-size:10.5px">
              <strong>Leakage control.</strong> The train/test split happens before any fitting. Classifiers are fitted only on the training partition; Isolation Forest is fitted on benign training rows only. Ground-truth labels are never passed to the detection pipeline at prediction time.
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><div><div class="card-title">Algorithm comparison</div><div class="card-sub">Weighted F1 across candidates</div></div></div>
          <div class="card-body">
            <div class="chart-box" id="modelsF1"></div>
            <div class="callout info mt-16" style="font-size:10.5px">The active classifier is selected automatically by highest weighted F1 on the held-out test split. Isolation Forest is evaluated separately as a binary anomaly detector.</div>
          </div>
        </div>
      </div>

      <div class="card mt-16">
        <div class="card-head"><div><div class="card-title">Model comparison table</div><div class="card-sub">All metrics are computed on the same held-out test partition</div></div></div>
        <div class="table-wrap"><table class="data"><thead><tr>
          <th>Algorithm</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1 (weighted)</th><th>F1 (macro)</th><th>ROC-AUC</th><th>Status</th>
        </tr></thead><tbody>${comparisonRows}</tbody></table></div>
      </div>

      <div class="grid grid-2 mt-16">
        <div class="card">
          <div class="card-head"><div><div class="card-title">Active models</div><div class="card-sub">Serving the live detection pipeline</div></div>${activeModels.length ? badge("ACTIVE", "resolved") : badge("NONE", "critical")}</div>
          <div class="card-body">
            ${
              activeModels.length
                ? `<div class="stack">${activeModels
                    .map((model) => {
                      const metrics = model.metrics || {};
                      const taskMetrics =
                        model.task_type === "classification"
                          ? [
                              ["Accuracy", metric(metrics.accuracy)],
                              ["Weighted F1", metric(metrics.f1_weighted)],
                              ["Macro F1", metric(metrics.f1_macro)],
                              ["ROC-AUC", metric(metrics.roc_auc_ovr_weighted)],
                            ]
                          : [
                              ["Precision", metric(metrics.precision)],
                              ["Recall", metric(metrics.recall)],
                              ["F1", metric(metrics.f1)],
                              ["ROC-AUC", metric(metrics.roc_auc)],
                            ];
                      return `<div class="status-tile">
                        <div class="row-between"><div><div class="s-label">${model.task_type === "classification" ? "CLASSIFIER" : "ANOMALY"}</div><div class="s-value" style="font-size:14px;font-family:Inter,sans-serif">${escapeHtml(model.name)}</div></div><span class="badge outline">#${model.id}</span></div>
                        <div class="s-note mono">${escapeHtml(model.version)} · trained ${escapeHtml(fmtDateTime(model.trained_at))}</div>
                        <div class="metric-grid mt-12">${taskMetrics
                          .map(([label, value]) => metricTile(label, value))
                          .join("")}</div>
                      </div>`;
                    })
                    .join("")}</div>`
                : '<div class="empty-state">' + icon("cpu") + "<strong>No active model</strong><span>Train models or activate a version below.</span></div>"
            }
          </div>
        </div>

        <div class="card">
          <div class="card-head"><div><div class="card-title">Feature importance</div><div class="card-sub">Top signals used by ${escapeHtml(classifierName)}</div></div></div>
          <div class="card-body">${featureBars(selected.top_features)}</div>
        </div>
      </div>

      <div class="grid grid-2 mt-16">
        <div class="card">
          <div class="card-head"><div><div class="card-title">Classifier confusion matrix</div><div class="card-sub">Rows are ground truth, columns are predictions</div></div><span class="badge outline">${fmtInt(selected.test_rows)} test rows</span></div>
          <div class="card-body">${confusionMatrix(selected.labels, selected.confusion_matrix, "Counts from the held-out test split. Diagonal cells are correct predictions.")}</div>
        </div>
        <div class="card">
          <div class="card-head"><div><div class="card-title">Anomaly confusion matrix</div><div class="card-sub">Binary normal vs anomaly evaluation</div></div><span class="badge outline">${fmtInt(anomaly.test_rows)} test rows</span></div>
          <div class="card-body">
            ${confusionMatrix(anomaly.labels, anomaly.confusion_matrix, "Anomaly detection is unsupervised; labels are only used for evaluation, never for fitting.")}
            <div class="grid grid-2 mt-16">
              ${metricTile("Precision", metric(anomaly.precision))}
              ${metricTile("Recall", metric(anomaly.recall))}
              ${metricTile("F1", metric(anomaly.f1))}
              ${metricTile("ROC-AUC", metric(anomaly.roc_auc))}
            </div>
          </div>
        </div>
      </div>

      <div class="grid grid-main mt-16">
        <div class="card">
          <div class="card-head"><div><div class="card-title">Per-class performance</div><div class="card-sub">Precision, recall and F1 for ${escapeHtml(classifierName)}</div></div></div>
          <div class="table-wrap"><table class="data"><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr></thead><tbody>${classRows}</tbody></table></div>
        </div>
        <div class="card">
          <div class="card-head"><div><div class="card-title">Honest interpretation</div><div class="card-sub">Read before quoting these numbers</div></div></div>
          <div class="card-body">
            <div class="callout warning" style="font-size:10.5px">
              <strong>Dataset scope.</strong> The bundled training dataset is synthetic and CICIDS-inspired. These scores demonstrate that the pipeline learns and evaluates correctly; they are not a benchmark of real-world detection efficacy.<br /><br />
              <strong>Separation of concerns.</strong> Dataset ground-truth labels are stored with flow records and used only for held-out evaluation. Model predictions, anomaly flags and severity scores are produced independently at inference time.<br /><br />
              <strong>Anomaly caveat.</strong> An anomaly flag means the flow is statistically unusual, not that it is malicious. Isolation Forest precision and recall are considerably lower than the supervised classifier.
            </div>
            <div class="row mt-12">${badge("CPU-ONLY", "outline")}${badge("NO GPU", "outline")}${badge("HELD-OUT SPLIT", "outline")}</div>
          </div>
        </div>
      </div>

      <div class="card mt-16">
        <div class="card-head"><div><div class="card-title">Model versions</div><div class="card-sub">Stored artifacts and activation state</div></div><span class="badge outline">${fmtInt(models.length)} versions</span></div>
        <div class="table-wrap"><table class="data"><thead><tr><th>ID</th><th>Name</th><th>Algorithm</th><th>Task</th><th>Version</th><th>Training rows</th><th>F1 / primary</th><th>Active</th><th>Trained</th><th>Action</th></tr></thead><tbody>
          ${models
            .map((model) => {
              const metrics = model.metrics || {};
              const primary = model.task_type === "classification" ? metrics.f1_weighted : metrics.f1;
              return `<tr>
                <td class="num">#${model.id}</td>
                <td>${escapeHtml(model.name)}</td>
                <td>${escapeHtml(model.algorithm)}</td>
                <td>${badge(model.task_type, "outline")}</td>
                <td class="mono" style="font-size:10px">${escapeHtml(model.version)}</td>
                <td class="num">${fmtInt(model.training_rows)}</td>
                <td class="num">${metric(primary)}</td>
                <td>${model.is_active ? badge("ACTIVE", "resolved") : badge("INACTIVE", "outline")}</td>
                <td class="mono">${escapeHtml(fmtDateTime(model.trained_at))}</td>
                <td>${isAdmin && !model.is_active ? `<button type="button" class="btn sm" data-activate="${model.id}">Activate</button>` : '<span class="dim">—</span>'}</td>
              </tr>`;
            })
            .join("") || '<tr><td class="empty-cell" colspan="10">No model versions stored.</td></tr>'}
        </tbody></table></div>
      </div>`;

    barChart(
      "modelsF1",
      Object.entries(comparison).map(([algorithm, values]) => ({
        label: algorithm,
        count: Math.round((Number(values.f1) || 0) * 10000) / 100,
      })),
      { horizontal: false, height: 260, color: "#3b82f6" },
    );

    body.querySelectorAll("[data-activate]").forEach((button) => {
      button.addEventListener("click", async () => {
        const modelId = Number(button.dataset.activate);
        const model = models.find((item) => item.id === modelId);
        const confirmed = await confirmDialog({
          title: "Activate model version",
          message: `Activate ${model?.name || "this model"} (${model?.version || modelId})? The current active ${model?.task_type || "model"} of this type will be deactivated.`,
          confirmText: "Activate",
        });
        if (!confirmed) return;
        setBusy(button, true, "Activating…");
        try {
          await api.post(`/api/models/${modelId}/activate`);
          toast("Model activated", "The detection pipeline will load the new artifact.", "success");
          await load();
        } catch (error) {
          toast("Could not activate model", error.message, "error");
          setBusy(button, false);
        }
      });
    });
  }

  function openTrainModal() {
    if (!isAdmin) return;
    openModal({
      title: "Train detection models",
      subtitle: "CPU-only scikit-learn training on a dataset inside the datasets directory",
      width: "560px",
      body: `<div class="stack">
        <div class="field">
          <label for="trainDataset">Dataset path</label>
          <input class="input" id="trainDataset" value="${escapeHtml(latestRun?.dataset || "datasets\\processed\\train.csv")}" />
          <span class="dim" style="font-size:10.5px">Relative to the project root. Must be a CSV inside the datasets directory.</span>
        </div>
        <div class="grid grid-2">
          <div class="field"><label for="trainTestSize">Test size</label><input class="input" id="trainTestSize" type="number" min="0.1" max="0.4" step="0.05" value="0.25" /></div>
          <div class="field"><label for="trainRandomState">Random state</label><input class="input" id="trainRandomState" type="number" value="42" /></div>
        </div>
        <div class="callout warning" style="font-size:10.5px">Training fits Random Forest, Decision Tree and Isolation Forest, writes new artifacts, and activates the best classifier by weighted F1. The run is audited. The API blocks concurrent training runs.</div>
      </div>`,
      footer: `<button type="button" class="btn" data-cancel>Cancel</button><button type="button" class="btn primary" data-train>${icon("cpu")} Start training</button>`,
      onMount(card) {
        card.querySelector("[data-cancel]").addEventListener("click", () => card.closest(".modal")?.querySelector("[data-modal-close]")?.click());
        card.querySelector("[data-train]").addEventListener("click", async () => {
          const button = card.querySelector("[data-train]");
          const dataset = card.querySelector("#trainDataset").value.trim();
          const testSize = Number(card.querySelector("#trainTestSize").value);
          const randomState = Number(card.querySelector("#trainRandomState").value);
          setBusy(button, true, "Training…");
          try {
            const result = await api.post("/api/models/train", {
              dataset_path: dataset || null,
              test_size: testSize,
              random_state: randomState,
            });
            card.closest(".modal")?.querySelector("[data-modal-close]")?.click();
            toast(
              "Training complete",
              `${result.models.length} models registered in ${fmtNumber(result.duration_seconds, 2)}s.`,
              "success",
            );
            await load();
          } catch (error) {
            toast("Training failed", error.message, "error");
            setBusy(button, false);
          }
        });
      },
    });
  }

  refreshButton.addEventListener("click", load);
  container.querySelector("#modelsTrain")?.addEventListener("click", openTrainModal);

  await load();
  return () => {
    /* no background work */
  };
}
