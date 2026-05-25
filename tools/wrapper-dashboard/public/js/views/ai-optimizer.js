import { $, escapeHtml } from "../dom.js";

export function renderAIOptimizer(state, actions) {
  const telemetry = state.telemetry || {};
  const context = telemetry.networkContext || state.dynamicRecommendations?.networkContext || {};
  const selector = $("networkContextSelect");
  if (selector) selector.value = context.selected || "unknown";
  const badge = $("networkContextBadge");
  if (badge) {
    badge.textContent = context.mixed ? "mixed log context detected" : (context.detected || "unknown");
    badge.className = `tag ${context.mixed ? "warn" : context.detected === "filtered" ? "running" : context.detected === "unfiltered" ? "ok" : ""}`;
  }
  const notes = context.notes || [];
  $("networkContextNotes").innerHTML = notes.length
    ? notes.map((note) => `<div class="validation-item"><span class="tag ${context.mixed ? "warn" : "ok"}">${context.mixed ? "warn" : "info"}</span> ${escapeHtml(note)}</div>`).join("")
    : "";
  const scores = telemetry.scores || {};
  const scoreRows = [
    ["Health", scores.healthScore],
    ["Active Resolvers", scores.activeResolverScore],
    ["MTU", scores.mtuScore],
    ["Compression", scores.compressionScore],
    ["Stream Pressure", scores.streamPressureScore]
  ];
  $("aiScores").innerHTML = scoreRows.map(([label, value]) => {
    const normalized = Number.isFinite(value) ? value : 0;
    return `
      <div class="score">
        <header><strong>${escapeHtml(label)}</strong><span>${normalized}/100</span></header>
        <div class="bar"><span style="width:${normalized}%"></span></div>
      </div>
    `;
  }).join("");

  const dynamic = state.dynamicRecommendations?.recommendations || [];
  $("dynamicRecommendations").innerHTML = dynamic.length ? dynamic.map((item) => {
    const evidenceId = `evidence-${item.id}`;
    const patchKeys = Object.keys(item.configPatch || {});
    return `
      <article class="recommendation dynamic-rec" data-id="${escapeHtml(item.id)}">
        <header>
          <b>${escapeHtml(item.id)}</b>
          <span class="tag ${severityTag(item.severity)}">${escapeHtml(item.severity)}</span>
        </header>
        <p>${escapeHtml(item.recommendation || item.condition || "Recommendation generated from current telemetry.")}</p>
        <div class="rec-meta">
          <span>confidence: ${escapeHtml(item.confidence || "medium")}</span>
          <span>${item.requiresRestart ? "restart required" : "live observation"}</span>
          <span>${patchKeys.length ? `patch: ${escapeHtml(patchKeys.join(", "))}` : "advisory"}</span>
        </div>
        <div class="rec-actions">
          <button type="button" data-preview="${escapeHtml(item.id)}">Preview</button>
          <button type="button" data-why="${escapeHtml(evidenceId)}">Why?</button>
          <button type="button" data-ignore="${escapeHtml(item.id)}">Ignore</button>
        </div>
        <ul id="${escapeHtml(evidenceId)}" class="evidence" hidden>
          ${(item.evidence || []).map((entry) => `<li>${escapeHtml(String(entry))}</li>`).join("") || "<li>No evidence captured yet.</li>"}
        </ul>
      </article>
    `;
  }).join("") : `<div class="validation-item"><span class="tag ok">ok</span> No dynamic recommendations yet.</div>`;

  $("dynamicRecommendations").querySelectorAll("[data-preview]").forEach((button) => {
    button.addEventListener("click", () => actions.previewDynamicPatch([button.dataset.preview]));
  });
  $("dynamicRecommendations").querySelectorAll("[data-why]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = $(button.dataset.why);
      if (target) target.hidden = !target.hidden;
    });
  });
  $("dynamicRecommendations").querySelectorAll("[data-ignore]").forEach((button) => {
    button.addEventListener("click", async () => {
      await actions.ignoreRecommendation(button.dataset.ignore);
    });
  });
}

export function setAIStatus(message, type) {
  $("aiOptimizerStatus").textContent = message;
  $("aiOptimizerStatus").className = `editor-status ${type || ""}`;
}

function severityTag(severity) {
  if (severity === "error") return "error";
  if (severity === "warn") return "warn";
  return "ok";
}
