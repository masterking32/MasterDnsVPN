import { get, post, postJson } from "./js/api.js";
import { $, escapeHtml } from "./js/dom.js";
import { connectEvents } from "./js/events.js";
import { dashboardState, setEditorDirty, setResolverFilter, setState } from "./js/state.js";
import { initTabs } from "./js/tabs.js";
import { renderAIOptimizer, setAIStatus } from "./js/views/ai-optimizer.js";
import { renderRecommendations, renderProfileHint } from "./js/views/config-optimizer.js";
import {
  parseResolvers,
  renderEditorFiles,
  renderSaveResult,
  setEditorStatus,
  updateEditorResolverCount
} from "./js/views/editor.js";
import { renderLogs } from "./js/views/logs.js";
import { renderMonitor } from "./js/views/monitor.js";
import { renderOverview } from "./js/views/overview.js";
import { renderStages } from "./js/views/plan-board.js";
import { renderResolvers } from "./js/views/resolvers.js";
import { renderValidation } from "./js/views/validation.js";

window.addEventListener("DOMContentLoaded", () => {
  bindControls();
  initTabs();
  connectEvents({
    refresh,
    loadEditor,
    isEditorDirty: () => dashboardState.editorDirty
  });
  refresh();
  loadEditor();
  setInterval(() => {
    if (!document.hidden) refresh();
  }, 5000);
});

function bindControls() {
  $("refreshBtn").addEventListener("click", refresh);
  $("startBtn").addEventListener("click", () => post("/api/start").then(refresh));
  $("stopBtn").addEventListener("click", () => post("/api/stop").then(refresh));
  $("previewBtn").addEventListener("click", previewBalanced);
  $("applyBtn").addEventListener("click", () => post("/api/apply-balanced").then(refresh));
  $("smokeBtn").addEventListener("click", () => post("/api/smoke").then(refresh));
  $("previewDynamicBtn").addEventListener("click", previewDynamicPatch);
  $("copyAIContextBtn").addEventListener("click", copyAIContext);
  $("exportGoodResolversBtn").addEventListener("click", () => exportGoodResolvers());
  $("exportFilteredResolversBtn").addEventListener("click", () => exportGoodResolvers("filtered"));
  $("exportUnfilteredResolversBtn").addEventListener("click", () => exportGoodResolvers("unfiltered"));
  $("networkContextSelect").addEventListener("change", setNetworkContext);
  $("reloadEditorBtn").addEventListener("click", loadEditor);
  $("stripCommentsBtn").addEventListener("click", stripConfigComments);
  $("dedupeResolversBtn").addEventListener("click", dedupeResolverEditor);
  $("saveEditorBtn").addEventListener("click", saveEditor);
  $("configEditor").addEventListener("input", () => {
    setEditorDirty(true);
    setEditorStatus("Unsaved TOML edits.", "");
  });
  $("resolverEditor").addEventListener("input", () => {
    setEditorDirty(true);
    updateEditorResolverCount();
    setEditorStatus("Unsaved resolver edits.", "");
  });
  $("resolverFilter").addEventListener("input", (event) => {
    setResolverFilter(event.target.value);
    loadResolvers();
  });
  document.querySelectorAll(".profile-tabs button").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".profile-tabs button").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      renderProfileHint(button.dataset.profile);
    });
  });
}

async function refresh() {
  setState(await get("/api/state"));
  render();
  await loadResolvers();
}

function render() {
  const state = dashboardState.state;
  $("subtitle").textContent = `${state.facts.version || "Unknown version"} | ${state.app.root}`;
  renderOverview(state);
  renderStages(state);
  renderRecommendations(state);
  renderAIOptimizer(state, { previewDynamicPatch, ignoreRecommendation });
  renderValidation(state);
  renderLogs(state);
  renderMonitor(state);
  updateEditorResolverCount();
}

async function loadResolvers() {
  const data = await get(`/api/resolvers?offset=${dashboardState.resolverOffset}&limit=250&q=${encodeURIComponent(dashboardState.resolverFilter)}`);
  renderResolvers(data);
}

async function loadEditor() {
  const data = await get("/api/editor");
  renderEditorFiles(data);
  setEditorDirty(false);
}

async function saveEditor() {
  const payload = {
    configText: $("configEditor").value,
    resolverText: $("resolverEditor").value,
    restart: $("restartAfterSave").checked
  };
  const result = await postJson("/api/save-editor", payload);
  renderSaveResult(result);
  if (!result.saved) return;
  setEditorDirty(false);
  await refresh();
  await loadResolvers();
}

async function stripConfigComments() {
  const result = await postJson("/api/strip-config-comments", { configText: $("configEditor").value });
  $("configEditor").value = result.configText;
  setEditorDirty(true);
  setEditorStatus("TOML comments removed in the editor. Save to write the file.", "");
}

function dedupeResolverEditor() {
  const resolvers = parseResolvers($("resolverEditor").value);
  $("resolverEditor").value = resolvers.join("\n") + "\n";
  setEditorDirty(true);
  updateEditorResolverCount();
  setEditorStatus("Resolver duplicates removed in the editor. Save to write the file.", "");
}

async function previewBalanced() {
  const data = await get("/api/preview-balanced");
  $("diff").textContent = data.diff.length
    ? data.diff.map((row) => `${row.type === "add" ? "+" : "-"}${row.line}: ${row.text}`).join("\n")
    : "Balanced recommendations are already applied.";
}

async function previewDynamicPatch(ids = null) {
  const selectedIds = Array.isArray(ids)
    ? ids
    : (dashboardState.state.dynamicRecommendations?.recommendations || []).map((item) => item.id);
  const data = await postJson("/api/recommendations/preview-patch", { ids: selectedIds });
  $("dynamicDiff").textContent = data.diff.length
    ? data.diff.map((row) => `${row.type === "add" ? "+" : "-"}${row.line}: ${row.text}`).join("\n")
    : data.explanation || "Selected dynamic recommendations do not change TOML.";
  setAIStatus(data.explanation || (data.changed ? "Preview generated. Nothing was saved." : "No TOML change for this selection."), data.changed ? "ok" : "");
}

async function copyAIContext() {
  const data = await get("/api/ai-context");
  const text = JSON.stringify(data, null, 2);
  try {
    await navigator.clipboard.writeText(text);
    setAIStatus("AI context copied with ENCRYPTION_KEY masked.", "ok");
  } catch {
    $("dynamicDiff").textContent = text;
    setAIStatus("Clipboard unavailable. AI context rendered below.", "");
  }
}

async function exportGoodResolvers(context = null) {
  const data = await postJson("/api/resolvers/export-good", { context });
  setAIStatus(`Exported ${data.count} ${data.context} known-good resolvers to ${data.file}.`, "ok");
}

async function setNetworkContext(event) {
  const data = await postJson("/api/network-context", { context: event.target.value });
  setAIStatus(`Network context set to ${data.selected}.`, data.mixed ? "warn" : "ok");
  await refresh();
}

async function ignoreRecommendation(id) {
  await postJson("/api/recommendations/ignore", { id });
  setAIStatus(`Ignored ${id}.`, "");
  await refresh();
}
