import { $, escapeHtml } from "../dom.js";

export function setEditorStatus(message, type) {
  $("editorStatus").textContent = message;
  $("editorStatus").className = `editor-status ${type || ""}`;
}

export function parseResolvers(text) {
  const seen = new Set();
  const resolvers = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (seen.has(line)) continue;
    seen.add(line);
    resolvers.push(line);
  }
  return resolvers;
}

export function updateEditorResolverCount() {
  const el = $("editorResolverCount");
  if (!el) return;
  el.textContent = `(${parseResolvers($("resolverEditor").value || "").length})`;
}

export function renderEditorFiles(data) {
  $("configEditor").value = data.configText;
  $("resolverEditor").value = data.resolverText;
  updateEditorResolverCount();
  setEditorStatus("Editor loaded from client_config.toml and client_resolvers.txt.", "ok");
}

export function renderSaveResult(result) {
  if (!result.saved) {
    setEditorStatus(result.errors.map((entry) => escapeHtml(entry)).join(" "), "error");
    return;
  }
  const warningText = result.warnings?.length ? ` Warnings: ${result.warnings.join(" ")}` : "";
  setEditorStatus(`${result.message} Resolvers saved: ${result.resolverCount}.${warningText}`, "ok");
}
