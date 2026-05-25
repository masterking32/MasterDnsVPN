import { $, escapeHtml } from "../dom.js";

export function renderValidation(state) {
  const entries = [
    ...state.validations.errors.map((text) => ({ type: "error", text })),
    ...state.validations.warnings.map((text) => ({ type: "warn", text }))
  ];
  $("validation").innerHTML = entries.length ? entries.map((entry) => `
    <div class="validation-item"><span class="tag ${entry.type}">${entry.type}</span> ${escapeHtml(entry.text)}</div>
  `).join("") : `<div class="validation-item"><span class="tag ok">ok</span> No validation errors.</div>`;
}
