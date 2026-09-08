import { $, escapeHtml } from "../dom.js";

export function renderMonitor(state) {
  $("monitor").innerHTML = state.recommendations.monitor.map((item) => `
    <div class="validation-item">${escapeHtml(item)}</div>
  `).join("");
}
