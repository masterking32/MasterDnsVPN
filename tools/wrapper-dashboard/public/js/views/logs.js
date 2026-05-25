import { $, escapeHtml } from "../dom.js";

export function renderLogs(state) {
  $("events").innerHTML = state.parsedEvents.slice(-8).reverse().map((event) => `
    <div class="event"><span class="tag">${escapeHtml(event.type)}</span> ${escapeHtml(event.line)}</div>
  `).join("") || `<div class="event">No parsed run events yet.</div>`;
  $("logs").textContent = state.logs.map((entry) => `${entry.time} ${entry.source} ${entry.line}`).join("\n");
}
