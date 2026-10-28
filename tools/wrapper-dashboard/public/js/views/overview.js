import { $, escapeHtml } from "../dom.js";

export function renderOverview(state) {
  const rows = [
    ["Status", state.runtime.status],
    ["PID", state.runtime.pid || "-"],
    ["Uptime", `${state.runtime.uptimeSeconds}s`],
    ["Proxy", state.facts.proxy],
    ["Resolvers", state.facts.resolverCount],
    ["Local DNS", state.facts.localDnsEnabled ? "enabled" : "disabled"]
  ];
  $("overview").innerHTML = rows.map(([label, value]) => `
    <div class="metric"><strong>${escapeHtml(label)}</strong>${escapeHtml(String(value))}</div>
  `).join("");
}
