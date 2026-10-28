import { $, escapeHtml } from "../dom.js";

export function renderResolvers(data) {
  $("resolverCount").textContent = `${data.filtered} shown from ${data.total}`;
  $("resolvers").innerHTML = data.items.map((item) => `
    <div class="resolver-row"><span>#${item.index}</span><span>${escapeHtml(item.value)}</span></div>
  `).join("");
}
