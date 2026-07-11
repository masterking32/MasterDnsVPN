import { escapeHtml } from "./dom.js";

const tabs = [
  ["overview", "Overview"],
  ["optimizer", "Optimizer"],
  ["editor", "Editor"],
  ["resolvers", "Resolvers"],
  ["logs", "Logs"]
];

export function initTabs() {
  const nav = document.querySelector("[data-tabs]");
  if (!nav) return;
  nav.innerHTML = tabs.map(([id, label]) => `
    <button type="button" data-tab="${escapeHtml(id)}">${escapeHtml(label)}</button>
  `).join("");
  nav.querySelectorAll("[data-tab]").forEach((button) => {
    button.addEventListener("click", () => activateTab(button.dataset.tab));
  });
  const initial = location.hash.replace("#", "") || "overview";
  activateTab(tabs.some(([id]) => id === initial) ? initial : "overview", false);
}

export function activateTab(tab, updateHash = true) {
  document.querySelectorAll("[data-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === tab);
  });
  document.querySelectorAll("[data-tab-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.tabPanel !== tab;
  });
  if (updateHash) history.replaceState(null, "", `#${tab}`);
}
