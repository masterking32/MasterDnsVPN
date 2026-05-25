import { $, escapeHtml } from "../dom.js";

export function renderRecommendations(state) {
  $("recommendations").innerHTML = state.recommendations.items.map((item) => {
    const changed = item.current !== item.recommended;
    const tag = item.requiresServerChange ? "warn" : changed ? "running" : "ok";
    const label = item.requiresServerChange ? "server coordinated" : changed ? "pending" : "applied";
    return `
      <article class="recommendation">
        <header>
          <b>${escapeHtml(item.key)}</b>
          <span class="tag ${tag}">${label}</span>
        </header>
        <strong>Current -> Recommended</strong>
        <code>${escapeHtml(JSON.stringify(item.current))} -> ${escapeHtml(JSON.stringify(item.recommended))}</code>
        <p>${escapeHtml(item.rationale)}</p>
      </article>
    `;
  }).join("");
}

export function renderProfileHint(profile) {
  const hints = {
    balanced: "Balanced is the active direct-apply profile.",
    speed: "Speed: use lower duplication only after logs show stable resolver behavior.",
    reliability: "Reliability: increase duplication and retries when retransmits/timeouts dominate.",
    scanner: "Scanner: use equal MTU bounds and clean resolver export for dedicated resolver testing.",
    debug: "Debug: temporarily raise LOG_LEVEL to DEBUG while collecting troubleshooting logs."
  };
  $("diff").textContent = hints[profile] || "";
}
