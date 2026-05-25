import { $, escapeHtml } from "../dom.js";

export function renderStages(state) {
  $("stages").innerHTML = state.stages.map((stage) => `
    <article class="stage">
      <header>
        <b>${escapeHtml(stage.title)}</b>
        <span class="tag ${escapeHtml(stage.status)}">${escapeHtml(stage.status)}</span>
      </header>
      <p>${escapeHtml(stage.target)}</p>
      <div class="bar"><span style="width:${stage.progress}%"></span></div>
    </article>
  `).join("");
}
