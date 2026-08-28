const state = {
  view: "dashboard",
  queryMode: "auto",
  history: [],
};

const HISTORY_KEY = "ska_history_v1";

/* ---------- clock ---------- */

function tickClock() {
  const el = document.getElementById("clock");
  const now = new Date();
  el.textContent = now.toISOString().slice(0, 19).replace("T", " ") + " UTC";
}
tickClock();
setInterval(tickClock, 1000);

/* ---------- navigation ---------- */

const navItems = document.querySelectorAll(".nav-item");
const views = {
  dashboard: document.getElementById("view-dashboard"),
  query: document.getElementById("view-query"),
  cvebrowser: document.getElementById("view-cvebrowser"),
  browser: document.getElementById("view-browser"),
  history: document.getElementById("view-history"),
};
const topstripTitle = document.getElementById("topstrip-title");
const railToggle = document.getElementById("rail-toggle");
const rail = document.getElementById("rail");

const VIEW_TITLES = {
  dashboard: "Dashboard",
  query: "Query",
  cvebrowser: "CVE Browser",
  browser: "Framework Browser",
  history: "Session History",
};

function showView(view, qmode) {
  state.view = view;
  Object.entries(views).forEach(([key, el]) => {
    el.hidden = key !== view;
  });
  topstripTitle.textContent = VIEW_TITLES[view];

  navItems.forEach((btn) => {
    const matches =
      btn.dataset.view === view &&
      (view !== "query" || btn.dataset.mode === (qmode || state.queryMode));
    btn.classList.toggle("active", matches);
    if (matches) btn.setAttribute("aria-current", "page"); else btn.removeAttribute("aria-current");
  });

  if (view === "query" && qmode) {
    setQueryMode(qmode);
  }
  if (view === "browser" && !browserLoaded) {
    loadFrameworkBrowser();
  }
  if (view === "cvebrowser" && !cveBrowserLoaded) {
    cveBrowserLoaded = true;
    loadCveBrowser();
  }
  if (view === "history") {
    renderHistory();
  }

  setRailOpen(false);
}

navItems.forEach((btn) => {
  btn.addEventListener("click", () => showView(btn.dataset.view, btn.dataset.mode));
});

function setRailOpen(open) {
  rail.classList.toggle("open", open);
  // Belt-and-braces: drive the transform directly from JS too, so this can
  // never be silently defeated by a CSS specificity/cascade surprise — an
  // inline style always wins over an external stylesheet rule.
  rail.style.transform = open ? "translateX(0)" : "";
}

railToggle.addEventListener("click", () => setRailOpen(!rail.classList.contains("open")));

document.addEventListener("click", (e) => {
  if (
    rail.classList.contains("open") &&
    !rail.contains(e.target) &&
    e.target !== railToggle &&
    !railToggle.contains(e.target)
  ) {
    setRailOpen(false);
  }
});

/* ---------- dashboard ---------- */

function setArc(id, fraction) {
  const el = document.getElementById(id);
  if (!el) return;
  const circumference = 176;
  const offset = circumference - Math.max(0, Math.min(1, fraction)) * circumference;
  el.style.transition = "stroke-dashoffset 900ms cubic-bezier(0.16, 1, 0.3, 1)";
  requestAnimationFrame(() => { el.style.strokeDashoffset = offset; });
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEVERITY_CLASS = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };

async function loadDashboard() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    document.getElementById("gauge-cve-value").textContent = data.cve_total.toLocaleString();
    document.getElementById("gauge-ctrl-value").textContent = data.compliance_total.toLocaleString();
    document.getElementById("gauge-fw-value").textContent = Object.keys(data.framework_counts).length;

    const critical = data.severity_counts.CRITICAL || 0;
    document.getElementById("gauge-crit-value").textContent = critical.toLocaleString();

    const importanceText = document.getElementById("importance-text");
    importanceText.textContent =
      `${data.high_severity_total.toLocaleString()} indexed CVEs are Critical or High severity. ` +
      `${data.linked_controls} of ${data.compliance_total} tracked compliance controls cross-link to a weakness type ` +
      `actually present in this index right now — those are the controls this index can tell you, with citations, ` +
      `that a real vulnerability implicates today.`;

    document.getElementById("rail-cve-count").textContent = data.cve_total.toLocaleString();
    document.getElementById("rail-control-count").textContent = data.compliance_total.toLocaleString();
    document.getElementById("topstrip-cves").textContent = data.cve_total.toLocaleString();
    document.getElementById("topstrip-controls").textContent = data.compliance_total.toLocaleString();

    setArc("gauge-cve-arc", 1);
    setArc("gauge-ctrl-arc", 1);
    setArc("gauge-fw-arc", Math.min(1, Object.keys(data.framework_counts).length / 6));
    // Critical CVEs are a small slice of any real-world index, so a raw
    // critical/total fraction reads as an always-empty dial. Show the dial
    // scaled against total *high-severity* volume (a legible band) and put
    // the true percentage of the whole index in the sub-label instead.
    const criticalOfHighSeverity = data.high_severity_total ? critical / data.high_severity_total : 0;
    setArc("gauge-crit-arc", criticalOfHighSeverity);
    const critPct = data.cve_total ? ((critical / data.cve_total) * 100).toFixed(1) : "0.0";
    document.querySelector('.gauge-panel:has(#gauge-crit-value) .gauge-sub').textContent = `${critPct}% OF INDEX`;

    const total = Object.values(data.severity_counts).reduce((a, b) => a + b, 0) || 1;
    const bar = document.getElementById("severity-bar");
    const legend = document.getElementById("severity-legend");
    bar.innerHTML = "";
    legend.innerHTML = "";

    const knownKeys = [...SEVERITY_ORDER, ...Object.keys(data.severity_counts).filter(k => !SEVERITY_ORDER.includes(k))];
    knownKeys.forEach((key) => {
      const count = data.severity_counts[key];
      if (!count) return;
      const cls = SEVERITY_CLASS[key] || "unknown";
      const seg = document.createElement("div");
      seg.className = `severity-seg ${cls}`;
      seg.style.width = `${(count / total) * 100}%`;
      bar.appendChild(seg);

      const chip = document.createElement("div");
      chip.className = "severity-chip";
      chip.innerHTML = `<span class="severity-swatch ${cls}"></span>${key} &mdash; ${count.toLocaleString()}`;
      legend.appendChild(chip);
    });

    const fwList = document.getElementById("framework-list");
    fwList.innerHTML = "";
    Object.entries(data.framework_counts).forEach(([name, count]) => {
      const row = document.createElement("div");
      row.className = "framework-row";
      row.innerHTML = `<span class="framework-name">${name}</span><span class="framework-count">${count}</span>`;
      fwList.appendChild(row);
    });
  } catch (err) {
    console.error("dashboard load failed", err);
    document.getElementById("importance-text").textContent =
      "Could not load index stats — the backend may still be starting up. Retrying shortly…";
    setTimeout(loadDashboard, 5000);
  }
}

/* ---------- minimal markdown (LLM answers only: bold/italic/code/lists/links) ---------- */

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function renderMarkdown(raw) {
  const escaped = escapeHtml(raw);
  const lines = escaped.split("\n");
  let html = "";
  let inList = false;

  const inline = (text) => text
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(?<!\*)\*([^*\n]+)\*(?!\*)/g, "<em>$1</em>")
    .replace(/\((CVE-\d{4}-\d{4,7})\)/g, `(<a href="https://nvd.nist.gov/vuln/detail/$1" target="_blank" rel="noopener noreferrer" class="inline-cve-link">$1</a>)`);

  for (const line of lines) {
    const bulletMatch = /^\s*[-*]\s+(.*)/.exec(line);
    if (bulletMatch) {
      if (!inList) { html += "<ul>"; inList = true; }
      html += `<li>${inline(bulletMatch[1])}</li>`;
      continue;
    }
    if (inList) { html += "</ul>"; inList = false; }
    if (line.trim() === "") { html += "<br/>"; continue; }
    html += `<p>${inline(line)}</p>`;
  }
  if (inList) html += "</ul>";
  return html;
}

/* ---------- query / transmission log ---------- */

const queryForm = document.getElementById("query-form");
const queryInput = document.getElementById("query-input");
const transmissionLog = document.getElementById("transmission-log");
const modeBtns = document.querySelectorAll(".mode-btn");
const queryTitle = document.getElementById("query-title");
const querySub = document.getElementById("query-sub");

const MODE_META = {
  auto: { title: "Query — Auto Route", sub: "Ask a question; the console routes it to the right retrieval domain.", placeholder: "Ask anything — CVEs or compliance controls..." },
  cve: { title: "Query — CVE Search", sub: "Grounded Q&A over indexed NVD CVE records.", placeholder: "e.g. What CVEs affect Apache 2.4.49?" },
  compliance: { title: "Query — Compliance Docs", sub: "Grounded Q&A over NIST / CIS / ISO / SOC 2 controls.", placeholder: "e.g. What does NIST say about vulnerability scanning?" },
};

function setQueryMode(mode) {
  state.queryMode = mode;
  modeBtns.forEach((b) => b.classList.toggle("active", b.dataset.qmode === mode));
  const meta = MODE_META[mode];
  queryTitle.textContent = meta.title;
  querySub.textContent = meta.sub;
  queryInput.placeholder = meta.placeholder;
  if (!transmissionLog.querySelector(".transmission")) {
    renderEmptyState();
  }
}

modeBtns.forEach((btn) => {
  btn.addEventListener("click", () => setQueryMode(btn.dataset.qmode));
});

function clearEmptyLog() {
  const empty = transmissionLog.querySelector(".empty-log, .example-questions");
  if (empty) empty.remove();
}

const EXAMPLE_QUESTIONS = {
  auto: ["What CVEs affect Apache 2.4.49?", "What does NIST say about vulnerability scanning?"],
  cve: ["What is Log4Shell and what CVE is it?", "What CVEs affect OpenSSL Heartbleed?"],
  compliance: ["What does CIS Control 7 require?", "How does NIST 800-53 address audit logging?"],
};

function renderEmptyState() {
  transmissionLog.innerHTML = "";
  const wrap = document.createElement("div");
  wrap.className = "example-questions";
  wrap.innerHTML = `<div class="foot-label" style="margin-bottom:8px;">TRY ONE OF THESE</div>`;
  (EXAMPLE_QUESTIONS[state.queryMode] || EXAMPLE_QUESTIONS.auto).forEach((q) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "example-chip";
    chip.textContent = q;
    chip.addEventListener("click", () => submitQuery(q));
    wrap.appendChild(chip);
  });
  transmissionLog.appendChild(wrap);
}

function addQueryTransmission(question) {
  clearEmptyLog();
  const el = document.createElement("div");
  el.className = "transmission";
  el.innerHTML = `
    <div class="transmission-head">
      <span class="transmission-tag query">Query</span>
      <span>${new Date().toLocaleTimeString()}</span>
    </div>
    <div class="transmission-body query-text"></div>
  `;
  el.querySelector(".query-text").textContent = question;
  transmissionLog.prepend(el);
  return el;
}

const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/;

function sourceChipHtml(source) {
  if (CVE_ID_RE.test(source)) {
    return `<a class="source-chip" href="https://nvd.nist.gov/vuln/detail/${source}" target="_blank" rel="noopener noreferrer">${source}</a>`;
  }
  return `<span class="source-chip">${escapeHtml(source)}</span>`;
}

function contextPanelHtml(retrievedContext) {
  if (!retrievedContext || !retrievedContext.length) return "";
  const items = retrievedContext.map((doc) => {
    const meta = doc.metadata || {};
    const metaBits = [];
    if (meta.severity) metaBits.push(`<span class="sev-badge ${(SEV_CLASS && SEV_CLASS[meta.severity]) || "unknown"}">${escapeHtml(meta.severity)}</span>`);
    if (meta.framework) metaBits.push(escapeHtml(meta.framework));
    return `
      <details class="context-item">
        <summary><span class="context-id">${escapeHtml(doc.id)}</span>${metaBits.length ? `<span class="context-meta">${metaBits.join(" ")}</span>` : ""}</summary>
        <div class="context-text">${escapeHtml(doc.text)}</div>
      </details>`;
  }).join("");
  return `
    <details class="context-panel">
      <summary class="context-panel-summary">📄 Show retrieved context (${retrievedContext.length} passage${retrievedContext.length > 1 ? "s" : ""} the model was given)</summary>
      <div class="context-panel-body">${items}</div>
    </details>`;
}

function metricsRowHtml(data) {
  const bits = [];
  if (data.timing) {
    bits.push(`${data.timing.retrieval_ms}ms retrieval`);
    if (data.timing.generation_ms) bits.push(`${(data.timing.generation_ms / 1000).toFixed(1)}s generation`);
  }
  if (data.usage) {
    bits.push(`${data.usage.input_tokens.toLocaleString()} in / ${data.usage.output_tokens.toLocaleString()} out tokens`);
  }
  return bits.length ? `<div class="metrics-row">${bits.join(" · ")}</div>` : "";
}

function buildFootHtml(data, routedTo) {
  let footHtml = "";
  if (routedTo) {
    footHtml += `<div class="foot-row"><span class="foot-label">Routed</span><span class="route-chip">${escapeHtml(routedTo)}</span></div>`;
  }
  if (data.sources && data.sources.length) {
    footHtml += `<div class="foot-row"><span class="foot-label">Sources</span>${data.sources.map(sourceChipHtml).join("")}</div>`;
  }
  if (data.related_controls && data.related_controls.length) {
    footHtml += `<div class="foot-row"><span class="foot-label">Route → Controls</span>${data.related_controls.map(c => `<span class="route-chip">${escapeHtml(c.framework)} ${escapeHtml(c.control_id)}</span>`).join("")}</div>`;
  }
  if (data.hallucinated_ids && data.hallucinated_ids.length) {
    footHtml += `<div class="warn-row">⚠ Unverified citation flagged and not trusted: ${escapeHtml(data.hallucinated_ids.join(", "))}</div>`;
  }
  if (data.error) {
    footHtml += `<div class="warn-row">⚠ ${escapeHtml(data.error)}</div>`;
  }
  footHtml += contextPanelHtml(data.retrieved_context);
  footHtml += metricsRowHtml(data);
  return footHtml;
}

function renderAnswerBlock(question, domain, data, routedTo) {
  const el = document.createElement("div");
  el.className = "transmission transmission-enter";
  const tagClass = domain === "compliance" ? "compliance" : "cve";
  const tagLabel = domain === "compliance" ? "Compliance" : "CVE";
  const footHtml = buildFootHtml(data, routedTo);

  el.innerHTML = `
    <div class="transmission-head">
      <span class="transmission-tag ${tagClass}">${tagLabel}</span>
      <span>${new Date().toLocaleTimeString()}</span>
    </div>
    <div class="transmission-body"></div>
    ${footHtml ? `<div class="transmission-foot">${footHtml}</div>` : ""}
  `;
  el.querySelector(".transmission-body").innerHTML = renderMarkdown(data.answer || data.error || "No response.");
  transmissionLog.prepend(el);
  requestAnimationFrame(() => el.classList.add("transmission-enter-active"));
}

/* ---------- streaming answer block ---------- */

function createStreamingBlock(domain) {
  const el = document.createElement("div");
  el.className = "transmission transmission-enter";
  const tagClass = domain === "compliance" ? "compliance" : "cve";
  const tagLabel = domain === "compliance" ? "Compliance" : "CVE";
  el.innerHTML = `
    <div class="transmission-head">
      <span class="transmission-tag ${tagClass}">${tagLabel}</span>
      <span>${new Date().toLocaleTimeString()}</span>
    </div>
    <div class="stage-line" hidden></div>
    <div class="transmission-body"><span class="stream-cursor"></span></div>
  `;
  transmissionLog.prepend(el);
  requestAnimationFrame(() => el.classList.add("transmission-enter-active"));
  return {
    el,
    bodyEl: el.querySelector(".transmission-body"),
    stageEl: el.querySelector(".stage-line"),
    raw: "",
  };
}

function setStage(block, message) {
  block.stageEl.hidden = false;
  block.stageEl.innerHTML = `<span class="stage-spinner"></span>${escapeHtml(message)}`;
}

function appendStreamingChunk(block, chunk) {
  block.stageEl.hidden = true;
  block.raw += chunk;
  block.bodyEl.innerHTML = renderMarkdown(block.raw) + '<span class="stream-cursor"></span>';
}

function finalizeStreamingBlock(block, data, routedTo) {
  block.stageEl.hidden = true;
  block.bodyEl.innerHTML = renderMarkdown(data.answer || block.raw || "No response.");
  const footHtml = buildFootHtml(data, routedTo);
  if (footHtml) {
    const foot = document.createElement("div");
    foot.className = "transmission-foot";
    foot.innerHTML = footHtml;
    block.el.appendChild(foot);
  }
}

function streamQuery(question, endpoint, domain, routedToLabel) {
  return new Promise((resolve) => {
    const block = createStreamingBlock(domain);
    const url = `${endpoint}?question=${encodeURIComponent(question)}`;
    const source = new EventSource(url);
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      source.close();
      resolve();
    };

    source.addEventListener("stage", (e) => {
      setStage(block, JSON.parse(e.data).message);
    });
    source.addEventListener("delta", (e) => {
      appendStreamingChunk(block, JSON.parse(e.data).text);
    });
    source.addEventListener("done", (e) => {
      const data = JSON.parse(e.data);
      finalizeStreamingBlock(block, data, routedToLabel || data.routed_to);
      pushHistory(question, data.domain || domain);
      finish();
    });
    source.addEventListener("stream_error", (e) => {
      const data = JSON.parse(e.data);
      finalizeStreamingBlock(block, { ...data, answer: block.raw }, routedToLabel);
      showToast(data.error || "The language model backend returned an error.", "error");
      pushHistory(question, "error");
      finish();
    });
    // Native EventSource "error": fires on a dropped/failed connection itself
    // (not a server-reported error — that's "stream_error" above). If we
    // already have partial or full text, keep it and just stop the spinner;
    // only show a hard failure message when nothing came through at all.
    source.addEventListener("error", () => {
      if (!block.raw) {
        finalizeStreamingBlock(block, { error: "Streaming connection failed or was interrupted." }, routedToLabel);
        showToast("Could not reach the console backend. Check your connection and try again.", "error");
        pushHistory(question, "error");
      } else {
        finalizeStreamingBlock(block, { answer: block.raw }, routedToLabel);
        pushHistory(question, domain);
      }
      finish();
    });
  });
}

const STREAM_ENDPOINTS = {
  auto: "/api/query/stream",
  cve: "/api/query/cve/stream",
  compliance: "/api/query/compliance/stream",
};

function streamAutoQuery(question) {
  return new Promise((resolve) => {
    const url = `${STREAM_ENDPOINTS.auto}?question=${encodeURIComponent(question)}`;
    const source = new EventSource(url);
    let settled = false;
    const finish = () => { if (!settled) { settled = true; source.close(); resolve(); } };

    // Single-domain path: one streaming block, filled in once the router's
    // choice ("meta") tells us which tag/color to render it under.
    let singleBlock = null;
    // Ambiguous ("both") path: two separate blocks, no token streaming —
    // see the /api/query/stream docstring for why.
    let cveBlock = null;
    let complianceBlock = null;
    const bothLabel = "both (ambiguous — merged CVE + compliance)";

    source.addEventListener("meta", (e) => {
      const { routed_to } = JSON.parse(e.data);
      if (routed_to === "both") {
        cveBlock = createStreamingBlock("cve");
        complianceBlock = createStreamingBlock("compliance");
        setStage(cveBlock, "Ambiguous question — querying both domains…");
        setStage(complianceBlock, "Ambiguous question — querying both domains…");
      } else {
        singleBlock = createStreamingBlock(routed_to);
      }
    });
    source.addEventListener("stage", (e) => {
      // Only the single-domain path streams stage progress; the ambiguous
      // "both" path resolves both pipelines in one blocking call server-side.
      if (singleBlock) setStage(singleBlock, JSON.parse(e.data).message);
    });
    source.addEventListener("delta", (e) => {
      if (singleBlock) appendStreamingChunk(singleBlock, JSON.parse(e.data).text);
    });
    source.addEventListener("done", (e) => {
      const data = JSON.parse(e.data);
      if (singleBlock) finalizeStreamingBlock(singleBlock, data, `auto → ${data.domain}`);
      pushHistory(question, data.domain);
      finish();
    });
    source.addEventListener("done_cve", (e) => {
      if (cveBlock) finalizeStreamingBlock(cveBlock, JSON.parse(e.data), bothLabel);
    });
    source.addEventListener("done_compliance", (e) => {
      if (complianceBlock) finalizeStreamingBlock(complianceBlock, JSON.parse(e.data), bothLabel);
      pushHistory(question, "both");
      finish();
    });
    source.addEventListener("stream_error", (e) => {
      const data = JSON.parse(e.data);
      if (singleBlock) finalizeStreamingBlock(singleBlock, { ...data, answer: singleBlock.raw }, null);
      if (cveBlock) finalizeStreamingBlock(cveBlock, data, bothLabel);
      if (complianceBlock) finalizeStreamingBlock(complianceBlock, data, bothLabel);
      if (!singleBlock && !cveBlock && !complianceBlock) renderAnswerBlock(question, "cve", data);
      showToast(data.error || "The language model backend returned an error.", "error");
      pushHistory(question, "error");
      finish();
    });
    source.addEventListener("error", () => {
      const fallback = { error: "Streaming connection failed or was interrupted." };
      if (!singleBlock?.raw && !cveBlock?.raw && !complianceBlock?.raw) {
        showToast("Could not reach the console backend. Check your connection and try again.", "error");
      }
      if (singleBlock && !singleBlock.raw) finalizeStreamingBlock(singleBlock, fallback, null);
      else if (singleBlock) finalizeStreamingBlock(singleBlock, { answer: singleBlock.raw }, null);
      if (cveBlock && !cveBlock.raw) finalizeStreamingBlock(cveBlock, fallback, bothLabel);
      if (complianceBlock && !complianceBlock.raw) finalizeStreamingBlock(complianceBlock, fallback, bothLabel);
      if (!singleBlock && !cveBlock && !complianceBlock) renderAnswerBlock(question, "cve", fallback);
      pushHistory(question, "error");
      finish();
    });
  });
}

async function submitQuery(question) {
  addQueryTransmission(question);
  const mode = state.queryMode;
  queryInput.disabled = true;
  const submitBtn = queryForm.querySelector(".query-submit");
  submitBtn.disabled = true;
  submitBtn.textContent = "Transmitting…";

  try {
    if (mode === "auto") {
      await streamAutoQuery(question);
    } else {
      await streamQuery(question, STREAM_ENDPOINTS[mode], mode, null);
    }
  } finally {
    queryInput.disabled = false;
    submitBtn.disabled = false;
    submitBtn.textContent = "Transmit";
    queryInput.focus();
  }
}

queryForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const q = queryInput.value.trim();
  if (!q) return;
  queryInput.value = "";
  submitQuery(q);
});

/* ---------- history (localStorage) ---------- */

function loadHistory() {
  try {
    state.history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    state.history = [];
  }
}

function pushHistory(question, domain) {
  state.history.unshift({ question, domain, time: new Date().toISOString() });
  state.history = state.history.slice(0, 100);
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history));
  } catch {
    /* storage unavailable in this viewer; history stays in-memory only */
  }
  if (state.view === "history") renderHistory();
}

function renderHistory() {
  const list = document.getElementById("history-list");
  list.innerHTML = "";
  if (!state.history.length) {
    list.innerHTML = `<div class="empty-log">NO HISTORY YET</div>`;
    return;
  }
  state.history.forEach((item) => {
    const row = document.createElement("div");
    row.className = "history-row";
    const t = new Date(item.time);
    row.innerHTML = `
      <span class="history-time">${t.toLocaleDateString()} ${t.toLocaleTimeString()}</span>
      <span class="history-question"></span>
      <span class="transmission-tag ${item.domain === "compliance" ? "compliance" : "cve"}">${item.domain}</span>
    `;
    row.querySelector(".history-question").textContent = item.question;
    row.addEventListener("click", () => {
      showView("query", item.domain === "compliance" ? "compliance" : "auto");
      queryInput.value = item.question;
      queryInput.focus();
    });
    list.appendChild(row);
  });
}

document.getElementById("history-clear").addEventListener("click", () => {
  state.history = [];
  try { localStorage.removeItem(HISTORY_KEY); } catch { /* no-op */ }
  renderHistory();
});

/* ---------- framework browser (legend + route) ---------- */

let browserLoaded = false;
let allControls = [];
let activeFrameworkFilter = null;

async function loadFrameworkBrowser() {
  try {
    const res = await fetch("/api/controls");
    allControls = await res.json();
    browserLoaded = true;

    const frameworks = [...new Set(allControls.map(c => c.framework))];
    const filterBar = document.getElementById("framework-filters");
    filterBar.innerHTML = "";
    const allBtn = document.createElement("button");
    allBtn.className = "legend-filter active";
    allBtn.textContent = "ALL";
    allBtn.addEventListener("click", () => setFrameworkFilter(null));
    filterBar.appendChild(allBtn);

    frameworks.forEach((fw) => {
      const btn = document.createElement("button");
      btn.className = "legend-filter";
      btn.textContent = fw.toUpperCase();
      btn.addEventListener("click", () => setFrameworkFilter(fw));
      filterBar.appendChild(btn);
    });

    renderLegendTable();
  } catch (err) {
    console.error("framework browser load failed", err);
  }
}

function setFrameworkFilter(fw) {
  activeFrameworkFilter = fw;
  document.querySelectorAll(".legend-filter").forEach((btn) => {
    btn.classList.toggle("active", (fw === null && btn.textContent === "ALL") || btn.textContent === (fw || "").toUpperCase());
  });
  renderLegendTable();
}

function renderLegendTable() {
  const table = document.getElementById("legend-table");
  table.querySelectorAll(".legend-row:not(.legend-header)").forEach(r => r.remove());

  const rows = activeFrameworkFilter
    ? allControls.filter(c => c.framework === activeFrameworkFilter)
    : allControls;

  rows.forEach((c) => {
    const row = document.createElement("div");
    row.className = "legend-row";
    const cweHtml = (c.cwe_links || []).map(id => `<span class="cwe-chip">${id}</span>`).join("") || "<span class=\"cwe-chip\">none</span>";
    row.innerHTML = `
      <span class="legend-id">${c.control_id}</span>
      <span class="legend-framework">${c.framework}</span>
      <span class="legend-title-cell">${c.title}<span class="legend-desc"></span></span>
      <span class="legend-cwe">${cweHtml}</span>
    `;
    row.querySelector(".legend-desc").textContent = c.text.length > 160 ? c.text.slice(0, 160) + "…" : c.text;
    table.appendChild(row);
  });
}

/* ---------- CVE browser ---------- */

let cveBrowserLoaded = false;
const cveState = { q: "", severity: "", sort: "published_desc", offset: 0, limit: 50, total: 0 };
let cveSearchDebounce = null;

const SEV_CLASS = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };

let cveRequestSeq = 0;

async function loadCveBrowser() {
  const params = new URLSearchParams({
    q: cveState.q,
    severity: cveState.severity,
    sort: cveState.sort,
    limit: cveState.limit,
    offset: cveState.offset,
  });
  const requestId = ++cveRequestSeq;
  try {
    const res = await fetch(`/api/cves?${params}`);
    const data = await res.json();
    if (requestId !== cveRequestSeq) return; // a newer request superseded this one
    cveState.total = data.total;
    renderCveTable(data.results);

    const label = document.getElementById("cve-count-label");
    const shown = data.results.length ? `${cveState.offset + 1}–${cveState.offset + data.results.length}` : "0";
    label.textContent = `SHOWING ${shown} OF ${data.total.toLocaleString()}`;

    document.getElementById("cve-prev").disabled = cveState.offset === 0;
    document.getElementById("cve-next").disabled = cveState.offset + cveState.limit >= data.total;
  } catch (err) {
    console.error("cve browser load failed", err);
  }
}

function renderCveTable(rows) {
  const table = document.getElementById("cve-table");
  table.querySelectorAll(".legend-row:not(.legend-header)").forEach((r) => r.remove());

  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "empty-log";
    empty.textContent = "NO MATCHING CVEs";
    table.appendChild(empty);
    return;
  }

  rows.forEach((cve) => {
    const row = document.createElement("div");
    row.className = "legend-row";
    row.style.gridTemplateColumns = "150px 90px 70px 1fr 130px";
    const sevClass = SEV_CLASS[cve.severity] || "unknown";
    const publishedDate = cve.published ? cve.published.slice(0, 10) : "—";
    row.innerHTML = `
      <span class="legend-id">${cve.cve_id}</span>
      <span><span class="sev-badge ${sevClass}">${cve.severity}</span></span>
      <span class="cve-score">${cve.score >= 0 ? cve.score.toFixed(1) : "—"}</span>
      <span class="cve-summary"></span>
      <span class="cve-published">${publishedDate}</span>
    `;
    row.querySelector(".cve-summary").textContent = cve.summary;
    row.style.cursor = "pointer";
    row.addEventListener("click", () => {
      showView("query", "cve");
      queryInput.value = `Tell me about ${cve.cve_id}`;
      submitQuery(queryInput.value);
      queryInput.value = "";
    });
    table.appendChild(row);
  });
}

document.getElementById("cve-search").addEventListener("input", (e) => {
  clearTimeout(cveSearchDebounce);
  cveSearchDebounce = setTimeout(() => {
    cveState.q = e.target.value.trim();
    cveState.offset = 0;
    loadCveBrowser();
  }, 350);
});

document.querySelectorAll("#view-cvebrowser .legend-filter[data-sev]").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#view-cvebrowser .legend-filter[data-sev]").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    cveState.severity = btn.dataset.sev;
    cveState.offset = 0;
    loadCveBrowser();
  });
});

document.querySelectorAll("#view-cvebrowser .legend-filter[data-sort]").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#view-cvebrowser .legend-filter[data-sort]").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    cveState.sort = btn.dataset.sort;
    cveState.offset = 0;
    loadCveBrowser();
  });
});

document.getElementById("cve-prev").addEventListener("click", () => {
  cveState.offset = Math.max(0, cveState.offset - cveState.limit);
  loadCveBrowser();
});
document.getElementById("cve-next").addEventListener("click", () => {
  cveState.offset += cveState.limit;
  loadCveBrowser();
});

/* ---------- refresh status ---------- */

async function loadRefreshStatus() {
  const el = document.getElementById("refresh-status");
  try {
    const res = await fetch("/api/refresh-status");
    const data = await res.json();
    if (!data.scheduled) {
      el.textContent = "REFRESH: NOT YET SCHEDULED";
      el.title = "Run refresh_index.py (see README) or wire it to a scheduler to keep this index current.";
      return;
    }
    const when = new Date(data.last_refresh_utc);
    const hoursAgo = Math.round((Date.now() - when.getTime()) / 3600000);
    el.textContent = `LAST REFRESH: ${hoursAgo < 1 ? "<1H AGO" : hoursAgo + "H AGO"}`;
    el.title = `${data.cves_upserted} CVEs upserted, ${data.days_window}-day window, at ${when.toISOString()}`;
  } catch {
    el.textContent = "REFRESH STATUS UNKNOWN";
  }
}

/* ---------- toasts ---------- */

const toastStack = document.getElementById("toast-stack");

function showToast(message, kind = "info", timeoutMs = 4500) {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = message;
  toastStack.appendChild(el);
  requestAnimationFrame(() => el.classList.add("toast-show"));
  setTimeout(() => {
    el.classList.remove("toast-show");
    setTimeout(() => el.remove(), 200);
  }, timeoutMs);
}

/* ---------- command palette ---------- */

const paletteOverlay = document.getElementById("palette-overlay");
const paletteInput = document.getElementById("palette-input");
const paletteResults = document.getElementById("palette-results");

const PALETTE_ACTIONS = [
  { kind: "view", label: "Dashboard", run: () => showView("dashboard") },
  { kind: "view", label: "Query — Auto Route", run: () => showView("query", "auto") },
  { kind: "view", label: "Query — CVE Search", run: () => showView("query", "cve") },
  { kind: "view", label: "Query — Compliance Docs", run: () => showView("query", "compliance") },
  { kind: "view", label: "CVE Browser", run: () => showView("cvebrowser") },
  { kind: "view", label: "Framework Browser", run: () => showView("browser") },
  { kind: "view", label: "Session History", run: () => showView("history") },
  ...Object.entries(EXAMPLE_QUESTIONS).flatMap(([mode, questions]) =>
    questions.map((q) => ({
      kind: `ask · ${mode}`,
      label: q,
      run: () => { showView("query", mode); queryInput.value = ""; submitQuery(q); },
    }))
  ),
];

let paletteActiveIndex = 0;
let paletteFiltered = PALETTE_ACTIONS;

function openPalette() {
  paletteOverlay.hidden = false;
  paletteInput.value = "";
  renderPaletteResults("");
  paletteInput.focus();
}

function closePalette() {
  paletteOverlay.hidden = true;
}

function renderPaletteResults(query) {
  const q = query.trim().toLowerCase();
  paletteFiltered = q ? PALETTE_ACTIONS.filter((a) => a.label.toLowerCase().includes(q)) : PALETTE_ACTIONS;
  paletteActiveIndex = 0;
  paletteResults.innerHTML = "";
  if (!paletteFiltered.length) {
    paletteResults.innerHTML = `<div class="palette-item">No matches</div>`;
    return;
  }
  paletteFiltered.forEach((action, i) => {
    const item = document.createElement("div");
    item.className = "palette-item" + (i === 0 ? " active" : "");
    item.innerHTML = `<span></span><span class="palette-item-kind">${escapeHtml(action.kind)}</span>`;
    item.querySelector("span").textContent = action.label;
    item.addEventListener("click", () => { action.run(); closePalette(); });
    paletteResults.appendChild(item);
  });
}

function movePaletteSelection(delta) {
  if (!paletteFiltered.length) return;
  paletteActiveIndex = (paletteActiveIndex + delta + paletteFiltered.length) % paletteFiltered.length;
  [...paletteResults.children].forEach((el, i) => el.classList.toggle("active", i === paletteActiveIndex));
  paletteResults.children[paletteActiveIndex]?.scrollIntoView({ block: "nearest" });
}

paletteInput.addEventListener("input", (e) => renderPaletteResults(e.target.value));
paletteInput.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { e.preventDefault(); movePaletteSelection(1); }
  else if (e.key === "ArrowUp") { e.preventDefault(); movePaletteSelection(-1); }
  else if (e.key === "Enter") {
    e.preventDefault();
    const action = paletteFiltered[paletteActiveIndex];
    if (action) { action.run(); closePalette(); }
  } else if (e.key === "Escape") {
    closePalette();
  }
});
paletteOverlay.addEventListener("click", (e) => { if (e.target === paletteOverlay) closePalette(); });
document.getElementById("palette-trigger").addEventListener("click", openPalette);

document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    openPalette();
  } else if (e.key === "/" && document.activeElement.tagName !== "INPUT" && paletteOverlay.hidden) {
    e.preventDefault();
    if (state.view !== "query") showView("query", state.queryMode);
    queryInput.focus();
  }
});

/* ---------- architecture modal ---------- */

const architectureOverlay = document.getElementById("architecture-overlay");
document.getElementById("architecture-body").innerHTML = `
  <h3>Pipeline</h3>
  <p>Each question is classified by a keyword-overlap <code>QueryRouter</code> into
  <strong>CVE</strong>, <strong>Compliance</strong>, or <strong>both</strong> (when ambiguous) —
  no LLM call needed for routing, so it's instant and free.</p>
  <p>The routed pipeline runs a <strong>hybrid retrieval</strong>: an exact CVE-ID lookup
  (bypasses ranking entirely), a Chroma vector search, and a BM25 keyword search — merged
  round-robin so neither source can crowd the other out.</p>
  <p>Retrieved passages are the <em>only</em> context sent to the model — the system prompt
  forbids citing anything not literally present in them.</p>
  <h3>Grounding check</h3>
  <p>After the model answers, every CVE ID it cites is checked against the IDs actually
  retrieved. Anything cited but not retrieved is flagged inline as
  <code>[UNVERIFIED]</code> instead of silently trusted — this is what stops a
  hallucinated CVE ID from reaching you as if it were real.</p>
  <h3>Cross-domain linking</h3>
  <p>Each CVE's CWE weakness type(s) are matched against a curated NIST/CIS/ISO control
  corpus, so a vulnerability answer can also surface which compliance controls it
  implicates — proven with a citation, not asserted.</p>
  <h3>Why streaming</h3>
  <p>Answers stream token-by-token from the model as they're generated. The grounding
  check still needs the complete answer text, so it only runs once streaming ends —
  you'll see the ⚠ unverified flag (if any) appear in the citation footer right after
  the last token lands.</p>
`;

function openArchitectureModal() { architectureOverlay.hidden = false; }
function closeArchitectureModal() { architectureOverlay.hidden = true; }
document.getElementById("architecture-trigger").addEventListener("click", openArchitectureModal);
document.getElementById("architecture-close").addEventListener("click", closeArchitectureModal);
architectureOverlay.addEventListener("click", (e) => { if (e.target === architectureOverlay) closeArchitectureModal(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !architectureOverlay.hidden) closeArchitectureModal();
});

/* ---------- export session ---------- */

function exportSessionMarkdown() {
  const blocks = [...transmissionLog.querySelectorAll(".transmission")];
  if (!blocks.length) {
    showToast("Nothing to export yet — ask a question first.", "warn");
    return;
  }
  const lines = [`# Security Knowledge Console — session export`, `Generated ${new Date().toISOString()}`, ""];
  blocks.slice().reverse().forEach((block) => {
    const tag = block.querySelector(".transmission-tag")?.textContent || "";
    const isQuestion = tag.trim() === "Query";
    const bodyText = block.querySelector(".transmission-body")?.textContent?.trim() || "";
    if (isQuestion) {
      lines.push(`## Q: ${bodyText}`, "");
    } else {
      lines.push(`**[${tag}]**`, "", bodyText, "");
      const sources = [...block.querySelectorAll(".source-chip")].map((s) => s.textContent.trim());
      if (sources.length) lines.push(`Sources: ${sources.join(", ")}`, "");
    }
  });
  const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ska-session-${Date.now()}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast("Session exported.", "info");
}

document.getElementById("history-export").addEventListener("click", exportSessionMarkdown);

/* ---------- init ---------- */

loadHistory();
loadDashboard();
loadRefreshStatus();
renderEmptyState();
