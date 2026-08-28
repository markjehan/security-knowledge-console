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
  auto: { title: "Query — Auto Route", sub: "Ask a question; the console routes it to the right retrieval domain.", endpoint: "/api/query", placeholder: "Ask anything — CVEs or compliance controls..." },
  cve: { title: "Query — CVE Search", sub: "Grounded Q&A over indexed NVD CVE records.", endpoint: "/api/query/cve", placeholder: "e.g. What CVEs affect Apache 2.4.49?" },
  compliance: { title: "Query — Compliance Docs", sub: "Grounded Q&A over NIST / CIS / ISO / SOC 2 controls.", endpoint: "/api/query/compliance", placeholder: "e.g. What does NIST say about vulnerability scanning?" },
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

function renderAnswerBlock(question, domain, data, routedTo) {
  const el = document.createElement("div");
  el.className = "transmission";
  const tagClass = domain === "compliance" ? "compliance" : "cve";
  const tagLabel = domain === "compliance" ? "Compliance" : "CVE";

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
}

async function submitQuery(question) {
  addQueryTransmission(question);
  const mode = state.queryMode;
  const meta = MODE_META[mode];
  queryInput.disabled = true;
  const submitBtn = queryForm.querySelector(".query-submit");
  submitBtn.disabled = true;
  submitBtn.textContent = "Transmitting…";

  try {
    const res = await fetch(meta.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });
    const data = await res.json();

    if (!res.ok) {
      renderAnswerBlock(question, "cve", { error: data.error || `Request failed (${res.status}).` });
      pushHistory(question, "error");
      return;
    }

    if (mode === "auto" && data.routed_to === "both") {
      renderAnswerBlock(question, "cve", data.cve, "both (ambiguous — merged CVE + compliance)");
      renderAnswerBlock(question, "compliance", data.compliance, "both (ambiguous — merged CVE + compliance)");
      pushHistory(question, "both");
    } else {
      const domain = data.domain || (data.routed_to === "compliance" ? "compliance" : "cve");
      const routedTo = mode === "auto" ? `auto → ${domain}` : null;
      renderAnswerBlock(question, domain, data, routedTo);
      pushHistory(question, domain);
    }
  } catch (err) {
    renderAnswerBlock(question, "cve", { error: "Transmission failed — could not reach the console backend." });
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

/* ---------- init ---------- */

loadHistory();
loadDashboard();
loadRefreshStatus();
renderEmptyState();
