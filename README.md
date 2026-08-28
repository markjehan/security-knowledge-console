# Security Knowledge Assistant — Two-Domain RAG Chatbot

## 1. Problem Statement
Security analysts routinely need two different kinds of answers: (a) "is this
product/version affected by a known vulnerability?" and (b) "what does our compliance
framework require regarding this kind of weakness?" Today these live in separate
manual lookups — NVD/CVE searches and standards documents (NIST/CIS/ISO) — with no
link between the two, even though a CVE's root-cause weakness (CWE) very often maps
directly onto a specific compliance control an organization is required to satisfy.

## 2. Use Case
A security console with five views, not just a chatbot:
- **Dashboard** — live instrument gauges (CVE/control counts, severity mix, framework
  coverage) plus a "Why this matters" panel that computes, from the live index, how many
  compliance controls actually cross-link to a weakness type present right now — the
  tool's real, provable value, not a vanity metric.
- **Query (Auto / CVE Search / Compliance Docs)** — grounded Q&A over NVD CVE data and
  NIST SP 800-53 / NIST CSF / CIS Controls v8 / ISO/IEC 27001 control titles. Auto mode
  routes a question to the right domain, and a CVE answer cross-links its CWE weakness
  type(s) to the compliance controls it implicates.
- **CVE Browser** — direct, searchable/filterable/sortable listing of every indexed CVE
  (severity, score, published date) for when you want to look, not ask.
- **Framework Browser** — the full compliance corpus as a browsable legend table.
- **History** — session query log (stored client-side).

**Why this matters, concretely:** today an analyst manually cross-references two
separate systems — NVD for vulnerabilities, standards documents for compliance
obligations — with nothing connecting them. This tool answers both from one place,
grounded in real data (not the LLM's memory, so it can't invent a CVE that doesn't
exist — see the grounding check below), and surfaces the actual link between a
vulnerability's root cause and the specific control an organization is obligated to
satisfy because of it. Nobody hands you that connection today.

## 3. Solution Overview
Two independent Retrieval-Augmented Generation (RAG) pipelines, each backed by its own
vector store, plus a lightweight router and a cross-domain linking layer:

1. **Ingestion** — NVD CVE feeds and a curated compliance-control corpus are each
   chunked, embedded, and stored in separate Chroma collections (`cves`, `compliance`).
2. **Hybrid retrieval** — every query combines vector similarity search with BM25
   keyword search, since exact identifiers (CVE IDs, control IDs, product/version
   strings) need literal matching that embeddings alone often miss.
3. **Routing** — `QueryRouter` classifies each question by keyword-domain overlap (or
   detects a literal CVE ID) to decide whether to query the CVE pipeline, the
   compliance pipeline, or both.
4. **Generation** — retrieved context is passed to Claude, constrained by a
   domain-specific system prompt to answer only from that context.
5. **Grounding check (CVE domain)** — every CVE ID cited in the generated answer is
   cross-referenced against the retrieved document set; any ID the model mentions but
   that wasn't actually retrieved is flagged `[UNVERIFIED]` rather than presented as
   fact. This matters because a hallucinated CVE ID in a security tool could mislead an
   analyst's remediation priorities.
6. **CWE → control cross-linking** — each CVE record carries its CWE weakness type(s)
   (parsed from NVD's `problemtype` data); `cwe_mapping.py` looks these up against a
   curated CWE→control table so the CVE answer can surface "related compliance
   controls" without another LLM call.

## 4. Dataset
- **CVE domain:** [NVD REST API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
  (official, public — the legacy 1.1 JSON feed files were retired by NIST and now
  return HTTP 403, so this project queries the current REST API instead). The API is
  rate-limited without a key (5 requests/30s) and restricts date-range queries to 120
  days per request, so `ingest.py` supports two modes: a full date-range sweep
  (`--start-year`/`--end-year`, optionally narrowed with `--keyword`) and a fast
  `--keywords` mode that pulls CVEs for a curated list of product names directly
  (no date windowing needed since keyword-scoped result sets are small). The demo
  dataset shipped with this project used the keyword mode with 8 well-known products
  (Apache HTTP Server, Log4j, OpenSSL, Microsoft Exchange Server, WordPress, Apache
  Struts, Linux kernel, Windows SMB) and ingested **53,739 real CVE records**.
- **Compliance domain:** a curated corpus (`data/compliance_corpus.json`) built from
  NIST SP 800-53 Rev. 5 and NIST Cybersecurity Framework (both U.S. government public
  domain), CIS Controls v8 control titles, and ISO/IEC 27001:2022 Annex A *control
  titles only* (the full ISO standard text is commercially licensed and is intentionally
  **not** reproduced here — only topic/title references, per ISO's licensing terms).
  Expand this file with more controls/framework text you have rights to use for a more
  complete corpus.

## 5. AI/ML Approach
- **Embeddings:** `sentence-transformers/all-MiniLM-L6-v2` (local, no API cost).
- **Vector store:** ChromaDB, two collections (`cves`, `compliance`).
- **Keyword retrieval:** BM25 (`rank_bm25`), merged with vector results per query.
- **Routing:** keyword-overlap classifier (`QueryRouter`) — no LLM call, kept cheap and
  low-latency; accuracy measured in `eval/evaluate.py`.
- **Generation:** Claude (Anthropic API), separate system prompts per domain.
- **Cross-linking:** deterministic CWE→control lookup table (`cwe_mapping.py`), not
  ML-based — a curated mapping is more reliable than an LLM guess for this kind of
  authoritative reference data.
- **Grounding/anti-hallucination check:** regex-extracts CVE IDs from the generated
  answer and verifies each against retrieved context.
- **Vulnerability alias expansion:** well-known CVE nicknames (Log4Shell, Heartbleed,
  Shellshock, EternalBlue, ProxyLogon, Spring4Shell, etc.) rarely appear verbatim in
  NVD's own description text, so `expand_query()` in `rag.py` appends the underlying
  technical terms/CVE ID for any recognized nickname before retrieval runs.
- **Exact-ID short-circuit:** a literal CVE ID mentioned in the query is fetched directly
  from the vector store rather than relying on BM25/vector ranking, which is necessary
  because BM25's length normalization can otherwise rank a document that merely
  *mentions* an ID above the canonical record for that ID (see Evaluation section).

## 6. Application Architecture
```
Browser (HTML/JS chat UI — Auto / CVE Search / Compliance Docs tabs)
        |
        v
   Flask app (app.py)
        |
        +--> /api/query/cve         --> CVERagPipeline
        +--> /api/query/compliance  --> ComplianceRagPipeline
        +--> /api/query (auto)      --> QueryRouter --> one or both pipelines
                                              |
                       CVERagPipeline ----> hybrid retrieval (Chroma "cves" + BM25)
                                        ----> Claude generation
                                        ----> grounding check
                                        ----> CWE --> cwe_mapping.py --> related controls
                                              |
                ComplianceRagPipeline ----> hybrid retrieval (Chroma "compliance" + BM25)
                                        ----> Claude generation

  Chroma "cves" store        <-- ingest.py            <-- NVD CVE feeds
  Chroma "compliance" store  <-- ingest_compliance.py  <-- data/compliance_corpus.json
```

## 7. Technology Stack
Python, Flask, HTML/CSS/JS, sentence-transformers, ChromaDB, rank_bm25, Anthropic API,
Docker, [cloud service — fill in once deployed, e.g. AWS App Runner / GCP Cloud Run].

## 8. Local Setup Instructions
```bash
python -m venv venv
source venv/bin/activate        # venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env            # add your ANTHROPIC_API_KEY

# Fast path (recommended): curated product keywords, no date windowing.
python ingest.py --keywords "Apache HTTP Server" "Log4j" "OpenSSL" \
  "Microsoft Exchange Server" "WordPress" "Apache Struts" "Linux kernel" "Windows SMB"

# Full sweep (slow without an NVD API key — ~6.5s/request, rate limited):
# python ingest.py --start-year 2021 --end-year 2025
# Get a free key at https://nvd.nist.gov/developers/request-an-api-key and set
# NVD_API_KEY in .env to raise the rate limit to 50 requests/30s.

python ingest_compliance.py

python app.py
```
Visit `http://localhost:5000`.

Both ingest commands are idempotent (`collection.upsert` by CVE ID / control ID), so
re-running them to add more products or controls is safe and won't create duplicates.

## 9. Deployment Details
_Fill in once deployed:_ cloud provider, service used, region, and the public URL.

## Data Freshness — Why Not "Live" Per-Query Lookup
The index is a **snapshot**, refreshed on a schedule rather than queried live against
NVD on every question. This is deliberate, not a shortcut: NVD's API is rate-limited
(5 requests/30s without an API key), so a live per-query lookup would add 10+ seconds
of latency to every single answer and would fall over completely under any real
concurrent usage. Production vulnerability-intelligence tools use the same pattern —
scheduled ingestion, not live lookup on the request path.

[refresh_index.py](refresh_index.py) re-runs ingestion for a recent date window
(default: last 7 days, `lastModStartDate`/`lastModEndDate` against NVD so it catches
both new and modified CVEs) and re-embeds the compliance corpus, upserting by ID so it
never duplicates records:

```bash
python refresh_index.py                 # last 7 days, all tracked product keywords
python refresh_index.py --days 1         # last 24h — suited to a daily cron
```

Wire it to an actual scheduler rather than running it by hand:
- **Local/VM:** cron (`0 2 * * * cd .../cve-rag-chatbot && venv/bin/python refresh_index.py`) or Windows Task Scheduler.
- **Cloud (once deployed):** Google Cloud Scheduler → Cloud Run job, or AWS EventBridge → Lambda/Fargate, on the same interval.

The Dashboard's topstrip shows real freshness (`GET /api/refresh-status`) — "REFRESH:
NOT YET SCHEDULED" until this job has actually run at least once in the current
environment, rather than implying a live-update capability that isn't there.

## 10. API/Web Application Usage
- Web UI: `GET /` — five-view console: Dashboard, Query (Auto/CVE/Compliance), CVE
  Browser, Framework Browser, History.
- `POST /api/query/cve` — `{"question": "..."}` →
  `{"answer", "sources", "hallucinated_ids", "related_controls"}`.
- `POST /api/query/compliance` — `{"question": "..."}` → `{"answer", "sources"}`.
- `POST /api/query` — auto-routed; returns either a single pipeline's response with
  `routed_to` set, or `{"routed_to": "both", "cve": {...}, "compliance": {...}}` when the
  question is ambiguous.
- `GET /api/stats` — dashboard data: totals, severity breakdown, framework coverage,
  and the computed `linked_controls` / `high_severity_total` importance metrics.
- `GET /api/cves?q=&severity=&sort=&limit=&offset=` — paginated, searchable, filterable,
  sortable CVE listing for the CVE Browser.
- `GET /api/controls` — full compliance control list for the Framework Browser.
- `GET /api/refresh-status` — last scheduled-refresh run, or `scheduled: false` if
  `refresh_index.py` has never run in this environment.
- `GET /healthz` — health check.

## 11. Docker Instructions
```bash
docker build -t security-knowledge-assistant .
docker run -p 8080:8080 --env-file .env -v $(pwd)/data:/app/data security-knowledge-assistant
```

## Evaluation
`eval/evaluate.py` runs a labeled test set (`eval/test_set.json`, split into `cve`,
`compliance`, and `routing` sections) and reports:
- **CVE domain:** Retrieval Recall@5, Answer Correctness, Grounding Rate.
- **Compliance domain:** Retrieval Recall@5, Answer Correctness.
- **Routing Accuracy:** did `QueryRouter` send each question to the correct domain?

```bash
python eval/evaluate.py
```

**Measured results** (retrieval + routing layers, against the 53,739-CVE / 15-control
demo dataset above; Answer Correctness/Grounding Rate additionally require a valid
`ANTHROPIC_API_KEY` to run the generation step):

| Metric | Result |
|---|---|
| CVE Retrieval Recall@5 | 5/6 (83%) |
| Compliance Retrieval Recall@5 | 3/3 (100%) |
| Routing Accuracy | 4/4 (100%) |

Two retrieval bugs were found and fixed while building this evaluation harness — worth
including in a report as evidence of genuine iteration, not just "it worked first try":
1. **BM25 tokenization bug**: the naive `.split()` tokenizer left trailing punctuation
   attached to query tokens (e.g. `"2.4.49?"`), so an exact version-string match against
   a document's clean `"2.4.49"` token silently failed. Fixed with a proper regex
   tokenizer shared between indexing and querying (see `HybridRetriever._tokenize` in
   `rag.py`).
2. **BM25 length-normalization bias**: CVEs affecting hundreds of vendors (e.g.
   Log4Shell/CVE-2021-44228) list every affected CPE in NVD's data; embedding that full
   list bloated the document long enough that BM25's length normalization suppressed its
   score below shorter documents that merely *mention* the CVE ID in passing. Fixed by
   (a) capping the indexed product list per CVE, and (b) adding an exact-ID short-circuit
   (`HybridRetriever._exact_id_hits`) so a literal CVE ID in the query always retrieves
   that record directly, regardless of ranking.

The one remaining recall miss (`"Is there a known vulnerability in Log4j related to JNDI
lookups?"`) is a genuine RAG limitation worth discussing in a report: the phrasing
doesn't literally name the CVE and isn't covered by the alias-expansion table, so neither
BM25 nor the embedding model surfaces CVE-2021-44228 in the top 5 for that exact wording.

Expand `eval/test_set.json` with more cases for a more robust evaluation before
submission — this is the section most worth strengthening for report/dissertation
credibility.

## Notes on Scope & Limitations (worth stating explicitly in a report)
- The compliance corpus is small and curated by hand for this project, not a complete
  ingestion of any standard — it demonstrates the architecture, not full framework
  coverage.
- ISO 27001 control **text** is commercially licensed; only control titles/topics are
  used here. A production version would need a licensed source or would omit ISO.
- Routing is a cheap heuristic, not a trained classifier — documented as a deliberate
  latency/cost tradeoff, with accuracy measured rather than assumed.
