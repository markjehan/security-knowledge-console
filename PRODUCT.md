# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Existing codebase: Flask backend serving server-rendered HTML (Jinja templates) with vanilla HTML/CSS/JS frontend (no framework). Redesign continues in this stack — no framework migration.

## Users

Primary user: a security analyst (the requester is one, working within an organization's security function) who needs fast, grounded answers about vulnerabilities (CVE data) and compliance obligations (NIST/CIS/ISO/SOC 2) during triage, remediation planning, or audit prep. *[Inferred from conversation: the requester described themselves as a cybersecurity analyst building this for organizational use, referencing other internal tools ("Ops Lens") the same team maintains — treat as evidence, not confirmed via direct interview.]*

Secondary/future users (not yet built for, noted as direction): compliance/audit staff who need control-lookup without needing to know CVE terminology; possibly execs/auditors reviewing compliance answers.

## Product Purpose

A two-domain Retrieval-Augmented Generation (RAG) assistant that answers vulnerability questions (grounded in real NVD CVE data) and compliance-control questions (grounded in a curated NIST/CIS/ISO corpus), auto-routing between the two, and cross-linking a CVE's weakness type (CWE) to the compliance controls it implicates. Built initially as an MSc assignment deliverable, with explicit intent to evolve into an internal organizational tool.

## Positioning

Unlike a plain CVE lookup (NVD website) or a plain compliance-document search, this tool answers across both domains from one interface and shows the link between them — "this vulnerability's weakness type maps to these specific controls you're required to satisfy." Every generated answer is grounded and hallucination-checked against retrieved source documents rather than the model's own training knowledge, which matters specifically because a fabricated CVE ID in a security tool has real operational cost.

## Operating Context

- Used during active security work: triage of a newly disclosed CVE, checking product/version exposure, preparing for a compliance audit, or drafting remediation guidance referencing a specific control.
- Data sources: NVD REST API 2.0 (real CVE records, currently ~54k ingested) and a curated compliance corpus (NIST SP 800-53, NIST CSF, CIS Controls v8, ISO/IEC 27001 control titles — SOC 2 addition planned).
- Currently a single-session local tool; direction is to become a recurring internal resource with periodically refreshed data (not yet built — scheduled ingestion is a stated next step, not implemented).

## Capabilities and Constraints

- Confirmed: hybrid retrieval (vector + BM25) over two Chroma collections; Claude (Anthropic API) generation; CVE↔control cross-linking via a curated CWE map; grounding check that flags any cited CVE ID absent from retrieved context.
- Confirmed: three interaction modes — CVE Search, Compliance Docs, Auto (routed).
- Undecided/open: authentication and multi-user access are not yet designed — assume single-user/local for this design pass unless stated otherwise.
- Undecided/open: whether query history and saved queries persist server-side (DB) or client-side only — recommend server-side once this becomes a multi-session/multi-user tool, but not required for this pass.
- Constraint: compliance corpus content must stay license-safe — ISO/IEC 27001 and SOC 2 (AICPA) full control text is commercially licensed; only topic/title-level references are used, never full clause text.

## Brand Commitments

None established yet. No existing name beyond the working title "Security Knowledge Assistant" / "CVE Research Assistant" used in code comments and README — not a confirmed product name, open to change.

## Evidence on Hand

- Real, live data: 53,739 ingested CVE records (NVD API 2.0) and 15 compliance controls (`data/compliance_corpus.json`), verified working end-to-end with real Claude generation.
- No existing brand assets, logo, or design system — this is the first design pass on this codebase.

## Product Principles

1. Grounded over fluent — every claim in an answer must be traceable to a retrieved source; unverifiable claims are flagged, never silently smoothed over.
2. Analyst speed over decoration — this is a working tool used under time pressure (triage, audit prep); density and scanability outrank whitespace-heavy marketing polish.
3. Two domains, one mental model — CVE and compliance data are visually and structurally distinct, but the cross-linking between them is a first-class feature, not an afterthought.
4. Built to grow — designed knowing the next phases are scheduled data refresh, more frameworks (SOC 2), multi-user access, and eventually a document-compliance-checking capability; the UI shell should not have to be re-architected for those additions.

## Accessibility & Inclusion

No standard specified yet; treat as a professional internal tool requiring reasonable WCAG AA-level care (contrast, keyboard nav, focus states) given it may be used by auditors/compliance staff, not just engineers.
