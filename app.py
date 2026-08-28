import json
import os
from collections import Counter
from dotenv import load_dotenv

load_dotenv()

from anthropic import APIError
from flask import Flask, Response, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from rag import CVERagPipeline, ComplianceRagPipeline, QueryRouter

app = Flask(__name__)

# Public, unauthenticated endpoints proxy straight to a paid LLM API, so a
# per-IP cap is the difference between "public demo" and "open API-key drain".
limiter = Limiter(get_remote_address, app=app, default_limits=["60 per hour"], storage_uri="memory://")

MAX_QUESTION_LENGTH = 500

COMPLIANCE_CORPUS_PATH = os.path.join(os.path.dirname(__file__), "data", "compliance_corpus.json")


def _validate_question(question: str) -> tuple | None:
    """Shared length/emptiness check. Returns an error response tuple, or
    None if the question is valid."""
    if not question:
        return jsonify({"error": "question is required"}), 400
    if len(question) > MAX_QUESTION_LENGTH:
        return jsonify({"error": f"question must be under {MAX_QUESTION_LENGTH} characters"}), 400
    return None


def _get_question() -> tuple[str, tuple | None]:
    """Shared validation for the JSON-body /api/query* endpoints. Returns
    (question, None) on success or ("", error_response) on failure."""
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    err = _validate_question(question)
    return ("", err) if err else (question, None)


def _get_question_from_args() -> tuple[str, tuple | None]:
    """Same validation for the SSE streaming endpoints, which use GET +
    querystring because the browser's EventSource API cannot send a POST
    body or custom headers."""
    question = (request.args.get("question") or "").strip()
    err = _validate_question(question)
    return ("", err) if err else (question, None)


def _sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _stream_response(generator):
    """Wraps a query_stream() generator as an SSE HTTP response, translating
    ("delta"/"done") tuples into named SSE events and turning any mid-stream
    LLM error into a terminal "error" event instead of a raw crash (the
    APIError errorhandler above only catches errors raised before the
    response starts streaming, not ones raised while it's in flight)."""
    def generate():
        try:
            for kind, payload in generator:
                if kind == "delta":
                    yield _sse_event("delta", {"text": payload})
                else:
                    yield _sse_event(kind, payload)
        except APIError as err:
            yield _sse_event("stream_error", {
                "error": "The language model backend returned an error. Check that "
                         "ANTHROPIC_API_KEY is set correctly in your .env file.",
                "detail": str(err),
            })

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.errorhandler(APIError)
def handle_llm_error(err):
    return jsonify({
        "error": "The language model backend returned an error. Check that "
                 "ANTHROPIC_API_KEY is set correctly in your .env file.",
        "detail": str(err),
    }), 502


@app.errorhandler(429)
def handle_rate_limit(err):
    return jsonify({"error": "Rate limit exceeded. Please wait before sending more queries."}), 429

_cve_pipeline = None
_compliance_pipeline = None


def get_cve_pipeline() -> CVERagPipeline:
    global _cve_pipeline
    if _cve_pipeline is None:
        _cve_pipeline = CVERagPipeline()
    return _cve_pipeline


def get_compliance_pipeline() -> ComplianceRagPipeline:
    global _compliance_pipeline
    if _compliance_pipeline is None:
        _compliance_pipeline = ComplianceRagPipeline()
    return _compliance_pipeline


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/query/cve", methods=["POST"])
@limiter.limit("20 per minute")
def api_query_cve():
    question, err = _get_question()
    if err:
        return err
    return jsonify(get_cve_pipeline().query(question))


@app.route("/api/query/compliance", methods=["POST"])
@limiter.limit("20 per minute")
def api_query_compliance():
    question, err = _get_question()
    if err:
        return err
    return jsonify(get_compliance_pipeline().query(question))


@app.route("/api/query", methods=["POST"])
@limiter.limit("20 per minute")
def api_query_auto():
    """Auto-routed endpoint: classifies the question and queries the right
    pipeline (or both, merged, if ambiguous)."""
    question, err = _get_question()
    if err:
        return err

    domain = QueryRouter.classify(question)

    if domain == "cve":
        result = get_cve_pipeline().query(question)
        result["routed_to"] = "cve"
        return jsonify(result)

    if domain == "compliance":
        result = get_compliance_pipeline().query(question)
        result["routed_to"] = "compliance"
        return jsonify(result)

    cve_result = get_cve_pipeline().query(question)
    compliance_result = get_compliance_pipeline().query(question)
    return jsonify({
        "routed_to": "both",
        "cve": cve_result,
        "compliance": compliance_result,
    })


@app.route("/api/query/cve/stream")
@limiter.limit("20 per minute")
def api_query_cve_stream():
    question, err = _get_question_from_args()
    if err:
        return err
    return _stream_response(get_cve_pipeline().query_stream(question))


@app.route("/api/query/compliance/stream")
@limiter.limit("20 per minute")
def api_query_compliance_stream():
    question, err = _get_question_from_args()
    if err:
        return err
    return _stream_response(get_compliance_pipeline().query_stream(question))


@app.route("/api/query/stream")
@limiter.limit("20 per minute")
def api_query_auto_stream():
    """Auto-routed streaming endpoint, single connection. Always emits a
    "meta" event first announcing the routing decision, so the frontend
    knows up front whether to render one streaming panel or two — before
    any "delta"/"done" (single-domain) or "done_cve"/"done_compliance"
    (ambiguous "both") events follow. When it's ambiguous, true streaming
    would mean interleaving two independent token streams into one UI panel
    each, which isn't worth the complexity — both pipelines just run to
    completion and land as two normal "done_*" events with no deltas."""
    question, err = _get_question_from_args()
    if err:
        return err

    domain = QueryRouter.classify(question)

    def generate():
        yield _sse_event("meta", {"routed_to": domain})
        try:
            if domain == "cve":
                for kind, payload in get_cve_pipeline().query_stream(question):
                    if kind == "done":
                        payload = {**payload, "routed_to": "cve"}
                    yield _sse_event(kind, payload)
            elif domain == "compliance":
                for kind, payload in get_compliance_pipeline().query_stream(question):
                    if kind == "done":
                        payload = {**payload, "routed_to": "compliance"}
                    yield _sse_event(kind, payload)
            else:
                yield _sse_event("done_cve", get_cve_pipeline().query(question))
                yield _sse_event("done_compliance", get_compliance_pipeline().query(question))
        except APIError as err:
            yield _sse_event("stream_error", {
                "error": "The language model backend returned an error. Check that "
                         "ANTHROPIC_API_KEY is set correctly in your .env file.",
                "detail": str(err),
            })

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/stats")
def api_stats():
    """Counts + severity breakdown for the dashboard instrument panel."""
    cve_collection = get_cve_pipeline().retriever.collection
    compliance_collection = get_compliance_pipeline().retriever.collection

    cve_total = cve_collection.count()
    severity_counts = Counter()
    cwe_seen = set()
    offset = 0
    page_size = 5000
    while True:
        page = cve_collection.get(include=["metadatas"], limit=page_size, offset=offset)
        ids = page["ids"]
        if not ids:
            break
        for meta in page["metadatas"]:
            severity_counts[meta.get("severity", "UNKNOWN")] += 1
            cwe_seen.update(c for c in meta.get("cwe_ids", "").split(",") if c)
        offset += len(ids)
        if len(ids) < page_size:
            break

    with open(COMPLIANCE_CORPUS_PATH) as f:
        controls = json.load(f)
    frameworks = Counter(c["framework"] for c in controls)

    # "Importance" metric: how many compliance controls actually cross-link to a
    # weakness type present somewhere in the live CVE index right now — this is
    # the tool's core, provable value (not a vanity count), so it's surfaced on
    # the dashboard rather than left implicit.
    linked_controls = sum(
        1 for c in controls if set(c.get("cwe_links", [])) & cwe_seen
    )
    high_severity = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)

    return jsonify({
        "cve_total": cve_total,
        "severity_counts": dict(severity_counts),
        "compliance_total": compliance_collection.count(),
        "framework_counts": dict(frameworks),
        "linked_controls": linked_controls,
        "high_severity_total": high_severity,
    })


@app.route("/api/controls")
def api_controls():
    """Full compliance control list for the Framework Browser view."""
    with open(COMPLIANCE_CORPUS_PATH) as f:
        controls = json.load(f)
    return jsonify(controls)


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": -1}


@app.route("/api/cves")
def api_cves():
    """Browsable, filterable, sortable CVE listing for the CVE Browser view.

    Loads full metadata+documents once per process into memory (cached on the
    collection wrapper) rather than re-paging Chroma on every request — with
    ~54k records this keeps browsing snappy without needing a real database.
    """
    global _cve_browse_cache
    collection = get_cve_pipeline().retriever.collection

    if _cve_browse_cache is None:
        rows = []
        offset = 0
        page_size = 5000
        while True:
            page = collection.get(include=["metadatas", "documents"], limit=page_size, offset=offset)
            ids = page["ids"]
            if not ids:
                break
            for _id, meta, doc in zip(ids, page["metadatas"], page["documents"]):
                first_line_desc = doc.split("Description:", 1)[-1].strip()
                rows.append({
                    "cve_id": _id,
                    "severity": meta.get("severity", "UNKNOWN"),
                    "score": meta.get("score", -1.0),
                    "published": meta.get("published", ""),
                    "cwe_ids": [c for c in meta.get("cwe_ids", "").split(",") if c],
                    "summary": first_line_desc[:220] + ("…" if len(first_line_desc) > 220 else ""),
                })
            offset += len(ids)
            if len(ids) < page_size:
                break
        _cve_browse_cache = rows

    rows = _cve_browse_cache

    q = (request.args.get("q") or "").strip().lower()
    severity = (request.args.get("severity") or "").strip().upper()
    sort = request.args.get("sort", "published_desc")
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))

    filtered = rows
    if q:
        filtered = [r for r in filtered if q in r["cve_id"].lower() or q in r["summary"].lower()]
    if severity:
        filtered = [r for r in filtered if r["severity"] == severity]

    if sort == "published_desc":
        filtered = sorted(filtered, key=lambda r: r["published"], reverse=True)
    elif sort == "published_asc":
        filtered = sorted(filtered, key=lambda r: r["published"])
    elif sort == "severity_desc":
        filtered = sorted(filtered, key=lambda r: SEVERITY_RANK.get(r["severity"], -1), reverse=True)
    elif sort == "score_desc":
        filtered = sorted(filtered, key=lambda r: r["score"] or -1, reverse=True)

    total = len(filtered)
    page = filtered[offset:offset + limit]

    return jsonify({"total": total, "results": page})


_cve_browse_cache = None


REFRESH_LOG_PATH = os.path.join(os.path.dirname(__file__), "data", "last_refresh.json")


@app.route("/api/refresh-status")
def api_refresh_status():
    """Reports the last time refresh_index.py ran, so the UI can show real
    data freshness instead of implying a live-update capability that isn't
    there. Absent file means the scheduled job has never run in this
    environment yet — a legitimate, disclosed state, not an error."""
    if not os.path.exists(REFRESH_LOG_PATH):
        return jsonify({"scheduled": False, "last_refresh_utc": None})
    with open(REFRESH_LOG_PATH) as f:
        data = json.load(f)
    return jsonify({"scheduled": True, **data})


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    # threaded=True: the SSE streaming endpoints hold a connection open for
    # the duration of an LLM generation, which would otherwise block every
    # other request (including the dashboard's own polling) on Flask's
    # single-threaded dev server.
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
