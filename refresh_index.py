"""
Scheduled refresh job: re-runs CVE ingestion for a recent date window and
re-embeds the compliance corpus, so the index stays current without a full
re-ingest and without ever querying NVD live on the request path (NVD is
rate-limited — 5 req/30s without an API key — so live-per-query lookup would
make every user question take 10+ seconds; a scheduled refresh is the
correct pattern here, the same one production vulnerability-intel tools use).

Run this on a schedule (cron / Windows Task Scheduler / a cloud scheduler
once deployed) rather than manually:

    # crontab -e (Linux/macOS host or a cloud VM) — every day at 02:00
    0 2 * * * cd /path/to/cve-rag-chatbot && venv/bin/python refresh_index.py >> refresh.log 2>&1

    # Windows Task Scheduler — daily trigger running:
    #   venv\\Scripts\\python.exe refresh_index.py

    # Cloud (once deployed): Google Cloud Scheduler -> Cloud Run job / AWS
    # EventBridge -> Lambda or Fargate task, on the same interval.

Usage:
    python refresh_index.py                # last 7 days, all tracked keywords
    python refresh_index.py --days 1        # last 24h only (for a daily cron)
    python refresh_index.py --keywords "Apache HTTP Server" "Log4j"
"""
import argparse
import datetime as dt
import json
import os

from ingest import fetch_query, upsert_docs, DB_DIR, EMBED_MODEL
import chromadb
from sentence_transformers import SentenceTransformer

DEFAULT_KEYWORDS = [
    "Apache HTTP Server", "Log4j", "OpenSSL", "Microsoft Exchange Server",
    "WordPress", "Apache Struts", "Linux kernel", "Windows SMB",
]

REFRESH_LOG_PATH = os.path.join(os.path.dirname(__file__), "data", "last_refresh.json")


def refresh_cves(days: int, keywords: list[str]):
    api_key = os.environ.get("NVD_API_KEY")
    client = chromadb.PersistentClient(path=DB_DIR)
    collection = client.get_or_create_collection("cves")
    model = SentenceTransformer(EMBED_MODEL)

    pub_end = dt.datetime.utcnow()
    pub_start = pub_end - dt.timedelta(days=days)

    total_new = 0
    for kw in keywords:
        params = {
            "keywordSearch": kw,
            "lastModStartDate": pub_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": pub_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        vulns = fetch_query(params, api_key)
        ingested = upsert_docs(collection, model, vulns)
        total_new += ingested
        print(f"[refresh] '{kw}': {len(vulns)} modified/new in window, {ingested} upserted")

    print(f"[refresh] Done. {total_new} CVE records upserted. Collection count: {collection.count()}")
    return total_new


def refresh_compliance():
    import ingest_compliance
    ingest_compliance.main()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=7,
                         help="Look back this many days for new/modified CVEs (default 7).")
    parser.add_argument("--keywords", nargs="+", default=DEFAULT_KEYWORDS,
                         help="Product keywords to refresh (default: the curated demo list).")
    parser.add_argument("--skip-compliance", action="store_true",
                         help="Skip re-embedding the compliance corpus (it rarely changes).")
    args = parser.parse_args()

    started = dt.datetime.utcnow()
    new_count = refresh_cves(args.days, args.keywords)

    if not args.skip_compliance:
        refresh_compliance()

    with open(REFRESH_LOG_PATH, "w") as f:
        json.dump({
            "last_refresh_utc": started.isoformat(),
            "days_window": args.days,
            "keywords": args.keywords,
            "cves_upserted": new_count,
        }, f, indent=2)

    print(f"[refresh] Wrote {REFRESH_LOG_PATH}")


if __name__ == "__main__":
    main()
