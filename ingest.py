"""
Fetches CVE records from the NVD REST API 2.0 (the legacy 1.1 JSON feeds were
retired), chunks each CVE into a retrievable document, embeds them, and
stores them in a persistent Chroma collection.

The API allows date windows of at most 120 days per request and is rate
limited (5 requests / 30s without an API key, 50 / 30s with one). Set
NVD_API_KEY in the environment to speed this up considerably.

Usage:
    python ingest.py --start-year 2021 --end-year 2025
    python ingest.py --start-year 2021 --end-year 2025 --keyword log4j
"""
import argparse
import datetime as dt
import os
import time

import requests
from tqdm import tqdm
import chromadb
from sentence_transformers import SentenceTransformer

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DB_DIR = os.path.join(os.path.dirname(__file__), "data", "chroma")
EMBED_MODEL = "all-MiniLM-L6-v2"
WINDOW_DAYS = 120
RESULTS_PER_PAGE = 2000


def date_windows(start_year: int, end_year: int, resume_from: str | None = None):
    start = dt.datetime.strptime(resume_from, "%Y-%m-%d") if resume_from else dt.datetime(start_year, 1, 1)
    end = min(dt.datetime(end_year, 12, 31, 23, 59, 59), dt.datetime.now())
    cursor = start
    while cursor < end:
        window_end = min(cursor + dt.timedelta(days=WINDOW_DAYS - 1), end)
        yield cursor, window_end
        cursor = window_end + dt.timedelta(seconds=1)


def fetch_query(params_base: dict, api_key: str | None) -> list[dict]:
    """Paginate through an NVD API 2.0 query (with retries) until exhausted."""
    headers = {"apiKey": api_key} if api_key else {}
    sleep_between_requests = 0.7 if api_key else 6.5

    items = []
    start_index = 0
    while True:
        params = {**params_base, "resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}

        resp = None
        last_exc = None
        for attempt in range(5):
            try:
                resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=90)
                if resp.status_code == 403:
                    time.sleep(10)
                    continue
                resp.raise_for_status()
                last_exc = None
                break
            except (requests.exceptions.RequestException,) as e:
                last_exc = e
                time.sleep(min(5 * (attempt + 1), 30))
        if last_exc is not None or resp is None:
            raise last_exc or RuntimeError("NVD request failed with no response")

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        items.extend(vulns)

        total = data.get("totalResults", len(items))
        start_index += RESULTS_PER_PAGE
        time.sleep(sleep_between_requests)

        if start_index >= total or not vulns:
            break

    return items


def fetch_window(pub_start: dt.datetime, pub_end: dt.datetime, keyword: str | None, api_key: str | None) -> list[dict]:
    params = {
        "pubStartDate": pub_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": pub_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    if keyword:
        params["keywordSearch"] = keyword
    return fetch_query(params, api_key)


def cve_to_document(vuln: dict) -> dict | None:
    cve = vuln["cve"]
    cve_id = cve["id"]

    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
    if not description:
        return None

    metrics = cve.get("metrics", {})
    score, severity = None, "UNKNOWN"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0]["cvssData"]
            score = cvss_data.get("baseScore")
            severity = metrics[key][0].get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
            break

    products = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                uri = cpe_match.get("criteria", "")
                parts = uri.split(":")
                if len(parts) > 4:
                    products.add(f"{parts[3]}:{parts[4]}")

    cwe_ids = set()
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwe_ids.add(value)

    published = cve.get("published", "")

    # Widely-affected CVEs (e.g. Log4Shell) can list hundreds of vendor CPEs. Embedding
    # the full list bloats document length enough to crush its BM25 score under length
    # normalization, so cap what goes into the retrievable text; the full set stays
    # queryable via metadata if needed.
    sorted_products = sorted(products)
    product_preview = sorted_products[:15]
    products_str = ", ".join(product_preview) or "not specified"
    if len(sorted_products) > len(product_preview):
        products_str += f", and {len(sorted_products) - len(product_preview)} more"

    text = (
        f"CVE ID: {cve_id}\n"
        f"Published: {published}\n"
        f"CVSS Score: {score} ({severity})\n"
        f"Affected products: {products_str}\n"
        f"Weakness type(s): {', '.join(sorted(cwe_ids)) or 'not specified'}\n"
        f"Description: {description}"
    )

    return {
        "id": cve_id,
        "text": text,
        "metadata": {
            "cve_id": cve_id,
            "severity": severity,
            "score": score if score is not None else -1.0,
            "published": published,
            "cwe_ids": ",".join(sorted(cwe_ids)),
        },
    }


def upsert_docs(collection, model, vulns: list[dict]) -> int:
    docs, ids, metas = [], [], []
    for vuln in vulns:
        doc = cve_to_document(vuln)
        if doc is None:
            continue
        docs.append(doc["text"])
        ids.append(doc["id"])
        metas.append(doc["metadata"])

    if not docs:
        return 0

    embeddings = model.encode(docs, batch_size=64).tolist()
    batch_size = 5000
    for i in range(0, len(docs), batch_size):
        collection.upsert(
            ids=ids[i:i + batch_size],
            documents=docs[i:i + batch_size],
            embeddings=embeddings[i:i + batch_size],
            metadatas=metas[i:i + batch_size],
        )
    return len(docs)


def main_keywords(keywords: list[str]):
    """Fast path: pull CVEs matching each keyword directly (no date windowing needed
    since keyword-scoped result sets are small), for a curated demo dataset."""
    api_key = os.environ.get("NVD_API_KEY")
    os.makedirs(DB_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=DB_DIR)
    collection = client.get_or_create_collection("cves")
    model = SentenceTransformer(EMBED_MODEL)

    total = 0
    for kw in tqdm(keywords, desc="Keywords"):
        try:
            vulns = fetch_query({"keywordSearch": kw}, api_key)
        except requests.exceptions.RequestException as e:
            print(f"Skipping keyword '{kw}': {e}")
            continue
        ingested = upsert_docs(collection, model, vulns)
        total += ingested
        print(f"Keyword '{kw}': fetched {len(vulns)}, ingested {ingested} (running total {total})")

    print("Done. Collection count:", collection.count())


def main(start_year: int, end_year: int, keyword: str | None, resume_from: str | None = None):
    api_key = os.environ.get("NVD_API_KEY")
    os.makedirs(DB_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=DB_DIR)
    collection = client.get_or_create_collection("cves")
    model = SentenceTransformer(EMBED_MODEL)

    windows = list(date_windows(start_year, end_year, resume_from))
    total_ingested = 0

    for win_start, win_end in tqdm(windows, desc="Date windows"):
        try:
            vulns = fetch_window(win_start, win_end, keyword, api_key)
        except requests.exceptions.RequestException as e:
            print(f"Skipping window {win_start.date()}..{win_end.date()}: {e}")
            continue

        ingested = upsert_docs(collection, model, vulns)
        total_ingested += ingested
        print(f"Window {win_start.date()}..{win_end.date()}: ingested {ingested} CVEs "
              f"(running total {total_ingested})")

    print("Done. Collection count:", collection.count())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-year", type=int)
    parser.add_argument("--end-year", type=int)
    parser.add_argument("--keyword", type=str, default=None,
                         help="Restrict a date-range ingest to CVEs matching this keyword (much faster).")
    parser.add_argument("--resume-from", type=str, default=None,
                         help="Resume ingestion from this date (YYYY-MM-DD) instead of Jan 1 of --start-year.")
    parser.add_argument("--keywords", nargs="+", default=None,
                         help="Fast path: ingest CVEs matching each keyword directly, no date windowing "
                              "(e.g. --keywords apache log4j openssl). Ignores --start-year/--end-year.")
    args = parser.parse_args()

    if args.keywords:
        main_keywords(args.keywords)
    else:
        if args.start_year is None or args.end_year is None:
            parser.error("--start-year/--end-year are required unless --keywords is used")
        main(args.start_year, args.end_year, args.keyword, args.resume_from)
