"""
Embeds the curated compliance corpus (NIST 800-53, NIST CSF, CIS Controls,
ISO 27001 control titles) into its own Chroma collection, separate from the
CVE collection, so the two document types can be retrieved independently.

Usage:
    python ingest_compliance.py
"""
import json
import os
import chromadb
from sentence_transformers import SentenceTransformer

DB_DIR = os.path.join(os.path.dirname(__file__), "data", "chroma")
CORPUS_PATH = os.path.join(os.path.dirname(__file__), "data", "compliance_corpus.json")
EMBED_MODEL = "all-MiniLM-L6-v2"


def main():
    with open(CORPUS_PATH) as f:
        controls = json.load(f)

    os.makedirs(DB_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=DB_DIR)
    collection = client.get_or_create_collection("compliance")
    model = SentenceTransformer(EMBED_MODEL)

    ids = [c["id"] for c in controls]
    docs = [c["text"] for c in controls]
    metas = [
        {
            "framework": c["framework"],
            "control_id": c["control_id"],
            "title": c["title"],
            "cwe_links": ",".join(c.get("cwe_links", [])),
        }
        for c in controls
    ]

    print(f"Embedding {len(docs)} compliance controls...")
    embeddings = model.encode(docs, show_progress_bar=True).tolist()

    collection.upsert(ids=ids, documents=docs, embeddings=embeddings, metadatas=metas)
    print("Done. Collection count:", collection.count())


if __name__ == "__main__":
    main()
