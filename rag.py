"""
RAG core for the security knowledge assistant. Two independent domains,
each with its own Chroma collection and hybrid retriever (vector + BM25,
since exact IDs/product strings need literal matching embeddings often miss):

  - CVERagPipeline: NVD CVE data ("what CVEs affect Apache 2.4.49?")
  - ComplianceRagPipeline: NIST/CIS/ISO control data ("what does NIST say
    about vulnerability scanning?")

A lightweight keyword-based QueryRouter decides which pipeline (or both) a
question should go to, and the CVE pipeline additionally cross-links each
CVE's CWE weakness type(s) to relevant compliance controls via cwe_mapping.py.

Every answer passes through a grounding check that flags any CVE ID the LLM
cites but that did not actually appear in retrieved context — hallucinated
CVE IDs are dangerous in a security-advisory context.
"""
import os
import re
from itertools import zip_longest
import chromadb
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer
from anthropic import Anthropic

from cwe_mapping import controls_for_cwes

DB_DIR = os.path.join(os.path.dirname(__file__), "data", "chroma")
EMBED_MODEL = "all-MiniLM-L6-v2"
LLM_MODEL = "claude-sonnet-5"
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

VULN_ALIASES = {
    "log4shell": "log4j jndi lookup remote code execution CVE-2021-44228",
    "heartbleed": "openssl heartbeat extension out-of-bounds read CVE-2014-0160",
    "shellshock": "bash environment variable function definition remote code execution",
    "eternalblue": "windows smb remote code execution CVE-2017-0144",
    "proxylogon": "microsoft exchange server server-side request forgery CVE-2021-26855",
    "proxyshell": "microsoft exchange server remote code execution",
    "spring4shell": "spring framework remote code execution CVE-2022-22965",
    "dirty cow": "linux kernel copy-on-write privilege escalation CVE-2016-5195",
    "meltdown": "cpu speculative execution information disclosure CVE-2017-5754",
    "spectre": "cpu speculative execution side-channel CVE-2017-5753",
}


def expand_query(query: str) -> str:
    """Append plain-language expansions for well-known vulnerability nicknames
    (e.g. "Log4Shell") that don't literally appear in NVD's CVE description text,
    so retrieval isn't limited to exact vocabulary overlap for famous CVEs."""
    q_lower = query.lower()
    extras = [expansion for alias, expansion in VULN_ALIASES.items() if alias in q_lower]
    return f"{query} {' '.join(extras)}" if extras else query


_embed_model = None


def get_embed_model() -> SentenceTransformer:
    global _embed_model
    if _embed_model is None:
        _embed_model = SentenceTransformer(EMBED_MODEL)
    return _embed_model


class HybridRetriever:
    """Vector similarity (Chroma) + BM25 keyword search over one collection."""

    _TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9.\-]*[a-z0-9]|[a-z0-9]")

    def __init__(self, collection_name: str):
        self.client = chromadb.PersistentClient(path=DB_DIR)
        self.collection = self.client.get_or_create_collection(collection_name)
        self.embed_model = get_embed_model()
        self._bm25 = None
        self._bm25_ids = None
        self._bm25_docs = None
        self._bm25_metas = None
        self._build_bm25_index()

    @classmethod
    def _tokenize(cls, text: str) -> list[str]:
        return cls._TOKEN_PATTERN.findall(text.lower())

    def _build_bm25_index(self):
        ids, docs, metas = [], [], []
        page_size = 5000
        offset = 0
        while True:
            page = self.collection.get(include=["documents", "metadatas"], limit=page_size, offset=offset)
            page_ids = page["ids"]
            if not page_ids:
                break
            ids.extend(page_ids)
            docs.extend(page["documents"])
            metas.extend(page["metadatas"])
            offset += len(page_ids)
            if len(page_ids) < page_size:
                break

        self._bm25_ids = ids
        self._bm25_docs = docs
        self._bm25_metas = metas
        tokenized = [self._tokenize(doc) for doc in docs]
        self._bm25 = BM25Okapi(tokenized) if tokenized else None

    def _vector_search(self, query: str, k: int) -> list[dict]:
        if self.collection.count() == 0:
            return []
        embedding = self.embed_model.encode([query]).tolist()
        results = self.collection.query(query_embeddings=embedding, n_results=k)
        return [
            {"id": _id, "text": doc, "metadata": meta}
            for _id, doc, meta in zip(
                results["ids"][0], results["documents"][0], results["metadatas"][0]
            )
        ]

    def _keyword_search(self, query: str, k: int) -> list[dict]:
        if self._bm25 is None:
            return []
        scores = self._bm25.get_scores(self._tokenize(query))
        top_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
        return [
            {"id": self._bm25_ids[i], "text": self._bm25_docs[i], "metadata": self._bm25_metas[i]}
            for i in top_idx
            if scores[i] > 0
        ]

    def _exact_id_hits(self, query: str) -> list[dict]:
        """Direct lookup for any literal ID mentioned in the query. BM25 ranks by
        term frequency/length normalization, which can rank a *mention* of an ID in
        another document's text above the canonical record itself (observed with
        Log4Shell: shorter follow-up-patch CVEs that reference CVE-2021-44228 in
        their description out-scored the CVE-2021-44228 record). An exact ID match
        should always win regardless of document length, so bypass ranking for it."""
        ids = set(CVE_ID_PATTERN.findall(query))
        if not ids:
            return []
        found = self.collection.get(ids=list(ids), include=["documents", "metadatas"])
        return [
            {"id": _id, "text": doc, "metadata": meta}
            for _id, doc, meta in zip(found["ids"], found["documents"], found["metadatas"])
        ]

    def retrieve(self, query: str, k: int = 5) -> list[dict]:
        """Exact ID hits first, then a round-robin merge of vector and keyword hits
        so neither source can crowd the other out of the remaining slots (a pure
        vector-first concat let semantically vague-but-close vector hits bury an
        exact keyword match)."""
        query = expand_query(query)
        exact_hits = self._exact_id_hits(query)
        vector_hits = self._vector_search(query, k)
        keyword_hits = self._keyword_search(query, k)

        merged = {}
        for hit in exact_hits:
            merged[hit["id"]] = hit
        for v, kw in zip_longest(vector_hits, keyword_hits):
            for hit in (v, kw):
                if hit is not None:
                    merged.setdefault(hit["id"], hit)
            if len(merged) >= k:
                break
        return list(merged.values())[:k]

    def refresh(self):
        """Rebuild the BM25 index after new documents are ingested."""
        self._build_bm25_index()


CVE_SYSTEM_PROMPT = """You are a security analyst assistant specializing in vulnerability \
intelligence. Answer the user's question using ONLY the CVE context provided below. \
Every CVE ID you mention in your answer MUST appear in the provided context — never \
invent or recall a CVE ID from your own training data. If the context does not contain \
enough information to answer, say so explicitly rather than guessing. Cite CVE IDs \
inline like (CVE-2021-44228)."""

COMPLIANCE_SYSTEM_PROMPT = """You are a compliance and security policy assistant. \
Answer the user's question using ONLY the framework/control context provided below \
(NIST SP 800-53, NIST CSF, CIS Controls, ISO/IEC 27001 control titles). Always cite the \
framework and control ID inline, e.g. (NIST 800-53 SI-2) or (CIS Control 7). If the \
context does not contain enough information to answer, say so explicitly rather than \
guessing or relying on general knowledge of the standard."""


class CVERagPipeline:
    def __init__(self):
        self.retriever = HybridRetriever("cves")
        self.llm = Anthropic()

    def retrieve(self, query: str, k: int = 5) -> list[dict]:
        return self.retriever.retrieve(query, k)

    def _ground_answer(self, answer: str, context_docs: list[dict]) -> tuple[str, list[str]]:
        context_ids = {doc["id"] for doc in context_docs}
        cited_ids = set(CVE_ID_PATTERN.findall(answer))
        hallucinated = cited_ids - context_ids
        for bad_id in hallucinated:
            answer = answer.replace(bad_id, f"{bad_id} [UNVERIFIED - not in retrieved sources]")
        return answer, sorted(hallucinated)

    def _related_controls(self, context_docs: list[dict]) -> list[dict]:
        cwe_ids = set()
        for doc in context_docs:
            raw = doc.get("metadata", {}).get("cwe_ids", "")
            cwe_ids.update(c for c in raw.split(",") if c)
        return controls_for_cwes(sorted(cwe_ids))

    def query(self, question: str, k: int = 5) -> dict:
        context_docs = self.retrieve(question, k)

        if not context_docs:
            return {
                "domain": "cve",
                "answer": "No relevant CVE data found in the index for this question.",
                "sources": [],
                "hallucinated_ids": [],
                "related_controls": [],
            }

        context_text = "\n\n---\n\n".join(doc["text"] for doc in context_docs)
        message = self.llm.messages.create(
            model=LLM_MODEL,
            max_tokens=1024,
            system=CVE_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Context:\n{context_text}\n\nQuestion: {question}"}],
        )
        raw_answer = message.content[0].text
        grounded_answer, hallucinated = self._ground_answer(raw_answer, context_docs)

        return {
            "domain": "cve",
            "answer": grounded_answer,
            "sources": [doc["id"] for doc in context_docs],
            "hallucinated_ids": hallucinated,
            "related_controls": self._related_controls(context_docs),
        }

    def query_stream(self, question: str, k: int = 5):
        """Generator version of query(): yields ("delta", text_chunk) events as
        the model produces them, then a single terminal ("done", metadata) event
        once the full answer is in. The grounding check needs the complete answer
        text (a hallucinated CVE ID could be split across two token chunks), so
        it can only run after streaming finishes — the UI surfaces it in the
        final metadata rather than as an inline mid-stream annotation."""
        context_docs = self.retrieve(question, k)

        if not context_docs:
            yield "done", {
                "domain": "cve",
                "answer": "No relevant CVE data found in the index for this question.",
                "sources": [],
                "hallucinated_ids": [],
                "related_controls": [],
            }
            return

        context_text = "\n\n---\n\n".join(doc["text"] for doc in context_docs)
        with self.llm.messages.stream(
            model=LLM_MODEL,
            max_tokens=1024,
            system=CVE_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Context:\n{context_text}\n\nQuestion: {question}"}],
        ) as stream:
            raw_answer = ""
            for chunk in stream.text_stream:
                raw_answer += chunk
                yield "delta", chunk

        grounded_answer, hallucinated = self._ground_answer(raw_answer, context_docs)
        yield "done", {
            "domain": "cve",
            "answer": grounded_answer,
            "sources": [doc["id"] for doc in context_docs],
            "hallucinated_ids": hallucinated,
            "related_controls": self._related_controls(context_docs),
        }


class ComplianceRagPipeline:
    def __init__(self):
        self.retriever = HybridRetriever("compliance")
        self.llm = Anthropic()

    def retrieve(self, query: str, k: int = 5) -> list[dict]:
        return self.retriever.retrieve(query, k)

    def query(self, question: str, k: int = 5) -> dict:
        context_docs = self.retrieve(question, k)

        if not context_docs:
            return {
                "domain": "compliance",
                "answer": "No relevant compliance control found in the index for this question.",
                "sources": [],
            }

        context_text = "\n\n---\n\n".join(doc["text"] for doc in context_docs)
        message = self.llm.messages.create(
            model=LLM_MODEL,
            max_tokens=1024,
            system=COMPLIANCE_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Context:\n{context_text}\n\nQuestion: {question}"}],
        )
        answer = message.content[0].text

        return {
            "domain": "compliance",
            "answer": answer,
            "sources": [
                f"{doc['metadata'].get('framework', '')} {doc['metadata'].get('control_id', doc['id'])}"
                for doc in context_docs
            ],
        }

    def query_stream(self, question: str, k: int = 5):
        """Generator version of query(); see CVERagPipeline.query_stream for the
        event shape ("delta"/"done")."""
        context_docs = self.retrieve(question, k)

        if not context_docs:
            yield "done", {
                "domain": "compliance",
                "answer": "No relevant compliance control found in the index for this question.",
                "sources": [],
            }
            return

        context_text = "\n\n---\n\n".join(doc["text"] for doc in context_docs)
        with self.llm.messages.stream(
            model=LLM_MODEL,
            max_tokens=1024,
            system=COMPLIANCE_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Context:\n{context_text}\n\nQuestion: {question}"}],
        ) as stream:
            answer = ""
            for chunk in stream.text_stream:
                answer += chunk
                yield "delta", chunk

        yield "done", {
            "domain": "compliance",
            "answer": answer,
            "sources": [
                f"{doc['metadata'].get('framework', '')} {doc['metadata'].get('control_id', doc['id'])}"
                for doc in context_docs
            ],
        }


CVE_STEMS = (
    "cve", "vulnerab", "exploit", "patch", "affect", "product", "version",
    "cvss", "severity", "advisory", "poc", "flaw", "bug", "software", "library",
    "server", "kernel",
)
COMPLIANCE_STEMS = (
    "nist", "iso", "27001", "cis ", "control", "framework", "complian",
    "polic", "requirement", "audit", "standard", "annex", "csf", "regulat",
)


class QueryRouter:
    """Cheap keyword-overlap classifier deciding which domain(s) a question targets.

    Kept intentionally simple (no LLM call) for latency/cost; see eval/evaluate.py
    for measured routing accuracy against a labeled test set. Uses prefix matching
    (not exact-set membership) so plurals/verb forms like "affects"/"affected" or
    "compliance"/"compliant" still match their stem.
    """

    @staticmethod
    def classify(question: str) -> str:
        if CVE_ID_PATTERN.search(question):
            return "cve"

        tokens = re.findall(r"[a-z0-9]+", question.lower())
        cve_score = sum(1 for t in tokens if any(t.startswith(s) for s in CVE_STEMS))
        compliance_score = sum(1 for t in tokens if any(t.startswith(s) for s in COMPLIANCE_STEMS))

        if cve_score > compliance_score:
            return "cve"
        if compliance_score > cve_score:
            return "compliance"
        return "both"
