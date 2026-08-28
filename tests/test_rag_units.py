"""
Unit tests for the pure, API-free pieces of the RAG pipeline: query
expansion, routing, and the hallucination-grounding check. Deliberately
excludes anything that calls Chroma or the Anthropic API so this suite runs
free and fast in CI.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rag import expand_query, QueryRouter, CVE_ID_PATTERN


def test_expand_query_adds_known_alias():
    expanded = expand_query("tell me about log4shell")
    assert "CVE-2021-44228" in expanded


def test_expand_query_leaves_unknown_terms_untouched():
    q = "what CVEs affect apache 2.4.49"
    assert expand_query(q) == q


def test_cve_id_pattern_matches_standard_ids():
    assert CVE_ID_PATTERN.findall("see CVE-2021-44228 and CVE-2017-0144") == [
        "CVE-2021-44228", "CVE-2017-0144",
    ]


def test_router_detects_literal_cve_id_regardless_of_wording():
    assert QueryRouter.classify("is CVE-2021-44228 patched") == "cve"


def test_router_classifies_cve_leaning_question():
    assert QueryRouter.classify("what CVEs affect apache http server 2.4.49") == "cve"


def test_router_classifies_compliance_leaning_question():
    assert QueryRouter.classify("what does NIST 800-53 say about audit controls") == "compliance"


def test_router_falls_back_to_both_when_ambiguous():
    assert QueryRouter.classify("hello") == "both"
