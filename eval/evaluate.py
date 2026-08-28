"""
Evaluation harness for the two-domain security knowledge assistant.

Measures:
  - CVE Retrieval Recall@5 / Answer Correctness / Grounding Rate
  - Compliance Retrieval Recall@5 / Answer Correctness
  - Routing Accuracy: did QueryRouter send the question to the right domain?

Usage:
    python eval/evaluate.py
"""
import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
from rag import CVERagPipeline, ComplianceRagPipeline, QueryRouter  # noqa: E402

TEST_SET_PATH = os.path.join(os.path.dirname(__file__), "test_set.json")


def eval_cve(pipeline: CVERagPipeline, cases: list[dict]):
    recall_hits = correctness_hits = 0
    total_cited = grounded_hits = 0
    results = []

    for case in cases:
        question = case["question"]
        expected = set(case["expected_cve_ids"])

        retrieved = pipeline.retrieve(question, k=5)
        retrieved_ids = {doc["id"] for doc in retrieved}
        recall_hit = bool(expected & retrieved_ids)
        recall_hits += int(recall_hit)

        response = pipeline.query(question)
        cited_ids = set(response["sources"])
        hallucinated = set(response["hallucinated_ids"])
        total_cited += len(cited_ids) + len(hallucinated)
        grounded_hits += len(cited_ids)

        correctness_hit = any(cve in response["answer"] for cve in expected)
        correctness_hits += int(correctness_hit)

        results.append({
            "question": question, "expected": sorted(expected),
            "retrieved": sorted(retrieved_ids), "recall_hit": recall_hit,
            "correctness_hit": correctness_hit, "hallucinated": sorted(hallucinated),
        })

    n = len(cases)
    print("\n=== CVE Domain ===")
    print(f"Retrieval Recall@5: {recall_hits}/{n} = {recall_hits / n:.2%}")
    print(f"Answer Correctness: {correctness_hits}/{n} = {correctness_hits / n:.2%}")
    if total_cited:
        print(f"Grounding Rate: {grounded_hits / total_cited:.2%}")
    return results


def eval_compliance(pipeline: ComplianceRagPipeline, cases: list[dict]):
    recall_hits = correctness_hits = 0
    results = []

    for case in cases:
        question = case["question"]
        expected = set(case["expected_control_ids"])

        retrieved = pipeline.retrieve(question, k=5)
        retrieved_control_ids = {doc["metadata"].get("control_id", "") for doc in retrieved}
        recall_hit = bool(expected & retrieved_control_ids)
        recall_hits += int(recall_hit)

        response = pipeline.query(question)
        correctness_hit = any(cid in response["answer"] for cid in expected)
        correctness_hits += int(correctness_hit)

        results.append({
            "question": question, "expected": sorted(expected),
            "retrieved": sorted(retrieved_control_ids), "recall_hit": recall_hit,
            "correctness_hit": correctness_hit,
        })

    n = len(cases)
    print("\n=== Compliance Domain ===")
    print(f"Retrieval Recall@5: {recall_hits}/{n} = {recall_hits / n:.2%}")
    print(f"Answer Correctness: {correctness_hits}/{n} = {correctness_hits / n:.2%}")
    return results


def eval_routing(cases: list[dict]):
    hits = 0
    results = []
    for case in cases:
        predicted = QueryRouter.classify(case["question"])
        hit = predicted == case["expected_domain"]
        hits += int(hit)
        results.append({"question": case["question"], "expected": case["expected_domain"],
                         "predicted": predicted, "hit": hit})

    n = len(cases)
    print("\n=== Routing ===")
    print(f"Routing Accuracy: {hits}/{n} = {hits / n:.2%}")
    return results


def run_eval():
    with open(TEST_SET_PATH) as f:
        test_set = json.load(f)

    cve_results = eval_cve(CVERagPipeline(), test_set["cve"])
    compliance_results = eval_compliance(ComplianceRagPipeline(), test_set["compliance"])
    routing_results = eval_routing(test_set["routing"])

    print("\n=== Per-case detail ===")
    print(json.dumps({
        "cve": cve_results,
        "compliance": compliance_results,
        "routing": routing_results,
    }, indent=2))


if __name__ == "__main__":
    run_eval()
