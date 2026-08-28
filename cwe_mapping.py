"""
Builds a CWE-ID -> compliance-control lookup from the curated compliance
corpus, used to cross-link a CVE's weakness type(s) to the framework
controls it violates.
"""
import json
import os
from collections import defaultdict

CORPUS_PATH = os.path.join(os.path.dirname(__file__), "data", "compliance_corpus.json")

_cwe_to_controls = None


def _load():
    global _cwe_to_controls
    if _cwe_to_controls is not None:
        return _cwe_to_controls

    with open(CORPUS_PATH) as f:
        controls = json.load(f)

    mapping = defaultdict(list)
    for c in controls:
        for cwe in c.get("cwe_links", []):
            mapping[cwe].append(
                {
                    "framework": c["framework"],
                    "control_id": c["control_id"],
                    "title": c["title"],
                }
            )

    _cwe_to_controls = dict(mapping)
    return _cwe_to_controls


def controls_for_cwes(cwe_ids: list[str]) -> list[dict]:
    """Return de-duplicated list of compliance controls linked to the given CWE IDs."""
    mapping = _load()
    seen = set()
    results = []
    for cwe in cwe_ids:
        for control in mapping.get(cwe, []):
            key = (control["framework"], control["control_id"])
            if key not in seen:
                seen.add(key)
                results.append(control)
    return results
