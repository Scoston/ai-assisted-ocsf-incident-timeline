import copy
import json
from pathlib import Path

import pytest

from timeline_demo.evaluation import score_review, score_sets
from timeline_demo.parsers.common import compact_json, sha256_of_text

ROOT = Path(__file__).resolve().parents[1]


def inputs():
    return (
        json.loads((ROOT / "benchmarks/synthetic_analysis.json").read_text()),
        json.loads((ROOT / "benchmarks/synthetic_review.json").read_text()),
    )


def test_precision_recall_preserves_empty_denominators():
    assert score_sets([], [])["precision"] is None
    assert score_sets([], ["missing"])["recall"] == 0
    assert score_sets(["a", "a", "b"], ["a", "c"]) == {
        "true_positive": 1,
        "false_positive": 1,
        "false_negative": 1,
        "precision": 0.5,
        "recall": 0.5,
    }


def test_valid_citations_can_be_unfaithful_and_duplicates_do_not_inflate_metrics():
    analysis, labels = inputs()
    result = score_review(analysis, ROOT / "examples/demo_bundle", labels)
    assert result["claim_precision"] == pytest.approx(1 / 3)
    assert result["claim_recall"] == 0.5
    assert result["citation_reference_validity"] == 1
    assert result["citation_faithfulness"] == pytest.approx(2 / 3)
    assert result["duplicate_claims"] == 1


@pytest.mark.parametrize(
    "fault",
    [
        "altered_analysis",
        "wrong_bundle",
        "invented_event",
        "missing_judgment",
        "duplicate_index",
        "unknown_claim",
        "missing_support",
        "duplicate_truth",
    ],
)
def test_unbound_or_incomplete_reviews_rejected(fault):
    analysis, labels = inputs()
    if fault == "altered_analysis":
        analysis["analysis"]["summary"] += " altered"
    elif fault == "wrong_bundle":
        labels["bundle_id"] = "0" * 64
    elif fault == "invented_event":
        analysis["receipt"]["evidence_refs"]["e1"] = "0" * 64
    elif fault == "missing_judgment":
        labels["findings"].pop()
    elif fault == "duplicate_index":
        labels["findings"][1]["finding_index"] = 0
    elif fault == "unknown_claim":
        labels["findings"][0]["matched_claim_id"] = "invented"
    elif fault == "missing_support":
        del labels["findings"][0]["supported_by_citations"]
    else:
        labels["expected_claim_ids"].append(labels["expected_claim_ids"][0])
    with pytest.raises(ValueError):
        score_review(analysis, ROOT / "examples/demo_bundle", labels)


def test_empty_analysis_is_unscored_not_perfect():
    analysis, labels = inputs()
    analysis = copy.deepcopy(analysis)
    analysis["analysis"]["findings"] = []
    labels["findings"] = []
    labels["analysis_sha256"] = sha256_of_text(compact_json(analysis["analysis"]))
    report = score_review(analysis, ROOT / "examples/demo_bundle", labels)
    assert report["claim_precision"] is None
    assert report["citation_faithfulness"] is None
    assert report["claim_recall"] == 0


@pytest.mark.parametrize(
    ("text", "ips"),
    [
        ("[2001:DB8::10] 2001:0db8:0:0:0:0:0:10", ["2001:db8::10"]),
        ("::ffff:192.0.2.1", ["::ffff:192.0.2.1"]),
        ("2026-09-01T10:00:00Z 10:00:00 999.2.3.4 2001:db8::xyz", []),
        ("https://[2001:db8::1]/ 198.51.100.10", ["198.51.100.10", "2001:db8::1"]),
        ("fe80::1%eth0", []),
    ],
)
def test_ipv6_candidate_extraction_uses_address_validation(text, ips):
    from timeline_demo.enrichment.ioc_extractor import extract_iocs_from_text

    assert extract_iocs_from_text(text)["ips"] == ips
