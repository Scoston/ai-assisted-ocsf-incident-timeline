"""Offline metrics. Human judgments are inputs; this module never asks a model to grade itself."""

from __future__ import annotations

import json

from timeline_demo.ai import validate_analysis
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.parsers.common import compact_json, sha256_of_text
from timeline_demo.pipeline import read_timeline


def score_sets(predicted, expected):
    predicted, expected = set(predicted), set(expected)
    tp, fp, fn = len(predicted & expected), len(predicted - expected), len(expected - predicted)
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def score_review(result, bundle, labels):
    """Score a complete review bound to the exact analysis JSON and source bundle.

    Claim matching and evidence support must be adjudicated by an analyst. Metrics
    assess the supplied review, not whether the reviewer or reference set is correct.
    """
    manifest = verify_bundle(bundle)
    analysis, receipt = result["analysis"], result["receipt"]
    refs = receipt["evidence_refs"]
    if receipt.get("bundle_id") != manifest["bundle_id"] or labels.get("bundle_id") != manifest["bundle_id"]:
        raise ValueError("evaluation source bundle mismatch")
    if labels.get("analysis_sha256") != sha256_of_text(compact_json(analysis)):
        raise ValueError("review labels belong to a different analysis")
    if labels.get("version") != "1.0" or not str(labels.get("reviewer", "")).strip():
        raise ValueError("review version and reviewer are required")
    if not isinstance(refs, dict) or any(not isinstance(v, str) for v in refs.values()):
        raise ValueError("invalid evidence reference map")
    event_ids = {e["event_uuid"] for e in read_timeline(bundle)}
    if not set(refs.values()) <= event_ids:
        raise ValueError("receipt references events outside this bundle")
    validate_analysis(analysis, refs)
    claims = labels.get("expected_claim_ids")
    if (
        not isinstance(claims, list)
        or any(not isinstance(v, str) or not v for v in claims)
        or len(set(claims)) != len(claims)
    ):
        raise ValueError("expected claim IDs must be unique nonempty strings")
    judgments = labels.get("findings")
    findings = analysis["findings"]
    if not isinstance(judgments, list) or len(judgments) != len(findings):
        raise ValueError("every finding needs one judgment")
    indexed = {}
    for judgment in judgments:
        index = judgment.get("finding_index")
        if type(index) is not int or not 0 <= index < len(findings) or index in indexed:
            raise ValueError("invalid or duplicate finding judgment")
        matched = judgment.get("matched_claim_id")
        if matched is not None and matched not in claims:
            raise ValueError("judgment matches an unknown reference claim")
        if type(judgment.get("supported_by_citations")) is not bool:
            raise ValueError("each finding requires a citation-support judgment")
        indexed[index] = judgment
    matched, unsupported, correct, duplicate = set(), 0, 0, 0
    for index in range(len(findings)):
        judgment = indexed[index]
        claim = judgment["matched_claim_id"]
        unsupported += not judgment["supported_by_citations"]
        # Credit each reference claim once. Repetition cannot inflate precision/recall.
        if claim is not None:
            duplicate += claim in matched
            if claim not in matched:
                correct += 1
                matched.add(claim)
    return {
        "evaluation_version": "1.0",
        "bundle_id": manifest["bundle_id"],
        "analysis_sha256": labels["analysis_sha256"],
        "labels_sha256": sha256_of_text(compact_json(labels)),
        "reviewer": labels["reviewer"],
        "model": receipt.get("model"),
        "task": receipt.get("task"),
        "findings": len(findings),
        "expected_claims": len(claims),
        "matched_claims": correct,
        "duplicate_claims": duplicate,
        "claim_precision": correct / len(findings) if findings else None,
        "claim_recall": correct / len(claims) if claims else None,
        "citation_reference_validity": 1.0 if findings else None,
        "citation_faithfulness": (len(findings) - unsupported) / len(findings) if findings else None,
        "model_tokens": 0,
        "scope": "finding-level analyst judgments; summary and next-step prose are not scored",
    }


def main(argv=None):
    import argparse
    from pathlib import Path
    from timeline_demo.parsers.readers import _strict_json

    parser = argparse.ArgumentParser(description="Score an existing analysis using analyst-reviewed labels")
    parser.add_argument("--analysis", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if Path(args.output).resolve().is_relative_to(Path(args.bundle).resolve()):
            raise ValueError("evaluation output must be outside the evidence bundle")
        result = score_review(
            _strict_json(Path(args.analysis).read_text(encoding="utf-8")),
            args.bundle,
            _strict_json(Path(args.labels).read_text(encoding="utf-8")),
        )
        with Path(args.output).open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.exit(2, f"timeline-evaluate: {exc}\n")


if __name__ == "__main__":
    main()
