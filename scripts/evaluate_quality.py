"""Report deterministic fixture accuracy and handwritten citation-scorer behavior."""

import argparse
import json
from pathlib import Path

from timeline_demo.enrichment.ioc_extractor import extract_iocs_from_text
from timeline_demo.evaluation import score_review, score_sets
from timeline_demo.parsers.common import file_hash
from timeline_demo.parsers.registry import SPECS, normalize_record

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    truth = json.loads((ROOT / "benchmarks/parser_truth.json").read_text())
    samples = json.loads((ROOT / "examples/parser_samples.json").read_text())
    assert file_hash(ROOT / "examples/parser_samples.json") == truth["fixture_sha256"]
    assert set(samples) == set(truth["expected"]) == set(SPECS)
    checked = correct = 0
    errors = []
    for name, expected in truth["expected"].items():
        events = normalize_record(samples[name], name, "fixture", "a" * 64, 1)
        assert len(events) == 1
        for key, value in expected.items():
            checked += 1
            correct += events[0][key] == value
            if events[0][key] != value:
                errors.append({"parser": name, "field": key, "expected": value, "actual": events[0][key]})
    predicted, expected = set(), set()
    per_case = []
    for index, case in enumerate(json.loads((ROOT / "benchmarks/ioc_truth.json").read_text())):
        actual = extract_iocs_from_text(case["text"])
        p = {(index, kind, value) for kind, values in actual.items() for value in values}
        e = {(index, kind, value) for kind, values in case["expected"].items() for value in values}
        predicted.update(p)
        expected.update(e)
        per_case.append({"name": case["name"], **score_sets(p, e)})
    report = {
        "scope": "synthetic fixture diagnostics; not real model or incident quality",
        "parser_fields": {
            "checked": checked,
            "correct": correct,
            "accuracy": correct / checked,
            "errors": errors,
        },
        "ioc_candidates": {**score_sets(predicted, expected), "cases": per_case},
        "synthetic_citation_scorer": score_review(
            json.loads((ROOT / "benchmarks/synthetic_analysis.json").read_text()),
            ROOT / "examples/demo_bundle",
            json.loads((ROOT / "benchmarks/synthetic_review.json").read_text()),
        ),
        "provider_model_quality": None,
        "model_tokens": 0,
        "fixture_hashes": {p.name: file_hash(p) for p in sorted((ROOT / "benchmarks").glob("*.json"))},
    }
    with Path(args.output).open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))
    if errors:
        raise SystemExit("parser truth mismatch")


if __name__ == "__main__":
    main()
