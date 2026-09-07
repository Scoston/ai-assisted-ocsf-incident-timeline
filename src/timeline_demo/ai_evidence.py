"""Zero-model-token evidence checks and content-addressed provenance.

Equality of a quoted field is testable. Entailment of unrestricted prose is not
established by that equality: hypotheses always need separate human adjudication.
"""

from __future__ import annotations

from importlib.resources import files

import jsonschema

from timeline_demo.parsers.common import compact_json, sha256_of_text
from timeline_demo.parsers.readers import _strict_json

VERIFIER_VERSION = "field-witness-1.0"
FIELDS = ("source", "activity", "status", "severity", "count", "first", "last") + tuple(
    f"examples.{i}.{key}" for i in range(2) for key in ("time", "actor", "asset", "ip")
)


def evidence_value(chunk, field):
    if field not in FIELDS:
        return None
    value = chunk["payload"]
    try:
        for part in field.split("."):
            value = value[int(part)] if isinstance(value, list) else value[part]
    except (KeyError, IndexError, ValueError):
        return None
    return str(value)


def digest(value):
    return sha256_of_text(compact_json(value))


def group_key(event):
    return tuple(str(event.get(k, "")) for k in ("parser_name", "activity_name", "status", "severity"))


def event_chunk(bundle_id, event):
    return "event-" + digest({"bundle_id": bundle_id, "event": event})


def verify_candidate(candidate, chunks):
    schema = _strict_json(
        files("timeline_demo").joinpath("resources/evidence_analysis.schema.json").read_text()
    )
    errors, claims = [], []
    try:
        jsonschema.validate(candidate, schema)
    except jsonschema.ValidationError:
        return {
            "version": VERIFIER_VERSION,
            "passed": False,
            "errors": ["invalid_output_schema"],
            "claims": [],
            "model_tokens": 0,
        }
    if candidate["abstain"] and (candidate["observations"] or candidate["hypotheses"]):
        errors.append("abstention_contains_claims")
    if not candidate["abstain"] and not candidate["observations"]:
        errors.append("observations_or_abstention_required")
    seen = set()
    for kind, items in (("observation", candidate["observations"]), ("hypothesis", candidate["hypotheses"])):
        for index, item in enumerate(items, 1):
            claim_id = ("o" if kind == "observation" else "h") + str(index)
            witnesses = [item] if kind == "observation" else item["evidence"]
            issues, citations = [], []
            for witness in witnesses:
                chunk = chunks.get(witness["chunk_ref"])
                if chunk is None:
                    issues.append("unknown_or_unsupplied_chunk")
                    continue
                expected = evidence_value(chunk, witness["field"])
                if expected is None or not expected.strip() or witness["value"] != expected:
                    issues.append("evidence_value_mismatch")
                citations.append(
                    {
                        **witness,
                        "chunk_id": chunk["chunk_id"],
                        "membership_sha256": chunk["membership_sha256"],
                    }
                )
            if kind == "observation":
                fingerprint = digest(item)
                if fingerprint in seen:
                    issues.append("duplicate_observation")
                seen.add(fingerprint)
            elif any(not item[k].strip() for k in ("interpretation", "alternative", "next_step")):
                issues.append("empty_hypothesis_prose")
            claims.append(
                {
                    "claim_id": claim_id,
                    "kind": kind,
                    "witnesses": citations,
                    "passed": not issues,
                    "errors": issues,
                    "semantic_support": "field_equality"
                    if kind == "observation"
                    else "requires_human_review",
                }
            )
            errors.extend(claim_id + ":" + issue for issue in issues)
    return {
        "version": VERIFIER_VERSION,
        "passed": not errors,
        "errors": errors,
        "claims": claims,
        "model_tokens": 0,
    }


def render_analysis(candidate, verification, coverage):
    """Only fixed templates can assert observations; arbitrary model prose stays a hypothesis."""
    if not verification["passed"]:
        raise ValueError("evidence checks failed")
    observations = []
    for claim, witness in zip(verification["claims"], candidate["observations"]):
        observations.append(
            {
                "claim_id": claim["claim_id"],
                "text": f"Recorded group {witness['chunk_ref']}: {witness['field']} = {witness['value']}",
                "citations": claim["witnesses"],
            }
        )
    hypotheses = []
    for index, hypothesis in enumerate(candidate["hypotheses"], 1):
        claim = next(c for c in verification["claims"] if c["claim_id"] == "h" + str(index))
        hypotheses.append(
            {
                "claim_id": claim["claim_id"],
                **hypothesis,
                "citations": claim["witnesses"],
                "classification": "human-reviewed hypothesis; not an established fact",
            }
        )
    return {
        "summary": "\n".join(o["text"] for o in observations)
        or "The model abstained; no observations were proposed.",
        "observations": observations,
        "hypotheses": hypotheses,
        "limitations": [
            f"Selected groups represent {coverage['covered_events']} of {coverage['total_events']} normalized events; only {coverage['representative_events_sent']} representative event examples were sent.",
            f"Acquisition contains {coverage['source_records']} source records and {coverage['quarantined_records']} quarantined records. Quarantine is not model context.",
            "Field equality does not establish source authenticity, complete collection, accurate clocks, causation, or semantic truth of a hypothesis.",
        ],
    }
