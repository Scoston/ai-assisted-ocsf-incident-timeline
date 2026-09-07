"""A verified receipt for an authenticated Tines service; never executes a story."""

from timeline_demo.ai_audit import append_audit
from timeline_demo.ai_evidence import digest


def approved_handoff(harness, bundle, action_id, *, review_policy, review_policy_sha256):
    accepted = harness.approved(
        bundle, action_id, review_policy=review_policy, review_policy_sha256=review_policy_sha256
    )
    receipt = {
        "version": "1.0",
        "case_id": accepted["receipt"]["case_id"],
        "bundle_id": accepted["receipt"]["bundle_id"],
        "action_id": action_id,
        "result_sha256": accepted["result_sha256"],
        "review_sha256": accepted["human_review"]["digest"],
        "evidence_chunk_ids": sorted(accepted["receipt"]["chunk_refs"].values()),
        "decision": "human_approved_analysis",
        "model_tokens": 0,
    }
    receipt["idempotency_key"] = digest(receipt)
    with harness._db() as db:
        append_audit(
            db, action_id, "handoff_prepared", {"destination": "tines", "receipt_sha256": digest(receipt)}
        )
    return receipt
