"""Action-local audit chains and pinned human-review policy.

SQLite permissions and deployment identity are the trust boundary. A hash chain
detects edits relative to a retained head; it cannot defeat an administrator who
rewrites the whole database and every external pin.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from timeline_demo.ai_evidence import digest
from timeline_demo.core.storage import no_links
from timeline_demo.parsers.common import compact_json, sha256_of_text
from timeline_demo.parsers.readers import _strict_json


def local_principal():
    if not hasattr(os, "getuid"):
        raise ValueError(
            "local human review requires an OS UID; use an authenticated service on this platform"
        )
    return "local:uid:" + str(os.getuid())


def initialize_audit(db):
    db.execute("""CREATE TABLE IF NOT EXISTS ai_audit (
        action_id TEXT NOT NULL, sequence INTEGER NOT NULL, event TEXT NOT NULL,
        time TEXT NOT NULL, payload TEXT NOT NULL, previous TEXT NOT NULL,
        digest TEXT NOT NULL, PRIMARY KEY(action_id, sequence))""")
    for operation in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS ai_audit_no_{operation.lower()}
            BEFORE {operation} ON ai_audit BEGIN
            SELECT RAISE(ABORT, 'AI audit events are append-only'); END""")


def append_audit(db, action_id, event, payload):
    last = db.execute(
        "SELECT sequence,digest FROM ai_audit WHERE action_id=? ORDER BY sequence DESC LIMIT 1", (action_id,)
    ).fetchone()
    record = {
        "action_id": action_id,
        "sequence": last[0] + 1 if last else 1,
        "event": event,
        "time": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
        "previous": last[1] if last else "0" * 64,
    }
    record["digest"] = digest(record)
    db.execute(
        "INSERT INTO ai_audit VALUES(?,?,?,?,?,?,?)",
        (
            action_id,
            record["sequence"],
            event,
            record["time"],
            compact_json(payload),
            record["previous"],
            record["digest"],
        ),
    )
    return record


def audit_records(db, action_id):
    rows = db.execute("SELECT * FROM ai_audit WHERE action_id=? ORDER BY sequence", (action_id,)).fetchall()
    records = [{**dict(row), "payload": _strict_json(row["payload"])} for row in rows]
    verify_records(records)
    return records


def verify_records(records):
    previous = "0" * 64
    action = records[0]["action_id"] if records else None
    for sequence, record in enumerate(records, 1):
        if (
            record["action_id"] != action
            or record["sequence"] != sequence
            or record["previous"] != previous
            or record["digest"] != digest({k: v for k, v in record.items() if k != "digest"})
        ):
            raise ValueError("AI audit chain integrity failure")
        previous = record["digest"]
    return previous


def record_call(db, action_id, event, **metadata):
    row = dict(db.execute("SELECT * FROM calls WHERE key=?", (action_id,)).fetchone())
    return append_audit(db, action_id, event, {"call_sha256": digest(row), **metadata})


def check_call(db, row):
    records = audit_records(db, row["key"])
    states = [r["payload"]["call_sha256"] for r in records if "call_sha256" in r["payload"]]
    if not states or states[-1] != digest(dict(row)):
        raise ValueError("AI call does not match its audit history")
    return records


def load_review_policy(path, expected_sha256):
    path = no_links(path)
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024 or sha256_of_text(raw.decode("utf-8")) != expected_sha256:
        raise ValueError("human-review policy pin mismatch")
    policy = _strict_json(raw)
    if (
        not isinstance(policy, dict)
        or set(policy) != {"version", "reviewers", "require_separation"}
        or policy["version"] != "1.0"
        or type(policy["require_separation"]) is not bool
        or not isinstance(policy["reviewers"], list)
    ):
        raise ValueError("invalid human-review policy")
    seen = set()
    for entry in policy["reviewers"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"principal", "cases"}
            or not isinstance(entry["principal"], str)
            or not entry["principal"]
            or entry["principal"] in seen
            or not isinstance(entry["cases"], list)
            or not entry["cases"]
            or any(not isinstance(c, str) or not c for c in entry["cases"])
        ):
            raise ValueError("invalid human reviewer")
        seen.add(entry["principal"])
    return policy


def authorize_reviewer(policy, principal, case_id, initiator):
    if not any(r["principal"] == principal and case_id in r["cases"] for r in policy["reviewers"]):
        raise PermissionError("human reviewer is not authorized for this case")
    if policy["require_separation"] and principal == initiator:
        raise PermissionError("reviewer must differ from the action initiator")


def validate_review(decision, candidate, verification):
    required = {"decision", "reason", "result_sha256", "acknowledge_coverage", "claims"}
    if (
        not isinstance(decision, dict)
        or set(decision) != required
        or decision["decision"] not in {"approve", "reject", "request_changes"}
        or not isinstance(decision["reason"], str)
        or not 1 <= len(decision["reason"].strip()) <= 2000
        or type(decision["acknowledge_coverage"]) is not bool
        or not isinstance(decision["claims"], dict)
    ):
        raise ValueError("invalid human decision")
    if decision["decision"] != "approve":
        return
    if not verification["passed"] or not decision["acknowledge_coverage"]:
        raise ValueError("approval requires passed evidence checks and acknowledged coverage")
    expected = {c["claim_id"]: c for c in verification["claims"]}
    if set(decision["claims"]) != set(expected):
        raise ValueError("every observation and hypothesis needs a human judgment")
    for claim_id, judgment in decision["claims"].items():
        claim = expected[claim_id]
        verdict = "supported" if claim["kind"] == "observation" else "plausible_hypothesis"
        if (
            not isinstance(judgment, dict)
            or set(judgment) != {"verdict", "rationale", "evidence_chunk_ids"}
            or judgment["verdict"] != verdict
            or not isinstance(judgment["rationale"], str)
            or not 1 <= len(judgment["rationale"].strip()) <= 2000
            or not isinstance(judgment["evidence_chunk_ids"], list)
            or any(not isinstance(v, str) for v in judgment["evidence_chunk_ids"])
            or set(judgment["evidence_chunk_ids"]) != {w["chunk_id"] for w in claim["witnesses"]}
        ):
            raise ValueError("claim judgment must cover its cited chunks and assess all associated prose")
