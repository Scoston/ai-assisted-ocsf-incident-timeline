"""Portable AI audit packages retain the full acquired evidence and every event locator."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from timeline_demo.ai_audit import append_audit, audit_records, verify_records
from timeline_demo.ai_evidence import digest, event_chunk, group_key
from timeline_demo.core.manifest import regular_members, safe_member, verify_bundle
from timeline_demo.core.storage import no_links, publish_tree
from timeline_demo.parsers.common import compact_json, file_hash
from timeline_demo.parsers.readers import _strict_json
from timeline_demo.pipeline import read_timeline


def evidence_rows(bundle, plan):
    groups = {tuple(c["group_key"]): (ref, c["chunk_id"]) for ref, c in plan["chunks"].items()}
    for event in read_timeline(bundle):
        ref, chunk_id = groups.get(group_key(event), (None, None))
        yield {
            "event_chunk_id": event_chunk(plan["identity"]["bundle_id"], event),
            "event_uuid": event["event_uuid"],
            "group_chunk_id": chunk_id,
            "model_chunk_ref": ref,
            "represented_in_model_group": ref is not None,
            "sent_as_representative": event["event_uuid"] in plan["evidence_refs"].values(),
            **{
                k: event[k]
                for k in (
                    "evidence_path",
                    "raw_file_hash",
                    "raw_data_hash",
                    "record_index",
                    "child_index",
                    "parser_name",
                    "parser_version",
                    "timeline_position",
                )
            },
        }


def inspect_chunk(harness, bundle, action_id, chunk_id, *, offset=0, limit=100):
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("invalid evidence page")
    harness._outside_bundle(bundle)
    harness._initialize()
    with harness._db() as db:
        db.execute("BEGIN IMMEDIATE")
        _, _, plan, _ = harness._read_action(db, bundle, action_id)
        matches, count = [], 0
        for locator in evidence_rows(bundle, plan):
            if chunk_id in {locator["event_chunk_id"], locator["group_chunk_id"]}:
                if offset <= count < offset + limit:
                    matches.append(locator)
                count += 1
        matched_ids = {v["event_uuid"]: v for v in matches}
        for event in read_timeline(bundle):
            if event["event_uuid"] in matched_ids:
                matched_ids[event["event_uuid"]]["normalized_event"] = event
        if not count:
            raise ValueError("chunk does not belong to this action and evidence bundle")
        append_audit(
            db, action_id, "evidence_opened", {"chunk_id": chunk_id, "offset": offset, "limit": limit}
        )
    return {
        "chunk_id": chunk_id,
        "total": count,
        "offset": offset,
        "locators": matches,
        "next_offset": offset + limit if offset + limit < count else None,
        "model_tokens": 0,
    }


def export_audit(harness, bundle, action_id, output):
    bundle, target = no_links(bundle), no_links(output)
    harness._outside_bundle(bundle)
    if (
        target.exists()
        or target.is_relative_to(bundle)
        or bundle.is_relative_to(target)
        or harness.path.is_relative_to(target)
    ):
        raise ValueError("AI audit export requires a new directory outside evidence and ledger")
    harness._initialize()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".ai-audit-") as temp:
        root = Path(temp) / "package"
        root.mkdir(mode=0o700)
        with harness._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM calls WHERE key=?", (action_id,)).fetchone()
            if row is not None:
                row, _, plan, _ = harness._read_action(db, bundle, action_id)
                call = dict(row)
            else:
                history = audit_records(db, action_id)
                identities = [r["payload"]["identity"] for r in history if "identity" in r["payload"]]
                if not identities:
                    raise ValueError("AI action is missing")
                from timeline_demo.ai import prepare

                identity = identities[-1]
                plan = prepare(bundle, identity["task"], identity["policy"])
                if plan["cache_key"] != action_id:
                    raise ValueError("planned AI action does not match evidence")
                call = None
            append_audit(db, action_id, "audit_exported", {"bundle_id": plan["identity"]["bundle_id"]})
            history = audit_records(db, action_id)
        record = {
            "version": "1.0",
            "action_id": action_id,
            "identity": plan["identity"],
            "call": call,
            "audit_head": history[-1]["digest"],
        }
        (root / "action.json").write_text(compact_json(record) + "\n", encoding="utf-8")
        (root / "audit.jsonl").write_text("".join(compact_json(r) + "\n" for r in history), encoding="utf-8")
        with (root / "chunks.jsonl").open("w", encoding="utf-8") as stream:
            for locator in evidence_rows(bundle, plan):
                stream.write(compact_json(locator) + "\n")
        # All acquired originals, receipts, duplicates and quarantine remain accessible.
        # The model sees only the minimized context; this copy never leaves the host automatically.
        shutil.copytree(bundle, root / "evidence_bundle", symlinks=True)
        verify_bundle(root / "evidence_bundle", plan["identity"]["manifest_sha256"])
        entries = {
            name: {
                "sha256": file_hash(safe_member(root, name)),
                "bytes": safe_member(root, name).stat().st_size,
            }
            for name in sorted(regular_members(root))
        }
        manifest = {
            "version": "1.0",
            "kind": "ai-audit",
            "action_id": action_id,
            "audit_head": record["audit_head"],
            "files": entries,
        }
        (root / "audit_manifest.json").write_text(compact_json(manifest) + "\n", encoding="utf-8")
        pin = file_hash(root / "audit_manifest.json")
        verify_audit_export(root, pin)
        publish_tree(root, target)
    return {
        "status": "exported",
        "action_id": action_id,
        "output": str(target),
        "manifest_sha256": pin,
        "audit_head": record["audit_head"],
        "model_tokens": 0,
    }


def verify_audit_export(directory, manifest_sha256):
    root = no_links(directory)
    members = regular_members(root)
    path = root / "audit_manifest.json"
    if path.stat().st_size > 16 * 1024**2 or file_hash(path) != manifest_sha256:
        raise ValueError("AI audit manifest pin mismatch")
    manifest = _strict_json(path.read_bytes())
    if (
        manifest.get("version") != "1.0"
        or manifest.get("kind") != "ai-audit"
        or not isinstance(manifest.get("files"), dict)
        or set(manifest["files"]) | {"audit_manifest.json"} != members
        or not {"action.json", "audit.jsonl", "chunks.jsonl"} <= set(manifest["files"])
    ):
        raise ValueError("AI audit package membership mismatch")
    for name, entry in manifest["files"].items():
        item = safe_member(root, name)
        if item.stat().st_size != entry["bytes"] or file_hash(item) != entry["sha256"]:
            raise ValueError("AI audit artifact integrity failure")
    record = _strict_json((root / "action.json").read_bytes())
    with (root / "audit.jsonl").open(encoding="utf-8") as stream:
        history = [_strict_json(line) for line in stream]
    head = verify_records(history)
    if (
        head != record["audit_head"]
        or head != manifest["audit_head"]
        or digest(record["identity"]) != record["action_id"]
        or record["action_id"] != manifest["action_id"]
        or not history
        or history[0]["action_id"] != record["action_id"]
    ):
        raise ValueError("AI audit identity mismatch")
    call = record["call"]
    if call is not None:
        states = [e["payload"]["call_sha256"] for e in history if "call_sha256" in e["payload"]]
        if (
            not states
            or states[-1] != digest(call)
            or call["key"] != record["action_id"]
            or _strict_json(call["request"]) != record["identity"]
        ):
            raise ValueError("AI audit call history mismatch")
    from timeline_demo.ai import Harness, prepare

    identity = record["identity"]
    bundle = root / "evidence_bundle"
    verify_bundle(bundle, identity["manifest_sha256"])
    plan = prepare(bundle, identity["task"], identity["policy"])
    if "external_provenance" in identity:
        plan["identity"]["external_provenance"] = identity["external_provenance"]
        plan["cache_key"] = digest(plan["identity"])
    if plan["identity"] != identity:
        raise ValueError("AI audit evidence reconstruction failed")
    if call and call["result"]:
        Harness._check_result(call, plan)
    with (root / "chunks.jsonl").open(encoding="utf-8") as stream:
        for locator in evidence_rows(bundle, plan):
            line = stream.readline()
            if not line or _strict_json(line) != locator:
                raise ValueError("AI event chunk provenance mismatch")
        if stream.read(1):
            raise ValueError("unexpected AI event chunks")
    return {
        "status": "integrity_verified",
        "action_id": record["action_id"],
        "audit_head": head,
        "model_tokens": 0,
        "limitation": "Integrity relative to the supplied pin; human approval and source authenticity are separate checks.",
    }
