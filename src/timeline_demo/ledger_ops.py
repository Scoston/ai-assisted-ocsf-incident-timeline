"""Read-only AI usage accounting and pinned recovery; never refund or dispatch."""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path

from timeline_demo.core.manifest import DIGEST, regular_members
from timeline_demo.core.storage import no_links, publish_tree
from timeline_demo.parsers.common import compact_json, file_hash, sha256_of_text
from timeline_demo.parsers.readers import _strict_json


@contextmanager
def read_ledger(path):
    path = no_links(path)
    if not path.is_file():
        raise ValueError("AI ledger is missing")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        yield db


def _usage(db):
    if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise ValueError("AI ledger integrity check failed")
    table = db.execute("SELECT type FROM sqlite_master WHERE name='calls'").fetchone()
    if table is None or table[0] != "table":
        raise ValueError("unsupported AI ledger")
    if db.execute("SELECT count(*) FROM calls").fetchone()[0] > 1000000:
        raise ValueError("AI ledger inspection limit exceeded")
    cases = {}
    for row in db.execute("SELECT * FROM calls ORDER BY key"):
        identity = _strict_json(row["request"])
        if (
            not isinstance(identity, dict)
            or sha256_of_text(compact_json(identity)) != row["key"]
            or identity.get("case_id") != row["case_id"]
            or not isinstance(row["case_id"], str)
            or not row["case_id"]
            or row["status"] not in {"pending", "completed", "failed"}
            or type(row["charged"]) is not int
            or row["charged"] < 0
        ):
            raise ValueError("invalid AI ledger reservation")
        known = row["response"] is not None
        if not known and row["charged"] != (
            len(compact_json(identity["request"]).encode("utf-8"))
            + 256
            + identity["request"]["max_output_tokens"]
        ):
            raise ValueError("AI ledger reservation was changed without provider usage")
        if known:
            response = _strict_json(row["response"])
            usage = response["usage"]
            values = [usage[k] for k in ("input_tokens", "output_tokens")]
            if any(type(v) is not int or v < 0 for v in values) or sum(values) != row["charged"]:
                raise ValueError("AI ledger usage mismatch")
        if row["status"] == "completed":
            from timeline_demo.ai import validate_analysis

            result = _strict_json(row["result"])
            receipt = result["receipt"]
            if (
                not known
                or result["status"] != "completed"
                or receipt["request_hash"] != row["key"]
                or any(receipt[k] != identity[k] for k in ("case_id", "bundle_id", "task"))
                or receipt["model"] != identity["request"]["model"]
                or any(receipt[k] != usage[k] for k in ("input_tokens", "output_tokens"))
            ):
                raise ValueError("invalid completed AI receipt")
            import jsonschema

            try:
                validate_analysis(result["analysis"], identity["evidence_refs"])
            except jsonschema.ValidationError:
                raise ValueError("invalid cached analysis") from None
        case = sha256_of_text(row["case_id"])
        counts = cases.setdefault(
            case,
            {
                k: 0
                for k in (
                    "calls",
                    "completed",
                    "pending",
                    "failed",
                    "charged_tokens",
                    "known_usage_tokens",
                    "reserved_unknown_tokens",
                )
            },
        )
        counts["calls"] += 1
        counts[row["status"]] += 1
        counts["charged_tokens"] += row["charged"]
        counts["known_usage_tokens" if known else "reserved_unknown_tokens"] += row["charged"]
    return {
        "version": "1.0",
        "cases": [{"case_hash": key, **value} for key, value in sorted(cases.items())],
        "model_tokens_this_operation": 0,
        "automatic_retries": False,
    }


def ledger_usage(path):
    with read_ledger(path) as db:
        return _usage(db)


def _new_target(source, output):
    target = no_links(output)
    if target.exists() or target.is_relative_to(source) or source.is_relative_to(target):
        raise ValueError("ledger recovery requires a new, separate directory")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return target


def ledger_backup(ledger, output):
    source = no_links(ledger)
    target = _new_target(source, output)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".timeline-ledger-") as temp:
        root = Path(temp) / "snapshot"
        root.mkdir(mode=0o700)
        # The read transaction freezes the snapshot, including WAL commits. The
        # backup API copies that same snapshot, not a live main-database file.
        with read_ledger(source) as db:
            usage = _usage(db)
            with closing(sqlite3.connect(root / "usage.sqlite")) as destination:
                db.backup(destination)
        entry = {"sha256": file_hash(root / "usage.sqlite"), "bytes": (root / "usage.sqlite").stat().st_size}
        record = {"version": "1.0", "kind": "ai-ledger", "files": {"usage.sqlite": entry}, "usage": usage}
        encoded = (compact_json(record) + "\n").encode("utf-8")
        if len(encoded) > 8 * 1024**2:
            raise ValueError("AI snapshot manifest exceeds restore limit")
        (root / "snapshot.json").write_bytes(encoded)
        publish_tree(root, target)
    return {
        "status": "backed_up",
        "snapshot": str(target),
        "snapshot_sha256": file_hash(target / "snapshot.json"),
        "usage": usage,
    }


def ledger_restore(snapshot, output, snapshot_sha256):
    source = no_links(snapshot)
    target = _new_target(source, output)
    if regular_members(source) != {"snapshot.json", "usage.sqlite"}:
        raise ValueError("AI snapshot membership mismatch")
    with (source / "snapshot.json").open("rb") as stream:
        raw = stream.read(8 * 1024**2 + 1)
    if (
        not isinstance(snapshot_sha256, str)
        or not DIGEST.fullmatch(snapshot_sha256)
        or len(raw) > 8 * 1024**2
        or hashlib.sha256(raw).hexdigest() != snapshot_sha256
    ):
        raise ValueError("AI snapshot does not match the independently recorded pin")
    value = _strict_json(raw)
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "kind", "files", "usage"}
        or value["version"] != "1.0"
        or value["kind"] != "ai-ledger"
        or not isinstance(value["files"], dict)
        or set(value["files"]) != {"usage.sqlite"}
    ):
        raise ValueError("unsupported AI snapshot")
    entry = value["files"]["usage.sqlite"]
    if (
        not isinstance(entry, dict)
        or set(entry) != {"bytes", "sha256"}
        or type(entry["bytes"]) is not int
        or entry["bytes"] < 0
        or (source / "usage.sqlite").stat().st_size != entry["bytes"]
        or file_hash(source / "usage.sqlite") != entry["sha256"]
    ):
        raise ValueError("AI snapshot database integrity failure")
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".timeline-ledger-") as temp:
        root = Path(temp) / "restored"
        root.mkdir(mode=0o700)
        shutil.copyfile(source / "usage.sqlite", root / "usage.sqlite")
        if file_hash(root / "usage.sqlite") != entry["sha256"]:
            raise ValueError("AI snapshot changed while restoring")
        usage = ledger_usage(root / "usage.sqlite")
        if usage != value["usage"]:
            raise ValueError("AI snapshot accounting mismatch")
        publish_tree(root, target)
    return {"status": "restored", "ledger": str(target / "usage.sqlite"), "usage": usage}
