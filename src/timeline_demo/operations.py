"""Read-only health reports and verified, non-destructive collector recovery."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import tempfile
import time
from contextlib import closing, contextmanager
from pathlib import Path

from timeline_demo.core.manifest import DIGEST, regular_members, safe_member, verify_bundle
from timeline_demo.core.storage import no_links, publish_tree
from timeline_demo.parsers.common import compact_json, file_hash, parse_time, sha256_of_text
from timeline_demo.parsers.readers import _strict_json


@contextmanager
def read_state(state):
    path = no_links(Path(state) / "collection.sqlite")
    if not path.is_file():
        raise ValueError("collection database is missing")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        yield db


def _inspect(db, state, *, verify_blobs=False, verify_bundles=False, stale_seconds=3600, now=None):
    now = time.time() if now is None else now
    if type(stale_seconds) is not int or stale_seconds < 1:
        raise ValueError("positive staleness threshold required")
    if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise ValueError("collection database integrity check failed")
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"runs", "pages", "watermarks"} <= tables:
        raise ValueError("unsupported collection database")
    issues, sources, blobs, published = [], {}, set(), []
    runs = db.execute("SELECT * FROM runs ORDER BY id").fetchall()
    if db.execute("SELECT count(*) FROM pages WHERE run_id NOT IN (SELECT id FROM runs)").fetchone()[0]:
        raise ValueError("orphan checkpoint pages")
    pages_count = received = included = pending = 0
    for run in runs:
        contract = _strict_json(run["contract"])
        if (
            sha256_of_text(run["contract"]) != run["id"]
            or run["drained"] not in (0, 1)
            or any(contract[key] != run[key] for key in ("start", "end", "case_id"))
        ):
            raise ValueError("invalid collection run contract")
        source = sha256_of_text(compact_json(contract["source"]))
        sources.setdefault(source, None)
        pages = db.execute("SELECT * FROM pages WHERE run_id=? ORDER BY n", (run["id"],)).fetchall()
        cursor = "null"
        for index, page in enumerate(pages, 1):
            if (
                page["n"] != index
                or page["cursor_hash"] != sha256_of_text(cursor)
                or type(page["included"]) is not int
                or type(page["received"]) is not int
                or not 0 <= page["included"] <= page["received"]
            ):
                raise ValueError("invalid checkpoint page sequence or counts")
            cursor = page["next_cursor"]
            _strict_json(cursor)
            stamp = parse_time(page["fetched_at"])[1] / 1000
            sources[source] = max(stamp, sources[source] or stamp)
            received += page["received"]
            included += page["included"]
            for key in ("body_sha", "records_sha"):
                digest = page[key]
                if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                    raise ValueError("invalid checkpoint blob digest")
                blobs.add(digest)
        if run["cursor"] != cursor or (pages and bool(run["drained"]) != (cursor == "null")):
            raise ValueError("checkpoint cursor does not match committed pages")
        pages_count += len(pages)
        if run["manifest_sha256"]:
            if not run["drained"] or not DIGEST.fullmatch(run["manifest_sha256"]):
                raise ValueError("invalid publication marker")
            if verify_bundles:
                manifest = verify_bundle(run["output"], run["manifest_sha256"])
                entry = manifest["files"].get("attachments/collection.json")
                if not entry:
                    raise ValueError("publication is missing collection provenance")
                report = _strict_json((Path(run["output"]) / "attachments/collection.json").read_bytes())
                if report.get("run_id") != run["id"]:
                    raise ValueError("publication belongs to another collector run")
            published.append(
                {"run_id": run["id"], "bundle": run["output"], "manifest_sha256": run["manifest_sha256"]}
            )
        else:
            pending += 1
            if not pages or now - parse_time(pages[-1]["fetched_at"])[1] / 1000 > stale_seconds:
                issues.append("stalled_run:" + run["id"])
    for digest in blobs:
        path = no_links(Path(state) / "blobs" / digest)
        if not path.is_file() or (verify_blobs and file_hash(path) != digest):
            raise ValueError("missing or altered committed collection blob")
    source_status = []
    for source, stamp in sorted(sources.items()):
        age = max(0, int(now - stamp)) if stamp is not None else None
        if age is None or age > stale_seconds:
            issues.append("stale_source:" + source)
        source_status.append({"source_hash": source, "last_page_age_seconds": age})
    if not sources:
        issues.append("no_sources_collected")
    watermarks = []
    for mark in db.execute("SELECT * FROM watermarks ORDER BY id"):
        if (
            type(mark["initial_ms"]) is not int
            or type(mark["through_ms"]) is not int
            or mark["through_ms"] < mark["initial_ms"]
        ):
            raise ValueError("invalid collector watermark")
        watermarks.append({"id": mark["id"], "lag_seconds": max(0, int(now - mark["through_ms"] / 1000))})
        if now - mark["through_ms"] / 1000 > stale_seconds:
            issues.append("lagging_watermark:" + mark["id"])
    return (
        {
            "version": "1.0",
            "healthy": not issues,
            "issues": issues,
            "runs": len(runs),
            "pending_runs": pending,
            "published_runs": len(published),
            "pages": pages_count,
            "received_records": received,
            "included_records": included,
            "sources": source_status,
            "watermarks": watermarks,
            "model_tokens": 0,
        },
        blobs,
        published,
    )


def health(state, **options):
    with read_state(state) as db:
        return _inspect(db, state, **options)[0]


def prometheus(report):
    lines = []
    for key in (
        "healthy",
        "runs",
        "pending_runs",
        "published_runs",
        "pages",
        "received_records",
        "included_records",
    ):
        lines += [f"# TYPE timeline_collection_{key} gauge", f"timeline_collection_{key} {int(report[key])}"]
    for source in report["sources"]:
        age = source["last_page_age_seconds"]
        lines.append(
            f'timeline_source_last_page_age_seconds{{source_hash="{source["source_hash"]}"}} {age if age is not None else -1}'
        )
    for mark in report["watermarks"]:
        lines.append(f'timeline_watermark_lag_seconds{{watermark="{mark["id"]}"}} {mark["lag_seconds"]}')
    return "\n".join(lines) + "\n"


def backup(state, output):
    state, target = no_links(state), no_links(output)
    if target.exists() or target.is_relative_to(state) or state.is_relative_to(target):
        raise ValueError("backup requires a new directory separate from collection state")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".timeline-backup-") as temp:
        root = Path(temp) / "snapshot"
        (root / "blobs").mkdir(parents=True, mode=0o700)
        # A separate reserved write lock prevents collector commits while SQLite's
        # backup API reads a consistent database and committed blobs are copied.
        with read_state(state) as source:
            with closing(
                sqlite3.connect((state / "collection.sqlite").as_uri() + "?mode=rw", uri=True, timeout=1)
            ) as lock:
                lock.execute("BEGIN IMMEDIATE")
                with closing(sqlite3.connect(root / "collection.sqlite")) as destination:
                    source.backup(destination)
                _, blobs, published = _inspect(source, state, verify_blobs=True)
                for digest in sorted(blobs):
                    shutil.copyfile(state / "blobs" / digest, root / "blobs" / digest)
                lock.rollback()
        entries = {
            name: {"sha256": file_hash(root / name), "bytes": (root / name).stat().st_size}
            for name in sorted(regular_members(root))
        }
        record = {
            "version": "1.0",
            "files": entries,
            "published_bundles": published,
            "published_bundles_included": False,
        }
        (root / "snapshot.json").write_text(compact_json(record) + "\n", encoding="utf-8")
        publish_tree(root, target)
    return {
        "status": "backed_up",
        "snapshot": str(target),
        "snapshot_sha256": file_hash(target / "snapshot.json"),
        "published_bundles_included": False,
        "published_bundles": published,
    }


def restore(snapshot, state, snapshot_sha256):
    source, target = no_links(snapshot), no_links(state)
    if target.exists() or target.is_relative_to(source) or source.is_relative_to(target):
        raise ValueError("restore requires a new directory separate from the snapshot")
    actual = regular_members(source)
    if "snapshot.json" not in actual:
        raise ValueError("snapshot manifest is missing")
    with (source / "snapshot.json").open("rb") as stream:
        raw = stream.read(8 * 1024**2 + 1)
    if (
        not isinstance(snapshot_sha256, str)
        or not DIGEST.fullmatch(snapshot_sha256)
        or len(raw) > 8 * 1024**2
        or hashlib.sha256(raw).hexdigest() != snapshot_sha256
    ):
        raise ValueError("snapshot does not match independently recorded SHA-256")
    manifest = _strict_json(raw)
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != "1.0"
        or manifest.get("published_bundles_included") is not False
        or not isinstance(manifest.get("files"), dict)
    ):
        raise ValueError("unsupported snapshot")
    entries = manifest["files"]
    if "collection.sqlite" not in entries or actual != set(entries) | {"snapshot.json"}:
        raise ValueError("snapshot file membership mismatch")
    for name, entry in entries.items():
        member = safe_member(source, name)
        if name != "collection.sqlite" and not (name.startswith("blobs/") and DIGEST.fullmatch(name[6:])):
            raise ValueError("unexpected snapshot file")
        if (
            not isinstance(entry, dict)
            or type(entry.get("bytes")) is not int
            or member.stat().st_size != entry["bytes"]
            or file_hash(member) != entry.get("sha256")
        ):
            raise ValueError("snapshot artifact integrity failure")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".timeline-restore-") as temp:
        root = Path(temp) / "state"
        (root / "blobs").mkdir(parents=True, mode=0o700)
        for name in entries:
            shutil.copyfile(source / name, root / name)
        with read_state(root) as db:
            report, _, published = _inspect(db, root, verify_blobs=True, verify_bundles=True)
        if published != manifest.get("published_bundles"):
            raise ValueError("snapshot publication inventory mismatch")
        publish_tree(root, target)
    return {"status": "restored", "state": str(target), "health": report}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collector health, monitoring and verified recovery")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("health")
    check.add_argument("--state", required=True)
    check.add_argument("--stale-seconds", type=int, default=3600)
    check.add_argument("--verify-blobs", action="store_true")
    check.add_argument("--verify-bundles", action="store_true")
    check.add_argument("--format", choices=["json", "prometheus"], default="json")
    save = commands.add_parser("backup")
    save.add_argument("--state", required=True)
    save.add_argument("--output", required=True)
    recover = commands.add_parser("restore")
    recover.add_argument("--snapshot", required=True)
    recover.add_argument("--snapshot-sha256", required=True)
    recover.add_argument("--state", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "health":
            result = health(
                args.state,
                stale_seconds=args.stale_seconds,
                verify_blobs=args.verify_blobs,
                verify_bundles=args.verify_bundles,
            )
            print(prometheus(result) if args.format == "prometheus" else json.dumps(result), end="\n")
            return 0 if result["healthy"] else 1
        result = (
            backup(args.state, args.output)
            if args.command == "backup"
            else restore(args.snapshot, args.state, args.snapshot_sha256)
        )
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        # Paths, case names and cursor data must not leak into monitoring logs.
        print(json.dumps({"status": "error", "healthy": False, "error": "state_operation_failed"}))
        return 2
