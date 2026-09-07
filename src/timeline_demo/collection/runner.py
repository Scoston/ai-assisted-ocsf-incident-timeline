"""Durable per-page commits and fixed windows; a cursor is not proof of completeness."""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from timeline_demo.core.manifest import verify_bundle
from timeline_demo.parsers.common import compact_json, file_hash, parse_time, sha256_of_text
from timeline_demo.parsers.readers import _strict_json
from timeline_demo.parsers.registry import SPECS, field
from timeline_demo.pipeline import Input, run_pipeline


def _iso(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec="milliseconds")


def _open(state):
    state = Path(state).resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    (state / "blobs").mkdir(exist_ok=True, mode=0o700)
    db = sqlite3.connect(state / "collection.sqlite", timeout=1, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA synchronous=FULL")
    db.execute(
        "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, contract TEXT, start TEXT, end TEXT, case_id TEXT, output TEXT, cursor TEXT, drained INTEGER DEFAULT 0, manifest_sha256 TEXT)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS pages (run_id TEXT, n INTEGER, body_sha TEXT, records_sha TEXT, received INTEGER, included INTEGER, cursor_hash TEXT, next_cursor TEXT, fetched_at TEXT, PRIMARY KEY(run_id,n), UNIQUE(run_id,cursor_hash))"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS watermarks (id TEXT PRIMARY KEY, initial_ms INTEGER, through_ms INTEGER)"
    )
    os.chmod(state / "collection.sqlite", 0o600)
    return db


def _blob(state, data):
    digest = hashlib.sha256(data).hexdigest()
    path = Path(state) / "blobs" / digest
    if path.exists():
        if file_hash(path) != digest:
            raise ValueError("collection blob integrity failure")
        return digest
    # Content-addressed uncommitted blobs may remain after interruption; never overwrite them.
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.link(temporary, path)
        if os.name == "posix":
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except FileExistsError:
        if file_hash(path) != digest:
            raise ValueError("collection blob collision") from None
    finally:
        temporary.unlink()
    return digest


def _checked_blob(state, digest):
    from timeline_demo.core.manifest import DIGEST

    if not DIGEST.fullmatch(str(digest)):
        raise ValueError("invalid collection blob reference")
    path = Path(state) / "blobs" / digest
    if path.is_symlink() or file_hash(path) != digest:
        raise ValueError("collection checkpoint references altered page bytes")
    return path


def _finalize(db, state, run, provider):
    pages = db.execute("SELECT * FROM pages WHERE run_id=? ORDER BY n", (run["id"],)).fetchall()
    inputs, attachments, entries = [], {}, []
    for index, page in enumerate(pages, 1):
        if page["n"] != index:
            raise ValueError("collection checkpoint has a missing page")
        body = _checked_blob(state, page["body_sha"])
        records = _checked_blob(state, page["records_sha"])
        # Readers use extensions; the blob store itself is content addressed.
        named = Path(state) / "blobs" / (page["records_sha"] + ".jsonl")
        if not named.exists():
            os.link(records, named)
        elif named.is_symlink() or file_hash(named) != page["records_sha"]:
            raise ValueError("collection record projection was altered")
        inputs.append(Input(provider.parser, named))
        attachments[f"attachments/collection-pages/{index:06}.json"] = body
        entries.append(
            {
                key: page[key]
                for key in (
                    "n",
                    "body_sha",
                    "records_sha",
                    "received",
                    "included",
                    "cursor_hash",
                    "fetched_at",
                )
            }
        )
    report = {
        "version": "1.0",
        "run_id": run["id"],
        "source": provider.identity,
        "window": {"start_inclusive": run["start"], "end_exclusive": run["end"]},
        "status": "pagination_drained",
        "source_completeness_proven": False,
        "received_records": sum(p["received"] for p in pages),
        "included_records": sum(p["included"] for p in pages),
        "excluded_outside_window": sum(p["received"] - p["included"] for p in pages),
        "pages": entries,
        "model_tokens": 0,
    }
    data = (compact_json(report) + "\n").encode()
    digest = _blob(state, data)
    attachments["attachments/collection.json"] = _checked_blob(state, digest)
    target = Path(run["output"])
    if target.exists():
        manifest = verify_bundle(target, run["manifest_sha256"])
        if manifest["files"].get("attachments/collection.json", {}).get("sha256") != digest:
            raise ValueError("existing collection output does not match this checkpoint")
    else:
        if run["manifest_sha256"]:
            raise ValueError("published collection output is missing; restore it before advancing")
        manifest = run_pipeline(inputs, target, run["case_id"], attachments=attachments)
    pin = file_hash(target / "audit_manifest.json")
    db.execute("UPDATE runs SET manifest_sha256=? WHERE id=?", (pin, run["id"]))
    return {
        "status": "completed",
        "run_id": run["id"],
        "bundle": str(target),
        "bundle_id": manifest["bundle_id"],
        "manifest_sha256": pin,
        "collection": report,
    }


def collect_window(
    provider,
    state,
    output,
    case_id,
    start,
    end,
    *,
    max_pages=100,
    max_records=100000,
    max_bytes=128 * 1024 * 1024,
    sleep=time.sleep,
):
    """Resume a fixed window. No final bundle or watermark is emitted while incomplete."""
    state, target = Path(state).resolve(), Path(output).resolve()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", case_id):
        raise ValueError("invalid collection case ID")
    if state.is_relative_to(target) or target.is_relative_to(state):
        raise ValueError("collection state and output directories must be separate")
    start_ms, end_ms = parse_time(start)[1], parse_time(end)[1]
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    if not 0 < end_ms - start_ms <= 86400000 or end_ms > now_ms:
        raise ValueError("collection requires a completed window of at most 24 hours")
    if provider.parser == "cloudtrail" and start_ms < now_ms - 90 * 86400000:
        raise ValueError("CloudTrail event history only covers the last 90 days")
    if any(type(v) is not int or v < 1 for v in (max_pages, max_records, max_bytes)):
        raise ValueError("positive collection budgets are required")
    start, end = _iso(start_ms), _iso(end_ms)
    contract = compact_json(
        {
            "source": provider.identity,
            "parser": provider.parser,
            "start": start,
            "end": end,
            "case_id": case_id,
        }
    )
    run_id = sha256_of_text(contract)
    with closing(_open(state)) as db:
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR IGNORE INTO runs (id,contract,start,end,case_id,output,cursor) VALUES (?,?,?,?,?,?,?)",
                (run_id, contract, start, end, case_id, str(target), "null"),
            )
            db.execute("COMMIT")
            for _ in range(max_pages + 1):
                db.execute("BEGIN IMMEDIATE")
                run = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
                if run["contract"] != contract or run["output"] != str(target):
                    raise ValueError("collection checkpoint configuration changed")
                prior = db.execute("SELECT * FROM pages WHERE run_id=? ORDER BY n", (run_id,)).fetchall()
                if _ == 0:
                    for page in prior:
                        _checked_blob(state, page["body_sha"])
                        _checked_blob(state, page["records_sha"])
                if run["drained"]:
                    result = _finalize(db, state, run, provider)
                    db.execute("COMMIT")
                    return result
                if _ == max_pages:
                    raise ValueError("collection page budget reached; resume the same window")
                cursor = _strict_json(run["cursor"])
                cursor_hash = sha256_of_text(run["cursor"])
                if db.execute(
                    "SELECT 1 FROM pages WHERE run_id=? AND cursor_hash=?", (run_id, cursor_hash)
                ).fetchone():
                    raise ValueError("collector pagination cycle detected")
                # Serialize collectors sharing a state DB while a request is in flight.
                sleep(provider.interval)
                page = provider.fetch(start, end, cursor)
                if not isinstance(page.body, bytes) or len(page.body) > 16 * 1024 * 1024:
                    raise ValueError("invalid or oversized collector response")
                _strict_json(page.body)
                body_sha = _blob(state, page.body)
                if not isinstance(page.records, list) or any(
                    not isinstance(row, dict) for row in page.records
                ):
                    raise ValueError("collector page has invalid records")
                spec = SPECS[provider.parser]
                included = [
                    record
                    for record in page.records
                    if start_ms <= parse_time(field(record, spec.time), spec.unit)[1] < end_ms
                ]
                data = "".join(compact_json(record) + "\n" for record in included).encode()
                if sum(p["received"] for p in prior) + len(page.records) > max_records:
                    raise ValueError(
                        "collection record budget reached; narrow the window or raise its budget"
                    )
                stored_bytes = sum(
                    (state / "blobs" / p["body_sha"]).stat().st_size
                    + (state / "blobs" / p["records_sha"]).stat().st_size
                    for p in prior
                )
                if stored_bytes + len(page.body) + len(data) > max_bytes:
                    raise ValueError("collection byte budget reached")
                if page.cursor is not None and not isinstance(page.cursor, dict):
                    raise ValueError("invalid collection continuation")
                next_cursor = compact_json(page.cursor)
                if page.cursor is not None and (
                    next_cursor == run["cursor"]
                    or db.execute(
                        "SELECT 1 FROM pages WHERE run_id=? AND cursor_hash=?",
                        (run_id, sha256_of_text(next_cursor)),
                    ).fetchone()
                ):
                    raise ValueError("collector pagination cycle detected")
                records_sha = _blob(state, data)
                db.execute(
                    "INSERT INTO pages VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        run_id,
                        len(prior) + 1,
                        body_sha,
                        records_sha,
                        len(page.records),
                        len(included),
                        cursor_hash,
                        next_cursor,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                db.execute(
                    "UPDATE runs SET cursor=?,drained=? WHERE id=?",
                    (next_cursor, int(page.cursor is None), run_id),
                )
                db.execute("COMMIT")
        except sqlite3.OperationalError:
            raise ValueError("collection state is unavailable or already in use; retry later") from None
        finally:
            if db.in_transaction:
                db.execute("ROLLBACK")


def collect_until(
    provider,
    state,
    output_root,
    case_prefix,
    initial_start,
    until,
    *,
    window_seconds=3600,
    overlap_seconds=300,
    max_windows=24,
    **budgets,
):
    """A scheduler-safe catch-up batch. Checkpoints advance only after verified publication."""
    initial, stop = parse_time(initial_start)[1], parse_time(until)[1]
    if initial >= stop or stop > int(datetime.now(timezone.utc).timestamp() * 1000):
        raise ValueError("rolling collection requires a completed, increasing time range")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", case_prefix):
        raise ValueError("invalid collection case prefix")
    if (
        type(window_seconds) is not int
        or type(overlap_seconds) is not int
        or not 0 <= overlap_seconds < window_seconds
        or window_seconds + overlap_seconds > 86400
        or type(max_windows) is not int
        or max_windows < 1
    ):
        raise ValueError("invalid rolling window policy")
    key = sha256_of_text(
        compact_json(
            {
                "source": provider.identity,
                "case_prefix": case_prefix,
                "output_root": str(Path(output_root).resolve()),
                "window_seconds": window_seconds,
                "overlap_seconds": overlap_seconds,
            }
        )
    )
    with closing(_open(state)) as db:
        db.execute("INSERT OR IGNORE INTO watermarks VALUES (?,?,?)", (key, initial, initial))
        mark = db.execute("SELECT * FROM watermarks WHERE id=?", (key,)).fetchone()
        if mark["initial_ms"] != initial:
            raise ValueError("initial collection boundary changed")
        through = mark["through_ms"]
    completed = []
    for _ in range(max_windows):
        if through >= stop:
            return {"status": "caught_up", "through": _iso(through), "windows": completed}
        end = min(through + window_seconds * 1000, stop)
        start = max(initial, through - overlap_seconds * 1000)
        case = case_prefix + "-" + str(end)
        result = collect_window(
            provider, state, Path(output_root) / case, case, _iso(start), _iso(end), **budgets
        )
        with closing(_open(state)) as db:
            db.execute("BEGIN IMMEDIATE")
            updated = db.execute(
                "UPDATE watermarks SET through_ms=? WHERE id=? AND through_ms=?", (end, key, through)
            )
            if updated.rowcount != 1:
                db.execute("ROLLBACK")
                raise ValueError("another collector advanced this watermark; resume")
            db.execute("COMMIT")
        completed.append({key: result[key] for key in ("run_id", "bundle", "bundle_id", "manifest_sha256")})
        through = end
    return {
        "status": "caught_up" if through >= stop else "paused",
        "through": _iso(through),
        "windows": completed,
    }
