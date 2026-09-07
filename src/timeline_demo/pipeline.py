"""Offline, disk-sorted ingestion shared by CLI, notebooks and Databricks jobs."""

from __future__ import annotations

import csv
import json
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from importlib.resources import files
from jsonschema import Draft202012Validator

from timeline_demo.core.manifest import safe_member, verify_bundle, write_manifest
from timeline_demo.core.storage import publish_tree
from timeline_demo.core.timeline_builder import PREFERRED_FIELD_ORDER, csv_value
from timeline_demo.enrichment.ioc_extractor import extract_iocs_from_text
from timeline_demo.parsers.common import compact_json, file_hash
from timeline_demo.parsers.readers import iter_records
from timeline_demo.parsers.registry import PARSER_VERSION, PROFILE_VERSION, SPECS, normalize_record

EVENT_VALIDATOR = Draft202012Validator(
    json.loads(files("timeline_demo").joinpath("resources/event.schema.json").read_text(encoding="utf-8"))
)


@dataclass(frozen=True)
class Input:
    parser: str
    path: str | Path


@dataclass(frozen=True)
class Limits:
    max_input_bytes: int = 10 * 1024**3
    max_records: int = 1000000
    max_events: int = 2000000
    max_iocs: int = 100000
    max_inputs: int = 1000

    def __post_init__(self):
        if any(type(value) is not int or value < 1 for value in vars(self).values()):
            raise ValueError("positive integer ingestion limits are required")


def run_pipeline(
    inputs,
    output_dir,
    case_id,
    *,
    quarantine=False,
    assume_timezone=None,
    parquet=False,
    attachments=None,
    limits=None,
):
    limits = limits or Limits()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", case_id):
        raise ValueError("case_id must be 1-128 letters, numbers, dots, dashes or underscores")
    inputs = list(inputs)
    if not inputs or len(inputs) > limits.max_inputs:
        raise ValueError("at least one input is required; input count must be within budget")
    copied = 0

    def copy_bounded(source, destination):
        nonlocal copied
        with Path(source).open("rb") as reader, destination.open("xb") as writer:
            for block in iter(lambda: reader.read(1024 * 1024), b""):
                copied += len(block)
                if copied > limits.max_input_bytes:
                    raise ValueError("ingestion input byte budget exceeded")
                writer.write(block)

    for item in inputs:
        if item.parser not in SPECS:
            raise ValueError("unsupported parser: " + item.parser)
        if not Path(item.path).is_file():
            raise ValueError("input is not a file: " + str(item.path))
    target = Path(output_dir).resolve()
    if target.as_posix().startswith("/Volumes/"):
        raise ValueError("use normalize_volume_sources for Databricks; SQLite staging requires local disk")
    if target.exists():
        raise FileExistsError("output already exists; choose a new bundle directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".timeline-", dir=target.parent) as work:
        work = Path(work)
        bundle = work / "bundle"
        (bundle / "evidence").mkdir(parents=True)
        iocs = {key: set() for key in ("ips", "domains", "urls", "sha256", "emails")}
        counts = {"source_records": 0, "emitted_events": 0, "quarantined_records": 0, "duplicate_events": 0}
        provenance = []
        with (
            sqlite3.connect(work / "sort.sqlite") as db,
            (bundle / "receipts.jsonl").open("w", encoding="utf-8") as receipts,
            (bundle / "quarantine.jsonl").open("w", encoding="utf-8") as rejected,
        ):
            db.execute(
                "CREATE TABLE events (uid TEXT PRIMARY KEY, epoch INTEGER NOT NULL, payload TEXT NOT NULL)"
            )
            for input_index, item in enumerate(inputs, 1):
                source = Path(item.path)
                # Copy first, then hash and parse the same snapshot; never parse the live source twice.
                snapshot = work / "snapshot"
                copy_bounded(source, snapshot)
                digest = file_hash(snapshot)
                extension = "".join(source.suffixes[-2:]) if source.suffix.lower() == ".gz" else source.suffix
                evidence_name = "evidence/" + digest + extension.lower()
                archived = bundle / evidence_name
                if archived.exists():
                    snapshot.unlink()
                else:
                    snapshot.rename(archived)
                provenance.append(
                    {
                        "parser": item.parser,
                        "parser_version": SPECS[item.parser].version,
                        "input_index": input_index,
                        "original_name": source.name,
                        "evidence_path": evidence_name,
                        "sha256": digest,
                        "bytes": archived.stat().st_size,
                    }
                )
                for index, raw, error in iter_records(archived, item.parser):
                    counts["source_records"] += 1
                    if counts["source_records"] > limits.max_records:
                        raise ValueError("ingestion record budget exceeded")
                    try:
                        if error:
                            raise ValueError(error)
                        events = normalize_record(
                            raw, item.parser, evidence_name, digest, index, assume_timezone
                        )
                    except (ValueError, TypeError, KeyError, OverflowError) as exc:
                        if not quarantine:
                            raise ValueError(f"{source.name}, record {index}: {exc}") from exc
                        counts["quarantined_records"] += 1
                        rejected.write(
                            compact_json(
                                {
                                    "parser": item.parser,
                                    "evidence_path": evidence_name,
                                    "record_index": index,
                                    "input_index": input_index,
                                    "reject_index": counts["quarantined_records"],
                                    "error": str(exc)[:500],
                                }
                            )
                            + "\n"
                        )
                        continue
                    for key, values in extract_iocs_from_text(compact_json(raw)).items():
                        iocs[key].update(values)
                    if sum(map(len, iocs.values())) > limits.max_iocs:
                        raise ValueError("ingestion IOC budget exceeded")
                    for event in events:
                        EVENT_VALIDATOR.validate(event)
                        counts["emitted_events"] += 1
                        if counts["emitted_events"] > limits.max_events:
                            raise ValueError("ingestion event budget exceeded")
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO events VALUES (?,?,?)",
                            (event["event_uuid"], event["epoch_ms"], compact_json(event)),
                        )
                        duplicate = cursor.rowcount == 0
                        counts["duplicate_events"] += int(duplicate)
                        receipts.write(
                            compact_json(
                                {
                                    "event_uuid": event["event_uuid"],
                                    "receipt_index": counts["emitted_events"],
                                    "input_index": input_index,
                                    "evidence_path": evidence_name,
                                    "record_index": index,
                                    "child_index": event["child_index"],
                                    "duplicate": duplicate,
                                }
                            )
                            + "\n"
                        )
                db.commit()
            counts["event_count"] = db.execute("SELECT count(*) FROM events").fetchone()[0]
            with (
                (bundle / "timeline.jsonl").open("w", encoding="utf-8") as jsonl,
                (bundle / "timeline.csv").open("w", encoding="utf-8", newline="") as csvfile,
            ):
                writer = csv.DictWriter(csvfile, fieldnames=PREFERRED_FIELD_ORDER, lineterminator="\n")
                writer.writeheader()
                for position, (payload,) in enumerate(
                    db.execute("SELECT payload FROM events ORDER BY epoch,uid"), 1
                ):
                    event = json.loads(payload)
                    event["timeline_position"] = position
                    jsonl.write(compact_json(event) + "\n")
                    writer.writerow({key: csv_value(event.get(key)) for key in PREFERRED_FIELD_ORDER})
        (bundle / "extracted_iocs.json").write_text(
            compact_json({k: sorted(v) for k, v in iocs.items()}) + "\n", encoding="utf-8"
        )
        if parquet:
            export_parquet(bundle)
        for name, source in (attachments or {}).items():
            if not name.startswith("attachments/"):
                raise ValueError("supporting artifacts must be under attachments/")
            destination = safe_member(bundle, name)
            if destination.exists():
                raise ValueError("supporting artifact collision")
            destination.parent.mkdir(parents=True, exist_ok=True)
            copy_bounded(source, destination)
        write_manifest(
            {
                "case_id": case_id,
                "profile_version": PROFILE_VERSION,
                "parser_version": PARSER_VERSION,
                "inputs": provenance,
                "counts": counts,
                "timezone_assumption": assume_timezone,
                "trust_boundary": {
                    "artifact_hashes": True,
                    "source_authenticity_proven": False,
                    "full_ocsf_conformance": False,
                    "ai_can_modify_evidence": False,
                },
            },
            bundle,
        )
        manifest = verify_bundle(bundle)
        # No partial output is exposed on failure. Existing bundles are never overwritten.
        publish_tree(bundle, target)
    return manifest


def read_timeline(bundle):
    with (Path(bundle) / "timeline.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def export_parquet(bundle):
    import pyarrow as pa
    import pyarrow.parquet as pq

    schema = pa.schema(
        [
            ("event_uuid", pa.string()),
            ("epoch_ms", pa.int64()),
            ("time_utc", pa.string()),
            ("ocsf_class_uid", pa.int64()),
            ("parser_name", pa.string()),
            ("record_json", pa.string()),
        ]
    )
    with pq.ParquetWriter(Path(bundle) / "timeline.parquet", schema, compression="zstd") as writer:
        rows = []
        for event in read_timeline(bundle):
            rows.append(
                {
                    **{k: event[k] for k in schema.names if k != "record_json"},
                    "record_json": compact_json(event),
                }
            )
            if len(rows) >= 2048:
                writer.write_table(pa.Table.from_pylist(rows, schema=schema))
                rows.clear()
        if rows:
            writer.write_table(pa.Table.from_pylist(rows, schema=schema))
