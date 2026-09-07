"""Deterministic core OCSF 1.3.0 exports, independently verified from evidence.

The timeline remains the project's lossless provenance index. This module emits
separate OCSF events only when source-backed fields satisfy the pinned schema.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import sqlite3
import tempfile
from contextlib import closing
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from timeline_demo.core.manifest import DIGEST, safe_member, verify_bundle
from timeline_demo.parsers.common import compact_json, file_hash, pick, sha256_of_text
from timeline_demo.parsers.readers import _strict_json, iter_records
from timeline_demo.pipeline import read_timeline

VERSION = "1.3.0"
MAPPING_VERSION = "ocsf-export-1.1.0"
RESOURCE_ROOT = files("timeline_demo").joinpath("resources/ocsf/1.3.0")
EXPORT_FILES = {"ocsf.jsonl", "rejections.jsonl"}
REPORT_VALIDATOR = Draft202012Validator(
    json.loads(
        files("timeline_demo")
        .joinpath("resources/ocsf_export_manifest.schema.json")
        .read_text(encoding="utf-8")
    )
)


@lru_cache(maxsize=1)
def schema_lock():
    return json.loads(RESOURCE_ROOT.joinpath("schema-lock.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=9)
def validator(class_uid):
    entry = schema_lock()["classes"].get(str(class_uid))
    if entry is None:
        raise ValueError(f"unsupported OCSF class: {class_uid}")
    data = RESOURCE_ROOT.joinpath(entry["file"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("packaged OCSF schema hash mismatch")
    schema = json.loads(data)

    def local_refs(node):
        if isinstance(node, dict):
            if "$ref" in node and not node["$ref"].startswith("#/"):
                raise ValueError("OCSF validation permits local schema references only")
            for value in node.values():
                local_refs(value)
        elif isinstance(node, list):
            for value in node:
                local_refs(value)

    local_refs(schema)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_event(event):
    """Validate all fields plus version/profile and cross-field identity rules."""
    if not isinstance(event, dict):
        raise ValueError("OCSF event must be an object")
    check = validator(event.get("class_uid"))
    error = next(check.iter_errors(event), None)
    if error:
        path = "/" + "/".join(str(p) for p in error.absolute_path)
        # Do not echo potentially sensitive source values into rejection logs.
        raise ValueError(f"OCSF {path}: {error.validator} constraint failed")
    metadata = event["metadata"]
    if metadata["version"] != VERSION:
        raise ValueError("OCSF metadata.version must be " + VERSION)
    if metadata.get("profiles") or metadata.get("extensions") or metadata.get("extension"):
        raise ValueError("OCSF profiles and extensions are outside this pinned core export")
    if event["type_uid"] != event["class_uid"] * 100 + event["activity_id"]:
        raise ValueError("OCSF type_uid does not match class_uid and activity_id")
    return event


def _text(value):
    if value is None:
        return ""
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value)
    raise ValueError("source text field has an unsupported type")


def _endpoint(value):
    value = _text(value)
    if not value or value == "-":
        return None
    try:
        return {"ip": str(ipaddress.ip_address(value))}
    except ValueError:
        # Preserve a source's non-IP endpoint label; do not invent an IP address.
        return {"name": value}


def _integer(value):
    if isinstance(value, bool):
        raise ValueError("boolean is not a numeric source field")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError:
            raise ValueError("source integer field is invalid") from None
    raise ValueError("source integer field is invalid")


def _source_record(raw, parser, child):
    record = copy.deepcopy(raw)
    if parser == "cloudtrail" and isinstance(record.get("detail"), dict):
        record = record["detail"]
    if parser == "m365_audit" and "AuditData" in record:
        record = (
            _strict_json(record["AuditData"]) if isinstance(record["AuditData"], str) else record["AuditData"]
        )
    if parser == "ocsf" and "record_json" in record:
        record = _strict_json(record["record_json"])
    if parser == "crowdstrike_detection" and record.get("behaviors"):
        record["behavior"] = record["behaviors"][child]
    if parser in {"defender_hunting", "azure_log_analytics"}:
        record = record["record"]
    if parser == "google_workspace":
        record["workspace_event"] = record["events"][child]
    if not isinstance(record, dict):
        raise ValueError("source must be an object")
    return record


def _vendor(parser):
    if parser in {"cloudtrail", "guardduty", "securityhub", "vpc_flow"}:
        return "Amazon Web Services"
    if parser in {
        "entra_signin",
        "entra_audit",
        "azure_activity",
        "m365_audit",
        "defender_alert",
        "defender_hunting",
        "azure_log_analytics",
        "windows_event",
    }:
        return "Microsoft"
    return {
        "gcp_audit": "Google",
        "google_workspace": "Google",
        "crowdstrike_detection": "CrowdStrike",
        "crowdstrike_alert": "CrowdStrike",
        "okta": "Okta",
        "zeek": "Zeek",
        "suricata": "OISF",
        "plaso": "Plaso",
        "tines_audit": "Tines",
        "databricks_audit": "Databricks",
        "ai_agent": "Unknown",
    }.get(parser, "Unknown")


def map_event(event, raw):
    """Map one source occurrence; never use model inference to fill required data."""
    if sha256_of_text(compact_json(raw)) != event["raw_data_hash"]:
        raise ValueError("source record hash does not match timeline reference")
    uid = event["ocsf_class_uid"]
    validator(uid)
    parser = event["parser_name"]
    record = _source_record(raw, parser, event["child_index"])
    provenance = {
        key: event[key]
        for key in (
            "event_uuid",
            "source_event_id",
            "parser_name",
            "parser_version",
            "raw_data_hash",
            "raw_file_hash",
            "evidence_path",
            "record_index",
            "child_index",
        )
    }
    provenance["mapping_version"] = MAPPING_VERSION
    if parser == "ocsf":
        # An aligned timeline or a different OCSF version cannot be relabeled as 1.3.0.
        validate_event(record)
        result = copy.deepcopy(record)
        if "timeline_export" in result.get("unmapped", {}):
            raise ValueError("native OCSF unmapped.timeline_export is already occupied")
        result.setdefault("unmapped", {})["timeline_export"] = provenance
        return validate_event(result)

    result = {
        "class_uid": uid,
        "category_uid": uid // 1000,
        "activity_id": 0,
        "time": event["epoch_ms"],
        "severity_id": {
            "unknown": 0,
            "informational": 1,
            "low": 2,
            "medium": 3,
            "high": 4,
            "critical": 5,
            "fatal": 6,
        }.get(event["severity"], 0),
        "message": event["activity_name"],
        "metadata": {
            "version": VERSION,
            "uid": event["event_uuid"],
            "product": {"name": event["product_name"], "vendor_name": _vendor(parser)},
            "original_time": event["original_timestamp"],
        },
        "unmapped": {"timeline_export": provenance, "source_status": event["status"]},
    }
    # Unknown is a schema-defined value. Vendor-specific actions stay in message/api.
    result["status_id"] = {"success": 1, "succeeded": 1, "failure": 2, "failed": 2}.get(
        event["status"].lower(), 0
    )
    actor = {"user": {"name": event["user_name"]}} if event["user_name"] else None
    source = _endpoint(event["src_ip"])
    if source and "src_endpoint" in validator(uid).schema["properties"]:
        result["src_endpoint"] = source
    if uid == 6003:
        result["api"] = {"operation": event["activity_name"]}
        if actor:
            result["actor"] = actor
    elif uid == 3002:
        if actor:
            result["user"] = actor["user"]
        if parser == "windows_event" or (
            parser == "azure_log_analytics" and str(event["activity_name"]).isdigit()
        ):
            if event["asset_name"]:
                result["dst_endpoint"] = {"hostname": event["asset_name"]}
            result["activity_id"] = 2 if str(event["activity_name"]) == "4634" else 1
            if str(event["activity_name"]) in {"4624", "4625"}:
                result["status_id"] = 1 if str(event["activity_name"]) == "4624" else 2
        else:
            service = pick(
                record,
                "appDisplayName",
                "AppDisplayName",
                "ResourceDisplayName",
                "target.0.displayName",
                "target.0.alternateId",
            )
            if service:
                result["service"] = {"name": _text(service)}
            if parser == "google_workspace":
                result["service"] = {"name": _text(pick(record, "id.applicationName"))}
            if parser == "defender_hunting" and event["asset_name"]:
                result["dst_endpoint"] = {"hostname": event["asset_name"]}
            if parser == "entra_signin":
                result["activity_id"] = 1
            elif event["activity_name"] == "user.session.start":
                result["activity_id"] = 1
            elif event["activity_name"] == "user.session.end":
                result["activity_id"] = 2
    elif uid == 2004:
        finding_id = pick(record, "id", "Id", "detection_id", "alert.signature_id")
        if parser == "crowdstrike_alert":
            finding_id = pick(record, "composite_id", "id")
        if finding_id is None and parser == "crowdstrike_detection":
            finding_id = pick(record, "behavior.id")
        if finding_id is None:
            raise ValueError("finding requires a source finding/signature identifier")
        result["finding_info"] = {"uid": _text(finding_id), "title": event["activity_name"]}
        if parser == "suricata":
            # A signature identifies a rule, not a unique finding occurrence.
            result["finding_info"]["uid"] = "timeline:" + event["event_uuid"]
            provenance["finding_uid_origin"] = "derived_from_source_record_and_parser_identity"
    elif uid in {4001, 4002, 4003}:
        destination = _endpoint(pick(record, "dstaddr", "id.resp_h", "dest_ip"))
        if parser in {"defender_hunting", "azure_log_analytics"}:
            destination = _endpoint(pick(record, "RemoteIP", "DestinationIP"))
            source = _endpoint(pick(record, "LocalIP", "SourceIP"))
            if source:
                result["src_endpoint"] = source
        if destination:
            result["dst_endpoint"] = destination
        for name, paths in [
            ("src_endpoint", ("srcport", "id.orig_p", "src_port", "LocalPort", "SourcePort")),
            ("dst_endpoint", ("dstport", "id.resp_p", "dest_port", "RemotePort", "DestinationPort")),
        ]:
            port = pick(record, *paths)
            if port is not None and port != "-" and name in result:
                result[name]["port"] = _integer(port)
        if uid == 4002:
            method = pick(record, "method", "http.http_method")
            status = pick(record, "status_code", "http.status")
            if not method or status is None:
                raise ValueError("HTTP export requires a source method and response status")
            result["http_request"] = {"http_method": _text(method)}
            result["http_response"] = {"code": _integer(status)}
            result["activity_id"] = {
                "CONNECT": 1,
                "DELETE": 2,
                "GET": 3,
                "HEAD": 4,
                "OPTIONS": 5,
                "POST": 6,
                "PUT": 7,
                "TRACE": 8,
            }.get(str(method).upper(), 99)
            if result["activity_id"] == 99:
                result["activity_name"] = _text(method)
        elif uid == 4003:
            query = pick(record, "query", "dns.rrname", "dns.queries.0.rrname")
            if not isinstance(query, str) or not query:
                raise ValueError("DNS export requires a source query name")
            result["query"] = {"hostname": query}
            # Combined sensor records may include both directions; leave activity unknown.
    elif uid in {1001, 1007}:
        host = pick(record, "Computer", "System.Computer", "host.name", "hostname", "DeviceName")
        if host:
            result["device"] = {"hostname": _text(host), "type_id": 0}
        subject = pick(
            record,
            "EventData.SubjectUserName",
            "username",
            "SubjectUserName",
            "InitiatingProcessAccountUpn",
            "InitiatingProcessAccountName",
        )
        if subject:
            result["actor"] = {"user": {"name": _text(subject)}}
        if uid == 1007:
            process_id = pick(record, "EventData.NewProcessId", "NewProcessId", "ProcessId")
            if process_id is not None:
                result["process"] = {"pid": _integer(process_id)}
            result["activity_id"] = 1  # The only mapped Windows process event is 4688.
            if parser == "defender_hunting":
                result["activity_id"] = {"ProcessCreated": 1, "ProcessTerminated": 2}.get(
                    record.get("ActionType"), 0
                )
        else:
            path = pick(record, "filename", "pathspec.location")
            if parser == "defender_hunting" and record.get("FileName"):
                path = str(record.get("FolderPath", "")).rstrip("\\/") + "/" + str(record["FileName"])
            if path:
                result["file"] = {
                    "name": str(path).replace("\\", "/").rsplit("/", 1)[-1],
                    "path": str(path),
                    "type_id": 0,
                }
    elif uid == 1008:
        log_name = pick(record, "Channel", "System.Channel", "winlog.channel")
        if log_name:
            result["log_name"] = _text(log_name)
        result["activity_id"] = 1  # Windows 1102: Clear.
    result["type_uid"] = uid * 100 + result["activity_id"]
    return validate_event(result)


def export_bundle(bundle, output, *, quarantine=False, manifest_sha256=None):
    """Export a verified bundle atomically; strict failure exposes no partial output."""
    bundle = Path(bundle).resolve()
    source_manifest = verify_bundle(bundle, manifest_sha256)
    source_pin = file_hash(bundle / "audit_manifest.json")
    target = Path(output).resolve()
    if target.is_relative_to(bundle):
        raise ValueError("OCSF export must be outside the evidence bundle")
    if target.exists():
        raise FileExistsError("OCSF export output already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ocsf-", dir=target.parent) as work:
        work = Path(work)
        result_dir = work / "export"
        result_dir.mkdir()
        counts = {"source_events": 0, "exported_events": 0, "rejected_events": 0}
        with sqlite3.connect(work / "join.sqlite") as db:
            db.execute(
                "CREATE TABLE events (uid TEXT PRIMARY KEY, path TEXT, parser TEXT, idx INTEGER, position INTEGER, payload TEXT, output TEXT, error TEXT)"
            )
            db.execute("CREATE INDEX source_record ON events(path,parser,idx)")
            for position, event in enumerate(read_timeline(bundle), 1):
                counts["source_events"] += 1
                db.execute(
                    "INSERT INTO events VALUES (?,?,?,?,?,?,NULL,NULL)",
                    (
                        event["event_uuid"],
                        event["evidence_path"],
                        event["parser_name"],
                        event["record_index"],
                        position,
                        compact_json(event),
                    ),
                )
            seen = set()
            for source in source_manifest["inputs"]:
                key = (source["evidence_path"], source["parser"])
                if key in seen:
                    continue
                seen.add(key)
                for index, raw, error in iter_records(safe_member(bundle, key[0]), key[1]):
                    for uid, payload in db.execute(
                        "SELECT uid,payload FROM events WHERE path=? AND parser=? AND idx=?", (*key, index)
                    ).fetchall():
                        try:
                            if error:
                                raise ValueError("source reader rejected referenced record")
                            mapped = compact_json(map_event(json.loads(payload), raw))
                            db.execute("UPDATE events SET output=? WHERE uid=?", (mapped, uid))
                        except (ValueError, TypeError, KeyError, IndexError, OverflowError) as exc:
                            # Mapping diagnostics are controlled messages; source values stay archived.
                            diagnostic = (
                                str(exc)[:300]
                                if isinstance(exc, ValueError)
                                else "source field type or structure is invalid"
                            )
                            db.execute("UPDATE events SET error=? WHERE uid=?", (diagnostic, uid))
            with (
                (result_dir / "ocsf.jsonl").open("w", encoding="utf-8") as accepted,
                (result_dir / "rejections.jsonl").open("w", encoding="utf-8") as rejected,
            ):
                for uid, payload, output_row, error in db.execute(
                    "SELECT uid,payload,output,error FROM events ORDER BY position"
                ):
                    if output_row is not None:
                        accepted.write(output_row + "\n")
                        counts["exported_events"] += 1
                    else:
                        event = json.loads(payload)
                        rejected.write(
                            compact_json(
                                {
                                    "event_uuid": uid,
                                    "class_uid": event["ocsf_class_uid"],
                                    "parser": event["parser_name"],
                                    "evidence_path": event["evidence_path"],
                                    "record_index": event["record_index"],
                                    "child_index": event["child_index"],
                                    "error": error or "referenced source record was not found",
                                }
                            )
                            + "\n"
                        )
                        counts["rejected_events"] += 1
        if counts["rejected_events"] and not quarantine:
            raise ValueError(
                f"{counts['rejected_events']} of {counts['source_events']} events cannot be exported; use --quarantine for rejection receipts"
            )
        if counts["source_events"] != source_manifest["counts"]["event_count"]:
            raise ValueError("source event count differs from evidence manifest")
        verify_bundle(bundle, source_pin)
        report = {
            "format": "timeline-ocsf-export-1.0",
            "ocsf_version": VERSION,
            "mapping_version": MAPPING_VERSION,
            "schema_lock_sha256": hashlib.sha256(
                RESOURCE_ROOT.joinpath("schema-lock.json").read_bytes()
            ).hexdigest(),
            "case_id": source_manifest["case_id"],
            "source_bundle_id": source_manifest["bundle_id"],
            "source_manifest_sha256": source_pin,
            "counts": counts,
            "profiles": [],
            "extensions": [],
            "model_tokens": 0,
            "files": {
                name: {"sha256": file_hash(result_dir / name), "bytes": (result_dir / name).stat().st_size}
                for name in sorted(EXPORT_FILES)
            },
        }
        (result_dir / "export_manifest.json").write_text(compact_json(report) + "\n", encoding="utf-8")
        verify_export(result_dir, bundle=bundle)
        result_dir.rename(target)
    return report


def verify_export(directory, *, manifest_sha256=None, bundle=None):
    """Check export integrity and every emitted event offline, optionally binding the source."""
    root = Path(directory).resolve()
    manifest_path = safe_member(root, "export_manifest.json")
    if manifest_sha256 and file_hash(manifest_path) != manifest_sha256:
        raise ValueError("OCSF export manifest pin mismatch")
    report = _strict_json(manifest_path.read_text(encoding="utf-8"))
    if not REPORT_VALIDATOR.is_valid(report):
        raise ValueError("invalid OCSF export manifest")
    expected_lock = hashlib.sha256(RESOURCE_ROOT.joinpath("schema-lock.json").read_bytes()).hexdigest()
    if report.get("schema_lock_sha256") != expected_lock:
        raise ValueError("OCSF schema lock mismatch")
    if set(report.get("files", {})) != EXPORT_FILES or {p.name for p in root.iterdir()} != EXPORT_FILES | {
        "export_manifest.json"
    }:
        raise ValueError("OCSF export membership mismatch")
    for name, entry in report["files"].items():
        path = safe_member(root, name)
        if path.stat().st_size != entry["bytes"] or file_hash(path) != entry["sha256"]:
            raise ValueError("OCSF export artifact mismatch: " + name)
    source = verify_bundle(bundle, report["source_manifest_sha256"]) if bundle is not None else None
    counts = {}
    # A private on-disk SQLite database keeps identity accounting bounded in memory.
    with closing(sqlite3.connect("")) as db:
        db.execute("CREATE TABLE seen (uid TEXT PRIMARY KEY)")
        db.execute("CREATE TABLE source (uid TEXT PRIMARY KEY, payload TEXT)")
        if bundle is not None:
            for event in read_timeline(bundle):
                db.execute("INSERT INTO source VALUES (?,?)", (event["event_uuid"], compact_json(event)))
        for name, key in [("ocsf.jsonl", "exported_events"), ("rejections.jsonl", "rejected_events")]:
            counts[key] = 0
            with safe_member(root, name).open(encoding="utf-8") as stream:
                for line in stream:
                    row = _strict_json(line)
                    if name == "ocsf.jsonl":
                        validate_event(row)
                        reference = row.get("unmapped", {}).get("timeline_export")
                        if (
                            not isinstance(reference, dict)
                            or reference.get("mapping_version") != report["mapping_version"]
                        ):
                            raise ValueError("OCSF event mapping version differs from its export manifest")
                    else:
                        reference = row
                        if (
                            not isinstance(row, dict)
                            or not isinstance(row.get("error"), str)
                            or not row["error"]
                        ):
                            raise ValueError("invalid OCSF rejection receipt")
                    if not isinstance(reference, dict) or not DIGEST.fullmatch(
                        str(reference.get("event_uuid", ""))
                    ):
                        raise ValueError("invalid OCSF source event reference")
                    try:
                        db.execute("INSERT INTO seen VALUES (?)", (reference["event_uuid"],))
                    except sqlite3.IntegrityError:
                        raise ValueError("duplicate OCSF source event reference") from None
                    if bundle is not None:
                        matched = db.execute(
                            "SELECT payload FROM source WHERE uid=?", (reference["event_uuid"],)
                        ).fetchone()
                        if matched is None:
                            raise ValueError("OCSF event is not in the bound source bundle")
                        original = json.loads(matched[0])
                        fields = ["evidence_path", "record_index", "child_index"]
                        if name == "ocsf.jsonl":
                            fields.extend(
                                [
                                    "source_event_id",
                                    "parser_name",
                                    "parser_version",
                                    "raw_data_hash",
                                    "raw_file_hash",
                                ]
                            )
                            if (
                                row["time"] != original["epoch_ms"]
                                or row["class_uid"] != original["ocsf_class_uid"]
                            ):
                                raise ValueError("OCSF time/class differs from source timeline")
                        elif (
                            row.get("class_uid") != original["ocsf_class_uid"]
                            or row.get("parser") != original["parser_name"]
                        ):
                            raise ValueError("OCSF rejection reference differs from source timeline")
                        if any(reference.get(key) != original[key] for key in fields):
                            raise ValueError("OCSF provenance differs from source timeline")
                    counts[key] += 1
    counts["source_events"] = counts["exported_events"] + counts["rejected_events"]
    if report.get("counts") != counts:
        raise ValueError("OCSF export count mismatch")
    if bundle is not None:
        if (
            source["bundle_id"] != report["source_bundle_id"]
            or source["case_id"] != report["case_id"]
            or source["counts"]["event_count"] != counts["source_events"]
        ):
            raise ValueError("OCSF source bundle binding mismatch")
    return report
