"""Bounded source readers. Yield errors so quarantine never silently drops a row."""

from __future__ import annotations

import csv
import gzip
import json
import re
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 32 * 1024 * 1024
WRAPPERS = ("Records", "records", "value", "resources", "Findings", "findings", "items")


def _strict_json(text):
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj:
                raise ValueError("duplicate JSON key: " + k)
            obj[k] = v
        return obj

    def reject(value):
        raise ValueError("non-finite JSON number: " + value)

    return json.loads(text, object_pairs_hook=pairs, parse_constant=reject)


def _row(index, value):
    return (index, value, None) if isinstance(value, dict) else (index, None, "record must be an object")


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError("unsupported Parquet field: " + type(value).__name__)


def iter_records(path, parser=None):
    path = Path(path)
    suffix = path.suffix.lower()
    opener = gzip.open if suffix == ".gz" else open
    fmt = path.with_suffix("").suffix.lower() if suffix == ".gz" else suffix
    if fmt == ".parquet":
        if suffix == ".gz":
            raise ValueError("use Parquet's internal compression, not .parquet.gz")
        import pyarrow.parquet as pq

        index = 0
        for batch in pq.ParquetFile(path).iter_batches(batch_size=2048):
            for value in batch.to_pylist():
                index += 1
                try:
                    yield _row(index, _strict_json(json.dumps(value, default=_json_default)))
                except (ValueError, TypeError) as exc:
                    yield index, None, str(exc)
        return
    if fmt == ".xml":
        # Exported Windows XML only; DTDs and custom entities are rejected.
        with opener(path, "rb") as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise ValueError("XML too large or contains DTD/entity declarations")
        if parser != "windows_event":
            raise ValueError("XML is supported only for windows_event exports")
        root = ET.fromstring(raw)
        for node in root.iter():
            node.tag = node.tag.split("}")[-1]
        nodes = [root] if root.tag == "Event" else root.findall("Event")
        if not nodes:
            raise ValueError("no Windows Event elements found")
        for index, node in enumerate(nodes, 1):
            system = node.find("System")
            if system is None:
                yield index, None, "Windows event has no System element"
                continue
            record = {child.tag: child.text for child in system}
            time = system.find("TimeCreated")
            record["TimeCreated"] = time.get("SystemTime") if time is not None else None
            record["EventData"] = {
                x.get("Name", str(i)): x.text for i, x in enumerate(node.findall("EventData/Data"))
            }
            yield _row(index, record)
        return
    with opener(path, "rt", encoding="utf-8-sig", newline="") as stream:
        if fmt in {".csv", ".tsv"}:
            csv.field_size_limit(MAX_RECORD_BYTES)
            reader = csv.DictReader(stream, delimiter="\t" if fmt == ".tsv" else ",")
            if reader.fieldnames and len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise ValueError("duplicate CSV header")
            for index, value in enumerate(reader, 1):
                if None in value or any(v is None for v in value.values()):
                    yield index, None, "CSV column count mismatch"
                else:
                    yield _row(index, value)
            return
        if fmt == ".json":
            text = stream.read(MAX_JSON_BYTES + 1)
            if len(text.encode("utf-8")) > MAX_JSON_BYTES:
                raise ValueError("JSON document exceeds 32 MiB; export JSONL")
            value = _strict_json(text)
            if isinstance(value, dict):
                for wrapper in WRAPPERS:
                    if isinstance(value.get(wrapper), list):
                        value = value[wrapper]
                        break
            if not isinstance(value, list):
                value = [value]
            for index, record in enumerate(value, 1):
                yield _row(index, record)
            return
        index = 0
        while True:
            line = stream.readline(MAX_RECORD_BYTES + 1)
            if not line:
                break
            index += 1
            if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
                raise ValueError("record exceeds 4 MiB")
            if not line.strip():
                continue
            try:
                if parser == "syslog" and not line.lstrip().startswith("{"):
                    match = re.fullmatch(
                        r"<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?\s*",
                        line,
                    )
                    if not match or int(match[1]) > 191:
                        raise ValueError("expected RFC 5424 version 1 syslog")
                    value = dict(
                        zip(
                            (
                                "pri",
                                "timestamp",
                                "hostname",
                                "app",
                                "pid",
                                "msgid",
                                "structured_data",
                                "message",
                            ),
                            match.groups(),
                        )
                    )
                elif parser == "vpc_flow" and not line.lstrip().startswith("{"):
                    fields = line.split()
                    if fields[:2] == ["version", "account-id"]:
                        continue
                    keys = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status".split()
                    if len(fields) != len(keys):
                        raise ValueError("expected AWS default 14-field VPC flow format")
                    value = dict(zip(keys, fields))
                else:
                    value = _strict_json(line)
                yield _row(index, value)
            except (ValueError, TypeError) as exc:
                yield index, None, str(exc)
