"""Strict timestamps and deterministic record identity (not RFC 8785)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from zoneinfo import ZoneInfo


def compact_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_of_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pick(record, *paths, default=None):
    for path in paths:
        value = record
        if path in record:  # Zeek uses literal dots in field names.
            value = record[path]
        else:
            for key in path.split("."):
                if isinstance(value, dict):
                    value = value.get(key)
                elif isinstance(value, list) and key.isdigit() and int(key) < len(value):
                    value = value[int(key)]
                else:
                    value = None
                    break
        if value is not None and value != "":
            return value
    return default


def parse_time(value, unit=None, assume_timezone=None):
    if value is None or value == "" or isinstance(value, bool):
        raise ValueError("missing or invalid timestamp")
    if unit and (
        isinstance(value, (int, float, Decimal)) or str(value).replace(".", "", 1).lstrip("-").isdigit()
    ):
        divisor = {"s": Decimal(1), "ms": Decimal(1000), "us": Decimal(1000000)}[unit]
        seconds = Decimal(str(value)) / divisor
        dt = datetime.fromtimestamp(float(seconds), timezone.utc)
        epoch_ms = int(seconds * 1000)
    else:
        if isinstance(value, (int, float)):
            raise ValueError("numeric timestamp requires a source-specific unit")
        dt = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
        if dt.tzinfo is None:
            if not assume_timezone:
                raise ValueError("timestamp has no timezone; provide an explicit assumption")
            zone = ZoneInfo(assume_timezone)
            # A DST fold/gap cannot be resolved by simply assigning a zone.
            if dt.replace(tzinfo=zone, fold=0).utcoffset() != dt.replace(tzinfo=zone, fold=1).utcoffset():
                raise ValueError("ambiguous or nonexistent local timestamp")
            dt = dt.replace(tzinfo=zone)
        epoch_ms = int(Decimal(str(dt.timestamp())) * 1000)
    offset = dt.strftime("%z")
    return dt.astimezone(timezone.utc).isoformat(), epoch_ms, offset[:3] + ":" + offset[3:]


def parse_iso_to_utc(value):
    return parse_time(value)


def coalesce(*values):
    return next((v for v in values if v is not None and v != ""), None)


def write_jsonl(path, records):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(compact_json(record) + "\n")


def load_json_records(path):
    from .readers import iter_records

    records = []
    for _, record, error in iter_records(Path(path)):
        if error:
            raise ValueError(error)
        records.append(record)
    return records
