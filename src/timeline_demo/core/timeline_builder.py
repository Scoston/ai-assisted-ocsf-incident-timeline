from __future__ import annotations

import copy
import csv
from pathlib import Path

from timeline_demo.parsers.common import compact_json, write_jsonl

PREFERRED_FIELD_ORDER = [
    "timeline_position",
    "time_utc",
    "epoch_ms",
    "source_name",
    "product_name",
    "activity_name",
    "status",
    "severity",
    "user_name",
    "asset_name",
    "src_ip",
    "event_uuid",
    "raw_data_hash",
    "raw_file_hash",
    "evidence_path",
    "record_index",
]


def build_timeline(events):
    ordered = sorted(copy.deepcopy(events), key=lambda e: (e["epoch_ms"], e["event_uuid"]))
    for position, event in enumerate(ordered, 1):
        event["timeline_position"] = position
    return ordered


def csv_value(value):
    text = compact_json(value) if isinstance(value, (dict, list)) else "" if value is None else str(value)
    # CSV is a presentation artifact. JSONL retains exact normalized strings.
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else text


def write_timeline_outputs(timeline, output_dir):
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    write_jsonl(root / "timeline.jsonl", timeline)
    with (root / "timeline.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=PREFERRED_FIELD_ORDER, lineterminator="\n")
        writer.writeheader()
        for event in timeline:
            writer.writerow({k: csv_value(event.get(k)) for k in PREFERRED_FIELD_ORDER})
