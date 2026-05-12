from __future__ import annotations

import csv
import json
from pathlib import Path


PREFERRED_FIELD_ORDER = [
    "timeline_position",
    "time_utc",
    "epoch_ms",
    "timezone_offset",
    "temporal_confidence",
    "source_name",
    "product_name",
    "parser_name",
    "parser_version",
    "ocsf_class_uid",
    "activity_name",
    "status",
    "severity",
    "user_name",
    "asset_name",
    "src_ip",
    "cloud_service",
    "cloud_region",
    "tactic",
    "technique",
    "source_event_id",
    "event_uuid",
    "raw_data_hash",
    "raw_file",
    "evidence_path",
    "metadata",
]


def build_timeline(events):
    ordered = sorted(
        events,
        key=lambda event: (
            event.get("epoch_ms") or 0,
            str(event.get("event_uuid")),
        ),
    )

    for idx, event in enumerate(ordered, start=1):
        event["timeline_position"] = idx
        event["temporal_confidence"] = event.get("temporal_confidence", 0.99)

    return ordered


def _all_fieldnames(records):
    discovered = set()

    for record in records:
        discovered.update(record.keys())

    ordered_fields = [field for field in PREFERRED_FIELD_ORDER if field in discovered]
    remaining_fields = sorted(discovered - set(ordered_fields))

    return ordered_fields + remaining_fields


def _csv_safe_record(record, fieldnames):
    safe = {}

    for field in fieldnames:
        value = record.get(field, "")

        if isinstance(value, (dict, list)):
            safe[field] = json.dumps(value, ensure_ascii=False, sort_keys=True)
        elif value is None:
            safe[field] = ""
        else:
            safe[field] = value

    return safe


def write_timeline_outputs(timeline, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    jsonl_path = output_dir / "timeline.jsonl"
    csv_path = output_dir / "timeline.csv"

    jsonl_path.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in timeline) + "\n",
        encoding="utf-8",
    )

    if not timeline:
        csv_path.write_text("", encoding="utf-8")
        return

    fieldnames = _all_fieldnames(timeline)

    with csv_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()

        for record in timeline:
            writer.writerow(_csv_safe_record(record, fieldnames))