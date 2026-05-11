from __future__ import annotations
import csv, json
from pathlib import Path

def build_timeline(events):
    ordered = sorted(events, key=lambda x: (x.get("epoch_ms") or 0, str(x.get("event_uuid"))))
    for idx, event in enumerate(ordered, start=1): event["timeline_position"] = idx; event["temporal_confidence"] = event.get("temporal_confidence", 0.99)
    return ordered

def write_timeline_outputs(timeline, output_dir):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "timeline.jsonl").write_text("\n".join(json.dumps(r) for r in timeline) + "\n", encoding="utf-8")
    if timeline:
        with (out / "timeline.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(timeline[0].keys())); writer.writeheader(); writer.writerows(timeline)
