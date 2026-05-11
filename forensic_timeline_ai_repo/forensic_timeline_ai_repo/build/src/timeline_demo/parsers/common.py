from __future__ import annotations
import hashlib, json, uuid
from datetime import datetime, timezone
from pathlib import Path

def sha256_of_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

def load_json_records(path: str | Path) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text: return []
    if text.startswith("{"):
        obj = json.loads(text)
        return obj["Records"] if isinstance(obj, dict) and isinstance(obj.get("Records"), list) else [obj]
    if text.startswith("["):
        obj = json.loads(text)
        return obj if isinstance(obj, list) else [obj]
    return [json.loads(line) for line in text.splitlines() if line.strip()]

def parse_iso_to_utc(ts):
    if not ts: return None, None, None
    dt = datetime.fromisoformat(str(ts).strip().replace("Z", "+00:00"))
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    off = dt.utcoffset(); mins = int(off.total_seconds() // 60) if off else 0
    sign = "+" if mins >= 0 else "-"; offset = f"{sign}{abs(mins)//60:02d}:{abs(mins)%60:02d}"
    dt = dt.astimezone(timezone.utc)
    return dt.isoformat(), int(dt.timestamp() * 1000), offset

def make_uuid(namespace, source_event_id, time_utc):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{namespace}|{source_event_id}|{time_utc or 'none'}"))

def compact_json(record): return json.dumps(record, sort_keys=True, separators=(",", ":"))
def coalesce(*values):
    for value in values:
        if value is not None and value != "": return value
    return None

def write_jsonl(path, records):
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8")
