from __future__ import annotations
from pathlib import Path
from .common import compact_json, coalesce, load_json_records, make_uuid, parse_iso_to_utc, sha256_of_text

def parse_crowdstrike_detection_file(path: str | Path):
    path = Path(path); sev_map = {"1":"low","2":"low","3":"medium","4":"medium","5":"medium","6":"high","7":"high","8":"high","9":"critical","10":"critical"}; out = []
    for record in load_json_records(path):
        behaviors = record.get("behaviors") or [{}]; behavior = behaviors[0] if isinstance(behaviors, list) and behaviors else {}
        time_utc, epoch_ms, offset = parse_iso_to_utc(coalesce(record.get("created_timestamp"), record.get("created_time"), record.get("timestamp"), behavior.get("timestamp")))
        seid = coalesce(record.get("detection_id"), record.get("id"), behavior.get("id"), sha256_of_text(compact_json(record))[:16])
        out.append({"parser_name":"crowdstrike_detection","parser_version":"1.0.0","source_name":"crowdstrike","product_name":"CrowdStrike Falcon","ocsf_class_uid":1004,"event_uuid":make_uuid("crowdstrike_detection",str(seid),time_utc),"source_event_id":seid,"activity_name":coalesce(behavior.get("display_name"),behavior.get("name"),record.get("scenario"),"CrowdStrike Detection"),"status":coalesce(record.get("status"),record.get("state"),"new"),"severity":sev_map.get(str(coalesce(record.get("severity"),behavior.get("severity"))),"high"),"time_utc":time_utc,"epoch_ms":epoch_ms,"timezone_offset":offset,"user_name":coalesce(behavior.get("user_name"),record.get("user_name")),"asset_name":coalesce((record.get("device") or {}).get("hostname"),record.get("hostname"),behavior.get("device_name")),"tactic":behavior.get("tactic"),"technique":behavior.get("technique"),"raw_data_hash":sha256_of_text(compact_json(record)),"raw_file":str(path),"evidence_path":str(path),"metadata":{"schema_version":"normalized-real-parser-1.0","read_only":True}})
    return out
