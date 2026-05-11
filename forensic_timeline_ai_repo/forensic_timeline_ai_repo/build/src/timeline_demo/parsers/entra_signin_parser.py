from __future__ import annotations
from pathlib import Path
from .common import compact_json, coalesce, load_json_records, make_uuid, parse_iso_to_utc, sha256_of_text

def parse_entra_signin_file(path: str | Path):
    path = Path(path); out = []
    for record in load_json_records(path):
        time_utc, epoch_ms, offset = parse_iso_to_utc(coalesce(record.get("CreatedDateTime"), record.get("createdDateTime"), record.get("TimeGenerated")))
        seid = coalesce(record.get("Id"), record.get("id"), sha256_of_text(compact_json(record))[:16])
        result_type = coalesce(record.get("ResultType"), record.get("resultType")); result_desc = coalesce(record.get("ResultDescription"), record.get("resultDescription"))
        status = "SUCCESS" if str(result_type) in {"0","success","Success",""} else coalesce(result_desc, str(result_type), "FAILURE")
        severity = "medium" if status == "SUCCESS" else "high"
        out.append({"parser_name":"entra_signin","parser_version":"1.0.0","source_name":"entra","product_name":"Microsoft Entra Sign-in Logs","ocsf_class_uid":1003,"event_uuid":make_uuid("entra_signin",str(seid),time_utc),"source_event_id":seid,"activity_name":coalesce(record.get("OperationName"),record.get("operationName"),"user.signin"),"status":status,"severity":severity,"time_utc":time_utc,"epoch_ms":epoch_ms,"timezone_offset":offset,"user_name":coalesce(record.get("UserPrincipalName"),record.get("userPrincipalName"),record.get("Identity")),"asset_name":coalesce(record.get("AppDisplayName"),record.get("ResourceDisplayName")),"src_ip":coalesce(record.get("IPAddress"),record.get("ipAddress")),"raw_data_hash":sha256_of_text(compact_json(record)),"raw_file":str(path),"evidence_path":str(path),"metadata":{"schema_version":"normalized-real-parser-1.0","read_only":True}})
    return out
