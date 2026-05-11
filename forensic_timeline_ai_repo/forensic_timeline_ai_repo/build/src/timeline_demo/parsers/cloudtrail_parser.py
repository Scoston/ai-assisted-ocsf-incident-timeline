from __future__ import annotations
from pathlib import Path
from .common import compact_json, coalesce, load_json_records, make_uuid, parse_iso_to_utc, sha256_of_text

def parse_cloudtrail_file(path: str | Path):
    path = Path(path); out = []
    for record in load_json_records(path):
        time_utc, epoch_ms, offset = parse_iso_to_utc(record.get("eventTime"))
        resources = record.get("resources") or [{}]
        resource_arn = resources[0].get("ARN") if isinstance(resources, list) and resources and isinstance(resources[0], dict) else None
        user_identity = record.get("userIdentity") or {}
        seid = coalesce(record.get("eventID"), sha256_of_text(compact_json(record))[:16])
        out.append({"parser_name":"cloudtrail","parser_version":"1.0.0","source_name":"aws","product_name":"AWS CloudTrail","ocsf_class_uid":1001,"event_uuid":make_uuid("cloudtrail",str(seid),time_utc),"source_event_id":seid,"activity_name":record.get("eventName"),"status":coalesce(record.get("errorCode"),"success"),"severity":"medium","time_utc":time_utc,"epoch_ms":epoch_ms,"timezone_offset":offset,"user_name":coalesce(user_identity.get("arn"),user_identity.get("userName"),user_identity.get("principalId")),"asset_name":coalesce(resource_arn,record.get("eventSource"),record.get("awsRegion")),"src_ip":record.get("sourceIPAddress"),"cloud_service":record.get("eventSource"),"cloud_region":record.get("awsRegion"),"raw_data_hash":sha256_of_text(compact_json(record)),"raw_file":str(path),"evidence_path":str(path),"metadata":{"schema_version":"normalized-real-parser-1.0","read_only":True}})
    return out
