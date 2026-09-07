import gzip
import json
from pathlib import Path

import pytest

from timeline_demo.parsers.common import parse_time
from timeline_demo.parsers.registry import SPECS, normalize_record, parse_file
from timeline_demo.pipeline import Input, read_timeline, run_pipeline

SAMPLES = json.loads((Path(__file__).resolve().parents[1] / "examples/parser_samples.json").read_text())


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_supported_source_contracts(name, tmp_path):
    path = tmp_path / "record.json"
    path.write_text(json.dumps(SAMPLES[name]))
    event = parse_file(path, name)[0]
    assert event["epoch_ms"] == 1788256800000
    assert event["time_utc"].startswith("2026-09-01T10:00:00")
    assert len(event["raw_data_hash"]) == len(event["event_uuid"]) == 64
    assert event["ocsf_class_uid"] >= 0
    if name == "syslog":
        assert event["ocsf_class_uid"] == 0
    assert set(SAMPLES) == set(SPECS)


@pytest.mark.parametrize("timestamp", [None, "", "2026-09-01T10:00:00", "not a date", True, 1788256800])
def test_ambiguous_timestamp_rejected(timestamp):
    with pytest.raises((ValueError, TypeError)):
        parse_time(timestamp)


def test_timestamp_offset_and_explicit_assumption():
    assert parse_time("2026-09-01T06:00:00-04:00")[1] == 1788256800000
    assert parse_time("2026-09-01T10:00:00", assume_timezone="UTC")[1] == 1788256800000
    for local in ["2026-11-01T01:30:00", "2026-03-08T02:30:00"]:
        with pytest.raises(ValueError):
            parse_time(local, assume_timezone="America/New_York")


def test_crowdstrike_preserves_each_behavior(tmp_path):
    raw = {**SAMPLES["crowdstrike_detection"], "behaviors": [{"name": "first"}, {"name": "second"}]}
    events = normalize_record(raw, "crowdstrike_detection", "raw", "a" * 64, 1)
    assert [e["activity_name"] for e in events] == ["first", "second"]
    assert events[0]["event_uuid"] != events[1]["event_uuid"]
    assert events[0]["raw_data_hash"] == events[1]["raw_data_hash"]


def test_graph_wrapper_and_m365_embedded_audit(tmp_path):
    p = tmp_path / "graph.json"
    p.write_text(json.dumps({"value": [SAMPLES["entra_signin"]]}))
    assert parse_file(p, "entra_signin")[0]["status"] == "success"
    p.write_text(json.dumps({"AuditData": json.dumps(SAMPLES["m365_audit"])}))
    assert parse_file(p, "m365_audit")[0]["activity_name"] == "FileAccessed"


def test_missing_entra_result_is_unknown():
    raw = dict(SAMPLES["entra_signin"])
    del raw["status"]
    assert normalize_record(raw, "entra_signin", "raw", "a" * 64, 1)[0]["status"] == "unknown"


def test_gzip_csv_xml_and_network_exports(tmp_path):
    gz = tmp_path / "raw.jsonl.gz"
    with gzip.open(gz, "wt") as stream:
        stream.write(json.dumps(SAMPLES["cloudtrail"]) + "\n")
    assert len(parse_file(gz, "cloudtrail")) == 1
    csv = tmp_path / "plaso.csv"
    csv.write_text('datetime,message\n2026-09-01T10:00:00Z,"file, modified"\n')
    assert parse_file(csv, "plaso")[0]["activity_name"] == "file, modified"
    xml = tmp_path / "events.xml"
    xml.write_text(
        '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><TimeCreated SystemTime="2026-09-01T10:00:00Z"/><Computer>host</Computer></System><EventData><Data Name="TargetUserName">alice</Data></EventData></Event></Events>'
    )
    assert parse_file(xml, "windows_event")[0]["user_name"] == "alice"
    log = tmp_path / "syslog.log"
    log.write_text("<84>1 2026-09-01T10:00:00Z host sshd 123 ID47 - Accepted login\n")
    assert parse_file(log, "syslog")[0]["severity"] == "medium"
    log.write_text(
        "2 123456789012 eni-1 198.51.100.10 203.0.113.1 1234 443 6 1 500 1788256800 1788256801 ACCEPT OK\n"
    )
    assert parse_file(log, "vpc_flow")[0]["src_ip"] == "198.51.100.10"


def test_parquet_reader(tmp_path):
    import pyarrow as pa
    import pyarrow.parquet as pq

    p = tmp_path / "audit.parquet"
    pq.write_table(pa.Table.from_pylist([SAMPLES["databricks_audit"]]), p)
    assert parse_file(p, "databricks_audit")[0]["activity_name"] == "runNow"


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":NaN}'])
def test_duplicate_keys_and_nonfinite_numbers_fail(tmp_path, text):
    p = tmp_path / "broken.json"
    p.write_text(text)
    with pytest.raises(ValueError):
        parse_file(p, "cloudtrail")


def test_quarantine_keeps_evidence_and_reject_receipts(tmp_path):
    p = tmp_path / "mixed.jsonl"
    p.write_text(json.dumps(SAMPLES["cloudtrail"]) + "\nnot-json\n" + json.dumps({"eventName": "bad"}) + "\n")
    with pytest.raises(ValueError):
        run_pipeline([Input("cloudtrail", p)], tmp_path / "strict", "test")
    assert not (tmp_path / "strict").exists()
    bundle = tmp_path / "quarantine"
    result = run_pipeline([Input("cloudtrail", p)], bundle, "test", quarantine=True)
    assert result["counts"]["quarantined_records"] == 2
    assert len(list(read_timeline(bundle))) == 1
    assert (bundle / result["inputs"][0]["evidence_path"]).read_bytes() == p.read_bytes()


def test_unmapped_generic_events_do_not_claim_process_activity():
    generic = {"TimeCreated": "2026-09-01T10:00:00Z", "EventID": 9999}
    event = normalize_record(generic, "windows_event", "raw", "a" * 64, 1)[0]
    assert event["ocsf_class_uid"] == 0
    assert event["metadata"]["ocsf_mapping_status"] == "unmapped"


def test_xml_entities_rejected(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><Event>&e;</Event>')
    with pytest.raises(ValueError, match="DTD/entity"):
        parse_file(p, "windows_event")


def test_csv_bad_columns_quarantined(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("datetime,message\n2026-09-01T10:00:00Z,ok\n2026-09-01T10:00:00Z,bad,extra\n")
    manifest = run_pipeline([Input("plaso", p)], tmp_path / "bundle", "csv-test", quarantine=True)
    assert manifest["counts"]["event_count"] == 1
    assert manifest["counts"]["quarantined_records"] == 1
