import copy
import json
from pathlib import Path

import pytest

from timeline_demo.cli import main
from timeline_demo.ocsf import export_bundle, map_event, schema_lock, validate_event, validator, verify_export
from timeline_demo.parsers.common import compact_json, file_hash
from timeline_demo.parsers.registry import normalize_record
from timeline_demo.pipeline import Input, run_pipeline

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = json.loads((ROOT / "examples/parser_samples.json").read_text())


def convert(parser, raw):
    event = normalize_record(raw, parser, "evidence/" + "a" * 64 + ".json", "a" * 64, 1)[0]
    return map_event(event, raw)


def rich_samples():
    samples = copy.deepcopy(SAMPLES)
    samples.pop("syslog")
    samples.pop("ocsf")
    additions = {
        "cloudtrail": {
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/example"},
            "sourceIPAddress": "198.51.100.10",
        },
        "entra_audit": {
            "initiatedBy": {"user": {"userPrincipalName": "alice@example.test", "ipAddress": "198.51.100.10"}}
        },
        "azure_activity": {"caller": "alice@example.test", "callerIpAddress": "198.51.100.10"},
        "m365_audit": {"UserId": "alice@example.test", "ClientIP": "198.51.100.10"},
        "gcp_audit": {
            "protoPayload": {
                "methodName": "storage.objects.get",
                "authenticationInfo": {"principalEmail": "alice@example.test"},
                "requestMetadata": {"callerIp": "198.51.100.10"},
            }
        },
        "tines_audit": {"ip_address": "198.51.100.10"},
        "databricks_audit": {"source_ip_address": "198.51.100.10"},
        "ai_agent": {"src_ip": "198.51.100.10"},
        "vpc_flow": {"dstaddr": "203.0.113.10", "srcport": "443", "dstport": "5678"},
        "zeek": {"id.resp_h": "203.0.113.10"},
        "suricata": {"alert": {"signature": "Synthetic signature", "signature_id": 1001, "severity": 1}},
        "entra_signin": {"appDisplayName": "Example application"},
        "okta": {
            "actor": {"alternateId": "alice@example.test"},
            "target": [{"alternateId": "Example application"}],
        },
        "windows_event": {"Computer": "host-1"},
        "plaso": {"hostname": "host-1", "username": "alice", "filename": "/tmp/example.txt"},
    }
    for name, extra in additions.items():
        samples[name].update(extra)
    return samples


@pytest.mark.parametrize("parser,raw", sorted(rich_samples().items()))
def test_all_mapped_vendor_contracts_have_valid_ocsf(parser, raw):
    result = convert(parser, raw)
    assert result["metadata"]["version"] == "1.3.0"
    assert result["type_uid"] == result["class_uid"] * 100 + result["activity_id"]
    assert result["unmapped"]["timeline_export"]["parser_name"] == parser
    validate_event(result)


@pytest.mark.parametrize(
    "parser,extra,uid,activity",
    [
        (
            "windows_event",
            {
                "EventID": 4688,
                "Computer": "host-1",
                "EventData": {"SubjectUserName": "alice", "NewProcessId": "0x1234"},
            },
            1007,
            1,
        ),
        ("windows_event", {"EventID": 1102, "Channel": "Security"}, 1008, 1),
        (
            "zeek",
            {"_path": "http", "id.resp_h": "203.0.113.10", "method": "GET", "status_code": 200},
            4002,
            3,
        ),
        (
            "suricata",
            {"event_type": "http", "dest_ip": "203.0.113.10", "http": {"http_method": "GET", "status": 200}},
            4002,
            3,
        ),
        ("zeek", {"_path": "dns", "query": "example.test"}, 4003, 0),
        ("suricata", {"event_type": "dns", "dns": {"rrname": "example.test"}}, 4003, 0),
    ],
)
def test_event_specific_fields_and_enumerations(parser, extra, uid, activity):
    result = convert(parser, {**SAMPLES[parser], **extra})
    assert result["class_uid"] == uid
    assert result["activity_id"] == activity
    if uid == 1007:
        assert result["process"]["pid"] == 4660


def test_every_advertised_class_is_pinned_and_self_contained():
    assert set(schema_lock()["classes"]) == {
        "1001",
        "1007",
        "1008",
        "2004",
        "3002",
        "4001",
        "4002",
        "4003",
        "6003",
    }
    for uid in schema_lock()["classes"]:
        check = validator(int(uid))
        assert check.schema["properties"]["class_uid"]["const"] == int(uid)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e["actor"].update(user={}),
        lambda e: e.update(type_uid=600304),
        lambda e: e.update(category_uid=1),
        lambda e: e["metadata"].update(version="1.2.0"),
        lambda e: e["metadata"].update(profiles=["cloud"]),
        lambda e: e["metadata"].update(extensions=[{"name": "custom", "uid": 99, "version": "1.0"}]),
        lambda e: e.update(unexpected_field=True),
        lambda e: e["src_endpoint"].update(port=70000),
    ],
)
def test_schema_and_semantic_constraints_fail_closed(mutate):
    event = convert("cloudtrail", rich_samples()["cloudtrail"])
    mutate(event)
    with pytest.raises(ValueError):
        validate_event(event)


def test_native_ocsf_preserves_fields_and_rejects_other_versions():
    event = convert("cloudtrail", rich_samples()["cloudtrail"])
    event.pop("unmapped")
    event["unmapped"] = {"vendor_field": {"value": 42}}
    original = copy.deepcopy(event)
    result = convert("ocsf", event)
    assert result["api"] == original["api"]
    assert result["unmapped"]["vendor_field"] == {"value": 42}
    assert event == original
    event["metadata"]["version"] = "1.8.0"
    with pytest.raises(ValueError, match="version"):
        convert("ocsf", event)


def test_hash_linkage_and_missing_required_data_are_rejected():
    raw = rich_samples()["cloudtrail"]
    event = normalize_record(raw, "cloudtrail", "raw", "a" * 64, 1)[0]
    with pytest.raises(ValueError, match="hash"):
        map_event(event, {**raw, "eventName": "altered"})
    for parser in ["cloudtrail", "ocsf", "syslog", "plaso"]:
        with pytest.raises(ValueError):
            convert(parser, SAMPLES[parser])


def test_export_round_trip_tamper_and_source_pins(tmp_path):
    bundle = ROOT / "examples/demo_bundle"
    before = file_hash(bundle / "audit_manifest.json")
    report = export_bundle(bundle, tmp_path / "first", manifest_sha256=before)
    assert report["counts"] == {"source_events": 5, "exported_events": 5, "rejected_events": 0}
    assert report["model_tokens"] == 0
    assert file_hash(bundle / "audit_manifest.json") == before
    second = export_bundle(bundle, tmp_path / "second")
    assert second == report
    assert verify_export(tmp_path / "first", bundle=bundle) == report
    for name in ["ocsf.jsonl", "rejections.jsonl", "export_manifest.json"]:
        assert (tmp_path / "first" / name).read_bytes() == (tmp_path / "second" / name).read_bytes()
    with pytest.raises(FileExistsError):
        export_bundle(bundle, tmp_path / "first")
    with pytest.raises(ValueError, match="outside"):
        export_bundle(bundle, bundle / "ocsf")
    with pytest.raises(ValueError, match="pin"):
        verify_export(tmp_path / "first", manifest_sha256="0" * 64)
    (tmp_path / "first/ocsf.jsonl").write_text("{}\n")
    with pytest.raises(ValueError, match="artifact"):
        verify_export(tmp_path / "first")


def test_quarantine_accounts_for_every_event_and_cli(tmp_path, capsys):
    source = tmp_path / "raw.json"
    source.write_text(compact_json([SAMPLES["cloudtrail"], rich_samples()["cloudtrail"]]))
    bundle = tmp_path / "bundle"
    run_pipeline([Input("cloudtrail", source), Input("cloudtrail", source)], bundle, "ocsf-case")
    with pytest.raises(ValueError, match="1 of 2"):
        export_bundle(bundle, tmp_path / "strict")
    assert not (tmp_path / "strict").exists()
    output = tmp_path / "out"
    assert main(["export-ocsf", str(bundle), "--output", str(output), "--quarantine"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["counts"] == {"source_events": 2, "exported_events": 1, "rejected_events": 1}
    assert main(["verify-ocsf", str(output), "--bundle", str(bundle)]) == 0
    rejected = json.loads((output / "rejections.jsonl").read_text())
    assert "required" in rejected["error"]
    assert len(rejected["event_uuid"]) == 64


def test_rehashed_invalid_event_still_fails_schema_validation(tmp_path):
    output = tmp_path / "export"
    export_bundle(ROOT / "examples/demo_bundle", output)
    data = [json.loads(line) for line in (output / "ocsf.jsonl").read_text().splitlines()]
    data[0]["metadata"]["product"] = {}
    (output / "ocsf.jsonl").write_text("".join(compact_json(row) + "\n" for row in data))
    manifest = json.loads((output / "export_manifest.json").read_text())
    manifest["files"]["ocsf.jsonl"] = {
        "sha256": file_hash(output / "ocsf.jsonl"),
        "bytes": (output / "ocsf.jsonl").stat().st_size,
    }
    (output / "export_manifest.json").write_text(compact_json(manifest))
    with pytest.raises(ValueError, match="OCSF"):
        verify_export(output)


@pytest.mark.parametrize(
    "alteration", ["duplicate", "foreign_reference", "changed_provenance", "manifest_shape"]
)
def test_export_identity_accounting_cannot_be_bypassed_by_rehashing(tmp_path, alteration):
    output = tmp_path / "export"
    bundle = ROOT / "examples/demo_bundle"
    export_bundle(bundle, output)
    manifest_path = output / "export_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    rows = [json.loads(line) for line in (output / "ocsf.jsonl").read_text().splitlines()]
    if alteration == "duplicate":
        rows[1] = rows[0]
    elif alteration == "foreign_reference":
        rows[0]["unmapped"]["timeline_export"]["event_uuid"] = "f" * 64
    elif alteration == "changed_provenance":
        rows[0]["unmapped"]["timeline_export"]["record_index"] = 999
    else:
        manifest["counts"]["source_events"] = "5"
    (output / "ocsf.jsonl").write_text("".join(compact_json(row) + "\n" for row in rows))
    manifest["files"]["ocsf.jsonl"] = {
        "sha256": file_hash(output / "ocsf.jsonl"),
        "bytes": (output / "ocsf.jsonl").stat().st_size,
    }
    manifest_path.write_text(compact_json(manifest))
    with pytest.raises(ValueError):
        verify_export(output, bundle=bundle)


def test_export_membership_symlink_and_cli_failures(tmp_path, capsys):
    output = tmp_path / "export"
    export_bundle(ROOT / "examples/demo_bundle", output)
    original = output / "ocsf.jsonl"
    external = tmp_path / "outside.jsonl"
    original.rename(external)
    original.symlink_to(external)
    with pytest.raises(SystemExit) as error:
        main(["verify-ocsf", str(output)])
    assert error.value.code == 2
    assert "escapes root" in capsys.readouterr().err
