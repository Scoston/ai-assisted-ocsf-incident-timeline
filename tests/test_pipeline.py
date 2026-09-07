import json
import subprocess
import sys

import pytest
from timeline_demo.core.manifest import safe_member, verify_bundle
from timeline_demo.parsers.common import file_hash
from timeline_demo.pipeline import Input, read_timeline, run_pipeline


def test_bundle_pin_and_tampering(bundle):
    pin = file_hash(bundle / "audit_manifest.json")
    assert verify_bundle(bundle, pin)["counts"]["event_count"] == 1
    with pytest.raises(ValueError):
        verify_bundle(bundle, "0" * 64)
    with (bundle / "timeline.jsonl").open("a") as stream:
        stream.write("{}\n")
    with pytest.raises(ValueError, match="integrity"):
        verify_bundle(bundle)


def test_source_tamper_and_unlisted_file(bundle):
    manifest = verify_bundle(bundle)
    raw = bundle / manifest["inputs"][0]["evidence_path"]
    raw.write_text("changed")
    with pytest.raises(ValueError):
        verify_bundle(bundle)


def test_no_path_escape_or_symlinks(bundle, tmp_path):
    for name in ["../secret", "/etc/passwd", "evidence/../../secret", "a\\b"]:
        with pytest.raises(ValueError):
            safe_member(bundle, name)
    (bundle / "link").symlink_to(tmp_path)
    with pytest.raises(ValueError):
        safe_member(bundle, "link/file")


def test_reproducible_sorted_dedup_with_receipts(tmp_path, cloudtrail):
    raw = tmp_path / "input.json"
    later = {**cloudtrail, "eventTime": "2026-09-01T12:00:00Z"}
    raw.write_text(json.dumps([later, cloudtrail, cloudtrail]))
    a = run_pipeline([Input("cloudtrail", raw)], tmp_path / "a", "case-a")
    b = run_pipeline([Input("cloudtrail", raw)], tmp_path / "b", "case-a")
    assert a == b
    events = list(read_timeline(tmp_path / "a"))
    assert len(events) == 2 and events[0]["epoch_ms"] < events[1]["epoch_ms"]
    assert a["counts"]["duplicate_events"] == 1
    receipts = (tmp_path / "a/receipts.jsonl").read_text().splitlines()
    assert len(receipts) == 3
    with pytest.raises(FileExistsError):
        run_pipeline([Input("cloudtrail", raw)], tmp_path / "a", "case-a")


def test_cli_exit_status(bundle):
    result = subprocess.run(
        [sys.executable, "-m", "timeline_demo.cli", "verify", str(bundle)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "integrity_verified"


def test_csv_injection_and_parquet_output(tmp_path, cloudtrail):
    import pyarrow.parquet as pq

    p = tmp_path / "source.json"
    p.write_text(json.dumps({**cloudtrail, "eventName": '=HYPERLINK("bad")'}))
    out = tmp_path / "bundle"
    run_pipeline([Input("cloudtrail", p)], out, "case", parquet=True)
    assert list(read_timeline(out))[0]["activity_name"].startswith("=")
    assert "'=HYPERLINK" in (out / "timeline.csv").read_text()
    assert pq.read_table(out / "timeline.parquet").num_rows == 1
    verify_bundle(out)


def test_repeated_source_receipts_remain_distinct(tmp_path, cloudtrail):
    p = tmp_path / "source.json"
    p.write_text(json.dumps(cloudtrail))
    out = tmp_path / "bundle"
    run_pipeline([Input("cloudtrail", p)] * 3, out, "case")
    receipts = (out / "receipts.jsonl").read_text().splitlines()
    assert len(receipts) == len(set(receipts)) == 3
    assert [json.loads(line)["receipt_index"] for line in receipts] == [1, 2, 3]
