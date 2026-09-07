"""Native boundary, loss accounting and every registered export identity."""

import copy
import csv
import json
import os
from pathlib import Path

import pytest

from timeline_demo.cli import main
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.integrations.plaso import (
    DockerBackend,
    NativeLimits,
    WARNING_TYPES,
    catalog,
    check_inventory,
    ingest_native,
)
from timeline_demo.parsers.common import compact_json, file_hash, sha256_of_text
from timeline_demo.parsers.plaso_events import L2T_FIELDS
from timeline_demo.parsers.registry import normalize_record, parse_file
from timeline_demo.pipeline import Input, Limits, read_timeline, run_pipeline

SAMPLE = json.loads((Path(__file__).resolve().parents[1] / "examples/parser_samples.json").read_text())[
    "plaso_event"
]


def census():
    value = catalog()
    return {
        "version": value["upstream_version"],
        "dependencies_validated": True,
        "native_dependency_versions": value["native_dependency_versions"],
        "entries": [e["id"] for e in value["entries"]],
        "source_hashes": value["source_hashes"],
    }


class Backend:
    def __init__(self, events=None, warnings=None, stored=None, broken_census=False):
        self.events = [copy.deepcopy(SAMPLE)] if events is None else events
        self.stats = {
            "events": len(self.events) if stored is None else stored,
            "warnings": dict.fromkeys(WARNING_TYPES, 0),
            "sessions": [{"aborted": False, "completion_time": 1788256800000000}],
        }
        self.stats["warnings"].update(warnings or {})
        self.broken_census = broken_census
        self.commands = []

    def resolve(self):
        return "sha256:" + "a" * 64

    def run(self, phase, runtime, source, entrypoint, args, limits):
        self.commands.append((phase, entrypoint, args))
        path = runtime / (phase + ".stdout")
        if phase == "inventory":
            value = census()
            if self.broken_census:
                value["entries"].pop()
            path.write_text(json.dumps(value))
        elif phase == "statistics":
            path.write_text(json.dumps(self.stats))
        else:
            path.write_text("")
            if phase == "extract":
                (runtime / "collection.plaso").write_bytes(b"synthetic-storage")
            else:
                (runtime / "events.jsonl").write_text("".join(compact_json(e) + "\n" for e in self.events))
        return path


def source(tmp_path):
    path = tmp_path / "acquired.bin"
    path.write_bytes(b"original artifact")
    return path


def test_inventory_is_complete_and_backend_must_match(capsys):
    assert check_inventory(census()) == {"parser": 59, "plugin": 186, "cookie_plugin": 4}
    assert len(catalog()["data_types"]) == 285
    assert main(["plaso-parsers"]) == 0
    assert json.loads(capsys.readouterr().out)["upstream_commit"] == catalog()["upstream_commit"]
    for key, bad in [("version", "old"), ("entries", []), ("source_hashes", {})]:
        value = census()
        value[key] = bad
        with pytest.raises(ValueError, match="inventory"):
            check_inventory(value)


@pytest.mark.parametrize("entry", catalog()["entries"], ids=lambda e: e["id"])
def test_every_registered_parser_identity_survives_projection(entry):
    # Contract coverage, not a claim that a synthetic event exercises a binary parser.
    raw = {**SAMPLE, "parser": entry["id"], "vendor_extension": {"nested": [1, "value"]}}
    original = copy.deepcopy(raw)
    event = normalize_record(raw, "plaso_event", "raw", "a" * 64, 1)[0]
    assert raw == original
    assert event["metadata"]["plaso"]["parser_chain"] == entry["id"]
    assert event["raw_data_hash"] == sha256_of_text(compact_json(raw))


@pytest.mark.parametrize("data_type", catalog()["data_types"])
def test_every_declared_data_type_is_importable_without_guessing(data_type):
    raw = {**SAMPLE, "data_type": data_type, "timestamp": 1788256800000123}
    event = normalize_record(raw, "plaso_event", "raw", "a" * 64, 1)[0]
    assert event["metadata"]["plaso"]["data_type"] == data_type
    assert event["metadata"]["plaso"]["timestamp_microseconds"] == "1788256800000123"
    if data_type not in {"fs:stat", "fs:stat:ntfs", "fs:ntfs:usn_change"}:
        assert event["ocsf_class_uid"] == 0


def test_json_dynamic_and_l2tcsv_exports(tmp_path):
    dynamic = tmp_path / "dynamic.csv"
    dynamic.write_text('Datetime,message,parser\n2026-09-01T10:00:00Z,"file, modified",filestat\n')
    assert parse_file(dynamic, "plaso_event")[0]["epoch_ms"] == 1788256800000
    path = tmp_path / "legacy.csv"

    def write(zone="UTC", date="09/01/2026", clock="10:00:00.000123"):
        row = dict.fromkeys(sorted(L2T_FIELDS), "-")
        row.update(
            date=date,
            time=clock,
            timezone=zone,
            desc="file, modified",
            format="filestat",
            type="Modification Time",
        )
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=sorted(L2T_FIELDS))
            writer.writeheader()
            writer.writerow(row)

    write()
    event = parse_file(path, "plaso_event")[0]
    assert event["epoch_ms"] == 1788256800000
    assert event["metadata"]["plaso"]["export_format"] == "l2tcsv"
    write("-04:00", clock="06:00:00")
    assert parse_file(path, "plaso_event")[0]["epoch_ms"] == 1788256800000
    write("CST")
    with pytest.raises(ValueError, match="assume-timezone"):
        parse_file(path, "plaso_event")
    assert (
        parse_file(path, "plaso_event", assume_timezone="Asia/Shanghai")[0]["timezone_assumption"]
        == "Asia/Shanghai"
    )
    write("EST", "11/01/2026", "01:30:00")
    with pytest.raises(ValueError, match="ambiguous"):
        parse_file(path, "plaso_event", assume_timezone="America/New_York")


def test_semantic_time_is_quarantined_without_fabricating_epoch(tmp_path):
    raw = {**SAMPLE, "timestamp": 0, "date_time": {"__class_name__": "NotSet"}}
    path = tmp_path / "events.jsonl"
    path.write_text(compact_json(raw) + "\n")
    with pytest.raises(ValueError, match="semantic"):
        parse_file(path, "plaso_event")
    report = run_pipeline([Input("plaso_event", path)], tmp_path / "bundle", "case", quarantine=True)
    assert report["counts"]["quarantined_records"] == 1
    assert report["counts"]["event_count"] == 0
    assert (tmp_path / "bundle" / report["inputs"][0]["evidence_path"]).read_bytes() == path.read_bytes()


def test_native_bridge_archives_evidence_and_checks_every_parser(tmp_path):
    backend = Backend([SAMPLE, SAMPLE])
    original = source(tmp_path)
    result = ingest_native(
        original, tmp_path / "work", tmp_path / "bundle", "case", backend=backend, year=2026
    )
    manifest = verify_bundle(tmp_path / "bundle")
    assert result["status"] == "completed" and result["model_tokens"] == 0
    assert manifest["counts"]["event_count"] == 1  # duplicate occurrence remains in receipts/raw
    assert json.loads((tmp_path / "work/receipt.json").read_text())["exported_records"] == 2
    assert (
        tmp_path / "bundle/attachments/plaso/sources" / file_hash(original)
    ).read_bytes() == original.read_bytes()
    assert (tmp_path / "bundle/attachments/plaso/collection.plaso").read_bytes() == b"synthetic-storage"
    args = next(args for phase, _, args in backend.commands if phase == "extract")
    assert "--preferred-year=2026" in args
    selected = next(a for a in args if a.startswith("--parsers=")).split("=", 1)[1].split(",")
    assert set(selected) == {e["name"] for e in catalog()["entries"] if e["kind"] == "parser"}
    assert "--include-all" in backend.commands[-1][2]
    event = list(read_timeline(tmp_path / "bundle"))[0]
    assert event["metadata"]["plaso"]["host_filestat"] is True


@pytest.mark.parametrize("warning", WARNING_TYPES)
def test_upstream_warnings_block_publication_unless_explicit(tmp_path, warning):
    original = source(tmp_path)
    with pytest.raises(ValueError, match="warnings"):
        ingest_native(
            original,
            tmp_path / "strict-work",
            tmp_path / "strict",
            "case",
            backend=Backend(warnings={warning: 1}),
        )
    assert not (tmp_path / "strict").exists()
    assert (tmp_path / "strict-work/failure.json").exists()
    result = ingest_native(
        original,
        tmp_path / "work",
        tmp_path / "bundle",
        "case",
        backend=Backend(warnings={warning: 1}),
        allow_partial=True,
    )
    assert result["status"] == "partial"


@pytest.mark.parametrize(
    "backend, message", [(Backend(stored=2), "count differs"), (Backend(broken_census=True), "inventory")]
)
def test_incomplete_export_or_inventory_never_publishes(tmp_path, backend, message):
    with pytest.raises(ValueError, match=message):
        ingest_native(
            source(tmp_path),
            tmp_path / "work",
            tmp_path / "bundle",
            "case",
            backend=backend,
            allow_partial=True,
        )
    assert not (tmp_path / "bundle").exists()


def test_existing_storage_and_colon_artifact_names(tmp_path):
    original = source(tmp_path)
    backend = Backend()
    ingest_native(
        original, tmp_path / "import-work", tmp_path / "import", "case", backend=backend, storage_file=True
    )
    assert "extract" not in [phase for phase, _, _ in backend.commands]
    acquired = tmp_path / "directory"
    acquired.mkdir()
    (acquired / "$UsnJrnl:$J").write_bytes(b"journal")
    ingest_native(acquired, tmp_path / "work", tmp_path / "bundle", "case", backend=Backend())
    assert json.loads((tmp_path / "work/source_inventory.json").read_text())[0]["path"] == "$UsnJrnl:$J"


def test_source_links_and_budgets_are_rejected(tmp_path):
    original = source(tmp_path)
    with pytest.raises(ValueError, match="byte budget"):
        ingest_native(
            original,
            tmp_path / "bytes-work",
            tmp_path / "bytes-bundle",
            "case",
            backend=Backend(),
            native_limits=NativeLimits(max_source_bytes=1),
        )
    with pytest.raises(ValueError, match="event count"):
        ingest_native(
            original,
            tmp_path / "count-work",
            tmp_path / "count-bundle",
            "case",
            backend=Backend([SAMPLE, SAMPLE]),
            limits=Limits(max_records=1),
        )
    directory = tmp_path / "directory"
    directory.mkdir()
    (directory / "linked").symlink_to(original)
    with pytest.raises(ValueError, match="links"):
        ingest_native(directory, tmp_path / "work", tmp_path / "bundle", "case", backend=Backend())


def test_docker_uses_immutable_id_no_shell_network_or_writable_evidence(tmp_path, monkeypatch):
    backend = DockerBackend()
    backend.image_id = "sha256:" + "b" * 64
    command = backend.command(
        "test",
        tmp_path / "runtime",
        tmp_path / "source",
        "python3",
        ["probe.py", "inventory"],
        NativeLimits(),
    )
    assert "--network=none" in command and "--read-only" in command and "--pull=never" in command
    assert "--cap-drop=ALL" in command and "--security-opt=no-new-privileges" in command
    assert command[command.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert command[-3] == backend.image_id
    assert any(v.endswith("dst=/source,readonly") for v in command)
    with pytest.raises(ValueError, match="mount paths"):
        backend.command("test", tmp_path / "comma,path", tmp_path, "python3", [], NativeLimits())


def test_split_image_entry_point_preserves_companions_and_rejects_escape(tmp_path):
    directory = tmp_path / "split"
    directory.mkdir()
    (directory / "image.E01").write_bytes(b"first segment")
    (directory / "image.E02").write_bytes(b"second segment")
    backend = Backend()
    ingest_native(
        directory, tmp_path / "work", tmp_path / "bundle", "case", backend=backend, entry_point="image.E01"
    )
    assert next(args for phase, _, args in backend.commands if phase == "extract")[-1] == "/source/image.E01"
    assert (tmp_path / "work/source/image.E02").read_bytes() == b"second segment"
    with pytest.raises(ValueError, match="entry point"):
        ingest_native(
            directory,
            tmp_path / "unsafe-work",
            tmp_path / "unsafe",
            "case",
            backend=Backend(),
            entry_point="../image.E01",
        )
