import json
import os
import sqlite3
import time
from pathlib import Path

import pytest

from timeline_demo.ai import Harness
from timeline_demo.collection import collect_window
from timeline_demo.collection.providers import Page
from timeline_demo.core.manifest import safe_member, verify_bundle, write_manifest
from timeline_demo.operations import backup, health, main, prometheus, restore
from timeline_demo.parsers.common import compact_json, file_hash, sha256_of_text
from timeline_demo.pipeline import Input, Limits, run_pipeline
from timeline_demo.signing import generate_keypair, public_entry, sign_artifact, write_trust
from timeline_demo.viewer import authorized_cases, load_access_policy, open_case


def rewrite(bundle, mutate):
    path = bundle / "audit_manifest.json"
    value = json.loads(path.read_text())
    mutate(value)
    value.pop("bundle_id")
    value["bundle_id"] = sha256_of_text(compact_json(value))
    path.write_text(compact_json(value))


@pytest.mark.parametrize("name", [".", "a/./b", "a//b", "a/", "C:secret", "a\x00b", 42])
def test_noncanonical_members_rejected(tmp_path, name):
    with pytest.raises(ValueError):
        safe_member(tmp_path, name)


@pytest.mark.parametrize("size", [True, -1, "0", 0.0])
def test_manifest_size_types_rejected(bundle, size):
    rewrite(bundle, lambda v: v["files"]["quarantine.jsonl"].update(bytes=size))
    with pytest.raises(ValueError, match="file entry"):
        verify_bundle(bundle)


def test_duplicate_manifest_keys_rejected(bundle):
    path = bundle / "audit_manifest.json"
    path.write_text(path.read_text().rstrip()[:-1] + ',"manifest_version":"2.0"}')
    with pytest.raises(ValueError, match="duplicate JSON"):
        verify_bundle(bundle)


@pytest.mark.skipif(os.name != "posix", reason="POSIX special files")
def test_fifo_and_unlisted_empty_directory_link_never_opened(bundle, tmp_path):
    os.mkfifo(bundle / "fifo")
    with pytest.raises(ValueError, match="special file"):
        verify_bundle(bundle)
    (bundle / "fifo").unlink()
    (bundle / "empty-link").symlink_to(tmp_path)
    with pytest.raises(ValueError, match="symlink|escapes root"):
        verify_bundle(bundle)


def test_nested_manifest_attachment_is_hashed(bundle):
    meta = verify_bundle(bundle)
    extra = bundle / "attachments/audit_manifest.json"
    extra.parent.mkdir()
    extra.write_text("synthetic")
    write_manifest({k: v for k, v in meta.items() if k not in {"files", "bundle_id"}}, bundle)
    assert "attachments/audit_manifest.json" in verify_bundle(bundle)["files"]


def test_bundle_parent_symlink_rejected(bundle, tmp_path):
    alias = tmp_path / "parent-alias"
    alias.symlink_to(tmp_path)
    with pytest.raises(ValueError, match="symlink"):
        verify_bundle(alias / "bundle")


@pytest.mark.parametrize("limit", ["max_records", "max_events", "max_input_bytes", "max_iocs", "max_inputs"])
def test_limits_abort_without_publishing(tmp_path, cloudtrail, limit):
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps([cloudtrail, cloudtrail]))
    kwargs = {limit: 1}
    with pytest.raises(ValueError, match="budget"):
        run_pipeline(
            [Input("cloudtrail", raw)] * 2, tmp_path / "out", "case", quarantine=True, limits=Limits(**kwargs)
        )
    assert not (tmp_path / "out").exists()


def test_private_outputs_and_ledger_symlink_rejection(bundle, tmp_path):
    if os.name == "posix":
        assert bundle.stat().st_mode & 0o777 == 0o700
        assert all(p.stat().st_mode & 0o777 == 0o600 for p in bundle.rglob("*") if p.is_file())
    link = tmp_path / "ledger.sqlite"
    link.symlink_to(bundle / "timeline.jsonl")
    with pytest.raises(ValueError, match="symlink"):
        Harness(link)
    with pytest.raises(ValueError, match="outside"):
        Harness(tmp_path / "a/../bundle/ledger.sqlite").run(bundle)


class Provider:
    parser = "entra_signin"
    identity = {"source": "entra_signin", "source_id": "synthetic"}
    interval = 0

    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = 0

    def fetch(self, *args):
        self.calls += 1
        return next(self.pages)


def page(cursor=None):
    rows = [{"id": "one", "createdDateTime": "2026-09-01T10:00:00Z"}]
    return Page(compact_json({"value": rows}).encode(), rows, cursor)


def collect(tmp_path, provider, *, state="state", **kwargs):
    return collect_window(
        provider,
        tmp_path / state,
        tmp_path / "bundle",
        "ops-case",
        "2026-09-01T10:00:00Z",
        "2026-09-01T11:00:00Z",
        **kwargs,
    )


def test_backup_restore_incomplete_and_resume_without_refetch(tmp_path):
    with pytest.raises(ValueError, match="page budget"):
        collect(tmp_path, Provider([page({"next": 2})]), max_pages=1)
    saved = backup(tmp_path / "state", tmp_path / "backup")
    restore(tmp_path / "backup", tmp_path / "restored", saved["snapshot_sha256"])
    provider = Provider([page()])
    collect(tmp_path, provider, state="restored")
    assert provider.calls == 1
    report = health(tmp_path / "restored", verify_blobs=True, verify_bundles=True)
    assert report["healthy"] and report["pages"] == 2 and report["published_runs"] == 1
    assert "timeline_collection_healthy 1" in prometheus(report)
    assert "synthetic" not in prometheus(report)


def test_completed_restore_verifies_external_bundles_and_replays(tmp_path):
    first = collect(tmp_path, Provider([page()]))
    saved = backup(tmp_path / "state", tmp_path / "backup")
    assert saved["published_bundles_included"] is False
    assert len(saved["published_bundles"]) == 1
    restore(tmp_path / "backup", tmp_path / "restored", saved["snapshot_sha256"])
    assert collect(tmp_path, Provider([]), state="restored") == first
    (tmp_path / "bundle/timeline.jsonl").write_text("tampered")
    with pytest.raises(ValueError):
        restore(tmp_path / "backup", tmp_path / "rejected", saved["snapshot_sha256"])
    assert not (tmp_path / "rejected").exists()


@pytest.mark.parametrize("fault", ["pin", "blob", "extra", "db", "link"])
def test_restore_rejects_tampering_and_never_overwrites(tmp_path, fault):
    collect(tmp_path, Provider([page()]))
    saved = backup(tmp_path / "state", tmp_path / "backup")
    root = tmp_path / "backup"
    pin = saved["snapshot_sha256"]
    if fault == "pin":
        pin = "0" * 64
    elif fault == "blob":
        next((root / "blobs").iterdir()).write_text("tampered")
    elif fault == "extra":
        (root / "extra").write_text("unlisted")
    elif fault == "db":
        (root / "collection.sqlite").write_bytes(b"not a database")
    else:
        (root / "link").symlink_to(tmp_path)
    with pytest.raises(ValueError):
        restore(root, tmp_path / "out", pin)
    assert not (tmp_path / "out").exists()
    with pytest.raises(ValueError, match="new directory"):
        restore(root, tmp_path / "state", pin)


def test_health_read_only_stale_and_missing(tmp_path, capsys):
    assert main(["health", "--state", str(tmp_path / "missing")]) == 2
    assert not (tmp_path / "missing").exists()
    collect(tmp_path, Provider([page()]))
    dbpath = tmp_path / "state/collection.sqlite"
    before = file_hash(dbpath)
    assert not health(tmp_path / "state", now=time.time() + 7200)["healthy"]
    assert file_hash(dbpath) == before
    assert main(["health", "--state", str(tmp_path / "state")]) == 0
    assert "healthy" in capsys.readouterr().out


@pytest.mark.parametrize("version", [None, "old-version"])
def test_incomplete_parser_upgrade_fails_before_network(tmp_path, version):
    with pytest.raises(ValueError):
        collect(tmp_path, Provider([page({"next": 2})]), max_pages=1)
    with sqlite3.connect(tmp_path / "state/collection.sqlite") as db:
        db.execute("UPDATE runs SET parser_version=?", (version,))
    provider = Provider([])
    with pytest.raises(ValueError, match="parser version"):
        collect(tmp_path, provider)
    assert provider.calls == 0


@pytest.fixture
def access(bundle, tmp_path):
    password = b"synthetic-password-only"
    keys = generate_keypair(tmp_path / "keys", password)
    key, entry = public_entry(keys["public_key"])
    trust = tmp_path / "trust.json"
    receipt = write_trust(trust, {"version": "1.0", "keys": {key: entry}})
    sig = tmp_path / "signature.json"
    sign_artifact(bundle, keys["private_key"], password, sig, trust, receipt["trust_store_sha256"])
    case = verify_bundle(bundle)["case_id"]
    policy = {
        "version": "1.0",
        "trust_store": str(trust),
        "trust_store_sha256": receipt["trust_store_sha256"],
        "principals": [{"issuer": "https://id.example.test", "subject": "analyst-1", "cases": [case]}],
        "cases": {
            case: {
                "bundle": str(bundle),
                "manifest_sha256": file_hash(bundle / "audit_manifest.json"),
                "signature": str(sig),
            }
        },
    }
    path = tmp_path / "access.json"
    path.write_text(compact_json(policy))
    return (
        load_access_policy(path, file_hash(path)),
        {"iss": "https://id.example.test", "sub": "analyst-1", "exp": time.time() + 300},
        case,
    )


def test_authorized_viewer_requires_case_pin_and_signature(access):
    policy, claims, case = access
    root, manifest, attestation = open_case(policy, claims, case)
    assert manifest["case_id"] == case and attestation["status"] == "trusted_signature_verified"
    Path(policy["cases"][case]["signature"]).unlink()
    with pytest.raises((ValueError, OSError)):
        open_case(policy, claims, case)


@pytest.mark.parametrize(
    "claim,value",
    [
        ("iss", "https://other.test"),
        ("sub", "other-user"),
        ("exp", 0),
        ("exp", "999999999999"),
        ("exp", float("nan")),
        ("exp", float("inf")),
    ],
)
def test_viewer_cross_tenant_subject_and_expiry_rejected(access, claim, value):
    policy, claims, _ = access
    with pytest.raises(PermissionError):
        authorized_cases(policy, {**claims, claim: value})


def test_viewer_cross_case_rejected_before_file_access(access):
    policy, claims, _ = access
    with pytest.raises(PermissionError):
        open_case(policy, claims, "unassigned-case")
