import copy
import json
from pathlib import Path

import pytest

from timeline_demo.core.manifest import verify_bundle, write_manifest
from timeline_demo.parsers.common import compact_json, file_hash
from timeline_demo.signing import (
    enforce_signature,
    generate_keypair,
    load_trust,
    main,
    public_entry,
    sign_artifact,
    verify_signature,
    write_trust,
)

PASSWORD = b"synthetic-test-password-only"


@pytest.fixture
def signer(tmp_path):
    keys = generate_keypair(tmp_path / "keys", PASSWORD)
    key_id, entry = public_entry(keys["public_key"])
    trust = tmp_path / "trust.json"
    receipt = write_trust(trust, {"version": "1.0", "keys": {key_id: entry}})
    return {
        **keys,
        "trust": trust,
        "pin": receipt["trust_store_sha256"],
        "signature": tmp_path / "bundle.sig.json",
    }


def signed(bundle, signer):
    return sign_artifact(
        bundle, signer["private_key"], PASSWORD, signer["signature"], signer["trust"], signer["pin"]
    )


def verify(bundle, signer, **kwargs):
    return verify_signature(bundle, signer["signature"], signer["trust"], signer["pin"], **kwargs)


def test_signing_encrypts_keys_preserves_bundle_and_replays(bundle, signer, tmp_path):
    before = file_hash(bundle / "audit_manifest.json")
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in Path(signer["private_key"]).read_bytes()
    signed(bundle, signer)
    report = verify(bundle, signer)
    assert report["status"] == "trusted_signature_verified"
    assert report["key_id"] == signer["key_id"]
    assert report["trusted_timestamp"] is False
    assert file_hash(bundle / "audit_manifest.json") == before
    another = tmp_path / "another.sig.json"
    sign_artifact(bundle, signer["private_key"], PASSWORD, another, signer["trust"], signer["pin"])
    assert another.read_bytes() == signer["signature"].read_bytes()
    with pytest.raises(FileExistsError):
        signed(bundle, signer)
    with pytest.raises(FileExistsError):
        generate_keypair(tmp_path / "keys", PASSWORD)


@pytest.mark.parametrize(
    "fault",
    ["signature", "algorithm", "kind", "unknown_key", "manifest", "pin", "trust", "file", "duplicate_json"],
)
def test_tamper_and_wrong_trust_rejected(bundle, signer, fault):
    signed(bundle, signer)
    doc = json.loads(signer["signature"].read_text())
    if fault in {"signature", "algorithm", "kind", "unknown_key"}:
        field, value = {
            "signature": ("signature", "A" * 86 + "=="),
            "algorithm": ("algorithm", "RSA"),
            "kind": ("kind", "ocsf-export"),
            "unknown_key": ("key_id", "0" * 64),
        }[fault]
        doc[field] = value
        signer["signature"].write_text(json.dumps(doc))
    elif fault == "manifest":
        # Replacing both artifacts and an unsigned manifest still cannot replace the signature.
        manifest = verify_bundle(bundle)
        (bundle / "timeline.csv").write_text("replaced\n")
        metadata = {k: v for k, v in manifest.items() if k not in {"bundle_id", "files", "manifest_version"}}
        write_manifest(metadata, bundle)
        verify_bundle(bundle)
    elif fault == "pin":
        signer["pin"] = "0" * 64
    elif fault == "trust":
        signer["trust"].write_text(signer["trust"].read_text() + " ")
    elif fault == "duplicate_json":
        text = signer["signature"].read_text().rstrip()
        signer["signature"].write_text(text[:-1] + ',"algorithm":"Ed25519"}')
    else:
        (bundle / "timeline.jsonl").write_text("changed\n")
    with pytest.raises(ValueError):
        verify(bundle, signer)


def test_rotation_verification_only_and_revocation(bundle, signer, tmp_path):
    signed(bundle, signer)
    policy = load_trust(signer["trust"], signer["pin"])
    second = generate_keypair(tmp_path / "next-key", PASSWORD)
    new_id, entry = public_entry(second["public_key"])
    policy["keys"][new_id] = entry
    policy["keys"][signer["key_id"]]["status"] = "verify_only"
    next_trust = tmp_path / "trust-v2.json"
    pin = write_trust(next_trust, policy)["trust_store_sha256"]
    assert verify_signature(bundle, signer["signature"], next_trust, pin)["key_status"] == "verify_only"
    with pytest.raises(ValueError, match="active"):
        sign_artifact(bundle, signer["private_key"], PASSWORD, tmp_path / "retired.sig", next_trust, pin)
    next_sig = tmp_path / "next.sig"
    sign_artifact(bundle, second["private_key"], PASSWORD, next_sig, next_trust, pin)
    assert verify_signature(bundle, next_sig, next_trust, pin)["key_id"] == new_id
    policy["keys"][signer["key_id"]]["status"] = "revoked"
    revoked = tmp_path / "trust-v3.json"
    revoked_pin = write_trust(revoked, policy)["trust_store_sha256"]
    with pytest.raises(ValueError, match="revoked"):
        verify_signature(bundle, signer["signature"], revoked, revoked_pin)
    assert verify_signature(bundle, next_sig, revoked, revoked_pin)["key_id"] == new_id


def test_ocsf_signatures_bind_kind_and_source(bundle, signer, tmp_path):
    from timeline_demo.ocsf import export_bundle

    target = tmp_path / "ocsf"
    export_bundle(bundle, target)
    sign_artifact(
        target,
        signer["private_key"],
        PASSWORD,
        signer["signature"],
        signer["trust"],
        signer["pin"],
        kind="ocsf-export",
        source_bundle=bundle,
    )
    assert verify_signature(
        target, signer["signature"], signer["trust"], signer["pin"], kind="ocsf-export", source_bundle=bundle
    )["artifact_id"] == file_hash(target / "export_manifest.json")
    with pytest.raises(ValueError):
        verify(bundle, signer)


@pytest.mark.parametrize(
    "fault", ["inside", "symlink", "missing_pin", "missing_signature", "wrong_password", "scope"]
)
def test_required_signature_boundaries(bundle, signer, tmp_path, fault):
    signed(bundle, signer)
    if fault == "inside":
        with pytest.raises(ValueError):
            sign_artifact(
                bundle, signer["private_key"], PASSWORD, bundle / "bad.sig", signer["trust"], signer["pin"]
            )
    elif fault == "symlink":
        pointer = tmp_path / "pointer.sig"
        pointer.symlink_to(signer["signature"])
        with pytest.raises(ValueError):
            verify_signature(bundle, pointer, signer["trust"], signer["pin"])
    elif fault in {"missing_pin", "missing_signature"}:
        with pytest.raises(ValueError):
            enforce_signature(
                bundle,
                require_signature=True,
                signature=signer["signature"] if fault == "missing_pin" else None,
                trust_store=signer["trust"],
            )
    elif fault == "wrong_password":
        with pytest.raises(ValueError, match="decrypt"):
            sign_artifact(
                bundle,
                signer["private_key"],
                b"wrong-password",
                tmp_path / "bad.sig",
                signer["trust"],
                signer["pin"],
            )
    else:
        policy = load_trust(signer["trust"], signer["pin"])
        policy["keys"][signer["key_id"]]["allowed_kinds"] = ["ocsf-export"]
        restricted = tmp_path / "restricted.json"
        pin = write_trust(restricted, policy)["trust_store_sha256"]
        with pytest.raises(ValueError, match="authorized"):
            verify_signature(bundle, signer["signature"], restricted, pin)


def test_trust_cli_is_versioned_and_prevents_revoked_reactivation(signer, tmp_path, capsys):
    new = tmp_path / "revoked.json"
    args = [
        "trust-status",
        "--trust-store",
        str(signer["trust"]),
        "--trust-store-sha256",
        signer["pin"],
        "--key-id",
        signer["key_id"],
        "--status",
        "revoked",
        "--output",
        str(new),
    ]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["trust_store_sha256"] == file_hash(new)
    with pytest.raises(SystemExit):
        main(
            [
                "trust-status",
                "--trust-store",
                str(new),
                "--trust-store-sha256",
                file_hash(new),
                "--key-id",
                signer["key_id"],
                "--status",
                "active",
                "--output",
                str(tmp_path / "reactivated.json"),
            ]
        )
    assert not (tmp_path / "reactivated.json").exists()


def test_databricks_gates_run_before_any_spark_writes(bundle, signer):
    from timeline_demo.integrations.databricks import (
        publish_bundle,
        publish_ocsf_export,
        job_signature_options,
    )

    with pytest.raises(ValueError, match="required"):
        publish_bundle(None, bundle, "main", "ir", require_signature=True)
    with pytest.raises(ValueError, match="required"):
        publish_ocsf_export(None, bundle, bundle, "main", "ir", require_signature=True)
    with pytest.raises(ValueError, match="complete"):
        job_signature_options(bundle, file_hash(bundle / "audit_manifest.json"), "true", "", "", "")
    assert job_signature_options(bundle, file_hash(bundle / "audit_manifest.json"), "false", "", "", "") == {}


def test_signature_upload_checks_replay_and_conflicts(bundle, signer):
    from test_integrations import FakeWorkspace
    from timeline_demo.integrations.databricks import DatabricksClient

    signed(bundle, signer)
    workspace = FakeWorkspace()
    client = DatabricksClient(workspace)
    remote = client.upload_signature(
        bundle, signer["signature"], "/Volumes/main/ir/signatures", signer["trust"], signer["pin"]
    )
    assert remote.endswith(verify_bundle(bundle)["bundle_id"] + ".sig.json")
    assert (
        client.upload_signature(
            bundle, signer["signature"], "/Volumes/main/ir/signatures", signer["trust"], signer["pin"]
        )
        == remote
    )
    workspace.files.uploads[remote] = b"altered"
    with pytest.raises(ValueError, match="conflicts"):
        client.upload_signature(
            bundle, signer["signature"], "/Volumes/main/ir/signatures", signer["trust"], signer["pin"]
        )


def test_policy_rejects_key_substitution(signer, tmp_path):
    policy = load_trust(signer["trust"], signer["pin"])
    changed = copy.deepcopy(policy)
    entry = changed["keys"].pop(signer["key_id"])
    changed["keys"]["0" * 64] = entry
    path = tmp_path / "substituted.json"
    path.write_text(compact_json(changed))
    with pytest.raises(ValueError, match="fingerprint"):
        load_trust(path, file_hash(path))


def test_deployment_policy_is_fixed_and_derives_sidecar_from_verified_identity(bundle, signer, monkeypatch):
    import yaml
    from timeline_demo.integrations.databricks import job_signature_options

    cfg = yaml.safe_load((Path(__file__).resolve().parents[1] / "databricks.yml").read_text())
    job = cfg["resources"]["jobs"]["publish_timeline"]
    assert {p["name"] for p in job["parameters"]} == {"bundle_path", "manifest_sha256"}
    for task in job["tasks"]:
        parameters = task["python_wheel_task"]["parameters"]
        assert "${var.trust_store_sha256}" in parameters
        assert "${var.require_signature}" in parameters
        assert "notebook_task" not in task
        dynamic = [value for value in parameters if "{{job.parameters." in value]
        assert set(dynamic) == {"{{job.parameters.bundle_path}}", "{{job.parameters.manifest_sha256}}"}
    calls = []
    monkeypatch.setattr("timeline_demo.signing.enforce_signature", lambda *a, **kw: calls.append(kw))
    result = job_signature_options(
        bundle,
        file_hash(bundle / "audit_manifest.json"),
        "true",
        "/Volumes/main/ir/signatures",
        "/Volumes/main/ir/trust/policy.json",
        signer["pin"],
    )
    assert result["signature"].endswith("/" + verify_bundle(bundle)["bundle_id"] + ".sig.json")
    assert calls[0]["trust_store_sha256"] == signer["pin"]


def test_main_verify_requires_signature_when_configured(bundle, signer, capsys):
    from timeline_demo.cli import main as timeline

    with pytest.raises(SystemExit) as caught:
        timeline(["verify", str(bundle), "--require-signature"])
    assert caught.value.code == 2
    signed(bundle, signer)
    assert (
        timeline(
            [
                "verify",
                str(bundle),
                "--require-signature",
                "--signature",
                str(signer["signature"]),
                "--trust-store",
                str(signer["trust"]),
                "--trust-store-sha256",
                signer["pin"],
            ]
        )
        == 0
    )
    assert (
        json.loads(capsys.readouterr().out)["signature_verification"]["status"]
        == "trusted_signature_verified"
    )


def test_oversized_sidecars_and_invalid_policy_status_fail(bundle, signer, tmp_path):
    signed(bundle, signer)
    signer["signature"].write_bytes(b" " * 8193)
    with pytest.raises(ValueError, match="size limit"):
        verify(bundle, signer)
    policy = load_trust(signer["trust"], signer["pin"])
    policy["keys"][signer["key_id"]]["status"] = []
    bad = tmp_path / "bad-policy.json"
    bad.write_text(compact_json(policy))
    with pytest.raises(ValueError, match="status"):
        load_trust(bad, file_hash(bad))


def test_keys_use_owner_only_permissions_on_posix(signer):
    import os
    import stat

    if os.name == "posix":
        assert stat.S_IMODE(Path(signer["private_key"]).stat().st_mode) == 0o600
        assert stat.S_IMODE(Path(signer["private_key"]).parent.stat().st_mode) == 0o700


def test_disabled_export_entry_does_not_initialize_spark(capsys):
    from timeline_demo.integrations.databricks import ocsf_job_main, run_ocsf_job

    assert run_ocsf_job(None, None, None, None, None, None)["status"] == "skipped"
    assert (
        ocsf_job_main(
            [
                "--bundle-path",
                "",
                "--manifest-sha256",
                "",
                "--catalog",
                "",
                "--schema",
                "",
                "--enabled",
                "false",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "skipped"
    with pytest.raises(ValueError, match="true or false"):
        run_ocsf_job(None, None, None, None, None, None, enabled="yes")
