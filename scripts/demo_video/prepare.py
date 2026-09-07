"""Execute the offline demonstration and save auditable, synthetic-only results."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from timeline_demo.ai import Harness, load_policy
from timeline_demo.collection import collect_window
from timeline_demo.collection.providers import Page
from timeline_demo.operations import backup, health, prometheus, restore
from timeline_demo.parsers.common import file_hash
from timeline_demo.pipeline import Input, read_timeline, run_pipeline
from timeline_demo.signing import (
    generate_keypair, public_entry, sign_artifact, verify_signature, write_trust,
)


def main():
    root = Path(__file__).resolve().parents[2]
    output = root / "output/demo-video/results"
    output.mkdir(parents=True, exist_ok=False)
    log = []

    def cli(*args, failure=False):
        executable = Path(sys.executable).parent / "timeline"
        run = subprocess.run([str(executable), *map(str, args)], cwd=root,
                             capture_output=True, text=True, timeout=120)
        log.append({"argv": ["timeline", *map(str, args)], "exit_code": run.returncode,
                    "stdout": run.stdout, "stderr": run.stderr})
        if failure:
            assert run.returncode != 0
            return run.stderr.strip()
        run.check_returncode()
        return json.loads(run.stdout)

    relative = "output/demo-video/results/bundle"
    manifest = cli("ingest", "--case-id", "demo-013",
                   "--input", "cloudtrail=examples/raw/aws/cloudtrail_real_sample.json",
                   "--input", "entra_signin=examples/raw/entra/entra_signin_real_sample.jsonl",
                   "--input", "crowdstrike_detection=examples/raw/edr/crowdstrike_detection_real_sample.json",
                   "--output", relative, "--parquet")
    assert manifest["counts"]["event_count"] == 5
    bundle = root / relative
    checked = cli("verify", relative)
    assert checked["bundle_id"] == manifest["bundle_id"]
    ocsf_path = "output/demo-video/results/ocsf"
    ocsf = cli("export-ocsf", relative, "--output", ocsf_path)
    cli("verify-ocsf", ocsf_path, "--bundle", relative)
    plan = cli("analyze", relative, "--task", "summarize")
    tines = cli("tines-request", relative, "--remote-bundle",
                "/Volumes/main/incident_timelines/evidence/" + manifest["bundle_id"], "--job-id", 1)
    parsers = cli("parsers")
    catalog = cli("plaso-parsers")
    assert len(parsers) == 28

    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        altered = work / "altered"
        shutil.copytree(bundle, altered)
        with (altered / "timeline.jsonl").open("a") as f:
            f.write("\n")
        tamper = cli("verify", altered, failure=True)

        password = b"temporary-synthetic-demo-key-only"
        keys = generate_keypair(work / "keys", password)
        key_id, entry = public_entry(keys["public_key"])
        policy = {"version": "1.0", "keys": {key_id: entry}}
        trust = work / "trust.json"
        pin = write_trust(trust, policy)["trust_store_sha256"]
        signature = work / "bundle.sig.json"
        source_pin = file_hash(bundle / "audit_manifest.json")
        sign_artifact(bundle, keys["private_key"], password, signature, trust, pin)
        active = verify_signature(bundle, signature, trust, pin)
        policy["keys"][key_id]["status"] = "verify_only"
        retired = work / "retired.json"
        retired_pin = write_trust(retired, policy)["trust_store_sha256"]
        retired_result = verify_signature(bundle, signature, retired, retired_pin)
        policy["keys"][key_id]["status"] = "revoked"
        revoked = work / "revoked.json"
        revoked_pin = write_trust(revoked, policy)["trust_store_sha256"]
        try:
            verify_signature(bundle, signature, revoked, revoked_pin)
        except ValueError as error:
            revoked_error = str(error)
        else:
            raise AssertionError("Revoked signature accepted")
        assert file_hash(bundle / "audit_manifest.json") == source_pin

        class Source:
            parser = "entra_signin"
            identity = {"source": "entra_signin", "source_id": "synthetic-recovery"}
            interval = 0

            def __init__(self, pages):
                self.pages, self.calls = iter(pages), 0

            def fetch(self, *args):
                self.calls += 1
                return next(self.pages)

        arguments = (work / "state", work / "collected", "recovery-demo",
                     "2026-09-01T10:00:00Z", "2026-09-01T11:00:00Z")
        first = Source([Page(b'{"value":[]}', [], {"next": 2})])
        try:
            collect_window(first, *arguments, max_pages=1)
        except ValueError as error:
            assert "page budget" in str(error)
            paused = str(error)
        else:
            raise AssertionError("Page budget did not pause acquisition")
        assert not arguments[1].exists()
        snapshot = backup(work / "state", work / "snapshot")
        restore(work / "snapshot", work / "restored", snapshot["snapshot_sha256"])
        second = Source([Page(b'{"value":[]}', [], None)])
        resumed = collect_window(second, work / "restored", *arguments[1:])
        report = health(work / "restored", verify_blobs=True, verify_bundles=True)
        assert report["healthy"] and second.calls == 1
        (output / "metrics.prom").write_text(prometheus(report))

        # Contract-only fixture: this is deliberately not presented as model output.
        import runpy
        fake = runpy.run_path(str(root / "tests/test_ai.py"))["FakeClient"]()
        harness = Harness(work / "analysis.sqlite", client=fake)
        first_analysis = harness.run(bundle, allow_ai=True)
        cached = harness.run(bundle, allow_ai=True)
        assert len(fake.calls) == 1 and cached["tokens_used_this_call"] == 0
        assert first_analysis["human_review_required"]

        samples = json.loads((root / "examples/parser_samples.json").read_text())
        inputs = []
        for name in ("github_audit", "kubernetes_audit", "plaso"):
            source = work / (name + ".jsonl")
            source.write_text(json.dumps(samples[name]) + "\n")
            inputs.append(Input(name, source))
        developer = work / "developer"
        run_pipeline(inputs, developer, "synthetic-developer-and-native-export")
        developer_events = [{key: event[key] for key in
                             ("source_name", "time_utc", "activity_name", "ocsf_class_uid")}
                            for event in read_timeline(developer)]

    configurations = [json.loads(p.read_text()) for p in (root / "examples/collectors").glob("*.json")]
    collectors = sorted({c["source"] for c in configurations})
    assert len(collectors) == 19
    data = {
        "release": "0.13.0", "feature_base_commit": "274fa8d037badafffbbf467b4d1ebd780a1166d9",
        "build_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "synthetic_only": True, "live_cloud_connections": False, "paid_model_calls": 0,
        "manifest": manifest, "ocsf": ocsf, "plan": plan, "tines_request": tines,
        "parsers": parsers, "collectors": collectors, "plaso": catalog,
        "tamper_error": tamper, "models": load_policy(), "developer_events": developer_events,
        "signing": {"active": active["key_status"], "retired": retired_result["key_status"],
                    "revoked_error": revoked_error, "bundle_unchanged": True},
        "recovery": {"pause_reason": paused, "resumed_fetches": second.calls,
                     "snapshot_verified": True, "health": report,
                     "model_tokens": resumed["collection"]["model_tokens"]},
        "cache_contract": {"provider": "offline test double", "calls": len(fake.calls),
                           "cache_hit": cached["cache_hit"], "repeat_tokens": cached["tokens_used_this_call"]},
        "notebooks": sorted(p.name for p in (root / "notebooks").glob("*.ipynb")),
    }
    assert len(data["notebooks"]) == 10
    (output / "recordings.json").write_text(json.dumps(data, indent=2) + "\n")
    (output / "commands.json").write_text(json.dumps(log, indent=2) + "\n")
    print(json.dumps({"events": 5, "parsers": len(parsers), "collectors": len(collectors),
                      "notebooks": 10, "tamper_rejected": True, "recovery_healthy": report["healthy"],
                      "paid_model_calls": 0}))


if __name__ == "__main__":
    main()
