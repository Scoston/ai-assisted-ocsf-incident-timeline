from __future__ import annotations

import argparse
import json
from pathlib import Path

from timeline_demo.parsers.registry import SPECS


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evidence-preserving OCSF-aligned incident timelines")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("parsers", help="List supported parser contracts")
    for name in ("collect", "collect-until"):
        collector = commands.add_parser(name, help="Collect read-only audit records with durable checkpoints")
        collector.add_argument("--config", required=True)
        collector.add_argument("--state", required=True)
        collector.add_argument("--output", required=True)
        collector.add_argument("--case-id", required=True)
        collector.add_argument("--start", required=True)
        collector.add_argument("--end", required=True)
        collector.add_argument("--max-pages", type=int, default=100)
        collector.add_argument("--max-records", type=int, default=100000)
        collector.add_argument("--max-bytes", type=int, default=134217728)
        if name == "collect-until":
            collector.add_argument("--window-seconds", type=int, default=3600)
            collector.add_argument("--overlap-seconds", type=int, default=300)
            collector.add_argument("--max-windows", type=int, default=24)
    ingest = commands.add_parser("ingest", help="Build an offline evidence bundle")
    ingest.add_argument("--input", action="append", required=True, metavar="PARSER=PATH")
    ingest.add_argument("--case-id", required=True)
    ingest.add_argument("--output", required=True)
    ingest.add_argument("--quarantine", action="store_true")
    ingest.add_argument("--assume-timezone")
    ingest.add_argument("--parquet", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("bundle")
    verify.add_argument("--manifest-sha256")
    ocsf = commands.add_parser("export-ocsf", help="Export schema-validated core OCSF 1.3.0 events")
    ocsf.add_argument("bundle")
    ocsf.add_argument("--output", required=True)
    ocsf.add_argument("--quarantine", action="store_true")
    ocsf.add_argument("--manifest-sha256")
    ocsf_verify = commands.add_parser("verify-ocsf", help="Verify OCSF export hashes and event schemas")
    ocsf_verify.add_argument("directory")
    ocsf_verify.add_argument("--manifest-sha256")
    ocsf_verify.add_argument("--bundle")
    analyze = commands.add_parser("analyze", help="Plan analysis; --allow-ai sends a bounded request")
    analyze.add_argument("bundle")
    analyze.add_argument("--task", choices=["summarize", "correlate", "review"], default="summarize")
    analyze.add_argument("--ledger", default="analysis/usage.sqlite")
    analyze.add_argument("--policy")
    analyze.add_argument("--allow-ai", action="store_true")
    analyze.add_argument("--output")
    upload = commands.add_parser("databricks-upload")
    upload.add_argument("bundle")
    upload.add_argument("--volume-root", required=True)
    download = commands.add_parser("databricks-download")
    download.add_argument("--remote-bundle", required=True)
    download.add_argument("--output", required=True)
    download.add_argument("--manifest-sha256", required=True)
    submit = commands.add_parser("databricks-submit")
    submit.add_argument("bundle")
    submit.add_argument("--remote-bundle", required=True)
    submit.add_argument("--job-id", type=int, required=True)
    status = commands.add_parser("databricks-status")
    status.add_argument("run_id", type=int)
    tines = commands.add_parser("tines-request")
    tines.add_argument("bundle")
    tines.add_argument("--remote-bundle", required=True)
    tines.add_argument("--job-id", type=int, required=True)
    for command in (verify, ocsf_verify, upload):
        command.add_argument("--signature")
        command.add_argument("--trust-store")
        command.add_argument("--trust-store-sha256")
        if command is not upload:
            command.add_argument("--require-signature", action="store_true")
    upload.add_argument("--signature-root")
    args = parser.parse_args(argv)
    try:
        if args.command == "parsers":
            result = {name: spec.product for name, spec in SPECS.items()}
        elif args.command in {"collect", "collect-until"}:
            from timeline_demo.collection import collect_window, collect_until
            from timeline_demo.collection.providers import make_provider
            from timeline_demo.parsers.readers import _strict_json

            provider = make_provider(_strict_json(Path(args.config).read_text(encoding="utf-8")))
            options = {
                "max_pages": args.max_pages,
                "max_records": args.max_records,
                "max_bytes": args.max_bytes,
            }
            if args.command == "collect":
                result = collect_window(
                    provider, args.state, args.output, args.case_id, args.start, args.end, **options
                )
            else:
                result = collect_until(
                    provider,
                    args.state,
                    args.output,
                    args.case_id,
                    args.start,
                    args.end,
                    window_seconds=args.window_seconds,
                    overlap_seconds=args.overlap_seconds,
                    max_windows=args.max_windows,
                    **options,
                )
        elif args.command == "ingest":
            from timeline_demo.pipeline import Input, run_pipeline

            inputs = []
            for value in args.input:
                name, separator, path = value.partition("=")
                if not separator:
                    raise ValueError("--input must use PARSER=PATH")
                inputs.append(Input(name, path))
            result = run_pipeline(
                inputs,
                args.output,
                args.case_id,
                quarantine=args.quarantine,
                assume_timezone=args.assume_timezone,
                parquet=args.parquet,
            )
        elif args.command == "verify":
            from timeline_demo.core.manifest import verify_bundle

            from timeline_demo.signing import enforce_signature

            attestation = enforce_signature(
                args.bundle,
                signature=args.signature,
                trust_store=args.trust_store,
                trust_store_sha256=args.trust_store_sha256,
                require_signature=args.require_signature,
                expected_manifest_sha256=args.manifest_sha256,
            )
            manifest = verify_bundle(args.bundle, args.manifest_sha256)
            result = {
                "status": "integrity_verified",
                "bundle_id": manifest["bundle_id"],
                "counts": manifest["counts"],
                "signature_verification": attestation,
            }
        elif args.command == "export-ocsf":
            from timeline_demo.ocsf import export_bundle

            result = export_bundle(
                args.bundle, args.output, quarantine=args.quarantine, manifest_sha256=args.manifest_sha256
            )
        elif args.command == "verify-ocsf":
            from timeline_demo.ocsf import verify_export

            from timeline_demo.signing import enforce_signature

            attestation = enforce_signature(
                args.directory,
                signature=args.signature,
                trust_store=args.trust_store,
                trust_store_sha256=args.trust_store_sha256,
                require_signature=args.require_signature,
                kind="ocsf-export",
                expected_manifest_sha256=args.manifest_sha256,
                source_bundle=args.bundle,
            )
            result = verify_export(args.directory, manifest_sha256=args.manifest_sha256, bundle=args.bundle)
            if attestation is not None:
                result = {**result, "signature_verification": attestation}
        elif args.command == "analyze":
            from timeline_demo.ai import Harness, load_policy, prepare

            root = Path(args.bundle).resolve()
            if Path(args.ledger).resolve().is_relative_to(root) or (
                args.output and Path(args.output).resolve().is_relative_to(root)
            ):
                raise ValueError("analysis must be stored outside the evidence bundle")
            if args.output and Path(args.output).exists():
                raise FileExistsError("analysis output already exists")
            policy = load_policy(args.policy)
            if args.allow_ai:
                result = Harness(args.ledger, policy=policy).run(args.bundle, args.task, allow_ai=True)
            else:
                plan = prepare(args.bundle, args.task, policy)
                result = {
                    "status": "planned",
                    **{
                        k: plan[k]
                        for k in ("model", "task", "coverage", "input_token_bound", "reserved_tokens")
                    },
                }
            if args.output:
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                with Path(args.output).open("x", encoding="utf-8") as stream:
                    stream.write(json.dumps(result, indent=2) + "\n")
        elif args.command == "tines-request":
            from timeline_demo.integrations.databricks import tines_request

            result = tines_request(args.bundle, args.remote_bundle, args.job_id)
        else:
            from timeline_demo.integrations.databricks import DatabricksClient

            client = DatabricksClient()
            if args.command == "databricks-upload":
                result = {}
                if any((args.signature, args.signature_root, args.trust_store, args.trust_store_sha256)):
                    if not all(
                        (args.signature, args.signature_root, args.trust_store, args.trust_store_sha256)
                    ):
                        raise ValueError(
                            "signed upload requires signature, signature root and pinned signer trust"
                        )
                    result["remote_signature"] = client.upload_signature(
                        args.bundle,
                        args.signature,
                        args.signature_root,
                        args.trust_store,
                        args.trust_store_sha256,
                    )
                result["remote_bundle"] = client.upload_bundle(args.bundle, args.volume_root)
            elif args.command == "databricks-download":
                result = client.download_bundle(args.remote_bundle, args.output, args.manifest_sha256)
            elif args.command == "databricks-submit":
                result = client.submit(args.bundle, args.remote_bundle, args.job_id)
            else:
                result = client.status(args.run_id)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, FileNotFoundError, FileExistsError, ImportError) as exc:
        parser.exit(2, f"timeline: {exc}\n")


if __name__ == "__main__":
    main()
