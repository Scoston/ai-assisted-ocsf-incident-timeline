"""Unity Catalog Volumes + Jobs SDK + insert-only Delta publication."""

from __future__ import annotations

import argparse
import hashlib
import re
import uuid
import tempfile
from pathlib import Path

from timeline_demo.core.manifest import verify_bundle
from timeline_demo.parsers.common import compact_json, file_hash

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def identifier(value):
    if not IDENTIFIER.fullmatch(value):
        raise ValueError("invalid Unity Catalog identifier")
    return value


def volume_path(path):
    parts = path.split("/")
    if len(parts) < 5 or parts[:2] != ["", "Volumes"]:
        raise ValueError("expected /Volumes/catalog/schema/volume path")
    for part in parts[2:5]:
        identifier(part)
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", p) or p in {".", ".."} for p in parts[5:]):
        raise ValueError("unsafe Volume path")
    return path


def normalize_volume_sources(inputs, output_bundle, case_id, *, client=None, **options):
    """Normalize on driver-local disk; publish sequential Volume objects, manifest last."""
    from timeline_demo.pipeline import run_pipeline

    volume_path(output_bundle)
    with tempfile.TemporaryDirectory(prefix="timeline-normalize-") as temp:
        local = Path(temp) / "bundle"
        manifest = run_pipeline(inputs, local, case_id, **options)
        (client or DatabricksClient()).upload_bundle_at(local, output_bundle)
    return manifest


def tines_request(bundle, remote_bundle, job_id):
    manifest = verify_bundle(bundle)
    volume_path(remote_bundle)
    if type(job_id) is not int or job_id <= 0:
        raise ValueError("job_id must be a positive integer")
    digest = file_hash(Path(bundle) / "audit_manifest.json")
    return {
        "contract_version": "1.0",
        "case_id": manifest["case_id"],
        "bundle_id": manifest["bundle_id"],
        "bundle_path": remote_bundle,
        "manifest_sha256": digest,
        "idempotency_key": hashlib.sha256(f"{job_id}:{digest}".encode()).hexdigest(),
    }


class DatabricksClient:
    def __init__(self, workspace=None):
        if workspace is None:
            from databricks.sdk import WorkspaceClient

            workspace = WorkspaceClient()  # Databricks unified auth: OAuth/profile/token.
        self.workspace = workspace

    def upload_bundle(self, bundle, volume_root):
        manifest = verify_bundle(bundle)
        remote = volume_path(volume_root.rstrip("/")) + "/" + manifest["bundle_id"]
        return self.upload_bundle_at(bundle, remote)

    def upload_bundle_at(self, bundle, remote):
        manifest = verify_bundle(bundle)
        pin = file_hash(Path(bundle) / "audit_manifest.json")
        return self._upload_artifact(
            bundle, remote, manifest["files"], "audit_manifest.json", lambda: verify_bundle(bundle, pin)
        )

    def upload_export(self, export, remote, bundle):
        from timeline_demo.ocsf import verify_export

        report = verify_export(export, bundle=bundle)
        pin = file_hash(Path(export) / "export_manifest.json")
        return self._upload_artifact(
            export,
            remote,
            report["files"],
            "export_manifest.json",
            lambda: verify_export(export, manifest_sha256=pin, bundle=bundle),
        )

    def _upload_artifact(self, bundle, remote, entries, marker, verify):
        volume_path(remote)
        names = sorted(entries) + [marker]  # Commit marker uploaded last.
        from databricks.sdk.errors import ResourceAlreadyExists

        for folder in sorted(
            {remote, *[remote + "/" + str(Path(name).parent) for name in names if "/" in name]}
        ):
            self.workspace.files.create_directory(folder)

        for name in names:
            if name == marker:
                verify()
            local = Path(bundle) / name
            path = remote + "/" + name
            try:
                with local.open("rb") as contents:
                    self.workspace.files.upload(path, contents, overwrite=False)
            except ResourceAlreadyExists:
                # Safe restart after a partial upload; conflicting remote bytes fail closed.
                response = self.workspace.files.download(path)
                digest = hashlib.sha256()
                count = 0
                with response.contents as contents:
                    for block in iter(lambda: contents.read(1024 * 1024), b""):
                        count += len(block)
                        if count > local.stat().st_size:
                            raise ValueError("remote artifact exceeds expected size")
                        digest.update(block)
                if digest.hexdigest() != file_hash(local):
                    raise ValueError("remote bundle conflict: " + name)
        return remote

    def upload_signature(self, bundle, signature, volume_root, trust_store, trust_store_sha256):
        from timeline_demo.signing import verify_signature, _read
        from databricks.sdk.errors import ResourceAlreadyExists
        from io import BytesIO

        receipt = verify_signature(bundle, signature, trust_store, trust_store_sha256)
        body = _read(signature, 8192)
        if hashlib.sha256(body).hexdigest() != receipt["signature_sha256"]:
            raise ValueError("signature changed after verification")
        root = volume_path(volume_root.rstrip("/"))
        remote = root + "/" + receipt["artifact_id"] + ".sig.json"
        self.workspace.files.create_directory(root)
        try:
            self.workspace.files.upload(remote, BytesIO(body), overwrite=False)
        except ResourceAlreadyExists:
            response = self.workspace.files.download(remote)
            with response.contents as stream:
                existing = stream.read(8193)
            if existing != body:
                raise ValueError("remote signature conflicts; use a new signature root for rotation")
        return remote

    def download_bundle(self, remote_bundle, output_dir, expected_manifest_sha256):
        from timeline_demo.core.manifest import safe_member

        volume_path(remote_bundle)
        if not re.fullmatch(r"[a-f0-9]{64}", expected_manifest_sha256):
            raise ValueError("an independently recorded manifest SHA-256 is required")
        target = Path(output_dir).resolve()
        if target.exists():
            raise FileExistsError("download target already exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".timeline-download-", dir=target.parent) as temp:
            root = Path(temp) / "bundle"
            root.mkdir()
            response = self.workspace.files.download(remote_bundle + "/audit_manifest.json")
            with response.contents as contents:
                raw = contents.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
                raise ValueError("downloaded manifest does not match pinned digest")
            from timeline_demo.core.manifest import parse_manifest
            from timeline_demo.core.storage import private_tree

            manifest = parse_manifest(raw)
            (root / "audit_manifest.json").write_bytes(raw)
            for name, entry in manifest["files"].items():
                local = safe_member(root, name)
                local.parent.mkdir(parents=True, exist_ok=True)
                response = self.workspace.files.download(remote_bundle + "/" + name)
                count = 0
                with response.contents as contents, local.open("xb") as stream:
                    for block in iter(lambda: contents.read(1024 * 1024), b""):
                        count += len(block)
                        if count > entry["bytes"]:
                            raise ValueError("download larger than manifest entry")
                        stream.write(block)
            result = verify_bundle(root, expected_manifest_sha256)
            private_tree(root)
            root.rename(target)
        return result

    def submit(self, bundle, remote_bundle, job_id):
        request = tines_request(bundle, remote_bundle, job_id)
        run = self.workspace.jobs.run_now(
            job_id=job_id,
            idempotency_token=request["idempotency_key"],
            job_parameters={
                "bundle_path": request["bundle_path"],
                "manifest_sha256": request["manifest_sha256"],
            },
        )
        return {"run_id": run.response.run_id, "request": request}

    def status(self, run_id):
        run = self.workspace.jobs.get_run(run_id=run_id)
        value = run.as_dict()
        return {"run_id": run_id, "state": value.get("state", {}), "run_page_url": value.get("run_page_url")}


TABLE_SCHEMAS = {
    "evidence_files": "case_id STRING, bundle_id STRING, evidence_path STRING, sha256 STRING, bytes BIGINT, metadata_json STRING",
    "timeline_events": "case_id STRING, bundle_id STRING, event_uuid STRING, epoch_ms BIGINT, time_utc STRING, parser_name STRING, ocsf_class_uid BIGINT, record_json STRING",
    "ingestion_receipts": "case_id STRING, bundle_id STRING, receipt_id STRING, record_json STRING",
    "quarantine": "case_id STRING, bundle_id STRING, receipt_id STRING, record_json STRING",
    "analysis": "case_id STRING, bundle_id STRING, request_hash STRING, human_review_required BOOLEAN, record_json STRING",
    "signature_verifications": "case_id STRING, bundle_id STRING, artifact_id STRING, key_id STRING, trust_store_sha256 STRING, signature_sha256 STRING, record_json STRING",
    "published_bundles": "case_id STRING, bundle_id STRING, manifest_sha256 STRING, manifest_json STRING",
    "ocsf_events": "case_id STRING, bundle_id STRING, export_id STRING, event_uuid STRING, class_uid BIGINT, type_uid BIGINT, time BIGINT, record_json STRING",
    "ocsf_rejections": "case_id STRING, bundle_id STRING, export_id STRING, event_uuid STRING, record_json STRING",
    "published_ocsf_exports": "case_id STRING, bundle_id STRING, export_id STRING, manifest_json STRING",
}


def _merge(spark, table, schema, frame, keys):
    spark.sql(
        f"CREATE TABLE IF NOT EXISTS {table} ({schema}) USING DELTA TBLPROPERTIES ('delta.appendOnly' = 'true')"
    )
    view = "timeline_stage_" + uuid.uuid4().hex
    frame.dropDuplicates(keys).createOrReplaceTempView(view)
    try:
        on = " AND ".join(f"t.{k}=s.{k}" for k in keys)
        spark.sql(f"MERGE INTO {table} t USING {view} s ON {on} WHEN NOT MATCHED THEN INSERT *")
    finally:
        spark.catalog.dropTempView(view)


def publish_bundle(
    spark,
    bundle,
    catalog,
    schema,
    expected_manifest_sha256=None,
    *,
    signature=None,
    trust_store=None,
    trust_store_sha256=None,
    require_signature=False,
):
    from timeline_demo.signing import enforce_signature

    attestation = enforce_signature(
        bundle,
        signature=signature,
        trust_store=trust_store,
        trust_store_sha256=trust_store_sha256,
        require_signature=require_signature,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    source_pin = (attestation["manifest_sha256"] if attestation else expected_manifest_sha256) or file_hash(
        Path(bundle) / "audit_manifest.json"
    )
    manifest = verify_bundle(bundle, source_pin)
    from pyspark.sql import functions as F

    prefix = f"`{identifier(catalog)}`.`{identifier(schema)}`"
    spark.sql(f"CREATE SCHEMA IF NOT EXISTS {prefix}")
    spark.conf.set("spark.sql.session.timeZone", "UTC")
    base = {"case_id": manifest["case_id"], "bundle_id": manifest["bundle_id"]}
    rows = [
        {
            **base,
            "evidence_path": str(Path(bundle) / item["evidence_path"]),
            "sha256": item["sha256"],
            "bytes": item["bytes"],
            "metadata_json": compact_json(item),
        }
        for item in manifest["inputs"]
    ]
    frame = spark.createDataFrame(rows, TABLE_SCHEMAS["evidence_files"])
    _merge(
        spark,
        prefix + ".evidence_files",
        TABLE_SCHEMAS["evidence_files"],
        frame,
        ["case_id", "bundle_id", "evidence_path"],
    )
    # Read strings with explicit projections, avoiding schema inference loss and driver collect().
    lines = spark.read.text(str(Path(bundle) / "timeline.jsonl"))
    frame = lines.select(
        F.lit(base["case_id"]).alias("case_id"),
        F.lit(base["bundle_id"]).alias("bundle_id"),
        *[
            F.get_json_object("value", "$." + key).cast(dtype).alias(key)
            for key, dtype in [
                ("event_uuid", "string"),
                ("epoch_ms", "long"),
                ("time_utc", "string"),
                ("parser_name", "string"),
                ("ocsf_class_uid", "long"),
            ]
        ],
        F.col("value").alias("record_json"),
    )
    _merge(
        spark,
        prefix + ".timeline_events",
        TABLE_SCHEMAS["timeline_events"],
        frame,
        ["case_id", "bundle_id", "event_uuid"],
    )
    for table, file in [("ingestion_receipts", "receipts.jsonl"), ("quarantine", "quarantine.jsonl")]:
        frame = spark.read.text(str(Path(bundle) / file)).select(
            F.lit(base["case_id"]).alias("case_id"),
            F.lit(base["bundle_id"]).alias("bundle_id"),
            F.sha2("value", 256).alias("receipt_id"),
            F.col("value").alias("record_json"),
        )
        _merge(
            spark, prefix + "." + table, TABLE_SCHEMAS[table], frame, ["case_id", "bundle_id", "receipt_id"]
        )
    spark.sql(
        f"CREATE TABLE IF NOT EXISTS {prefix}.analysis ({TABLE_SCHEMAS['analysis']}) USING DELTA TBLPROPERTIES ('delta.appendOnly' = 'true')"
    )
    # Spark reads are lazy; recheck source bytes and current pinned policy before the marker.
    verify_bundle(bundle, source_pin)
    if attestation is not None:
        attestation = enforce_signature(
            bundle,
            signature=signature,
            trust_store=trust_store,
            trust_store_sha256=trust_store_sha256,
            require_signature=True,
            expected_manifest_sha256=source_pin,
        )
        _publish_attestation(spark, prefix, base, attestation)
    # Publication marker is last; readers use a view joined to it to exclude partial runs.
    frame = spark.createDataFrame(
        [
            {
                **base,
                "manifest_sha256": source_pin,
                "manifest_json": compact_json(manifest),
            }
        ],
        TABLE_SCHEMAS["published_bundles"],
    )
    _merge(
        spark,
        prefix + ".published_bundles",
        TABLE_SCHEMAS["published_bundles"],
        frame,
        ["case_id", "bundle_id"],
    )
    spark.sql(
        f"CREATE OR REPLACE VIEW {prefix}.published_timeline AS SELECT e.* FROM {prefix}.timeline_events e INNER JOIN {prefix}.published_bundles b ON e.case_id=b.case_id AND e.bundle_id=b.bundle_id"
    )
    return {
        "case_id": base["case_id"],
        "bundle_id": base["bundle_id"],
        "event_count": manifest["counts"]["event_count"],
        "table": catalog + "." + schema + ".published_timeline",
        "signature_verification": attestation,
    }


def _publish_attestation(spark, prefix, base, attestation):
    row = {
        "case_id": base["case_id"],
        "bundle_id": base["bundle_id"],
        **{
            key: attestation[key]
            for key in ("artifact_id", "key_id", "trust_store_sha256", "signature_sha256")
        },
        "record_json": compact_json(attestation),
    }
    frame = spark.createDataFrame([row], TABLE_SCHEMAS["signature_verifications"])
    _merge(
        spark,
        prefix + ".signature_verifications",
        TABLE_SCHEMAS["signature_verifications"],
        frame,
        ["case_id", "bundle_id", "artifact_id", "key_id", "trust_store_sha256", "signature_sha256"],
    )


def publish_ocsf_export(
    spark,
    export_dir,
    bundle,
    catalog,
    schema,
    expected_export_sha256=None,
    *,
    signature=None,
    trust_store=None,
    trust_store_sha256=None,
    require_signature=False,
):
    """Publish a validated, source-bound OCSF export with a separate final marker.

    Paths must be readable by Spark workers (for Databricks use a UC Volume).
    This does not run a model, create a second raw bundle or alter source tables.
    """
    from timeline_demo.signing import enforce_signature
    from timeline_demo.ocsf import verify_export

    attestation = enforce_signature(
        export_dir,
        signature=signature,
        trust_store=trust_store,
        trust_store_sha256=trust_store_sha256,
        require_signature=require_signature,
        kind="ocsf-export",
        source_bundle=bundle,
        expected_manifest_sha256=expected_export_sha256,
    )
    from pyspark.sql import functions as F

    export_id = (attestation["manifest_sha256"] if attestation else expected_export_sha256) or file_hash(
        Path(export_dir) / "export_manifest.json"
    )
    report = verify_export(export_dir, manifest_sha256=export_id, bundle=bundle)
    prefix = f"`{identifier(catalog)}`.`{identifier(schema)}`"
    spark.sql(f"CREATE SCHEMA IF NOT EXISTS {prefix}")
    base = {"case_id": report["case_id"], "bundle_id": report["source_bundle_id"], "export_id": export_id}
    keys = ["case_id", "bundle_id", "export_id", "event_uuid"]
    for table, filename in [("ocsf_events", "ocsf.jsonl"), ("ocsf_rejections", "rejections.jsonl")]:
        rows = spark.read.text(str(Path(export_dir) / filename))
        fields = [F.lit(value).alias(key) for key, value in base.items()]
        event_path = "$.unmapped.timeline_export.event_uuid" if table == "ocsf_events" else "$.event_uuid"
        fields.append(F.get_json_object("value", event_path).alias("event_uuid"))
        if table == "ocsf_events":
            fields.extend(
                F.get_json_object("value", "$." + name).cast("long").alias(name)
                for name in ("class_uid", "type_uid", "time")
            )
        fields.append(F.col("value").alias("record_json"))
        _merge(spark, prefix + "." + table, TABLE_SCHEMAS[table], rows.select(*fields), keys)
    # Spark reads are lazy; verify again after all inserts and before making them visible.
    verify_export(export_dir, manifest_sha256=export_id, bundle=bundle)
    if attestation is not None:
        attestation = enforce_signature(
            export_dir,
            signature=signature,
            trust_store=trust_store,
            trust_store_sha256=trust_store_sha256,
            require_signature=True,
            kind="ocsf-export",
            source_bundle=bundle,
            expected_manifest_sha256=export_id,
        )
        _publish_attestation(spark, prefix, base, attestation)
    marker = spark.createDataFrame(
        [{**base, "manifest_json": compact_json(report)}], TABLE_SCHEMAS["published_ocsf_exports"]
    )
    _merge(
        spark, prefix + ".published_ocsf_exports", TABLE_SCHEMAS["published_ocsf_exports"], marker, keys[:-1]
    )
    spark.sql(
        f"CREATE OR REPLACE VIEW {prefix}.published_ocsf AS SELECT e.* FROM {prefix}.ocsf_events e INNER JOIN {prefix}.published_ocsf_exports p ON e.case_id=p.case_id AND e.bundle_id=p.bundle_id AND e.export_id=p.export_id"
    )
    return {
        **base,
        "counts": report["counts"],
        "table": catalog + "." + schema + ".published_ocsf",
        "signature_verification": attestation,
    }


def publish_analysis(spark, result, catalog, schema):
    from timeline_demo.ai import validate_analysis

    if result.get("status") != "completed" or result.get("human_review_required") is not True:
        raise ValueError("only validated, review-required analysis may be published")
    receipt = result["receipt"]
    validate_analysis(result["analysis"], receipt["evidence_refs"])
    prefix = f"`{identifier(catalog)}`.`{identifier(schema)}`"
    frame = spark.createDataFrame(
        [
            {
                "case_id": receipt["case_id"],
                "bundle_id": receipt["bundle_id"],
                "request_hash": receipt["request_hash"],
                "human_review_required": True,
                "record_json": compact_json(result),
            }
        ],
        TABLE_SCHEMAS["analysis"],
    )
    _merge(
        spark,
        prefix + ".analysis",
        TABLE_SCHEMAS["analysis"],
        frame,
        ["case_id", "bundle_id", "request_hash"],
    )


def job_signature_options(bundle, manifest_pin, required, signature_root, trust_store, trust_pin):
    # Policy comes from deployment literals, never incoming Tines job parameters.
    if required not in {"true", "false"}:
        raise ValueError("require_signature must be true or false")
    if required == "false" and not any((signature_root, trust_store, trust_pin)):
        return {}
    if not all((signature_root, trust_store, trust_pin)):
        raise ValueError("signature enforcement requires complete deployment policy")
    manifest = verify_bundle(bundle, manifest_pin)
    signature = volume_path(signature_root.rstrip("/")) + "/" + manifest["bundle_id"] + ".sig.json"
    options = {
        "signature": signature,
        "trust_store": volume_path(trust_store),
        "trust_store_sha256": trust_pin,
        "require_signature": True,
    }
    from timeline_demo.signing import enforce_signature

    enforce_signature(bundle, expected_manifest_sha256=manifest_pin, **options)
    return options


def run_ocsf_job(
    spark,
    bundle,
    manifest_pin,
    catalog,
    schema,
    export_root,
    *,
    enabled="false",
    quarantine="false",
    signature_options=None,
):
    """Shared export task logic; deployment uses positional wheel parameters."""
    from timeline_demo.ocsf import MAPPING_VERSION, export_bundle, verify_export
    from timeline_demo.signing import enforce_signature

    if enabled not in {"true", "false"} or quarantine not in {"true", "false"}:
        raise ValueError("enabled and quarantine must be true or false")
    if enabled == "false":
        return {"status": "skipped", "reason": "OCSF export is disabled"}
    options = signature_options or {}
    enforce_signature(bundle, expected_manifest_sha256=manifest_pin, **options)
    manifest = verify_bundle(bundle, manifest_pin)
    destination = Path(export_root) / (manifest["bundle_id"] + "-" + MAPPING_VERSION)
    if destination.resolve().is_relative_to(Path(bundle).resolve()):
        raise ValueError("OCSF export must be outside the evidence bundle")
    on_volume = str(destination).startswith("/Volumes/")
    if (destination / "export_manifest.json").is_file():
        report = verify_export(destination, bundle=bundle)
    elif on_volume:
        volume_path(str(destination))
        with tempfile.TemporaryDirectory(prefix="timeline-ocsf-job-") as temp:
            local = Path(temp) / "export"
            report = export_bundle(
                bundle, local, manifest_sha256=manifest_pin, quarantine=quarantine == "true"
            )
            DatabricksClient().upload_export(local, str(destination), bundle)
    else:
        report = export_bundle(
            bundle, destination, manifest_sha256=manifest_pin, quarantine=quarantine == "true"
        )
    if report["counts"]["rejected_events"] and quarantine != "true":
        raise ValueError("strict OCSF publication rejects an existing partial export")
    enforce_signature(bundle, expected_manifest_sha256=manifest_pin, **options)
    return {
        "status": "published",
        **publish_ocsf_export(
            spark,
            destination,
            bundle,
            catalog,
            schema,
            expected_export_sha256=file_hash(destination / "export_manifest.json"),
        ),
    }


def inspect_publication(spark, bundle, manifest_pin, catalog, schema, *, signature_options=None):
    from timeline_demo.signing import enforce_signature

    options = signature_options or {}
    attestation = enforce_signature(bundle, expected_manifest_sha256=manifest_pin, **options)
    manifest = verify_bundle(bundle, manifest_pin)
    from pyspark.sql import functions as F

    table = f"`{identifier(catalog)}`.`{identifier(schema)}`.published_timeline"
    count = (
        spark.table(table)
        .where((F.col("case_id") == manifest["case_id"]) & (F.col("bundle_id") == manifest["bundle_id"]))
        .count()
    )
    if count != manifest["counts"]["event_count"]:
        raise ValueError("published event count differs from source manifest")
    verify_bundle(bundle, manifest_pin)
    if attestation is not None:
        attestation = enforce_signature(bundle, expected_manifest_sha256=manifest_pin, **options)
    return {
        "status": "publication_verified",
        "case_id": manifest["case_id"],
        "bundle_id": manifest["bundle_id"],
        "event_count": count,
        "signature_verification": attestation,
    }


def _job_parser(ocsf=False):
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-path", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--require-signature", choices=["true", "false"], default="false")
    parser.add_argument("--signature-root", default="")
    parser.add_argument("--trust-store", default="")
    parser.add_argument("--trust-store-sha256", default="")
    if ocsf:
        parser.add_argument("--enabled", choices=["true", "false"], default="false")
        parser.add_argument("--quarantine", choices=["true", "false"], default="false")
        parser.add_argument("--export-root", default="")
    return parser


def _job_options(args):
    volume_path(args.bundle_path)
    identifier(args.catalog)
    identifier(args.schema)
    if not re.fullmatch(r"[a-f0-9]{64}", args.manifest_sha256):
        raise ValueError("manifest SHA-256 is required")
    return job_signature_options(
        args.bundle_path,
        args.manifest_sha256,
        args.require_signature,
        args.signature_root,
        args.trust_store,
        args.trust_store_sha256,
    )


def job_main(argv=None):
    args = _job_parser().parse_args(argv)
    options = _job_options(args)
    from pyspark.sql import SparkSession

    spark = SparkSession.builder.getOrCreate()
    result = publish_bundle(
        spark, args.bundle_path, args.catalog, args.schema, args.manifest_sha256, **options
    )
    print(compact_json(result))
    return 0


def ocsf_job_main(argv=None):
    args = _job_parser(ocsf=True).parse_args(argv)
    if args.enabled == "false":
        print(compact_json({"status": "skipped", "reason": "OCSF export is disabled"}))
        return 0
    options = _job_options(args)
    volume_path(args.export_root)
    from pyspark.sql import SparkSession

    spark = SparkSession.builder.getOrCreate()
    result = run_ocsf_job(
        spark,
        args.bundle_path,
        args.manifest_sha256,
        args.catalog,
        args.schema,
        args.export_root,
        enabled=args.enabled,
        quarantine=args.quarantine,
        signature_options=options,
    )
    print(compact_json(result))
    return 0


def inspect_job_main(argv=None):
    args = _job_parser().parse_args(argv)
    options = _job_options(args)
    from pyspark.sql import SparkSession

    spark = SparkSession.builder.getOrCreate()
    result = inspect_publication(
        spark, args.bundle_path, args.manifest_sha256, args.catalog, args.schema, signature_options=options
    )
    print(compact_json(result))
    return 0


if __name__ == "__main__":
    job_main()
