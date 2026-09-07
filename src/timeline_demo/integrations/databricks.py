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
        names = sorted(manifest["files"]) + ["audit_manifest.json"]  # Commit marker uploaded last.
        from databricks.sdk.errors import ResourceAlreadyExists

        for folder in sorted(
            {remote, *[remote + "/" + str(Path(name).parent) for name in names if "/" in name]}
        ):
            self.workspace.files.create_directory(folder)

        for name in names:
            local = Path(bundle) / name
            path = remote + "/" + name
            try:
                with local.open("rb") as contents:
                    self.workspace.files.upload(path, contents, overwrite=False)
            except ResourceAlreadyExists:
                # Safe restart after a partial upload; conflicting remote bytes fail closed.
                response = self.workspace.files.download(path)
                digest = hashlib.sha256()
                with response.contents as contents:
                    for block in iter(lambda: contents.read(1024 * 1024), b""):
                        digest.update(block)
                if digest.hexdigest() != file_hash(local):
                    raise ValueError("remote bundle conflict: " + name)
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
            import json

            manifest = json.loads(raw)
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
    "published_bundles": "case_id STRING, bundle_id STRING, manifest_sha256 STRING, manifest_json STRING",
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


def publish_bundle(spark, bundle, catalog, schema, expected_manifest_sha256=None):
    from pyspark.sql import functions as F

    manifest = verify_bundle(bundle, expected_manifest_sha256)
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
    # Publication marker is last; readers use a view joined to it to exclude partial runs.
    frame = spark.createDataFrame(
        [
            {
                **base,
                "manifest_sha256": file_hash(Path(bundle) / "audit_manifest.json"),
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


def job_main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-path", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--schema", required=True)
    args = parser.parse_args()
    volume_path(args.bundle_path)
    if not re.fullmatch(r"[a-f0-9]{64}", args.manifest_sha256):
        raise ValueError("manifest SHA-256 is required")
    from pyspark.sql import SparkSession

    spark = SparkSession.builder.getOrCreate()
    result = publish_bundle(spark, args.bundle_path, args.catalog, args.schema, args.manifest_sha256)
    print(compact_json(result))


if __name__ == "__main__":
    job_main()
