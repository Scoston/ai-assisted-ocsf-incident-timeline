# Databricks notebook source
# Attach the project wheel. The deployed job skips this task unless explicitly enabled.
from pathlib import Path
import re
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.integrations.databricks import publish_ocsf_export, volume_path
from timeline_demo.ocsf import MAPPING_VERSION, export_bundle, verify_export
from timeline_demo.parsers.common import compact_json, file_hash


dbutils.widgets.text("enabled", "false")
dbutils.widgets.text("quarantine", "false")
dbutils.widgets.text("bundle_path", "")
dbutils.widgets.text("manifest_sha256", "")
dbutils.widgets.text("export_root", "")
dbutils.widgets.text("catalog", "")
dbutils.widgets.text("schema", "")

if dbutils.widgets.get("enabled") not in {"true", "false"}:
    raise ValueError("enabled must be true or false")
if dbutils.widgets.get("enabled") == "false":
    dbutils.notebook.exit('{"status":"skipped","reason":"OCSF export is disabled"}')

# COMMAND ----------

source = volume_path(dbutils.widgets.get("bundle_path"))
source_pin = dbutils.widgets.get("manifest_sha256")
if not re.fullmatch(r"[a-f0-9]{64}", source_pin):
    raise ValueError("a pinned source manifest SHA-256 is required")
manifest = verify_bundle(source, source_pin)
export_root = volume_path(dbutils.widgets.get("export_root"))
quarantine = dbutils.widgets.get("quarantine")
if quarantine not in {"true", "false"}:
    raise ValueError("quarantine must be true or false")
destination = Path(export_root) / (manifest["bundle_id"] + "-" + MAPPING_VERSION)
if destination.resolve().is_relative_to(Path(source).resolve()):
    raise ValueError("OCSF export must be outside the evidence bundle")
if destination.exists():
    report = verify_export(destination, bundle=source)
else:
    report = export_bundle(source, destination, manifest_sha256=source_pin, quarantine=quarantine == "true")
if report["counts"]["rejected_events"] and quarantine != "true":
    raise ValueError("strict OCSF publication rejects an existing partial export")

# COMMAND ----------
result = publish_ocsf_export(
    spark,
    destination,
    source,
    dbutils.widgets.get("catalog"),
    dbutils.widgets.get("schema"),
    expected_export_sha256=file_hash(destination / "export_manifest.json"),
)
dbutils.notebook.exit(compact_json({"status": "published", **result}))
