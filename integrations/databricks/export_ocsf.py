# Databricks notebook source
# Interactive analyst adapter. Scheduled enforcement uses positional wheel tasks.
from timeline_demo.integrations.databricks import job_signature_options, run_ocsf_job, volume_path
from timeline_demo.parsers.common import compact_json

for name, default in {
    "enabled": "false",
    "quarantine": "false",
    "require_signature": "false",
    "bundle_path": "",
    "manifest_sha256": "",
    "export_root": "",
    "catalog": "",
    "schema": "",
    "signature_root": "",
    "trust_store": "",
    "trust_store_sha256": "",
}.items():
    dbutils.widgets.text(name, default)

if dbutils.widgets.get("enabled") == "false":
    dbutils.notebook.exit('{"status":"skipped","reason":"OCSF export is disabled"}')

source = volume_path(dbutils.widgets.get("bundle_path"))
source_pin = dbutils.widgets.get("manifest_sha256")
options = job_signature_options(
    source,
    source_pin,
    dbutils.widgets.get("require_signature"),
    dbutils.widgets.get("signature_root"),
    dbutils.widgets.get("trust_store"),
    dbutils.widgets.get("trust_store_sha256"),
)
result = run_ocsf_job(
    spark,
    source,
    source_pin,
    dbutils.widgets.get("catalog"),
    dbutils.widgets.get("schema"),
    volume_path(dbutils.widgets.get("export_root")),
    enabled=dbutils.widgets.get("enabled"),
    quarantine=dbutils.widgets.get("quarantine"),
    signature_options=options,
)
dbutils.notebook.exit(compact_json(result))
