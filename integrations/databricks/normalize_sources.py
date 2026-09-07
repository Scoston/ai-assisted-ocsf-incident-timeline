# Databricks notebook source
# MAGIC %md
# MAGIC # Normalize source exports already in a Unity Catalog Volume
# MAGIC Install the project wheel on the cluster first. Supply JSON source specifications and a new output directory. Inputs must be files, not SQL statements or arbitrary URLs.

# COMMAND ----------
import json
from timeline_demo.pipeline import Input
from timeline_demo.integrations.databricks import volume_path, normalize_volume_sources

for name, default in [
    ("sources_json", "[]"),
    ("case_id", ""),
    ("output_bundle", ""),
    ("timezone_assumption", ""),
]:
    dbutils.widgets.text(name, default)  # noqa: F821
sources = json.loads(dbutils.widgets.get("sources_json"))  # noqa: F821
inputs = [Input(item["parser"], volume_path(item["path"])) for item in sources]
manifest = normalize_volume_sources(
    inputs,
    volume_path(dbutils.widgets.get("output_bundle")),
    dbutils.widgets.get("case_id"),  # noqa: F821
    assume_timezone=dbutils.widgets.get("timezone_assumption") or None,
)  # noqa: F821
print(json.dumps({"bundle_id": manifest["bundle_id"], "counts": manifest["counts"]}, indent=2))
