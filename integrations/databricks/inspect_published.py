# Databricks notebook source
# MAGIC %md
# MAGIC # Inspect a published investigation
# MAGIC The preceding job task verifies hashes and publishes the bundle. This notebook reads the committed view.

# COMMAND ----------
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.integrations.databricks import identifier
from pyspark.sql import functions as F

for name in ["bundle_path", "manifest_sha256", "catalog", "schema"]:
    dbutils.widgets.text(name, "")  # noqa: F821
params = {name: dbutils.widgets.get(name) for name in ["bundle_path", "manifest_sha256", "catalog", "schema"]}  # noqa: F821
manifest = verify_bundle(params["bundle_path"], params["manifest_sha256"])
table = f"{identifier(params['catalog'])}.{identifier(params['schema'])}.published_timeline"
rows = spark.table(table).where(
    (F.col("case_id") == manifest["case_id"]) & (F.col("bundle_id") == manifest["bundle_id"])
)  # noqa: F821
assert rows.count() == manifest["counts"]["event_count"], "Published event count differs from manifest"
display(rows.orderBy("epoch_ms", "event_uuid").limit(200))  # noqa: F821

# COMMAND ----------
# MAGIC %md
# MAGIC Review the raw evidence and quarantine entries before drawing conclusions. AI analysis is an optional separate step in `03_ai_harness.ipynb`.
