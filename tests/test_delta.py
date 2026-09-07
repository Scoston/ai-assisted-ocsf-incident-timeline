"""Real Spark/Delta gate, enabled with TIMELINE_TEST_DELTA=1 (requires JVM + Delta jars)."""

import os
import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("TIMELINE_TEST_DELTA") != "1", reason="requires local Spark/Delta runtime"
)


def test_delta_publication_and_replay(bundle, tmp_path):
    from delta import configure_spark_with_delta_pip
    from pyspark.sql import SparkSession
    from timeline_demo.integrations.databricks import publish_bundle, publish_ocsf_export
    from timeline_demo.ocsf import export_bundle

    builder = (
        SparkSession.builder.master("local[2]")
        .appName("timeline-delta-test")
        .config("spark.sql.extensions", "io.delta.sql.DeltaSparkSessionExtension")
        .config("spark.sql.catalog.spark_catalog", "org.apache.spark.sql.delta.catalog.DeltaCatalog")
        .config("spark.sql.warehouse.dir", str(tmp_path / "warehouse"))
        .config("spark.sql.shuffle.partitions", "2")
        .config("spark.ui.enabled", "false")
        .config("spark.databricks.delta.snapshotPartitions", "2")
    )
    spark = configure_spark_with_delta_pip(builder).getOrCreate()
    try:
        result = publish_bundle(spark, str(bundle), "spark_catalog", "timeline_test")
        assert spark.table(result["table"]).count() == 1
        publish_bundle(spark, str(bundle), "spark_catalog", "timeline_test")
        assert spark.table(result["table"]).count() == 1
        assert spark.table("spark_catalog.timeline_test.published_bundles").count() == 1
        assert spark.table("spark_catalog.timeline_test.ingestion_receipts").count() == 1
        export_dir = tmp_path / "ocsf"
        export_bundle(bundle, export_dir)
        for _ in range(2):
            ocsf = publish_ocsf_export(spark, export_dir, bundle, "spark_catalog", "timeline_test")
            assert spark.table(ocsf["table"]).count() == 1
        assert spark.table("spark_catalog.timeline_test.published_ocsf_exports").count() == 1
        row = spark.table(ocsf["table"]).first()
        assert row.class_uid == 6003 and row.time == 1788256800000
        assert len(row.event_uuid) == 64
        assert spark.table("spark_catalog.timeline_test.ocsf_rejections").count() == 0
    finally:
        spark.stop()
