"""Real Spark/Delta gate, enabled with TIMELINE_TEST_DELTA=1 (requires JVM + Delta jars)."""

import os
import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("TIMELINE_TEST_DELTA") != "1", reason="requires local Spark/Delta runtime"
)


def test_delta_publication_and_replay(bundle, tmp_path):
    from delta import configure_spark_with_delta_pip
    from pyspark.sql import SparkSession
    from timeline_demo.integrations.databricks import publish_bundle, publish_ocsf_export, inspect_publication
    from timeline_demo.ocsf import export_bundle
    from timeline_demo.signing import generate_keypair, public_entry, write_trust, sign_artifact

    password = b"synthetic-delta-signing-password"
    signer = generate_keypair(tmp_path / "signer", password)
    key_id, entry = public_entry(signer["public_key"])
    policy = {"version": "1.0", "keys": {key_id: entry}}
    trust = tmp_path / "trust.json"
    pin = write_trust(trust, policy)["trust_store_sha256"]
    signature = tmp_path / "source.sig.json"
    sign_artifact(bundle, signer["private_key"], password, signature, trust, pin)
    options = {
        "signature": signature,
        "trust_store": trust,
        "trust_store_sha256": pin,
        "require_signature": True,
    }
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
        result = publish_bundle(spark, str(bundle), "spark_catalog", "timeline_test", **options)
        assert spark.table(result["table"]).count() == 1
        publish_bundle(spark, str(bundle), "spark_catalog", "timeline_test", **options)
        assert spark.table(result["table"]).count() == 1
        assert spark.table("spark_catalog.timeline_test.published_bundles").count() == 1
        assert spark.table("spark_catalog.timeline_test.ingestion_receipts").count() == 1
        export_dir = tmp_path / "ocsf"
        export_bundle(bundle, export_dir)
        export_signature = tmp_path / "export.sig.json"
        sign_artifact(
            export_dir,
            signer["private_key"],
            password,
            export_signature,
            trust,
            pin,
            kind="ocsf-export",
            source_bundle=bundle,
        )
        export_options = {**options, "signature": export_signature}
        for _ in range(2):
            ocsf = publish_ocsf_export(
                spark, export_dir, bundle, "spark_catalog", "timeline_test", **export_options
            )
            assert spark.table(ocsf["table"]).count() == 1
        assert spark.table("spark_catalog.timeline_test.published_ocsf_exports").count() == 1
        row = spark.table(ocsf["table"]).first()
        assert row.class_uid == 6003 and row.time == 1788256800000
        assert len(row.event_uuid) == 64
        assert spark.table("spark_catalog.timeline_test.ocsf_rejections").count() == 0
        assert spark.table("spark_catalog.timeline_test.signature_verifications").count() == 2
        from timeline_demo.parsers.common import file_hash

        inspected = inspect_publication(
            spark,
            bundle,
            file_hash(bundle / "audit_manifest.json"),
            "spark_catalog",
            "timeline_test",
            signature_options=options,
        )
        assert inspected["status"] == "publication_verified"
        assert inspected["signature_verification"]["key_id"] == key_id
        assert result["signature_verification"]["key_id"] == key_id
        # A real Delta write must also enforce and preserve the human review binding.
        from timeline_demo.ai import Harness
        from timeline_demo.integrations.databricks import publish_analysis
        from test_ai import FakeClient
        from test_ai_evidence import adjudicate, review_config

        harness = Harness(tmp_path / "ai.sqlite", client=FakeClient())
        action_id = harness.run(bundle, allow_ai=True)["action_id"]
        review_options = review_config(tmp_path)
        with pytest.raises(ValueError):
            publish_analysis(
                spark,
                {"action_id": action_id},
                "spark_catalog",
                "timeline_test",
                bundle=bundle,
                ledger=harness.path,
                **review_options,
            )
        harness.review(bundle, action_id, adjudicate(harness.inspect(bundle, action_id)), **review_options)
        accepted = harness.approved(bundle, action_id, **review_options)
        for _ in range(2):
            publish_analysis(
                spark,
                accepted,
                "spark_catalog",
                "timeline_test",
                bundle=bundle,
                ledger=harness.path,
                **review_options,
            )
        release = spark.table("spark_catalog.timeline_test.analysis_releases")
        assert release.count() == 1
        assert release.first().review_sha256 == accepted["human_review"]["digest"]
        assert release.first().human_review_required is False
        policy["keys"][key_id]["status"] = "revoked"
        revoked = tmp_path / "revoked.json"
        revoked_pin = write_trust(revoked, policy)["trust_store_sha256"]
        with pytest.raises(ValueError, match="revoked"):
            publish_bundle(
                spark,
                str(bundle),
                "spark_catalog",
                "timeline_test",
                **{**options, "trust_store": revoked, "trust_store_sha256": revoked_pin},
            )
        assert spark.table("spark_catalog.timeline_test.signature_verifications").count() == 2
    finally:
        spark.stop()
