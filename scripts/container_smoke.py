"""Exercise installed release artifacts with no network and a read-only container root."""

import json
import os
from pathlib import Path
from importlib.metadata import version

from timeline_demo.ai import Harness
from timeline_demo.collection import collect_window
from timeline_demo.collection.providers import Page
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.ocsf import export_bundle, verify_export
from timeline_demo.operations import backup, health, restore
from timeline_demo.pipeline import Input, run_pipeline


def main():
    assert os.getuid() == 10001
    root = Path("/data")
    bundle = root / "offline"
    run_pipeline([Input("cloudtrail", "/samples/raw/aws/cloudtrail_real_sample.json")], bundle, "container")
    assert verify_bundle(bundle)["counts"]["event_count"] > 0
    export_bundle(bundle, root / "ocsf")
    verify_export(root / "ocsf", bundle=bundle)
    assert Harness(root / "ledger.sqlite").run(bundle)["status"] == "planned"
    assert (root / "ledger.sqlite").is_file()  # Planning is also audited, with no model dispatch.

    class EmptySource:
        parser = "entra_signin"
        identity = {"source": "entra_signin", "source_id": "container-synthetic"}
        interval = 0

        def fetch(self, *args):
            return Page(b'{"value":[]}', [], None)

    args = (
        EmptySource(),
        root / "state",
        root / "collected",
        "container-collector",
        "2026-09-01T10:00:00Z",
        "2026-09-01T11:00:00Z",
    )
    collect_window(*args)
    snapshot = backup(root / "state", root / "backup")
    restore(root / "backup", root / "restored", snapshot["snapshot_sha256"])
    assert health(root / "restored", verify_blobs=True, verify_bundles=True)["healthy"]
    print(
        json.dumps(
            {
                "status": "passed",
                "version": version("forensic-timeline-ai-demo"),
                "model_tokens": 0,
                "uid": os.getuid(),
            }
        )
    )


if __name__ == "__main__":
    main()
