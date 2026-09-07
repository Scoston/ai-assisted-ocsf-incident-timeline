"""Verify that the distribution contains all hash-pinned OCSF resources."""

import hashlib
import json
import sys
import zipfile
from pathlib import Path


def main():
    wheel = Path(sys.argv[1])
    prefix = "timeline_demo/resources/ocsf/1.3.0/"
    with zipfile.ZipFile(wheel) as archive:
        lock = json.loads(archive.read(prefix + "schema-lock.json"))
        for entry in lock["classes"].values():
            data = archive.read(prefix + entry["file"])
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("wheel schema hash mismatch: " + entry["file"])
        for name in ["LICENSE", "NOTICE"]:
            if not archive.read(prefix + name):
                raise ValueError("missing schema license/notice")
        archive.read("timeline_demo/resources/ocsf_export_manifest.schema.json")
        archive.read("timeline_demo/resources/evidence_analysis.schema.json")
        catalog = json.loads(archive.read("timeline_demo/resources/plaso_catalog.json"))
        assert len(catalog["entries"]) == 249
        archive.read("timeline_demo/resources/plaso_NOTICE.txt")
    print(f"{wheel.name}: {len(lock['classes'])} pinned OCSF schemas and notices verified")


if __name__ == "__main__":
    main()
