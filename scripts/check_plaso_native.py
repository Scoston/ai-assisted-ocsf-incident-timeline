"""CI: real log2timeline -> storage -> psort -> verified bundle, using upstream fixtures."""

import argparse
from contextlib import contextmanager
import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from timeline_demo.core.manifest import verify_bundle
from timeline_demo.integrations.plaso import DEFAULT_IMAGE, DockerBackend, NativeLimits, ingest_native
from timeline_demo.pipeline import read_timeline

# Each family must produce its native event type, beyond generic file metadata.
FIXTURES = {
    "evtx/System.evtx": "windows:evtx:record",
    "example.lnk": "windows:lnk:link",
    "firefox/places.sqlite": "firefox:places:page_visited",
    "plist/History.plist": "safari:history:visit",
    "esxi.log": "vmware:esxi:log:entry",
    "systemd/journal/system.journal": "systemd:journal",
    "winprefetch/NOTEPAD.EXE-D8414F97.pf": "windows:prefetch:execution",
    "regf/NTUSER.DAT": "windows:registry:key_value",
    "syslog.gz": "syslog:line",
}


@contextmanager
def fixture_work():
    with tempfile.TemporaryDirectory(prefix="timeline-plaso-ci-") as directory:
        try:
            yield directory
        except BaseException:
            # CI sources are public upstream fixtures only. Expose bounded tool
            # diagnostics so an integration failure can be fixed, then clean up.
            for path in sorted(Path(directory).rglob("*.stderr")):
                print(path.relative_to(directory), path.read_text(errors="replace")[-4000:])
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).absolute()
    output.mkdir(parents=True, exist_ok=True)
    backend = DockerBackend(args.image)
    image_id = backend.resolve()
    # Never run the fixture-copy container. Sources and their license stay pinned
    # in the image, without placing third-party evidence in this repository.
    container = "timeline-plaso-fixtures-" + uuid.uuid4().hex
    subprocess.run(["docker", "create", "--name", container, image_id], check=True, capture_output=True)
    try:
        with fixture_work() as directory:
            root = Path(directory)
            source = root / "fixtures"
            source.mkdir()
            for name in [*FIXTURES, "syslog_image.dd"]:
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["docker", "cp", container + ":/opt/plaso-source/test_data/" + name, str(destination)],
                    check=True,
                )
            disk = root / "syslog_image.dd"
            (source / disk.name).rename(disk)
            result = ingest_native(
                source,
                root / "work",
                root / "bundle",
                "plaso-native-ci",
                image=args.image,
                allow_partial=True,
                year=2012,
                native_limits=NativeLimits(timeout_seconds=600),
            )
            events = list(read_timeline(root / "bundle"))
            data_types = {e["metadata"]["plaso"]["data_type"] for e in events}
            missing = set(FIXTURES.values()) - data_types
            if missing:
                raise ValueError("native fixture families missing: " + ", ".join(sorted(missing)))
            receipt = json.loads((root / "work/receipt.json").read_text())
            assert receipt["storage"]["events"] == receipt["exported_records"]
            assert verify_bundle(root / "bundle")["counts"] == result["counts"]
            # Read-only import of the resulting storage must preserve event IDs.
            imported = ingest_native(
                root / "work/runtime/collection.plaso",
                root / "import-work",
                root / "import-bundle",
                "plaso-storage-ci",
                image=args.image,
                storage_file=True,
                allow_partial=True,
            )
            assert {e["event_uuid"] for e in read_timeline(root / "import-bundle")} == {
                e["event_uuid"] for e in events
            }
            image_result = ingest_native(
                disk,
                root / "image-work",
                root / "image-bundle",
                "plaso-image-ci",
                image=args.image,
                allow_partial=True,
                year=2012,
                native_limits=NativeLimits(timeout_seconds=600),
            )
            image_types = {e["metadata"]["plaso"]["data_type"] for e in read_timeline(root / "image-bundle")}
            assert "syslog:line" in image_types, image_types
            report = {
                "native": result,
                "storage_import": imported,
                "disk_image": image_result,
                "fixture_data_types": sorted(data_types),
                "storage": receipt["storage"],
                "limitations": "Representative end-to-end fixtures; see upstream parser-suite skips separately.",
            }
            # Retain validation summaries only; upstream artifacts can contain
            # realistic historical data and must not become public CI artifacts.
            (output / "native-report.json").write_text(json.dumps(report, indent=2) + "\n")
            shutil.copyfile(root / "work/runtime/inventory.stdout", output / "backend-inventory.json")
            print(
                json.dumps(
                    {
                        "native_counts": result["counts"],
                        "image_counts": image_result["counts"],
                        "coverage": result["parser_coverage"],
                    }
                )
            )
    finally:
        subprocess.run(["docker", "rm", "--force", container], check=False, capture_output=True)


if __name__ == "__main__":
    main()
