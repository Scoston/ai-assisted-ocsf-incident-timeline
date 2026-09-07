"""Evidence-preserving bridge to the complete pinned Plaso parser collection."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from zoneinfo import ZoneInfo

from timeline_demo.core.manifest import regular_members, verify_bundle
from timeline_demo.core.storage import no_links, private_file
from timeline_demo.parsers.common import compact_json, file_hash
from timeline_demo.parsers.readers import _strict_json, iter_records
from timeline_demo.pipeline import Input, Limits, run_pipeline

DEFAULT_IMAGE = "timeline-plaso:20260720-00fcc6e"
WARNING_TYPES = (
    "extraction_warning",
    "preprocessing_warning",
    "recovery_warning",
    "timelining_warning",
    "analysis_warning",
)


def catalog():
    return _strict_json(files("timeline_demo").joinpath("resources/plaso_catalog.json").read_text())


def check_inventory(actual):
    expected = catalog()
    if (
        not isinstance(actual, dict)
        or actual.get("version") != expected["upstream_version"]
        or actual.get("entries") != [e["id"] for e in expected["entries"]]
        or actual.get("source_hashes") != expected["source_hashes"]
    ):
        raise ValueError("Plaso backend does not match the complete pinned parser inventory")
    return {
        kind: sum(e["kind"] == kind for e in expected["entries"])
        for kind in ("parser", "plugin", "cookie_plugin")
    }


@dataclass(frozen=True)
class NativeLimits:
    max_source_bytes: int = 10 * 1024**3
    max_work_bytes: int = 20 * 1024**3
    max_source_files: int = 10000
    timeout_seconds: int = 3600
    memory_mb: int = 4096

    def __post_init__(self):
        if any(type(v) is not int or v < 1 for v in vars(self).values()):
            raise ValueError("positive integer Plaso limits are required")


def _write(path, value):
    private_file(path)
    path.write_text(compact_json(value) + "\n", encoding="utf-8")


def _json_result(path):
    with path.open("rb") as stream:
        raw = stream.read(8 * 1024**2 + 1)
    if len(raw) > 8 * 1024**2:
        raise ValueError("Plaso metadata exceeds its size limit")
    return _strict_json(raw)


def _size(root):
    return sum((root / name).stat().st_size for name in regular_members(root))


class DockerBackend:
    """Resolve one local immutable image ID; never pull or execute via a shell."""

    def __init__(self, image=DEFAULT_IMAGE, executable="docker"):
        if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}", image):
            raise ValueError("invalid Plaso image reference")
        self.image = image
        self.executable = executable
        self.image_id = None

    def resolve(self):
        try:
            result = subprocess.run(
                [self.executable, "image", "inspect", "--format", "{{.Id}}", self.image],
                check=True,
                capture_output=True,
                timeout=30,
                text=True,
            )
        except (OSError, subprocess.SubprocessError):
            raise ValueError(
                "build or load the approved Plaso image in the local Docker engine first"
            ) from None
        image_id = result.stdout.strip()
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
            raise ValueError("Docker did not return an immutable image ID")
        self.image_id = image_id
        return image_id

    def command(self, name, runtime, source, entrypoint, args, limits):
        if self.image_id is None:
            raise ValueError("resolve the Plaso image before execution")
        if os.name != "posix":
            raise ValueError("use a Linux/WSL collector host for native Plaso execution")
        for path in (runtime, source):
            if any(c in str(path) for c in (",", "\n", "\r")):
                raise ValueError("Docker mount paths cannot contain commas or newlines")
        return [
            self.executable,
            "run",
            "--rm",
            "--pull=never",
            "--name",
            name,
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--pids-limit=256",
            "--memory",
            f"{limits.memory_mb}m",
            "--memory-swap",
            f"{limits.memory_mb}m",
            "--cpus=2",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=268435456,mode=1777",
            "--workdir=/work",
            "--tmpfs",
            "/data:ro,nosuid,nodev,size=1024,mode=555",
            "--mount",
            f"type=bind,src={runtime},dst=/work",
            "--mount",
            f"type=bind,src={source},dst=/source,readonly",
            "--entrypoint",
            entrypoint,
            self.image_id,
            *args,
        ]

    def run(self, phase, runtime, source, entrypoint, args, limits):
        name = "timeline-plaso-" + uuid.uuid4().hex
        command = self.command(name, runtime, source, entrypoint, args, limits)
        _write(runtime / (phase + ".command.json"), command)
        stdout, stderr = runtime / (phase + ".stdout"), runtime / (phase + ".stderr")
        private_file(stdout)
        private_file(stderr)
        process = None
        try:
            with stdout.open("wb") as out, stderr.open("wb") as err:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
                start = time.monotonic()
                while process.poll() is None:
                    if time.monotonic() - start > limits.timeout_seconds:
                        raise ValueError("Plaso phase exceeded its time budget; retained work is incomplete")
                    if (
                        _size(runtime) > limits.max_work_bytes
                        or max(stdout.stat().st_size, stderr.stat().st_size) > 8 * 1024**2
                    ):
                        raise ValueError(
                            "Plaso phase exceeded its disk/log budget; retained work is incomplete"
                        )
                    time.sleep(0.25)
                if process.returncode:
                    raise ValueError(f"Plaso {phase} phase failed; inspect the retained private work logs")
            if (
                _size(runtime) > limits.max_work_bytes
                or max(stdout.stat().st_size, stderr.stat().st_size) > 8 * 1024**2
            ):
                raise ValueError("Plaso phase exceeded its disk/log budget")
        finally:
            if process is not None and process.poll() is None:
                # Terminating the Docker CLI alone can leave its container running.
                try:
                    subprocess.run(
                        [self.executable, "rm", "--force", name],
                        timeout=15,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                finally:
                    process.kill()
                    process.wait(timeout=15)
        return stdout


def _source_names(source, maximum):
    if not source.is_dir():
        return [source.name]
    names, seen = [], 0
    # Evidence names such as $UsnJrnl:$J are valid on acquisition hosts. Bundle
    # attachments use content hashes, so manifest path restrictions need not
    # discard those names. Refuse links, devices and unbounded directory trees.
    pending = [source]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                seen += 1
                if seen > maximum * 2:
                    raise ValueError("Plaso source directory entry budget exceeded")
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    pending.append(Path(entry.path))
                elif stat.S_ISREG(mode):
                    names.append(Path(entry.path).relative_to(source).as_posix())
                    if len(names) > maximum:
                        raise ValueError("Plaso source file count budget exceeded")
                else:
                    raise ValueError("Plaso source cannot contain links or special files")
    return sorted(names)


def _snapshot(source, target, limits):
    names = _source_names(source, limits.max_source_files)
    if not names or len(names) > limits.max_source_files:
        raise ValueError("Plaso source is empty or exceeds the file count budget")
    total, records = 0, []
    for name in names:
        original = source / name if source.is_dir() else source
        original = no_links(original)
        if not original.is_file():
            raise ValueError("Plaso source must contain regular files or acquired images")
        before = original.stat()
        copied = target / name
        copied.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        private_file(copied)
        digest = hashlib.sha256()
        with original.open("rb") as reader, copied.open("wb") as writer:
            while block := reader.read(1024**2):
                total += len(block)
                if total > limits.max_source_bytes:
                    raise ValueError("Plaso source byte budget exceeded")
                digest.update(block)
                writer.write(block)
        after = original.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("Plaso source changed during acquisition")
        os.utime(copied, ns=(before.st_atime_ns, before.st_mtime_ns))
        records.append(
            {
                "path": name,
                "sha256": digest.hexdigest(),
                "bytes": before.st_size,
                "mtime_ns": before.st_mtime_ns,
                "ctime_ns": before.st_ctime_ns,
                "mode": before.st_mode,
                "attachment": "attachments/plaso/sources/" + digest.hexdigest(),
            }
        )
    return records


def ingest_native(
    source,
    work,
    output,
    case_id,
    *,
    image=DEFAULT_IMAGE,
    storage_file=False,
    entry_point=None,
    timezone="UTC",
    year=None,
    allow_partial=False,
    native_limits=None,
    limits=None,
    backend=None,
):
    native_limits, limits = native_limits or NativeLimits(), limits or Limits()
    source, work, output = no_links(source), no_links(work), no_links(output)
    ZoneInfo(timezone)
    if year is not None and (type(year) is not int or not 1 <= year <= 9999):
        raise ValueError("invalid Plaso base year")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", case_id):
        raise ValueError("invalid Plaso case ID")
    if work.exists() or output.exists() or not source.exists():
        raise ValueError("Plaso requires an existing source and new work/output directories")
    for a, b in ((source, work), (source, output), (work, output)):
        if a.is_relative_to(b) or b.is_relative_to(a):
            raise ValueError("Plaso source, work and output must be separate")
    if storage_file and not source.is_file():
        raise ValueError("Plaso storage import requires one storage file")
    if entry_point is not None:
        entry = Path(entry_point)
        if (
            not source.is_dir()
            or storage_file
            or entry.is_absolute()
            or ".." in entry.parts
            or not entry.parts
            or not no_links(source / entry).is_file()
        ):
            raise ValueError("Plaso entry point must name an acquired file within the source directory")
        entry_point = entry.as_posix()
    backend = backend or DockerBackend(image)
    image_id = backend.resolve()
    work.mkdir(parents=True, mode=0o700)
    snapshot, runtime = work / "source", work / "runtime"
    snapshot.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    receipt = {
        "version": "1.0",
        "case_id": case_id,
        "image_id": image_id,
        "upstream_commit": catalog()["upstream_commit"],
        "status": "started",
        "source_completeness_proven": False,
        "model_tokens": 0,
        "timezone": timezone,
        "base_year": year,
        "entry_point": entry_point,
        "allow_partial": allow_partial,
        "host_filestat_basis": "staged-copy metadata; original host stat is inventoried separately",
    }
    try:
        records = _snapshot(source, snapshot, native_limits)
        _write(work / "source_inventory.json", records)
        inventory_path = backend.run(
            "inventory",
            runtime,
            snapshot,
            "python3",
            ["/opt/timeline-plaso/probe.py", "inventory"],
            native_limits,
        )
        receipt["parser_coverage"] = check_inventory(_json_result(inventory_path))
        storage = "/source/" + source.name if storage_file else "/work/collection.plaso"
        if not storage_file:
            names = [e["name"] for e in catalog()["entries"] if e["kind"] == "parser"]
            args = [
                "--unattended",
                "--single-process",
                "--status-view=none",
                "--data=/opt/plaso-source/plaso/data",
                "--parsers=" + ",".join(names),
                "--timezone=" + timezone,
                "--partitions=all",
                "--vss-stores=all",
                "--storage-file=" + storage,
            ]
            if year is not None:
                args.append("--preferred-year=" + str(year))
            args.append(
                "/source/" + entry_point
                if entry_point
                else "/source"
                if source.is_dir()
                else "/source/" + source.name
            )
            backend.run("extract", runtime, snapshot, "/usr/bin/log2timeline.py", args, native_limits)
        stats_path = backend.run(
            "statistics",
            runtime,
            snapshot,
            "python3",
            ["/opt/timeline-plaso/probe.py", "statistics", storage],
            native_limits,
        )
        stats = _json_result(stats_path)
        if (
            not isinstance(stats, dict)
            or type(stats.get("events")) is not int
            or stats["events"] < 0
            or not isinstance(stats.get("warnings"), dict)
            or set(stats["warnings"]) != set(WARNING_TYPES)
            or any(type(v) is not int or v < 0 for v in stats["warnings"].values())
            or not isinstance(stats.get("sessions"), list)
            or not stats["sessions"]
        ):
            raise ValueError("invalid Plaso storage statistics")
        if any(not isinstance(s, dict) for s in stats["sessions"]):
            raise ValueError("invalid Plaso storage sessions")
        incomplete = any(stats["warnings"].values()) or any(
            s.get("aborted") is not False
            or type(s.get("completion_time")) is not int
            or s["completion_time"] <= 0
            for s in stats["sessions"]
        )
        receipt["storage"] = stats
        if incomplete and not allow_partial:
            raise ValueError(
                "Plaso reports warnings or incomplete sessions; review before allowing partial evidence"
            )
        if stats["events"] > limits.max_records:
            raise ValueError("Plaso event count exceeds ingestion budget")
        backend.run(
            "export",
            runtime,
            snapshot,
            "/usr/bin/psort.py",
            [
                "--status-view=none",
                "--data=/opt/plaso-source/plaso/data",
                "--include-all",
                "-o",
                "json_line",
                "-w",
                "/work/events.jsonl",
                storage,
            ],
            native_limits,
        )
        exported = runtime / "events.jsonl"
        count = 0
        for _ in iter_records(exported, "plaso_event"):
            count += 1
            if count > limits.max_records:
                raise ValueError("Plaso export exceeds the record budget")
        if count != stats["events"]:
            raise ValueError("Plaso export count differs from stored events; publication blocked")
        for entry in records:
            if file_hash(snapshot / entry["path"]) != entry["sha256"]:
                raise ValueError("staged Plaso evidence changed")
        receipt.update(
            {
                "status": "partial" if incomplete else "extracted",
                "exported_records": count,
                "export_sha256": file_hash(exported),
            }
        )
        _write(work / "receipt.json", receipt)
        catalog_path = work / "catalog.json"
        _write(catalog_path, catalog())
        attachments = {entry["attachment"]: snapshot / entry["path"] for entry in records}
        attachments.update(
            {
                "attachments/plaso/receipt.json": work / "receipt.json",
                "attachments/plaso/source_inventory.json": work / "source_inventory.json",
                "attachments/plaso/catalog.json": catalog_path,
            }
        )
        if not storage_file:
            attachments["attachments/plaso/collection.plaso"] = runtime / "collection.plaso"
        for name in regular_members(runtime):
            if name not in {"events.jsonl", "collection.plaso"}:
                attachments["attachments/plaso/runtime/" + name] = runtime / name
        manifest = run_pipeline(
            [Input("plaso_event", exported)],
            output,
            case_id,
            quarantine=allow_partial,
            attachments=attachments,
            limits=limits,
        )
        verify_bundle(output)
        return {
            "status": "partial" if incomplete or manifest["counts"]["quarantined_records"] else "completed",
            "bundle": str(output),
            "bundle_id": manifest["bundle_id"],
            "counts": manifest["counts"],
            "manifest_sha256": file_hash(output / "audit_manifest.json"),
            "work": str(work),
            "parser_coverage": receipt["parser_coverage"],
            "model_tokens": 0,
        }
    except BaseException as exc:
        receipt.update({"status": "failed", "error_type": type(exc).__name__})
        _write(work / "failure.json", receipt)
        raise
