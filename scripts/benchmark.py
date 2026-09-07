"""Reproducible synthetic workloads; isolated workers measure process peak RSS."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

from timeline_demo.ai import prepare
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.evaluation import score_sets
from timeline_demo.ocsf import export_bundle, verify_export
from timeline_demo.parsers.common import compact_json, file_hash
from timeline_demo.pipeline import Input, run_pipeline

ROOT = Path(__file__).resolve().parents[1]


def generate(path, count, shape):
    if not 1 <= count <= 1000000 or shape not in {"repeated", "diverse"}:
        raise ValueError("unsupported benchmark workload")
    with Path(path).open("x", encoding="utf-8") as stream:
        for index in range(count - 1, -1, -1):
            row = {
                "eventTime": datetime.fromtimestamp(1788256800 + index / 1000, timezone.utc).isoformat(
                    timespec="milliseconds"
                ),
                "eventName": "SyntheticAction" + str(index if shape == "diverse" else index % 4),
                "eventID": "synthetic-" + str(index),
                "eventSource": "synthetic.example.test",
                "userIdentity": {"userName": "analyst", "type": "IAMUser"},
                "sourceIPAddress": str(
                    IPv4Address(
                        int(IPv4Address("198.18.0.1")) + (index % 131070 if shape == "diverse" else index % 4)
                    )
                ),
            }
            line = compact_json(row) + "\n"
            stream.write(line)
            if index % 10 == 0:
                stream.write(line)
    return {"unique_events": count, "source_records": count + (count + 9) // 10}


def timed(fn):
    start = time.perf_counter()
    result = fn()
    return result, round(time.perf_counter() - start, 6)


def worker(count, shape, ocsf_max_events):
    import resource

    with tempfile.TemporaryDirectory(prefix="timeline-benchmark-") as temporary:
        root = Path(temporary)
        source, bundle = root / "cloudtrail.jsonl", root / "bundle"
        truth = generate(source, count, shape)
        manifest, ingest_s = timed(
            lambda: run_pipeline([Input("cloudtrail", source)], bundle, "synthetic-benchmark")
        )
        _, verify_s = timed(lambda: verify_bundle(bundle))
        assert manifest["counts"]["event_count"] == truth["unique_events"]
        assert manifest["counts"]["source_records"] == truth["source_records"]
        assert manifest["counts"]["duplicate_events"] == truth["source_records"] - count
        plan, prepare_s = timed(lambda: prepare(bundle))
        export_s = export_verify_s = None
        if count <= ocsf_max_events:
            exported, export_s = timed(lambda: export_bundle(bundle, root / "ocsf"))
            assert exported["counts"]["exported_events"] == count
            _, export_verify_s = timed(lambda: verify_export(root / "ocsf", bundle=bundle))
        iocs = json.loads((bundle / "extracted_iocs.json").read_text())
        expected_ips = {
            str(IPv4Address(int(IPv4Address("198.18.0.1")) + index))
            for index in range(min(count, 131070 if shape == "diverse" else 4))
        }
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {
            "shape": shape,
            **truth,
            "source_sha256": file_hash(source),
            "source_bytes": source.stat().st_size,
            "bundle_bytes": sum(p.stat().st_size for p in bundle.rglob("*") if p.is_file()),
            "timeline_bytes": (bundle / "timeline.jsonl").stat().st_size,
            "ingest_seconds": ingest_s,
            "verify_seconds": verify_s,
            "ai_prepare_seconds": prepare_s,
            "ocsf_export_seconds": export_s,
            "ocsf_verify_seconds": export_verify_s,
            "process_peak_rss_mib": round(peak / (1024 * 1024 if sys.platform == "darwin" else 1024), 3),
            "events_per_second": round(count / ingest_s, 2),
            "ai_input_token_upper_bound": plan["input_token_bound"],
            "ai_request_bytes": len(compact_json(plan["request"]).encode()),
            "ai_coverage": plan["coverage"],
            "ioc_ip_metrics": score_sets(iocs["ips"], expected_ips),
            "model_tokens": 0,
        }


def provenance():
    source_paths = sorted(
        [
            *ROOT.glob("src/timeline_demo/**/*.py"),
            *ROOT.glob("src/timeline_demo/resources/**/*.json"),
            Path(__file__),
        ]
    )
    hashes = {p.relative_to(ROOT).as_posix(): file_hash(p) for p in source_paths}
    try:
        base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        base, dirty = None, None
    cpu = platform.processor()
    if Path("/proc/cpuinfo").exists():
        cpu = next(
            (
                line.split(":", 1)[1].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")
            ),
            cpu,
        )
    cgroup = {}
    for name in ("cpu.max", "memory.max"):
        p = Path("/sys/fs/cgroup") / name
        if p.exists():
            cgroup[name] = p.read_text().strip()
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu": cpu,
        "logical_cpus_visible": os.cpu_count(),
        "cgroup_limits": cgroup,
        "package_version": importlib.metadata.version("forensic-timeline-ai-demo"),
        "base_commit": base,
        "working_tree_dirty": dirty,
        "source_files_sha256": hashes,
        "source_set_sha256": hashlib.sha256(compact_json(hashes).encode()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="1000,10000,100000")
    parser.add_argument("--shapes", default="repeated,diverse")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--ocsf-max-events", type=int, default=1000)
    parser.add_argument("--output")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(int(args.sizes), args.shapes, args.ocsf_max_events)))
        return
    if not args.output or not 1 <= args.repeats <= 10:
        parser.error("output and 1..10 repeats required")
    if Path(args.output).exists():
        raise FileExistsError(args.output)
    report = {
        "benchmark_version": "1.0",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "environment": provenance(),
        "ocsf_max_events": args.ocsf_max_events,
        "scope": "synthetic offline JSONL; sequential fresh processes; one warm storage environment; no network/provider/model performance",
        "runs": [],
    }
    for shape in args.shapes.split(","):
        for size in args.sizes.split(","):
            for repeat in range(args.repeats):
                command = [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    "--sizes",
                    size,
                    "--shapes",
                    shape,
                    "--ocsf-max-events",
                    str(args.ocsf_max_events),
                ]
                value = json.loads(subprocess.check_output(command, cwd=ROOT, text=True, timeout=900))
                report["runs"].append({"repeat": repeat + 1, **value})
                print(
                    f"{shape} {size}: {value['ingest_seconds']:.3f}s, {value['process_peak_rss_mib']:.1f} MiB",
                    flush=True,
                )
    with Path(args.output).open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
