"""Portable artifact integrity. Hashes do not establish source authenticity."""

from __future__ import annotations

import os
import re
import stat
import hashlib
from pathlib import Path, PurePosixPath

from timeline_demo.parsers.common import compact_json, file_hash, sha256_of_text
from timeline_demo.parsers.readers import _strict_json

DIGEST = re.compile(r"[a-f0-9]{64}\Z")
REQUIRED = {"timeline.jsonl", "timeline.csv", "receipts.jsonl", "quarantine.jsonl", "extracted_iocs.json"}
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 100000


def safe_member(root, name):
    if not isinstance(name, str) or len(name) > 1024 or any(ord(c) < 32 for c in name):
        raise ValueError("unsafe bundle member")
    rel = PurePosixPath(name)
    if (
        not name
        or rel.is_absolute()
        or ".." in rel.parts
        or "\\" in name
        or ":" in name
        or rel.as_posix() != name
        or name == "."
    ):
        raise ValueError("unsafe bundle member")
    path = Path(root).joinpath(*rel.parts)
    if not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError("bundle member escapes root")
    if any(p.is_symlink() for p in [path, *path.parents] if p != Path(root).parent):
        raise ValueError("symlinks are not allowed in bundles")
    return path


def regular_members(root):
    """Reject special files before opening anything, including FIFOs and directory links."""
    root = Path(root)
    safe_member(root, "audit_manifest.json")
    found = set()
    seen = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = Path(directory) / name
            seen += 1
            if seen > MAX_MEMBERS:
                raise ValueError("bundle has too many members")
            mode = path.lstat().st_mode
            rel = path.relative_to(root).as_posix()
            safe_member(root, rel)
            if stat.S_ISREG(mode):
                found.add(rel)
            elif not stat.S_ISDIR(mode):
                raise ValueError("bundle contains a symlink or special file")
            if len(found) > MAX_MEMBERS:
                raise ValueError("bundle has too many members")
    return found


def parse_manifest(raw):
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds size limit")
    manifest = _strict_json(raw)
    if not isinstance(manifest, dict) or manifest.get("manifest_version") != "2.0":
        raise ValueError("unsupported manifest")
    entries = manifest.get("files")
    if not isinstance(entries, dict) or not REQUIRED <= set(entries) or len(entries) > MAX_MEMBERS:
        raise ValueError("bundle is missing required artifacts or has too many members")
    if "audit_manifest.json" in entries:
        raise ValueError("manifest cannot list itself")
    for name, entry in entries.items():
        # Validate paths without depending on a download destination's current contents.
        if not isinstance(entry, dict) or set(entry) != {"sha256", "bytes"}:
            raise ValueError("invalid manifest file entry")
        if (
            not isinstance(entry["sha256"], str)
            or not DIGEST.fullmatch(entry["sha256"])
            or type(entry["bytes"]) is not int
            or entry["bytes"] < 0
        ):
            raise ValueError("invalid manifest file entry")
        if not isinstance(name, str):
            raise ValueError("invalid manifest member")
    if not isinstance(manifest.get("case_id"), str) or not isinstance(manifest.get("counts"), dict):
        raise ValueError("invalid manifest metadata")
    required_counts = {
        "event_count",
        "source_records",
        "emitted_events",
        "quarantined_records",
        "duplicate_events",
    }
    if not required_counts <= set(manifest["counts"]) or any(
        type(n) is not int or n < 0 for n in manifest["counts"].values()
    ):
        raise ValueError("invalid manifest counts")
    if not isinstance(manifest.get("inputs"), list) or not manifest["inputs"]:
        raise ValueError("manifest input provenance is missing")
    for source in manifest["inputs"]:
        if not isinstance(source, dict) or not isinstance(source.get("evidence_path"), str):
            raise ValueError("invalid input provenance")
        entry = entries.get(source["evidence_path"], {})
        if (
            not entry
            or entry.get("sha256") != source.get("sha256")
            or entry.get("bytes") != source.get("bytes")
        ):
            raise ValueError("input provenance differs from archived artifact")
    body = {k: v for k, v in manifest.items() if k != "bundle_id"}
    if sha256_of_text(compact_json(body)) != manifest.get("bundle_id"):
        raise ValueError("bundle identity mismatch")
    return manifest


def write_manifest(metadata, output_dir):
    root = Path(output_dir)
    files = {
        name: {"sha256": file_hash(root / name), "bytes": (root / name).stat().st_size}
        for name in sorted(regular_members(root) - {"audit_manifest.json"})
    }
    manifest = {"manifest_version": "2.0", **metadata, "files": files}
    manifest["bundle_id"] = sha256_of_text(compact_json(manifest))
    (root / "audit_manifest.json").write_text(compact_json(manifest) + "\n", encoding="utf-8")
    return manifest


def verify_bundle(root, expected_manifest_sha256=None):
    root = Path(root)
    path = safe_member(root, "audit_manifest.json")
    actual = regular_members(root)
    if "audit_manifest.json" not in actual:
        raise ValueError("bundle manifest is missing")
    with path.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if expected_manifest_sha256 and hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise ValueError("manifest does not match the independently supplied SHA-256")
    manifest = parse_manifest(raw)
    expected = set(manifest["files"]) | {"audit_manifest.json"}
    if actual != expected:
        raise ValueError("unlisted or missing bundle artifacts")
    for name, entry in manifest["files"].items():
        member = safe_member(root, name)
        if not isinstance(entry, dict) or not DIGEST.fullmatch(str(entry.get("sha256", ""))):
            raise ValueError("invalid manifest file entry")
        if member.stat().st_size != entry.get("bytes") or file_hash(member) != entry["sha256"]:
            raise ValueError("artifact integrity failure: " + name)
    return manifest
