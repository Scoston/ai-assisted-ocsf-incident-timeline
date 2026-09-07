"""Portable artifact integrity. Hashes do not establish source authenticity."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

from timeline_demo.parsers.common import compact_json, file_hash, sha256_of_text

DIGEST = re.compile(r"[a-f0-9]{64}\Z")
REQUIRED = {"timeline.jsonl", "timeline.csv", "receipts.jsonl", "quarantine.jsonl", "extracted_iocs.json"}


def safe_member(root, name):
    rel = PurePosixPath(name)
    if not name or rel.is_absolute() or ".." in rel.parts or "\\" in name:
        raise ValueError("unsafe bundle member")
    path = Path(root).joinpath(*rel.parts)
    if not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError("bundle member escapes root")
    if any(p.is_symlink() for p in [path, *path.parents] if p != Path(root).parent):
        raise ValueError("symlinks are not allowed in bundles")
    return path


def write_manifest(metadata, output_dir):
    root = Path(output_dir)
    files = {
        p.relative_to(root).as_posix(): {"sha256": file_hash(p), "bytes": p.stat().st_size}
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.name != "audit_manifest.json"
    }
    manifest = {"manifest_version": "2.0", **metadata, "files": files}
    manifest["bundle_id"] = sha256_of_text(compact_json(manifest))
    (root / "audit_manifest.json").write_text(compact_json(manifest) + "\n", encoding="utf-8")
    return manifest


def verify_bundle(root, expected_manifest_sha256=None):
    root = Path(root)
    path = safe_member(root, "audit_manifest.json")
    if expected_manifest_sha256 and file_hash(path) != expected_manifest_sha256:
        raise ValueError("manifest does not match the independently supplied SHA-256")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != "2.0" or not isinstance(manifest.get("files"), dict):
        raise ValueError("unsupported manifest")
    body = {k: v for k, v in manifest.items() if k != "bundle_id"}
    if sha256_of_text(compact_json(body)) != manifest.get("bundle_id"):
        raise ValueError("bundle identity mismatch")
    if not REQUIRED <= set(manifest["files"]):
        raise ValueError("bundle is missing required artifacts")
    expected = set(manifest["files"]) | {"audit_manifest.json"}
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    if actual != expected:
        raise ValueError("unlisted or missing bundle artifacts")
    for name, entry in manifest["files"].items():
        member = safe_member(root, name)
        if not isinstance(entry, dict) or not DIGEST.fullmatch(str(entry.get("sha256", ""))):
            raise ValueError("invalid manifest file entry")
        if member.stat().st_size != entry.get("bytes") or file_hash(member) != entry["sha256"]:
            raise ValueError("artifact integrity failure: " + name)
    return manifest
