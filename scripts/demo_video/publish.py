"""Publish only a hash-pinned, reviewed candidate; never rebuild during promotion."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

TAG = "demo-v0.13.0"


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True, timeout=180)


def main():
    approval = json.loads(Path("demos/v0.13.0/approved.json").read_text())
    asset = approval["candidate_asset"]
    if not re.fullmatch(r"candidate-[0-9a-f]{40}\.zip", asset):
        raise ValueError("Invalid reviewed candidate name")
    if not re.fullmatch(r"[0-9a-f]{64}", approval["candidate_sha256"]):
        raise ValueError("Invalid review digest")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        gh("release", "download", TAG, "--pattern", asset, "--dir", str(root))
        candidate = root / asset
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != approval["candidate_sha256"]:
            raise ValueError("Candidate changed after review")
        output = root / "verified"
        output.mkdir()
        expected = approval["files"]
        with zipfile.ZipFile(candidate) as archive:
            if len(archive.namelist()) != len(expected) or set(archive.namelist()) != set(expected):
                raise ValueError("Candidate members differ from the reviewed inventory")
            for info in archive.infolist():
                if not re.fullmatch(r"[A-Za-z0-9_.-]+", info.filename) or info.file_size > 500_000_000:
                    raise ValueError("Unsafe media member")
                data = archive.read(info)
                if hashlib.sha256(data).hexdigest() != expected[info.filename]:
                    raise ValueError("Media checksum mismatch")
                (output / info.filename).write_bytes(data)
        provenance = json.loads((output / "timeline-v0.13.0-demo-provenance.json").read_text())
        if provenance["build_commit"] != approval["candidate_commit"]:
            raise ValueError("Unexpected source commit")
        release = json.loads(gh("release", "view", TAG, "--json", "assets"))
        existing = {a["name"] for a in release["assets"]}
        for path in sorted(output.iterdir()):
            if path.name in existing:
                downloaded = root / "existing" / path.name
                downloaded.parent.mkdir(exist_ok=True)
                gh("release", "download", TAG, "--pattern", path.name, "--dir", str(downloaded.parent))
                if hashlib.sha256(downloaded.read_bytes()).hexdigest() != expected[path.name]:
                    raise ValueError("Existing release file conflicts with reviewed media")
            else:
                gh("release", "upload", TAG, str(path))
        gh("release", "edit", TAG, "--title", "v0.13.0 — complete feature demo", "--prerelease=false",
           "--latest=false", "--notes-file", "demos/v0.13.0/release-notes.md")
        print("Published reviewed MP4 and companion files to", TAG)


if __name__ == "__main__":
    main()
