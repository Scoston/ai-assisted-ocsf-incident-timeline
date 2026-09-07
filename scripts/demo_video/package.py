"""Package synthetic capture evidence alongside the finished media files."""

import hashlib
from pathlib import Path
import zipfile

root = Path("output/demo-video")
deliver = root / "deliverables"
with zipfile.ZipFile(deliver / "timeline-v0.13.0-demo-sources.zip", "x", zipfile.ZIP_DEFLATED) as archive:
    for path in sorted((root / "capture").iterdir()):
        if path.is_file():
            archive.write(path, str(path.relative_to(root)))
    for name in ("results/commands.json", "results/recordings.json", "audio/timing.json"):
        archive.write(root / name, name)
(deliver / "SHA256SUMS").write_text("".join(
    f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
    for p in sorted(deliver.iterdir()) if p.name != "SHA256SUMS"
))
