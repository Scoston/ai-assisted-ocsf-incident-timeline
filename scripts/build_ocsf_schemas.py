"""Reproduce validators from an explicitly supplied, hash-pinned upstream export.

Install ocsf-json-schema==1.2.0 in a development environment, then run:
  python scripts/build_ocsf_schemas.py /path/to/official-export.json --check
No network requests or generator dependencies are needed by the application.
"""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "src/timeline_demo/resources/ocsf/1.3.0"
    lock = json.loads((root / "schema-lock.json").read_text())
    source = args.source.read_bytes()
    if hashlib.sha256(source).hexdigest() != lock["source_sha256"]:
        parser.error("source does not match the reviewed schema-lock.json pin")
    if importlib.metadata.version(lock["generator"]) != lock["generator_version"]:
        parser.error("install the exact generator version recorded in schema-lock.json")
    from ocsf_json_schema import OcsfJsonSchemaEmbedded

    catalog = json.loads(source)
    if catalog["version"] != lock["version"]:
        parser.error("schema version mismatch")
    generator = OcsfJsonSchemaEmbedded(catalog)
    for entry in lock["classes"].values():
        schema = generator.get_class_schema(entry["name"], profiles=lock["profiles"])
        data = (json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            parser.error("generated schema differs from reviewed pin: " + entry["file"])
        target = root / entry["file"]
        if args.check:
            if target.read_bytes() != data:
                parser.error("packaged schema differs: " + entry["file"])
        else:
            target.write_bytes(data)
    print(f"Verified {len(lock['classes'])} OCSF {lock['version']} class schemas")


if __name__ == "__main__":
    main()
