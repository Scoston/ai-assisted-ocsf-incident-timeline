"""Run inside the pinned backend; report actual registrations and storage state."""

import hashlib
import inspect
import json
import sys
from pathlib import Path

import plaso
from plaso.parsers import manager
from plaso.parsers.cookie_plugins import manager as cookies
from plaso.storage import factory


def inventory():
    entries = []
    root = Path(plaso.__file__).resolve().parent.parent
    for parser in manager.ParsersManager.GetParserObjects().values():
        entries.append(parser.NAME)
        if parser.SupportsPlugins():
            entries.extend(parser.NAME + "/" + name for name, _ in parser.GetPlugins())
    entries.extend("cookie/" + plugin.NAME for plugin in cookies.CookiePluginsManager.GetPlugins())
    hashes = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((root / "plaso/parsers").rglob("*.py"))
    }
    return {
        "version": plaso.__version__,
        "entries": sorted(entries),
        "source_hashes": hashes,
        "module_path": str(Path(inspect.getfile(manager)).resolve()),
    }


def statistics(path):
    reader = factory.StorageFactory.CreateStorageReaderForFile(path)
    if reader is None:
        raise ValueError("unsupported Plaso storage format")
    with reader:
        sessions = [
            {"aborted": session.aborted, "completion_time": session.completion_time}
            for session in reader.GetSessions()
        ]
        return {
            "events": reader.GetNumberOfAttributeContainers("event"),
            "warnings": {
                kind: reader.GetNumberOfAttributeContainers(kind)
                for kind in (
                    "extraction_warning",
                    "preprocessing_warning",
                    "recovery_warning",
                    "timelining_warning",
                    "analysis_warning",
                )
            },
            "sessions": sessions,
        }


if __name__ == "__main__":
    result = inventory() if sys.argv[1:] == ["inventory"] else statistics(sys.argv[2])
    print(json.dumps(result, sort_keys=True))
