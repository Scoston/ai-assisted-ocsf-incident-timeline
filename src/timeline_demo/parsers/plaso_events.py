"""Import Plaso events from every parser without inventing source-specific fields."""

import copy
import re
from datetime import datetime

from timeline_demo.parsers.common import parse_time, pick

L2T_FIELDS = frozenset(
    "date time timezone MACB source sourcetype type user host short desc version filename inode notes format extra".split()
)
SEMANTIC_TIMES = frozenset({"InvalidTime", "NotSet", "NotApplicable", "Never", "Infinity", "SemanticTime"})


def project(raw, assume_timezone=None):
    record = copy.deepcopy(raw)
    kind = record.get("__container_type__")
    if kind not in (None, "event"):
        raise ValueError("Plaso input must contain event records")
    date_time = record.get("date_time")
    if isinstance(date_time, dict) and date_time.get("__class_name__") in SEMANTIC_TIMES:
        raise ValueError("Plaso semantic/invalid time has no defensible timeline position")
    if L2T_FIELDS <= set(record):
        # l2tcsv uses US month/day/year, even on hosts with other locale settings.
        date = datetime.strptime(record["date"], "%m/%d/%Y").date()
        wall_time = str(record["time"])
        if not re.fullmatch(r"\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?", wall_time):
            raise ValueError("invalid l2tcsv time")
        stamp = date.isoformat() + "T" + wall_time
        zone = str(record["timezone"])
        if zone in {"UTC", "GMT", "Z", "+00:00"}:
            stamp += "+00:00"
        elif re.fullmatch(r"[+-]\d{2}:?\d{2}", zone):
            stamp += zone
        elif assume_timezone:
            # Display abbreviations (e.g. CST) do not uniquely identify a zone.
            stamp = parse_time(stamp, assume_timezone=assume_timezone)[0]
        else:
            raise ValueError("non-UTC l2tcsv requires an explicit --assume-timezone or numeric offset")
        record.update(
            {
                "timestamp": stamp,
                "message": record["desc"],
                "parser": record["format"],
                "username": record["user"],
                "hostname": record["host"],
                "timestamp_desc": record["type"],
            }
        )
        export_format = "l2tcsv"
    else:
        export_format = "psort_event"
    stamp = pick(record, "timestamp", "datetime", "Datetime")
    if stamp is None:
        raise ValueError("Plaso event requires its exported timestamp")
    chain = pick(record, "parser", "_parser_chain", default="")
    data_type = record.get("data_type", "")
    if not isinstance(chain, str) or not isinstance(data_type, str):
        raise ValueError("Plaso parser chain and data type must be strings")
    message = pick(record, "message", "data_type", "timestamp_desc", default=chain)
    if not isinstance(message, str) or not message:
        raise ValueError("Plaso event has no source description")
    record.update({"timestamp": stamp, "message": message})
    pathspec = record.get("pathspec")
    metadata = {
        "parser_chain": chain,
        "data_type": data_type,
        "timestamp_description": str(record.get("timestamp_desc", "")),
        "artifact_path": str(pick(record, "display_name", "filename", default="")),
        "export_format": export_format,
        "host_filestat": chain == "filestat"
        and isinstance(pathspec, dict)
        and pathspec.get("type_indicator") == "OS",
    }
    if type(stamp) is int or (isinstance(stamp, str) and re.fullmatch(r"-?\d+", stamp)):
        metadata["timestamp_microseconds"] = str(stamp)
    return record, metadata
