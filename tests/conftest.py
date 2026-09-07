import json
from pathlib import Path

import pytest
from timeline_demo.pipeline import Input, run_pipeline

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def cloudtrail():
    return {
        "eventTime": "2026-09-01T10:00:00Z",
        "eventID": "ct-1",
        "eventName": "AssumeRole",
        "userIdentity": {"arn": "arn:aws:iam::123456789012:user/alice"},
        "eventSource": "sts.amazonaws.com",
        "sourceIPAddress": "198.51.100.10",
    }


@pytest.fixture
def bundle(tmp_path, cloudtrail):
    raw = tmp_path / "cloudtrail.json"
    raw.write_text(json.dumps({"Records": [cloudtrail]}))
    target = tmp_path / "bundle"
    run_pipeline([Input("cloudtrail", raw)], target, "test-001")
    return target
