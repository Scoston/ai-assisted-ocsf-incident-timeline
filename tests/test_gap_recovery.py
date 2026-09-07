import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest

from timeline_demo.ai import Harness
from timeline_demo.collection import collect_until
from timeline_demo.collection.runner import _open
from timeline_demo.ledger_ops import ledger_usage, ledger_backup, ledger_restore
from timeline_demo.operations import health, inventory, load_inventory, main, prometheus, backup, restore
from timeline_demo.parsers.common import compact_json, file_hash
from test_ai import FakeClient
from test_collection import Provider, page, signin, START, END


def rolling(tmp, provider, end=END, state="state", **options):
    return collect_until(
        provider, tmp / state, tmp / "bundles", "rolling", START, end, sleep=lambda _: None, **options
    )


def test_partial_window_survives_moving_end_and_backup(tmp_path):
    provider = Provider([page([signin(1)], {"next": 2})])
    partial = "2026-09-01T10:30:00Z"
    with pytest.raises(ValueError, match="page budget"):
        rolling(tmp_path, provider, partial, max_pages=1)
    saved = backup(tmp_path / "state", tmp_path / "snapshot")
    restore(tmp_path / "snapshot", tmp_path / "restored", saved["snapshot_sha256"])
    provider.pages = [page([signin(2)]), page([signin(3, "2026-09-01T10:45:00Z")])]
    result = rolling(tmp_path, provider, state="restored")
    assert result["status"] == "caught_up" and len(result["windows"]) == 2
    assert provider.calls[1][1].startswith("2026-09-01T10:30:00")
    assert provider.calls[1][2] == {"next": 2}
    report = health(tmp_path / "restored", verify_blobs=True, verify_bundles=True)
    assert report["pending_runs"] == 0 and report["pages"] == 3
    assert rolling(tmp_path, Provider([]), state="restored")["windows"] == []


def test_pending_window_cannot_shrink_or_change_initial_boundary(tmp_path):
    provider = Provider([page([], {"next": 2})])
    with pytest.raises(ValueError, match="page budget"):
        rolling(tmp_path, provider, max_pages=1)
    with pytest.raises(ValueError, match="pending"):
        rolling(tmp_path, provider, "2026-09-01T10:30:00Z")
    assert len(provider.calls) == 1


def test_legacy_partial_window_is_adopted(tmp_path):
    provider = Provider([page([], {"next": 2})])
    with pytest.raises(ValueError, match="page budget"):
        rolling(tmp_path, provider, "2026-09-01T10:30:00Z", max_pages=1)
    with sqlite3.connect(tmp_path / "state/collection.sqlite") as db:
        db.execute("ALTER TABLE watermarks DROP COLUMN pending_end_ms")
        db.execute("ALTER TABLE watermarks DROP COLUMN contract")
    provider.pages = [page([]), page([])]
    rolling(tmp_path, provider)
    assert provider.calls[1][2] == {"next": 2}
    assert provider.calls[1][1].startswith("2026-09-01T10:30:00")


def test_concurrent_schema_upgrade_and_now_settling(tmp_path, monkeypatch):
    with closing(_open(tmp_path / "state")) as db:
        db.execute("ALTER TABLE runs DROP COLUMN parser_version")
        db.execute("ALTER TABLE watermarks DROP COLUMN pending_end_ms")
        db.execute("ALTER TABLE watermarks DROP COLUMN contract")

    def migrate(_):
        with closing(_open(tmp_path / "state")) as db:
            return {row[1] for row in db.execute("PRAGMA table_info(watermarks)")}

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all("pending_end_ms" in columns for columns in pool.map(migrate, range(4)))
    monkeypatch.setattr("timeline_demo.collection.runner.time.time", lambda: 1788260400)
    provider = Provider([page([])])
    rolling(tmp_path, provider, "now", settling_seconds=300)
    assert provider.calls[0][1].startswith("2026-09-01T10:55:00")


def test_inventory_detects_never_started_source_without_provider_setup(tmp_path, capsys):
    config = {"source": "entra_signin", "source_id": "test"}
    provider = Provider([page([])])
    provider.identity = {"collector_version": "1.0.0", **config}
    rolling(tmp_path, provider)
    expected = inventory(
        [config, {"source": "databricks_audit", "source_id": "missing", "warehouse_id": "abc"}]
    )
    path = tmp_path / "inventory.json"
    path.write_text(compact_json(expected))
    report = health(tmp_path / "state", expected_sources=load_inventory(path), stale_seconds=100000000)
    assert not report["healthy"] and report["missing_sources"] == 1
    assert "timeline_collection_missing_sources 1" in prometheus(report)
    assert "missing" not in json.dumps(report["sources"])
    assert main(["health", "--state", str(tmp_path / "state"), "--inventory", str(path)]) == 1
    assert "missing_source:" in capsys.readouterr().out
    path.write_text('{"version":"1.0","source_hashes":["invalid"]}')
    with pytest.raises(ValueError):
        load_inventory(path)


def test_ai_recovery_keeps_cache_and_ambiguous_charges(bundle, tmp_path):
    ledger = tmp_path / "usage.sqlite"
    client = FakeClient()
    harness = Harness(ledger, client=client)
    harness.run(bundle, allow_ai=True)
    client.failure = TimeoutError("private-value")
    with pytest.raises(TimeoutError):
        harness.run(bundle, "correlate", allow_ai=True)
    before = ledger_usage(ledger)
    assert before["cases"][0]["completed"] == before["cases"][0]["failed"] == 1
    assert before["cases"][0]["known_usage_tokens"] == 200
    assert before["cases"][0]["reserved_unknown_tokens"] > 200
    assert "private-value" not in json.dumps(before)
    saved = ledger_backup(ledger, tmp_path / "backup")
    result = ledger_restore(tmp_path / "backup", tmp_path / "recovered", saved["snapshot_sha256"])
    assert result["usage"] == before
    client = FakeClient()
    recovered = Harness(result["ledger"], client=client)
    assert recovered.run(bundle, allow_ai=True)["cache_hit"]
    with pytest.raises(ValueError, match="already attempted"):
        recovered.run(bundle, "correlate", allow_ai=True)
    assert client.calls == []
    assert ledger_usage(result["ledger"]) == before


@pytest.mark.parametrize("fault", ["pin", "database", "extra", "link", "accounting"])
def test_ai_restore_rejects_corruption_and_never_overwrites(bundle, tmp_path, fault):
    ledger = tmp_path / "usage.sqlite"
    Harness(ledger, client=FakeClient()).run(bundle, allow_ai=True)
    saved = ledger_backup(ledger, tmp_path / "backup")
    root = tmp_path / "backup"
    pin = saved["snapshot_sha256"]
    if fault == "pin":
        pin = "0" * 64
    elif fault == "database":
        (root / "usage.sqlite").write_text("corrupt")
    elif fault == "extra":
        (root / "unlisted").write_text("extra")
    elif fault == "link":
        (root / "usage.sqlite").unlink()
        (root / "usage.sqlite").symlink_to(ledger)
    else:
        value = json.loads((root / "snapshot.json").read_text())
        value["usage"]["cases"][0]["charged_tokens"] = 0
        (root / "snapshot.json").write_text(compact_json(value))
        pin = file_hash(root / "snapshot.json")
    with pytest.raises(ValueError):
        ledger_restore(root, tmp_path / "recovered", pin)
    assert not (tmp_path / "recovered").exists()
    with pytest.raises(ValueError):
        ledger_restore(root, tmp_path, pin)


def test_ai_wal_backup_keeps_pending_reservation(bundle, tmp_path):
    ledger = tmp_path / "usage.sqlite"
    harness = Harness(ledger, client=FakeClient(failure=TimeoutError()))
    with pytest.raises(TimeoutError):
        harness.run(bundle, allow_ai=True)
    with closing(sqlite3.connect(ledger)) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("UPDATE calls SET status='pending',error=NULL")
        db.commit()
        saved = ledger_backup(ledger, tmp_path / "snapshot")
    result = ledger_restore(tmp_path / "snapshot", tmp_path / "recovered", saved["snapshot_sha256"])
    assert result["usage"]["cases"][0]["pending"] == 1
    with pytest.raises(ValueError, match="already attempted"):
        Harness(result["ledger"], client=FakeClient()).run(bundle, allow_ai=True)


@pytest.mark.parametrize("value", [True, 1.5, "200", -1])
def test_invalid_provider_usage_keeps_reservation(bundle, tmp_path, value):
    from types import SimpleNamespace
    from test_ai import FakeResponse

    response = FakeResponse()
    response.usage = SimpleNamespace(input_tokens=value, output_tokens=80)
    ledger = tmp_path / "usage.sqlite"
    with pytest.raises(ValueError, match="invalid usage"):
        Harness(ledger, client=FakeClient(response)).run(bundle, allow_ai=True)
    report = ledger_usage(ledger)["cases"][0]
    assert report["failed"] == 1 and report["known_usage_tokens"] == 0
    assert report["reserved_unknown_tokens"] > 200


def test_ledger_cli_is_read_only_and_sanitizes_errors(bundle, tmp_path, capsys):
    ledger = tmp_path / "usage.sqlite"
    Harness(ledger, client=FakeClient()).run(bundle, allow_ai=True)
    before = file_hash(ledger)
    assert main(["ledger-usage", "--ledger", str(ledger)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["cases"][0]["calls"] == 1 and file_hash(ledger) == before
    assert main(["ledger-usage", "--ledger", str(tmp_path / "private-missing.sqlite")]) == 2
    assert "private-missing" not in capsys.readouterr().out
