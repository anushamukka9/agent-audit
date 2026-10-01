"""Tests for JSONL and CSV export."""

import csv
import json
from pathlib import Path

import pytest

from agent_audit import AuditStore, export_csv, export_events, export_jsonl


def seed(path: Path, count: int = 3) -> AuditStore:
    store = AuditStore(path)
    for i in range(count):
        store.append(
            run_id="run-1",
            actor="anusha",
            agent_id="agent-1",
            action=f"tool.{i}",
            parameters={"n": i},
            policy_decision="allow",
            policy_id="pol-1",
            human_approval="approved" if i == 0 else "skipped",
            diff="--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new" if i == 1 else None,
        )
    return store


def test_export_jsonl_round_trip(tmp_path):
    src = tmp_path / "audit.jsonl"
    seed(src)
    dest = tmp_path / "out.jsonl"
    assert export_jsonl(AuditStore(src).iter_events(), dest) == 3
    lines = dest.read_text().splitlines()
    assert len(lines) == 3
    first = json.loads(lines[0])
    assert first["action"] == "tool.0"
    assert first["policy_id"] == "pol-1"
    assert "event_hash" in first and "prev_hash" in first


def test_export_csv_columns_and_rows(tmp_path):
    src = tmp_path / "audit.jsonl"
    seed(src)
    dest = tmp_path / "out.csv"
    assert export_csv(AuditStore(src).iter_events(), dest) == 3
    with open(dest, newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 3
    assert rows[0]["action"] == "tool.0"
    assert rows[0]["policy_decision"] == "allow"
    assert rows[0]["human_approval"] == "approved"
    assert rows[0]["event_hash"] == rows[1]["prev_hash"]
    assert rows[1]["diff"].startswith("--- a")


def test_export_csv_truncates_huge_diffs(tmp_path):
    store = AuditStore(tmp_path / "audit.jsonl")
    store.append(
        run_id="r",
        actor="a",
        agent_id="g",
        action="write",
        diff="x" * 5000,
    )
    dest = tmp_path / "out.csv"
    export_csv(store.iter_events(), dest)
    with open(dest, newline="") as fh:
        row = next(csv.DictReader(fh))
    assert len(row["diff"]) < 5000
    assert row["diff"].endswith("...[truncated]")


def test_export_events_dispatch(tmp_path):
    src = tmp_path / "audit.jsonl"
    seed(src, count=2)
    assert export_events(src, tmp_path / "o.jsonl", format="jsonl") == 2
    assert export_events(src, tmp_path / "o.csv", format="csv") == 2
    with pytest.raises(ValueError, match="unknown export format"):
        export_events(src, tmp_path / "o.txt", format="txt")


def test_export_events_accepts_store(tmp_path):
    src = tmp_path / "audit.jsonl"
    store = seed(src, count=2)
    assert export_events(store, tmp_path / "o.csv", format="csv") == 2


def test_export_empty_store(tmp_path):
    src = tmp_path / "audit.jsonl"
    src.touch()
    dest = tmp_path / "o.csv"
    assert export_events(src, dest, format="csv") == 0
    with open(dest, newline="") as fh:
        assert len(list(csv.DictReader(fh))) == 0
