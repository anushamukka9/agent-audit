"""Tests for the append-only store, chain verification, and pinning."""

import json
from pathlib import Path

import pytest

from agent_audit import AuditStore, Event


def make_store(path: Path, count: int = 3) -> AuditStore:
    store = AuditStore(path)
    for i in range(count):
        store.append(
            run_id="run-1",
            actor="anusha",
            agent_id="agent-1",
            action=f"tool.call.{i}",
            parameters={"n": i},
        )
    return store


def test_append_links_chain(tmp_path):
    store = make_store(tmp_path / "audit.jsonl", count=3)
    events = list(store.iter_events())
    assert [e.seq for e in events] == [0, 1, 2]
    assert events[0].prev_hash == "0" * 64
    assert events[1].prev_hash == events[0].event_hash
    assert events[2].prev_hash == events[1].event_hash


def test_verify_clean_chain(tmp_path):
    store = make_store(tmp_path / "audit.jsonl", count=5)
    result = store.verify()
    assert result.valid
    assert result.event_count == 5
    assert result.head_hash == store.head_hash()
    assert result.problems == ()


def test_verify_empty_store(tmp_path):
    store = AuditStore(tmp_path / "audit.jsonl")
    result = store.verify()
    assert result.valid
    assert result.event_count == 0
    assert store.head_hash() is None


def test_verify_missing_file(tmp_path):
    store = AuditStore(tmp_path / "nope.jsonl")
    assert store.verify().valid


def test_detects_altered_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_store(path, count=3)
    lines = path.read_text().splitlines()
    data = json.loads(lines[1])
    data["parameters"] = {"n": 999, "extra": "tampered"}
    lines[1] = json.dumps(data, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    result = AuditStore(path).verify()
    assert not result.valid
    reasons = {p.reason for p in result.problems}
    assert "hash_mismatch" in reasons
    tampered = [p for p in result.problems if p.reason == "hash_mismatch"]
    assert tampered[0].index == 1


def test_detects_raw_byte_flip(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_store(path, count=2)
    raw = path.read_bytes()
    # Flip a byte inside the first line's action value; JSON stays valid.
    raw = raw.replace(b"tool.call.0", b"tool.call.X", 1)
    path.write_bytes(raw)

    result = AuditStore(path).verify()
    assert not result.valid
    assert any(p.reason == "hash_mismatch" for p in result.problems)


def test_detects_deleted_middle_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_store(path, count=4)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")

    result = AuditStore(path).verify()
    assert not result.valid
    reasons = {p.reason for p in result.problems}
    assert "seq_gap" in reasons
    assert "broken_link" in reasons


def test_detects_malformed_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_store(path, count=2)
    with open(path, "a") as fh:
        fh.write("this is not json\n")
    result = AuditStore(path).verify()
    assert not result.valid
    assert any(p.reason == "malformed" for p in result.problems)


def test_tail_truncation_passes_plain_verify_but_fails_pin(tmp_path):
    # Honest behavior worth pinning down in a test: the chain alone
    # cannot tell you the tail was cut. The pin is what catches it.
    path = tmp_path / "audit.jsonl"
    pin = tmp_path / "pin.json"
    store = make_store(path, count=3)
    store.pin_head(pin)

    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")

    assert AuditStore(path).verify().valid
    pinned = AuditStore(path).verify_with_pin(pin)
    assert not pinned.valid
    assert pinned.problems[0].reason == "pin_mismatch"


def test_pin_round_trip(tmp_path):
    path = tmp_path / "audit.jsonl"
    pin = tmp_path / "pin.json"
    store = make_store(path, count=2)
    head = store.pin_head(pin)
    assert head == store.head_hash()
    saved = json.loads(pin.read_text())
    assert saved["head_hash"] == head
    assert saved["event_count"] == 2
    result = AuditStore(path).verify_with_pin(pin)
    assert result.valid


def test_pin_rejects_tampered_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    pin = tmp_path / "pin.json"
    make_store(path, count=2).pin_head(pin)
    lines = path.read_text().splitlines()
    data = json.loads(lines[0])
    data["action"] = "evil.action"
    lines[0] = json.dumps(data, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    result = AuditStore(path).verify_with_pin(pin)
    assert not result.valid


def test_pin_missing_file_reports_problem(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_store(path, count=1)
    result = AuditStore(path).verify_with_pin(tmp_path / "nope.json")
    assert not result.valid
    assert result.problems[0].reason == "pin_mismatch"


def test_pin_empty_store_raises(tmp_path):
    with pytest.raises(ValueError, match="empty"):
        AuditStore(tmp_path / "audit.jsonl").pin_head(tmp_path / "pin.json")


def test_append_continues_chain_across_instances(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_store(path, count=2)
    reopened = AuditStore(path)
    reopened.append(run_id="run-1", actor="a", agent_id="g", action="tool.late")
    result = reopened.verify()
    assert result.valid
    assert result.event_count == 3


def test_append_accepts_event_object(tmp_path):
    store = AuditStore(tmp_path / "audit.jsonl")
    event = Event(run_id="r", actor="a", agent_id="g", action="act")
    stored = store.append(event)
    assert stored.seq == 0
    assert stored.event_hash
    assert store.verify().valid


def test_appends_are_durable_and_ordered(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = AuditStore(path)
    for i in range(50):
        store.append(run_id="r", actor="a", agent_id="g", action=f"a{i}")
    events = list(AuditStore(path).iter_events())
    assert len(events) == 50
    assert [e.seq for e in events] == list(range(50))


def test_parameters_with_secrets_are_redacted_in_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = AuditStore(path)
    store.append(
        run_id="r",
        actor="a",
        agent_id="g",
        action="login",
        parameters={"password": "hunter2"},
    )
    raw = path.read_text()
    assert "hunter2" not in raw
    assert "***REDACTED***" in raw
