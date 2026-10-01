"""Tests for query helpers."""

from pathlib import Path

from agent_audit import AuditStore, filter_events, iter_events


def seed(path: Path) -> None:
    store = AuditStore(path)
    rows = [
        ("run-1", "agent-a", "tool.read", "allow", "skipped"),
        ("run-1", "agent-a", "tool.write", "allow", "approved"),
        ("run-1", "agent-b", "tool.exec", "deny", "skipped"),
        ("run-2", "agent-a", "tool.read", "allow", "pending"),
        ("run-2", "agent-b", "tool.exec", "deny", "skipped"),
    ]
    for run_id, agent_id, action, decision, approval in rows:
        store.append(
            run_id=run_id,
            actor="anusha",
            agent_id=agent_id,
            action=action,
            policy_decision=decision,
            human_approval=approval,
        )


def test_filter_by_run_id(tmp_path):
    seed(tmp_path / "a.jsonl")
    assert len(filter_events(tmp_path / "a.jsonl", run_id="run-1")) == 3
    assert len(filter_events(tmp_path / "a.jsonl", run_id="run-2")) == 2


def test_filter_by_agent_id(tmp_path):
    seed(tmp_path / "a.jsonl")
    assert len(filter_events(tmp_path / "a.jsonl", agent_id="agent-a")) == 3


def test_filter_by_action(tmp_path):
    seed(tmp_path / "a.jsonl")
    assert len(filter_events(tmp_path / "a.jsonl", action="tool.exec")) == 2


def test_filter_by_decision(tmp_path):
    seed(tmp_path / "a.jsonl")
    denied = filter_events(tmp_path / "a.jsonl", decision="deny")
    assert len(denied) == 2
    assert all(e.policy_decision == "deny" for e in denied)


def test_filter_by_approval(tmp_path):
    seed(tmp_path / "a.jsonl")
    assert len(filter_events(tmp_path / "a.jsonl", approval="approved")) == 1
    assert len(filter_events(tmp_path / "a.jsonl", approval="pending")) == 1


def test_filter_combines_criteria(tmp_path):
    seed(tmp_path / "a.jsonl")
    events = filter_events(tmp_path / "a.jsonl", run_id="run-1", decision="deny")
    assert len(events) == 1
    assert events[0].agent_id == "agent-b"


def test_no_filters_returns_everything(tmp_path):
    seed(tmp_path / "a.jsonl")
    assert len(filter_events(tmp_path / "a.jsonl")) == 5


def test_no_match_returns_empty(tmp_path):
    seed(tmp_path / "a.jsonl")
    assert filter_events(tmp_path / "a.jsonl", run_id="nope") == []


def test_accepts_store_instance(tmp_path):
    path = tmp_path / "a.jsonl"
    seed(path)
    store = AuditStore(path)
    assert len(filter_events(store, action="tool.read")) == 2
    assert len(list(iter_events(store))) == 5
