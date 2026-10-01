"""Tests for the Event model, sanitization, and hashing."""

import json

import pytest

from agent_audit import Event, sanitize_parameters


def make_event(**kwargs):
    base = dict(run_id="run-1", actor="anusha", agent_id="agent-1", action="tool.call")
    base.update(kwargs)
    return Event(**base)


def test_hash_is_deterministic():
    event = make_event()
    event.prev_hash = "0" * 64
    assert event.compute_hash() == event.compute_hash()


def test_hash_changes_when_payload_changes():
    first = make_event(action="tool.a")
    second = make_event(action="tool.b")
    first.prev_hash = second.prev_hash = "0" * 64
    assert first.compute_hash() != second.compute_hash()


def test_hash_commits_to_previous_hash():
    event = make_event()
    event.prev_hash = "a" * 64
    with_prev_a = event.compute_hash()
    event.prev_hash = "b" * 64
    assert event.compute_hash() != with_prev_a


def test_sanitize_redacts_secret_keys():
    params = {
        "password": "hunter2",
        "api_key": "sk-test-123",
        "authToken": "abc",
        "session_cookie": "xyz",
        "query": "select * from users",
    }
    clean = sanitize_parameters(params)
    assert clean["password"] == "***REDACTED***"
    assert clean["api_key"] == "***REDACTED***"
    assert clean["authToken"] == "***REDACTED***"
    assert clean["session_cookie"] == "***REDACTED***"
    assert clean["query"] == "select * from users"


def test_sanitize_redacts_nested_keys():
    params = {"config": {"credentials": {"token": "abc123"}, "retries": 3}}
    clean = sanitize_parameters(params)
    assert clean["config"]["credentials"]["token"] == "***REDACTED***"
    assert clean["config"]["retries"] == 3


def test_sanitize_truncates_long_strings():
    params = {"blob": "x" * 5000}
    clean = sanitize_parameters(params)
    assert len(clean["blob"]) < 5000
    assert clean["blob"].endswith("...[truncated]")


def test_sanitize_does_not_mutate_input():
    params = {"password": "hunter2"}
    sanitize_parameters(params)
    assert params["password"] == "hunter2"


def test_event_sanitizes_on_construction():
    event = make_event(parameters={"api_key": "sk-test-123", "ok": 1})
    assert event.parameters["api_key"] == "***REDACTED***"
    assert event.parameters["ok"] == 1


def test_rejects_bad_decision():
    with pytest.raises(ValueError, match="policy_decision"):
        make_event(policy_decision="maybe")


def test_rejects_bad_approval():
    with pytest.raises(ValueError, match="human_approval"):
        make_event(human_approval="later")


def test_rejects_empty_required_fields():
    with pytest.raises(ValueError):
        make_event(run_id="")
    with pytest.raises(ValueError):
        make_event(actor="")
    with pytest.raises(ValueError):
        make_event(agent_id="")
    with pytest.raises(ValueError):
        make_event(action="")


def test_from_dict_round_trip():
    event = make_event()
    event.seq = 4
    event.prev_hash = "c" * 64
    event.event_hash = event.compute_hash()
    data = event.to_dict()
    rebuilt = Event.from_dict(data)
    assert rebuilt.to_dict() == data
    assert rebuilt.event_hash == event.event_hash


def test_timestamp_is_iso8601():
    event = make_event()
    assert event.timestamp.endswith("Z")
    assert "T" in event.timestamp


def test_to_dict_is_json_serializable():
    event = make_event(parameters={"nested": [1, 2, {"k": "v"}]})
    json.dumps(event.to_dict())
