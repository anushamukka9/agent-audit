"""Tests for the SIEM exporters (Splunk, Elastic ECS, Datadog) and
the Grafana dashboard builder."""

import json
from pathlib import Path

import pytest

from agent_audit import (
    AuditStore,
    build_grafana_dashboard,
    export_events,
    export_siem,
    to_datadog_event,
    to_ecs_event,
    to_splunk_event,
    write_grafana_dashboard,
)
from agent_audit.cli import main


def seed(path: Path, count: int = 3) -> AuditStore:
    store = AuditStore(path)
    decisions = ["allow", "deny", "allow"]
    approvals = ["approved", "skipped", "pending"]
    for i in range(count):
        store.append(
            run_id="run-1",
            actor="anusha",
            agent_id="agent-1",
            action=f"tool.{i}",
            parameters={"n": i},
            policy_decision=decisions[i % 3],
            policy_id="pol-1",
            human_approval=approvals[i % 3],
        )
    return store


def first_event(store: AuditStore):
    return next(store.iter_events())


def test_splunk_envelope_shape(tmp_path):
    store = seed(tmp_path / "audit.jsonl")
    env = to_splunk_event(first_event(store))
    assert env["sourcetype"] == "agent_audit:event"
    assert env["source"] == "agent-audit"
    assert env["host"] == "agent-audit"
    # 2026-era timestamps parse to a positive epoch float.
    assert env["time"] > 1_700_000_000
    assert env["event"]["action"] == "tool.0"
    assert env["event"]["event_hash"]
    assert "index" not in env


def test_splunk_index_and_host_options(tmp_path):
    store = seed(tmp_path / "audit.jsonl", count=1)
    env = to_splunk_event(first_event(store), host="prod-1", index="agents")
    assert env["host"] == "prod-1"
    assert env["index"] == "agents"


def test_splunk_export_lines(tmp_path):
    src = tmp_path / "audit.jsonl"
    seed(src)
    dest = tmp_path / "splunk.jsonl"
    assert export_siem(src, dest, format="splunk") == 3
    lines = dest.read_text().splitlines()
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    assert [p["event"]["action"] for p in parsed] == ["tool.0", "tool.1", "tool.2"]
    # Chain survives the export: each event points at the previous hash.
    assert parsed[1]["event"]["prev_hash"] == parsed[0]["event"]["event_hash"]


def test_ecs_mapping(tmp_path):
    store = seed(tmp_path / "audit.jsonl")
    events = list(store.iter_events())
    allow_doc = to_ecs_event(events[0])
    assert allow_doc["@timestamp"] == events[0].timestamp
    assert allow_doc["ecs"]["version"]
    assert allow_doc["event"]["action"] == "tool.0"
    assert allow_doc["event"]["outcome"] == "success"
    assert allow_doc["event"]["sequence"] == events[0].seq
    assert allow_doc["user"]["name"] == "anusha"
    assert allow_doc["agent"]["id"] == "agent-1"
    assert allow_doc["labels"]["run_id"] == "run-1"
    assert allow_doc["agent_audit"]["event_hash"] == events[0].event_hash

    deny_doc = to_ecs_event(events[1])
    assert deny_doc["event"]["outcome"] == "failure"
    assert "denied" in deny_doc["event"]["type"]
    assert "deny" in deny_doc["message"]


def test_elastic_bulk_export_is_paired_lines(tmp_path):
    src = tmp_path / "audit.jsonl"
    seed(src, count=2)
    dest = tmp_path / "bulk.ndjson"
    assert export_siem(src, dest, format="elastic", index="agents-prod") == 2
    lines = dest.read_text().splitlines()
    assert len(lines) == 4
    action = json.loads(lines[0])
    assert action == {"index": {"_index": "agents-prod", "_id": action["index"]["_id"]}}
    doc = json.loads(lines[1])
    assert doc["event"]["action"] == "tool.0"
    assert json.loads(lines[2])["index"]["_index"] == "agents-prod"


def test_datadog_record(tmp_path):
    store = seed(tmp_path / "audit.jsonl")
    events = list(store.iter_events())
    rec = to_datadog_event(events[1])  # the denied one
    assert rec["ddsource"] == "agent-audit"
    assert rec["service"] == "agent-audit"
    assert rec["status"] == "ERROR"
    assert "policy_decision:deny" in rec["ddtags"]
    assert "policy_id:pol-1" in rec["ddtags"]
    assert rec["agent_audit"]["action"] == "tool.1"
    ok = to_datadog_event(events[0])
    assert ok["status"] == "OK"


def test_datadog_export_lines(tmp_path):
    src = tmp_path / "audit.jsonl"
    seed(src, count=2)
    dest = tmp_path / "dd.jsonl"
    assert export_siem(src, dest, format="datadog", service="my-agents") == 2
    parsed = [json.loads(line) for line in dest.read_text().splitlines()]
    assert all(p["service"] == "my-agents" for p in parsed)


def test_export_events_dispatches_siem_formats(tmp_path):
    src = tmp_path / "audit.jsonl"
    seed(src, count=2)
    for fmt in ("splunk", "elastic", "datadog"):
        dest = tmp_path / f"out.{fmt}"
        assert export_events(src, dest, format=fmt) == 2
        assert dest.read_text().strip()


def test_export_siem_rejects_unknown_format(tmp_path):
    src = tmp_path / "audit.jsonl"
    seed(src, count=1)
    with pytest.raises(ValueError, match="unknown SIEM format"):
        export_siem(src, tmp_path / "o.txt", format="syslog")


def test_siem_export_empty_store(tmp_path):
    src = tmp_path / "audit.jsonl"
    src.touch()
    dest = tmp_path / "o.jsonl"
    assert export_siem(src, dest, format="splunk") == 0
    assert dest.read_text() == ""


def test_cli_export_siem_and_dashboard(tmp_path, capsys):
    src = tmp_path / "audit.jsonl"
    seed(src, count=2)
    out = tmp_path / "splunk.jsonl"
    assert main(["export", str(src), "-o", str(out), "--format", "splunk"]) == 0
    assert "exported 2 events" in capsys.readouterr().out
    assert len(out.read_text().splitlines()) == 2

    dash = tmp_path / "dash.json"
    assert main(["dashboard", "-o", str(dash)]) == 0
    data = json.loads(dash.read_text())
    assert data["title"] == "Agent activity (agent-audit)"


def test_dashboard_structure():
    dash = build_grafana_dashboard()
    assert dash["uid"] == "agent-audit-activity"
    assert dash["schemaVersion"] >= 30
    titles = [p["title"] for p in dash["panels"]]
    assert len(titles) == len(set(titles)) >= 5
    assert any("Denied" in t for t in titles)
    assert any("over time" in t for t in titles)
    var_names = [v["name"] for v in dash["templating"]["list"]]
    assert "datasource" in var_names
    assert "agent_id" in var_names and "run_id" in var_names
    for panel in dash["panels"]:
        assert panel["datasource"]["uid"] == "${datasource}"
        assert panel["gridPos"]["w"] > 0


def test_dashboard_queries_use_ecs_export_fields():
    dash = build_grafana_dashboard()
    queries = " ".join(p["targets"][0]["query"] for p in dash["panels"])
    # These are the namespaced fields to_ecs_event actually writes.
    assert "agent_audit.policy_decision" in queries
    assert "agent_audit.human_approval" in queries


def test_write_dashboard_round_trip(tmp_path):
    dest = write_grafana_dashboard(tmp_path / "nested" / "dash.json")
    assert json.loads(Path(dest).read_text())["uid"] == "agent-audit-activity"


def test_shipped_dashboard_file_matches_builder():
    shipped = Path(__file__).resolve().parent.parent / "dashboards" / "agent-activity.json"
    assert shipped.exists(), "dashboards/agent-activity.json must be shipped in the repo"
    assert json.loads(shipped.read_text()) == build_grafana_dashboard()
