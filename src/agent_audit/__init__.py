"""agent-audit: tamper-evident audit logging for AI agent runs.

An append-only, hash-chained event log. Every entry commits to the
SHA-256 hash of the entry before it, so anyone can re-verify the chain
later and find out exactly where it was altered.

Quickstart:
    from agent_audit import AuditStore

    store = AuditStore("audit.jsonl")
    store.append(
        run_id="run-123",
        actor="anusha",
        agent_id="planner-1",
        action="shell.exec",
        parameters={"cmd": "ls /tmp"},
        policy_decision="allow",
        policy_id="default-allow",
    )
    result = store.verify()
    assert result.valid
"""

from .export import CSV_COLUMNS, export_csv, export_events, export_jsonl
from .models import (
    GENESIS_PREV_HASH,
    Event,
    sanitize_parameters,
    utc_now_iso,
)
from .query import filter_events, iter_events
from .siem import (
    SIEM_FORMATS,
    build_grafana_dashboard,
    export_datadog,
    export_elastic,
    export_siem,
    export_splunk,
    to_datadog_event,
    to_ecs_event,
    to_splunk_event,
    write_grafana_dashboard,
)
from .store import AuditStore, VerificationProblem, VerificationResult

__version__ = "0.2.0"

__all__ = [
    "GENESIS_PREV_HASH",
    "CSV_COLUMNS",
    "SIEM_FORMATS",
    "AuditStore",
    "Event",
    "VerificationProblem",
    "VerificationResult",
    "build_grafana_dashboard",
    "export_csv",
    "export_datadog",
    "export_elastic",
    "export_events",
    "export_jsonl",
    "export_siem",
    "export_splunk",
    "filter_events",
    "iter_events",
    "sanitize_parameters",
    "to_datadog_event",
    "to_ecs_event",
    "to_splunk_event",
    "utc_now_iso",
    "write_grafana_dashboard",
]
