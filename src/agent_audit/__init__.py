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
from .store import AuditStore, VerificationProblem, VerificationResult

__version__ = "0.1.0"

__all__ = [
    "GENESIS_PREV_HASH",
    "CSV_COLUMNS",
    "AuditStore",
    "Event",
    "VerificationProblem",
    "VerificationResult",
    "export_csv",
    "export_events",
    "export_jsonl",
    "filter_events",
    "iter_events",
    "sanitize_parameters",
    "utc_now_iso",
]
