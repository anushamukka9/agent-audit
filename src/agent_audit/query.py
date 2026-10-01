"""Query helpers: filter events by run, agent, action, or decision."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from .models import Event
from .store import AuditStore


def iter_events(source: str | Path | AuditStore) -> Iterator[Event]:
    """Yield every event in a store, oldest first."""
    store = source if isinstance(source, AuditStore) else AuditStore(source)
    yield from store.iter_events()


def filter_events(
    source: str | Path | AuditStore,
    *,
    run_id: str | None = None,
    agent_id: str | None = None,
    action: str | None = None,
    decision: str | None = None,
    approval: str | None = None,
    actor: str | None = None,
) -> list[Event]:
    """Return events matching all of the given criteria.

    Each criterion is an exact match; pass None to ignore it.
    ``decision`` matches the policy decision ("allow" or "deny").
    """
    wanted = {
        "run_id": run_id,
        "agent_id": agent_id,
        "action": action,
        "policy_decision": decision,
        "human_approval": approval,
        "actor": actor,
    }
    active = {k: v for k, v in wanted.items() if v is not None}
    return [
        event
        for event in iter_events(source)
        if all(getattr(event, key) == value for key, value in active.items())
    ]
