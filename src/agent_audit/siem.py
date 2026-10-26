"""SIEM export: Splunk, Elastic (ECS), and Datadog formats, plus a
Grafana dashboard for agent activity.

The plain JSONL and CSV exports are fine for a human with a text
editor. They are not what a SIEM wants. Each platform here has a
shape it ingests natively:

- Splunk: one HEC event envelope per line (``time``, ``host``,
  ``source``, ``sourcetype``, ``index``, ``event``), ready to POST to
  a HTTP Event Collector endpoint or to drop in a monitored file.
- Elastic: ECS (Elastic Common Schema) documents in ``_bulk`` NDJSON,
  an action line and a document line per event, ready for
  ``POST /agent-audit-*/_bulk`` or a Logstash/Beats pipeline that
  expects ECS field names.
- Datadog: one JSON log record per line with ``ddsource``, ``ddtags``,
  ``service``, ``hostname``, and the event fields as attributes, the
  shape the Datadog Logs API and log pipelines accept.

Every format carries the full event, including ``event_hash`` and
``prev_hash``, so a SIEM alert can always be traced back to a line in
the original chain and re-verified there. Exporting does not extend
the tamper-evidence story into the SIEM: once an event leaves the
chain file, the SIEM copy is only as trustworthy as the SIEM. See
docs/siem-export.md for the honest version of that.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Event
from .store import AuditStore

#: Values stamped on every exported record so SIEM content can be
#: filtered to this tool and this format version.
SOURCE_NAME = "agent-audit"
SPLUNK_SOURCETYPE = "agent_audit:event"
ECS_VERSION = "8.11.0"
DEFAULT_ELASTIC_INDEX = "agent-audit"
DEFAULT_DATADOG_SERVICE = "agent-audit"

SIEM_FORMATS = ("splunk", "elastic", "datadog")


def _epoch_seconds(timestamp: str) -> float:
    """Parse the store's ISO-8601 timestamps to epoch seconds.

    Falls back to 0.0 for an unparseable value rather than failing the
    whole export; the original timestamp string is always carried
    alongside, so nothing is hidden.
    """
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _base_fields(event: Event) -> dict[str, Any]:
    """The full event dict every SIEM format starts from."""
    return event.to_dict()


def to_splunk_event(
    event: Event, *, host: str = "agent-audit", index: str | None = None
) -> dict[str, Any]:
    """One event as a Splunk HEC envelope."""
    envelope: dict[str, Any] = {
        "time": _epoch_seconds(event.timestamp),
        "host": host,
        "source": SOURCE_NAME,
        "sourcetype": SPLUNK_SOURCETYPE,
        "event": _base_fields(event),
    }
    if index:
        envelope["index"] = index
    return envelope


def to_ecs_event(event: Event) -> dict[str, Any]:
    """One event mapped to Elastic Common Schema field names.

    The mapping is deliberately small and documented in
    docs/siem-export.md: ``@timestamp``, ``event.*`` for the audit
    semantics, ``user.name`` for the actor, ``agent.*``-style fields
    under ``labels`` are avoided in favour of a namespaced
    ``agent_audit`` object that keeps every original field.
    """
    allowed = event.policy_decision == "allow"
    doc: dict[str, Any] = {
        "@timestamp": event.timestamp,
        "ecs": {"version": ECS_VERSION},
        "event": {
            "id": event.event_id,
            "kind": "event",
            "category": ["iam", "process"],
            "type": ["info"] if allowed else ["denied"],
            "action": event.action,
            "outcome": "success" if allowed else "failure",
            "sequence": event.seq,
            "dataset": "agent_audit.event",
            "provider": SOURCE_NAME,
        },
        "message": (
            f"{event.agent_id} ran {event.action}: {event.policy_decision}"
            + (f" by {event.policy_id}" if event.policy_id else "")
        ),
        "user": {"name": event.actor},
        "agent": {"id": event.agent_id, "name": event.agent_id, "type": "ai-agent"},
        "labels": {
            "run_id": event.run_id,
            "policy_decision": event.policy_decision,
            "human_approval": event.human_approval,
        },
        "agent_audit": _base_fields(event),
    }
    if event.policy_id:
        doc["labels"]["policy_id"] = event.policy_id
    return doc


def to_datadog_event(
    event: Event, *, hostname: str = "agent-audit", service: str = DEFAULT_DATADOG_SERVICE
) -> dict[str, Any]:
    """One event as a Datadog log record."""
    status = "OK" if event.policy_decision == "allow" else "ERROR"
    tags = [
        f"run_id:{event.run_id}",
        f"agent_id:{event.agent_id}",
        f"policy_decision:{event.policy_decision}",
        f"human_approval:{event.human_approval}",
    ]
    if event.policy_id:
        tags.append(f"policy_id:{event.policy_id}")
    record: dict[str, Any] = {
        "timestamp": event.timestamp,
        "hostname": hostname,
        "service": service,
        "ddsource": SOURCE_NAME,
        "ddtags": ",".join(tags),
        "status": status,
        "message": f"{event.agent_id} ran {event.action}: {event.policy_decision}",
        "agent_audit": _base_fields(event),
    }
    return record


def _write_lines(events: Iterable[Event], dest: str | Path, render) -> int:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(dest, "w", encoding="utf-8") as fh:
        for event in events:
            for line in render(event):
                fh.write(json.dumps(line, ensure_ascii=True) + "\n")
            count += 1
    return count


def export_splunk(
    events: Iterable[Event],
    dest: str | Path,
    *,
    host: str = "agent-audit",
    index: str | None = None,
) -> int:
    """Write events as Splunk HEC envelopes, one JSON object per line."""
    return _write_lines(events, dest, lambda e: [to_splunk_event(e, host=host, index=index)])


def export_datadog(
    events: Iterable[Event],
    dest: str | Path,
    *,
    hostname: str = "agent-audit",
    service: str = DEFAULT_DATADOG_SERVICE,
) -> int:
    """Write events as Datadog log records, one JSON object per line."""
    return _write_lines(
        events, dest, lambda e: [to_datadog_event(e, hostname=hostname, service=service)]
    )


def export_elastic(
    events: Iterable[Event], dest: str | Path, *, index: str = DEFAULT_ELASTIC_INDEX
) -> int:
    """Write events as Elastic ``_bulk`` NDJSON in ECS shape.

    Each event becomes two lines: an ``index`` action line naming the
    index and the event id, then the ECS document itself.
    """

    def render(event: Event):
        action = {"index": {"_index": index, "_id": event.event_id}}
        return [action, to_ecs_event(event)]

    return _write_lines(events, dest, render)


def export_siem(
    source: str | Path | AuditStore,
    dest: str | Path,
    format: str = "splunk",
    **kwargs: Any,
) -> int:
    """Export a whole store in one SIEM format. Returns the event count.

    ``format`` is one of "splunk", "elastic", or "datadog". Extra
    keyword arguments pass through to the matching exporter (``host``
    and ``index`` for Splunk, ``index`` for Elastic, ``hostname`` and
    ``service`` for Datadog).
    """
    store = source if isinstance(source, AuditStore) else AuditStore(source)
    events = store.iter_events()
    if format == "splunk":
        return export_splunk(events, dest, **kwargs)
    if format == "elastic":
        return export_elastic(events, dest, **kwargs)
    if format == "datadog":
        return export_datadog(events, dest, **kwargs)
    raise ValueError(f"unknown SIEM format: {format!r} (want one of {SIEM_FORMATS})")


def build_grafana_dashboard() -> dict[str, Any]:
    """A Grafana dashboard model for agent activity, as a dict.

    The panels query an Elasticsearch data source holding the ECS
    export (the default variable ``datasource`` is picked at import
    time in Grafana). Queries use the ECS field names from
    :func:`to_ecs_event`, so the dashboard and the exporter cannot
    drift apart without a test noticing.
    """
    ds = {"type": "elasticsearch", "uid": "${datasource}"}

    def panel(pid, title, ptype, query, grid, **extra):
        base = {
            "id": pid,
            "title": title,
            "type": ptype,
            "datasource": ds,
            "gridPos": grid,
            "targets": [{"refId": "A", "query": query, "metrics": [{"type": "count", "id": "1"}]}],
        }
        base.update(extra)
        return base

    return {
        "uid": "agent-audit-activity",
        "title": "Agent activity (agent-audit)",
        "description": (
            "What my agents did, what policy allowed, and what a human approved. "
            "Built for the Elastic ECS export from agent-audit; see docs/siem-export.md."
        ),
        "tags": ["agent-audit", "ai-agents", "audit"],
        "timezone": "utc",
        "schemaVersion": 39,
        "version": 1,
        "refresh": "1m",
        "time": {"from": "now-24h", "to": "now"},
        "templating": {
            "list": [
                {
                    "name": "datasource",
                    "label": "Elasticsearch data source",
                    "type": "datasource",
                    "pluginId": "elasticsearch",
                    "current": {},
                    "hide": 0,
                    "query": "elasticsearch",
                    "refresh": 1,
                    "regex": "",
                    "skipUrlSync": False,
                },
                {
                    "name": "agent_id",
                    "label": "Agent",
                    "type": "query",
                    "datasource": ds,
                    "query": {"query": "agent_audit.agent_id", "type": "lucene"},
                    "current": {"selected": True, "text": "All", "value": "$__all"},
                    "includeAll": True,
                    "multi": True,
                    "hide": 0,
                    "refresh": 2,
                    "skipUrlSync": False,
                },
                {
                    "name": "run_id",
                    "label": "Run",
                    "type": "query",
                    "datasource": ds,
                    "query": {"query": "agent_audit.run_id", "type": "lucene"},
                    "current": {"selected": True, "text": "All", "value": "$__all"},
                    "includeAll": True,
                    "multi": True,
                    "hide": 0,
                    "refresh": 2,
                    "skipUrlSync": False,
                },
            ]
        },
        "panels": [
            panel(
                1,
                "Events over time",
                "timeseries",
                "agent_audit.agent_id:$agent_id AND agent_audit.run_id:$run_id",
                {"h": 8, "w": 16, "x": 0, "y": 0},
            ),
            panel(
                2,
                "Denied actions",
                "stat",
                "agent_audit.policy_decision:deny",
                {"h": 8, "w": 4, "x": 16, "y": 0},
                options={"colorMode": "value", "graphMode": "none"},
            ),
            panel(
                3,
                "Pending approvals",
                "stat",
                "agent_audit.human_approval:pending",
                {"h": 8, "w": 4, "x": 20, "y": 0},
                options={"colorMode": "value", "graphMode": "none"},
            ),
            panel(
                4,
                "Decisions (allow vs deny)",
                "piechart",
                "*",
                {"h": 8, "w": 8, "x": 0, "y": 8},
            ),
            panel(
                5,
                "Top agents by events",
                "barchart",
                "*",
                {"h": 8, "w": 8, "x": 8, "y": 8},
            ),
            panel(
                6,
                "Top actions",
                "barchart",
                "*",
                {"h": 8, "w": 8, "x": 16, "y": 8},
            ),
            panel(
                7,
                "Denied and approved events (detail)",
                "table",
                "agent_audit.policy_decision:deny OR agent_audit.human_approval:approved",
                {"h": 8, "w": 24, "x": 0, "y": 16},
            ),
        ],
    }


def write_grafana_dashboard(dest: str | Path) -> Path:
    """Write :func:`build_grafana_dashboard` to ``dest`` as JSON."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(build_grafana_dashboard(), indent=2) + "\n", encoding="utf-8")
    return dest
