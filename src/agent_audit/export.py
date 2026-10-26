"""One-command export of an audit log to JSONL or CSV.

SIEM formats (Splunk, Elastic, Datadog) live in :mod:`agent_audit.siem`
and are dispatched from :func:`export_events` here, so one function
covers every destination.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path

from .models import Event
from .store import AuditStore

#: Columns written by the CSV exporter, in order.
CSV_COLUMNS = (
    "event_id",
    "timestamp",
    "seq",
    "run_id",
    "actor",
    "agent_id",
    "action",
    "policy_decision",
    "policy_id",
    "human_approval",
    "prev_hash",
    "event_hash",
    "diff",
)

#: Diffs longer than this are truncated in CSV output so one row cannot
#: swallow the whole file. JSONL export keeps the full diff.
CSV_DIFF_LIMIT = 2000


def _shorten_diff(diff: str | None) -> str:
    if not diff:
        return ""
    if len(diff) <= CSV_DIFF_LIMIT:
        return diff
    return diff[:CSV_DIFF_LIMIT] + "...[truncated]"


def export_jsonl(events: Iterable[Event], dest: str | Path) -> int:
    """Write events as JSONL (one event per line). Returns the count."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(dest, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event.to_dict(), ensure_ascii=True) + "\n")
            count += 1
    return count


def export_csv(events: Iterable[Event], dest: str | Path) -> int:
    """Write events as CSV with a fixed column set. Returns the count."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(dest, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for event in events:
            row = {col: getattr(event, col, "") for col in CSV_COLUMNS}
            row["diff"] = _shorten_diff(row["diff"])
            row["policy_id"] = row["policy_id"] or ""
            writer.writerow(row)
            count += 1
    return count


def export_events(source: str | Path | AuditStore, dest: str | Path, format: str = "jsonl") -> int:
    """Export a whole store to ``dest`` in the given format.

    ``format`` is "jsonl", "csv", or a SIEM format from
    :mod:`agent_audit.siem` ("splunk", "elastic", "datadog").
    Returns the number of events written.
    """
    from .siem import SIEM_FORMATS, export_siem

    store = source if isinstance(source, AuditStore) else AuditStore(source)
    if format == "jsonl":
        return export_jsonl(store.iter_events(), dest)
    if format == "csv":
        return export_csv(store.iter_events(), dest)
    if format in SIEM_FORMATS:
        return export_siem(store, dest, format=format)
    raise ValueError(
        f"unknown export format: {format!r} (want 'jsonl', 'csv', or one of {SIEM_FORMATS})"
    )
