"""Standalone verification for hash-chained audit logs.

:class:`AuditStore.verify` answers "is my log intact" from inside the
application that wrote it. This module answers the same question for a
log file you are holding but did not write: a file a teammate sent you,
a log pulled out of CI artifacts, an export from another host. It
walks the file line by line, needs no store object, and never writes
anything.

Two modes:

- Full mode (the default) collects every problem, like
  :meth:`AuditStore.verify`.
- Fail-fast mode (``fail_fast=True``) stops at the first broken link
  and reports only that one. That is the mode you want in a CI gate:
  the log is either intact or it is not, and the first break is where
  you start reading.

What a walk proves, per line: the JSON parses, the required fields are
present, the sequence number continues the count (a gap means an event
was dropped), ``prev_hash`` matches the previous event's hash (a
mismatch means events were reordered, dropped, or swapped), the stored
``event_hash`` matches a fresh computation (a mismatch means the event
was altered), and no ``event_id`` appears twice (a repeat means an
event was replayed or copied in).

Tail truncation is the one thing a walk alone cannot see: the
remaining chain still verifies. Pass ``pin_path`` to compare the head
against a pin written earlier, which is what catches it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from .models import GENESIS_PREV_HASH, Event
from .store import VerificationProblem

#: Fields every stored event must carry for the chain to be checkable.
REQUIRED_FIELDS = (
    "event_id",
    "timestamp",
    "seq",
    "run_id",
    "actor",
    "agent_id",
    "action",
    "prev_hash",
    "event_hash",
)

OnEvent = Callable[[int, Event], None]


@dataclass
class ChainReport:
    """Outcome of :func:`verify_file` or :func:`verify_lines`."""

    path: str
    valid: bool
    event_count: int
    problems: tuple[VerificationProblem, ...] = ()
    head_hash: str | None = None
    detail: str = ""

    @property
    def first_failure(self) -> VerificationProblem | None:
        """The first broken link, or None when the chain is intact."""
        return self.problems[0] if self.problems else None

    def to_dict(self) -> dict:
        """JSON-ready dict, the shape the CLI prints with --format json."""
        return {
            "path": self.path,
            "valid": self.valid,
            "event_count": self.event_count,
            "head_hash": self.head_hash,
            "detail": self.detail,
            "first_failure": (
                {
                    "index": self.first_failure.index,
                    "reason": self.first_failure.reason,
                    "detail": self.first_failure.detail,
                }
                if self.first_failure is not None
                else None
            ),
            "problems": [
                {"index": p.index, "reason": p.reason, "detail": p.detail} for p in self.problems
            ],
        }


def verify_lines(
    lines: Iterable[str],
    *,
    fail_fast: bool = False,
    source: str = "<memory>",
    on_event: OnEvent | None = None,
) -> ChainReport:
    """Walk raw JSONL lines and report every broken link (or the first).

    ``on_event`` is called with ``(index, event)`` for each line that
    parses and passes every check, which is how the CLI prints its
    verbose per-event output without re-reading the file.

    In fail-fast mode the walk stops at the first broken link, so the
    report's ``event_count`` counts the events walked up to and
    including the broken one, not the file's total.
    """
    problems: list[VerificationProblem] = []
    expected_seq = 0
    expected_prev = GENESIS_PREV_HASH
    seen_ids: set[str] = set()
    head_hash: str | None = None
    count = 0
    stopped_early = False

    for index, raw in enumerate(lines):
        line = raw.strip()
        if not line:
            continue
        line_problems: list[VerificationProblem] = []
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            line_problems.append(VerificationProblem(index, "malformed", f"not valid JSON: {exc}"))
            problems.extend(line_problems)
            if fail_fast:
                stopped_early = True
                break
            continue
        missing = [name for name in REQUIRED_FIELDS if name not in data]
        if missing:
            line_problems.append(
                VerificationProblem(index, "malformed", f"missing fields: {', '.join(missing)}")
            )
            problems.extend(line_problems)
            if fail_fast:
                stopped_early = True
                break
            continue

        event = Event.from_dict(data)
        if event.seq != expected_seq:
            line_problems.append(
                VerificationProblem(
                    index,
                    "seq_gap",
                    f"expected seq {expected_seq}, found {event.seq}; entries are missing",
                )
            )
            expected_seq = event.seq  # keep checking the rest
        if event.prev_hash != expected_prev:
            line_problems.append(
                VerificationProblem(index, "broken_link", "prev_hash does not match previous hash")
            )
        if event.event_hash != event.compute_hash():
            line_problems.append(
                VerificationProblem(
                    index,
                    "hash_mismatch",
                    "stored event_hash does not match recomputed hash; this entry was altered",
                )
            )
        if event.event_id in seen_ids:
            line_problems.append(
                VerificationProblem(
                    index,
                    "duplicate_id",
                    f"event_id {event.event_id} appears more than once; "
                    "an entry was replayed or copied in",
                )
            )
        seen_ids.add(event.event_id)

        expected_prev = event.compute_hash()
        head_hash = event.event_hash
        expected_seq += 1
        count += 1

        if line_problems:
            problems.extend(line_problems)
            if fail_fast:
                stopped_early = True
                break
        elif on_event is not None:
            on_event(index, event)

    if fail_fast and problems:
        problems = problems[:1]
    valid = not problems
    if valid:
        detail = "chain intact"
    elif stopped_early and problems:
        first = problems[0]
        detail = f"first broken link at line {first.index}: [{first.reason}] {first.detail}"
    else:
        detail = f"{len(problems)} problem(s) found"
    return ChainReport(
        path=source,
        valid=valid,
        event_count=count,
        problems=tuple(problems),
        head_hash=head_hash,
        detail=detail,
    )


def verify_file(
    path: str | Path,
    *,
    fail_fast: bool = False,
    pin_path: str | Path | None = None,
    on_event: OnEvent | None = None,
) -> ChainReport:
    """Verify the hash-chained log at ``path`` without opening a store.

    A missing file verifies as an empty, valid log, matching
    :meth:`AuditStore.verify`. When ``pin_path`` is given and the chain
    itself is intact, the head hash and event count are also compared
    against the pin, which is the check that catches tail truncation.
    """
    path = Path(path)
    if not path.exists():
        return ChainReport(
            path=str(path), valid=True, event_count=0, detail="store file does not exist yet"
        )
    with open(path, encoding="utf-8") as fh:
        report = verify_lines(fh, fail_fast=fail_fast, source=str(path), on_event=on_event)
    if pin_path is None or not report.valid:
        return report
    return _check_pin(report, Path(pin_path))


def _check_pin(report: ChainReport, pin_path: Path) -> ChainReport:
    try:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        problem = VerificationProblem(-1, "pin_mismatch", f"cannot read pin file: {exc}")
        return ChainReport(
            path=report.path,
            valid=False,
            event_count=report.event_count,
            problems=(problem,),
            head_hash=report.head_hash,
            detail="pin file unreadable",
        )
    head_ok = pin.get("head_hash") == report.head_hash
    count_ok = "event_count" not in pin or pin.get("event_count") == report.event_count
    if head_ok and count_ok:
        return ChainReport(
            path=report.path,
            valid=True,
            event_count=report.event_count,
            problems=(),
            head_hash=report.head_hash,
            detail="chain intact and head matches pin",
        )
    problem = VerificationProblem(
        max(report.event_count - 1, 0),
        "pin_mismatch",
        "chain head does not match the pinned hash; "
        "events were removed from the tail or the pin is stale",
    )
    return ChainReport(
        path=report.path,
        valid=False,
        event_count=report.event_count,
        problems=(problem,),
        head_hash=report.head_hash,
        detail="head hash does not match pin",
    )


def first_broken_link(path: str | Path) -> VerificationProblem | None:
    """The first problem in the log at ``path``, or None if it is intact.

    A fail-fast walk, so this costs one pass up to the break and no
    more. This is the function to reach for in a CI gate.
    """
    return verify_file(path, fail_fast=True).first_failure
