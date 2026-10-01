"""Append-only JSONL store with a SHA-256 hash chain.

Every line in the file is one event as JSON. Nothing is ever rewritten
in place: new events go on the end, each one carrying the hash of the
entry before it. :meth:`AuditStore.verify` replays the whole chain and
reports the first place it breaks, which is how you catch tampering or
truncation after the fact.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from .models import GENESIS_PREV_HASH, Event, utc_now_iso


class VerificationProblem(NamedTuple):
    """One thing wrong with the chain."""

    index: int  # 0-based line number in the store file
    reason: str  # malformed | seq_gap | broken_link | hash_mismatch | pin_mismatch
    detail: str


@dataclass
class VerificationResult:
    """Outcome of :meth:`AuditStore.verify`."""

    valid: bool
    event_count: int
    problems: tuple[VerificationProblem, ...] = ()
    head_hash: str | None = None
    detail: str = field(default="", repr=False)


class AuditStore:
    """An append-only, hash-chained event log backed by a JSONL file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._head: Event | None = None
        self._load_head()

    # -- context manager -------------------------------------------------
    def __enter__(self) -> AuditStore:
        return self

    def __exit__(self, *_: object) -> None:
        self._head = None

    # -- appending -------------------------------------------------------
    def append(self, event: Event | None = None, **kwargs: object) -> Event:
        """Append an event and return it with chain fields filled in.

        Pass a ready-made :class:`Event`, or the event fields as keyword
        arguments and one will be built for you.
        """
        if event is None:
            event = Event(**kwargs)  # type: ignore[arg-type]
        if self._head is None:
            event.seq = 0
            event.prev_hash = GENESIS_PREV_HASH
        else:
            event.seq = self._head.seq + 1
            event.prev_hash = self._head.event_hash
        event.event_hash = event.compute_hash()

        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event.to_dict(), ensure_ascii=True, separators=(",", ":"))
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._head = event
        return event

    def event_count(self) -> int:
        """Number of events currently in the store."""
        return (self._head.seq + 1) if self._head is not None else 0

    def head_hash(self) -> str | None:
        """Hash of the most recent event, or None for an empty store."""
        return self._head.event_hash if self._head is not None else None

    def iter_events(self) -> Iterator[Event]:
        """Yield events in order, oldest first."""
        if not self.path.exists():
            return
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield Event.from_dict(json.loads(line))

    # -- verification ----------------------------------------------------
    def verify(self) -> VerificationResult:
        """Re-hash the whole chain and report any tampering or gaps.

        Checks, per line: the JSON parses, all required fields are
        present, the sequence number continues the count (a gap means
        entries were deleted), each ``prev_hash`` matches the previous
        event's hash, and each ``event_hash`` matches a fresh
        computation. All problems are reported, not just the first.
        """
        problems: list[VerificationProblem] = []
        expected_seq = 0
        expected_prev = GENESIS_PREV_HASH
        head_hash: str | None = None
        count = 0

        if not self.path.exists():
            return VerificationResult(True, 0, (), None, "store file does not exist yet")

        with open(self.path, encoding="utf-8") as fh:
            for index, raw in enumerate(fh):
                line = raw.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    problems.append(
                        VerificationProblem(index, "malformed", f"not valid JSON: {exc}")
                    )
                    continue
                missing = [
                    name
                    for name in (
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
                    if name not in data
                ]
                if missing:
                    problems.append(
                        VerificationProblem(
                            index, "malformed", f"missing fields: {', '.join(missing)}"
                        )
                    )
                    continue
                event = Event.from_dict(data)
                if event.seq != expected_seq:
                    problems.append(
                        VerificationProblem(
                            index,
                            "seq_gap",
                            f"expected seq {expected_seq}, found {event.seq}; entries are missing",
                        )
                    )
                    expected_seq = event.seq  # keep checking the rest
                if event.prev_hash != expected_prev:
                    problems.append(
                        VerificationProblem(
                            index, "broken_link", "prev_hash does not match previous hash"
                        )
                    )
                if event.event_hash != event.compute_hash():
                    problems.append(
                        VerificationProblem(
                            index,
                            "hash_mismatch",
                            "stored event_hash does not match recomputed hash; "
                            "this entry was altered",
                        )
                    )
                expected_prev = event.compute_hash()
                head_hash = event.event_hash
                expected_seq += 1
                count += 1

        valid = not problems
        return VerificationResult(
            valid,
            count,
            tuple(problems),
            head_hash,
            "chain intact" if valid else f"{len(problems)} problem(s) found",
        )

    # -- head-hash pinning ------------------------------------------------
    def pin_head(self, pin_path: str | Path) -> str:
        """Write the current head hash to ``pin_path`` for later comparison.

        Keep the pin somewhere the log writer cannot reach: a separate
        host, an object store with versioning, a printed QR code, whatever
        fits your setup. The chain alone cannot tell you the log was
        truncated if you have nothing to compare the head against.
        """
        head = self.head_hash()
        if head is None:
            raise ValueError("cannot pin an empty store")
        pin_path = Path(pin_path)
        pin_path.parent.mkdir(parents=True, exist_ok=True)
        pin_path.write_text(
            json.dumps(
                {
                    "head_hash": head,
                    "event_count": self.event_count(),
                    "pinned_at": utc_now_iso(),
                    "store": str(self.path),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return head

    def verify_with_pin(self, pin_path: str | Path) -> VerificationResult:
        """Verify the chain, then compare its head against a stored pin.

        This is the check that catches whole-tail truncation: the
        remaining chain still verifies on its own, but its head no longer
        matches the hash you pinned earlier.
        """
        result = self.verify()
        if not result.valid:
            return result
        try:
            pin = json.loads(Path(pin_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return VerificationResult(
                False,
                result.event_count,
                (VerificationProblem(-1, "pin_mismatch", f"cannot read pin file: {exc}"),),
                result.head_hash,
                "pin file unreadable",
            )
        if pin.get("head_hash") != result.head_hash:
            problem = VerificationProblem(
                result.event_count - 1,
                "pin_mismatch",
                "chain head does not match the pinned hash; "
                "events were removed from the tail or the pin is stale",
            )
            return VerificationResult(
                False,
                result.event_count,
                (problem,),
                result.head_hash,
                "head hash does not match pin",
            )
        result.detail = "chain intact and head matches pin"
        return result

    # -- internals -------------------------------------------------------
    def _load_head(self) -> None:
        raw = self._read_last_line()
        if raw is None:
            return
        try:
            self._head = Event.from_dict(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            self._head = None

    def _read_last_line(self) -> str | None:
        """Read the last non-empty line without loading the whole file."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        with open(self.path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            # Step back over trailing newlines to land inside the last line.
            while pos > 0:
                fh.seek(pos - 1)
                if fh.read(1) == b"\n":
                    pos -= 1
                else:
                    break
            # Walk backwards to the newline that starts this line.
            buf = b""
            while pos > 0:
                step = min(65536, pos)
                pos -= step
                fh.seek(pos)
                chunk = fh.read(step)
                idx = chunk.rfind(b"\n")
                if idx != -1:
                    buf = chunk[idx + 1 :] + buf
                    break
                buf = chunk + buf
            line = buf.decode("utf-8")
            return line or None
