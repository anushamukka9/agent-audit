"""Event model, parameter sanitization, and hash-chain math.

An event is a plain dict under the hood. The chain links entries
together: each event stores the SHA-256 hash of the previous event, and
its own hash covers that previous hash plus its own fields. Change one
byte of history and every hash after it stops matching.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

#: Previous-hash value used for the first event in a chain.
GENESIS_PREV_HASH = "0" * 64

#: Fields covered by the event hash, in canonical order.
FIELD_ORDER = (
    "event_id",
    "timestamp",
    "seq",
    "run_id",
    "actor",
    "agent_id",
    "action",
    "parameters",
    "policy_decision",
    "policy_id",
    "human_approval",
    "diff",
)

VALID_DECISIONS = ("allow", "deny")
VALID_APPROVALS = ("approved", "skipped", "pending")
REDACTED = "***REDACTED***"

#: Longest parameter string kept verbatim before truncation.
MAX_PARAM_VALUE_LEN = 4096

_SENSITIVE_KEY = re.compile(
    r"(passw|passwd|secret|token|api[_-]?key|auth|credential|"
    r"private[_-]?key|session|cookie|bearer)",
    re.IGNORECASE,
)


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sanitize_parameters(params: Any, _depth: int = 0) -> Any:
    """Return a redacted copy of a parameters dict.

    Values under keys that look like they hold secrets (password, token,
    api_key, and friends) become "***REDACTED***", unless the value is a
    container, which is traversed instead so non-secret structure is
    kept. Very long strings are truncated so one giant blob cannot bloat
    the log. Anything else is copied through unchanged.
    """
    if isinstance(params, dict):
        if _depth > 4:
            return repr(params)[:200]
        cleaned: dict[Any, Any] = {}
        for key, value in params.items():
            if (
                isinstance(key, str)
                and _SENSITIVE_KEY.search(key)
                and not isinstance(value, (dict, list, tuple))
            ):
                cleaned[key] = REDACTED
            else:
                cleaned[key] = sanitize_parameters(value, _depth + 1)
        return cleaned
    if isinstance(params, (list, tuple)):
        if _depth > 4:
            return repr(params)[:200]
        return [sanitize_parameters(item, _depth + 1) for item in params]
    if isinstance(params, str) and len(params) > MAX_PARAM_VALUE_LEN:
        return params[:MAX_PARAM_VALUE_LEN] + "...[truncated]"
    return params


@dataclass
class Event:
    """One audited action in an agent run.

    The fields you set describe what happened. ``seq``, ``prev_hash``,
    and ``event_hash`` are filled in by :class:`AuditStore.append` when
    the event joins the chain; you do not need to set them yourself.
    """

    run_id: str
    actor: str
    agent_id: str
    action: str
    parameters: dict[str, Any] = field(default_factory=dict)
    policy_decision: str = "allow"
    policy_id: str | None = None
    human_approval: str = "skipped"
    diff: str | None = None
    event_id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: str = field(default_factory=utc_now_iso)
    seq: int = 0
    prev_hash: str = GENESIS_PREV_HASH
    event_hash: str = ""

    def __post_init__(self) -> None:
        for name in ("run_id", "actor", "agent_id", "action"):
            if not getattr(self, name):
                raise ValueError(f"Event.{name} must be a non-empty string")
        if self.policy_decision not in VALID_DECISIONS:
            raise ValueError(
                f"policy_decision must be one of {VALID_DECISIONS}, got {self.policy_decision!r}"
            )
        if self.human_approval not in VALID_APPROVALS:
            raise ValueError(
                f"human_approval must be one of {VALID_APPROVALS}, got {self.human_approval!r}"
            )
        self.parameters = sanitize_parameters(dict(self.parameters or {}))

    def payload(self) -> dict[str, Any]:
        """The canonical dict this event's hash is computed over."""
        return {name: getattr(self, name) for name in FIELD_ORDER}

    def compute_hash(self) -> str:
        """SHA-256 over the canonical JSON of this event's fields.

        Covers every field in :data:`FIELD_ORDER` plus ``prev_hash``,
        so the hash commits to the event's content and its position in
        the chain.
        """
        payload = self.payload()
        payload["prev_hash"] = self.prev_hash
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Full event dict, including chain fields, as stored in JSONL."""
        data = asdict(self)
        data["parameters"] = sanitize_parameters(data["parameters"])
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        """Rebuild an event from a stored dict. No re-sanitization."""
        event = cls.__new__(cls)
        for name in FIELD_ORDER + ("prev_hash", "event_hash"):
            setattr(event, name, data.get(name))
        return event
