# Event schema

One event per line in the JSONL store. Fields you set when logging:

| Field | Type | Required | What it means |
|---|---|---|---|
| `run_id` | string | yes | Correlation id for the whole agent run. Every event from one run shares it. |
| `actor` | string | yes | Who initiated the run: a human user id, or a service name like `scheduler`. |
| `agent_id` | string | yes | Which agent acted: `planner-1`, `research-agent`, whatever names you use. |
| `action` | string | yes | What it did: a tool name (`shell.exec`, `file.write`) or an operation. |
| `parameters` | object | no | Sanitized arguments. Secret-looking keys are redacted; see below. Defaults to `{}`. |
| `policy_decision` | string | no | `allow` or `deny`. Defaults to `allow`. |
| `policy_id` | string or null | no | Which policy made the call, e.g. `no-destructive-shell`. |
| `human_approval` | string | no | `approved`, `skipped`, or `pending`. Defaults to `skipped`. |
| `diff` | string or null | no | For write operations: a small unified diff of before/after. |

Chain fields, filled in by `AuditStore.append` (do not set these yourself):

| Field | Type | What it means |
|---|---|---|
| `event_id` | string | Random 32-hex-char id, unique per event. |
| `timestamp` | string | UTC ISO-8601, millisecond precision, e.g. `2026-10-01T22:47:00.123Z`. |
| `seq` | integer | 0-based position in the chain. A gap means entries were deleted. |
| `prev_hash` | string | SHA-256 of the previous event. `000...0` for the first event. |
| `event_hash` | string | SHA-256 over the canonical JSON of every field above plus `prev_hash`. |

## Parameter sanitization

Before an event is written, its parameters are copied and cleaned:

- Any key matching `password`, `passwd`, `secret`, `token`, `api_key`,
  `auth`, `credential`, `private_key`, `session`, `cookie`, or `bearer`
  (case-insensitive, substrings count) has its value replaced with
  `***REDACTED***`. This applies at any nesting depth.
- Strings longer than 4096 characters are truncated with a
  `...[truncated]` marker so one giant blob cannot bloat the log.
- Everything else passes through unchanged, and the caller's dict is
  never mutated.

This is a safety net, not a guarantee. If your parameters carry a
secret under an unusual key name, it will be logged in the clear. Name
your secret fields obviously, or redact them before you call `append`.

## A real event

```json
{"event_id":"9f2c...","timestamp":"2026-10-01T22:47:00.123Z","seq":7,
 "run_id":"run-123","actor":"anusha","agent_id":"planner-1",
 "action":"shell.exec","parameters":{"cmd":"ls /tmp"},
 "policy_decision":"deny","policy_id":"no-destructive-shell",
 "human_approval":"skipped","diff":null,
 "prev_hash":"a91f...","event_hash":"4bd2..."}
```
