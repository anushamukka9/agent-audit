# agent-audit

Tamper-evident audit logging for AI agent runs. An append-only,
hash-chained event log: every entry commits to the SHA-256 hash of the
entry before it, so you can re-verify the whole chain later and find
out exactly where it was altered. Zero runtime dependencies.

## Why this exists

I run agents that call tools, write files, and occasionally try things
they should not. When something goes wrong I want to answer two
questions: what did it actually do, and can I prove nobody edited the
log afterwards? Most agent frameworks either log to a plain text file
anyone can rewrite, or ship a heavy observability platform I do not
want to operate.

So I built the boring version. JSONL on disk, one event per line, each
line chained to the last with SHA-256. A `verify` command that replays
the chain and tells you the exact line where it breaks. A pin file you
keep somewhere the writer cannot reach, which is what actually catches
tail truncation. Nothing clever, nothing to operate, and the whole
thing fits in your head in an afternoon.

## Quickstart

```bash
pip install agent-audit
```

```bash
agent-audit init audit.jsonl

agent-audit log audit.jsonl \
  --run-id run-123 \
  --actor anusha \
  --agent planner-1 \
  --action web.search \
  --params '{"query": "hash chain audit log"}' \
  --decision allow \
  --policy-id read-only-tools

agent-audit verify audit.jsonl
# events: 1
# valid: True
# detail: chain intact
```

In Python:

```python
from agent_audit import AuditStore

store = AuditStore("audit.jsonl")

store.append(
    run_id="run-123",
    actor="anusha",
    agent_id="planner-1",
    action="file.write",
    parameters={"path": "/tmp/notes.txt"},
    policy_decision="allow",
    policy_id="writes-need-approval",
    human_approval="approved",
    diff="--- a/notes.txt\n+++ b/notes.txt\n@@ -1 +1 @@\n-old\n+new\n",
)

result = store.verify()
assert result.valid
```

Thirty seconds, start to finish. See
[docs/quickstart.md](docs/quickstart.md) for more, and
[examples/demo_run.py](examples/demo_run.py) for a full fake agent run
with a denied action and a human approval.

## What gets logged

Each event records the run id, actor (who initiated: a user id or a
service), agent identity, action (tool name or operation), sanitized
parameters, the policy decision (`allow`/`deny` plus which policy made
the call), human approval state (`approved`/`skipped`/`pending`), and
an optional before/after diff for write operations. Secret-looking
parameter values are redacted before anything hits the disk. The full
field list is in [docs/event-schema.md](docs/event-schema.md).

## CLI

```bash
agent-audit init audit.jsonl                        # create an empty store
agent-audit log audit.jsonl --run-id r --actor u --agent a --action tool.call
agent-audit verify audit.jsonl                      # re-hash the chain
agent-audit verify audit.jsonl --pin-out head.pin   # pin the head hash
agent-audit verify audit.jsonl --pin head.pin       # verify against the pin
agent-audit export audit.jsonl -o out.csv --format csv
agent-audit query audit.jsonl --decision deny       # JSONL of denied actions
```

## Python API

```python
from agent_audit import AuditStore, filter_events, export_events

store = AuditStore("audit.jsonl")

# Query: exact-match filters, combinable
denied = filter_events(store, run_id="run-123", decision="deny")
approved_writes = filter_events(store, approval="approved")

# Export
export_events(store, "audit.csv", format="csv")   # or "jsonl"

# Pin the head hash somewhere the writer cannot reach, then verify
# against it later. This is what catches tail truncation.
store.pin_head("/secure/vault/run-123.pin")
result = store.verify_with_pin("/secure/vault/run-123.pin")
```

How verification works and why the pin matters:
[docs/verification.md](docs/verification.md).

## Benchmarks

Measured on this machine (see [benchmarks/results.md](benchmarks/results.md)
for the setup). Appends are single-threaded with fsync per event, which
is the default durability setting.

| Benchmark | Result |
|---|---|
| Append throughput (1,000 events, single-threaded, fsync) | 49 events/sec |
| Append throughput (10,000 events, single-threaded, fsync) | 56 events/sec |
| Full-chain verification (10,000 events) | 31,875 events/sec |
| Average bytes per event | 480 |
| CSV export (50,000 events) | 1.15 s |

## Honest limitations

- A hash chain detects tampering only if the head hash is pinned
  somewhere the attacker cannot reach. Without a pin, anyone who can
  rewrite the file can rebuild a valid chain from scratch.
- It cannot protect against a compromised logger process writing lies.
  The chain proves the log was not altered after writing, not that
  what was written was true.
- Verification is O(n): it re-hashes every entry.
- Timestamps come from the writer's clock; clock skew across hosts is
  real.
- Parameter sanitization redacts secret-looking keys, but a secret
  under an innocent key name lands in the log in the clear.

The full list, with the reasoning: [docs/limitations.md](docs/limitations.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Small and focused stays small
and focused: chain behavior needs adversarial tests, every feature
documents what it cannot do, and there are no em-dashes in this repo.

## License

MIT. See [LICENSE](LICENSE).
