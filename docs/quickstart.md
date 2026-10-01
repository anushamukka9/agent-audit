# Quickstart

Install:

```bash
pip install agent-audit
```

Create a store and log your first event:

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
```

Verify the chain whenever you want:

```bash
agent-audit verify audit.jsonl
```

In Python, the same thing looks like this:

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
print(result.valid, result.event_count)
```

A few things worth knowing up front:

- Every append is fsynced, so an event is on disk before `append`
  returns. That costs some throughput; the benchmark numbers are
  measured with fsync on.
- Parameters are sanitized on the way in. Anything under a
  secret-looking key (`password`, `api_key`, `token`, and friends)
  becomes `***REDACTED***`. The original value never touches the file.
- Timestamps are UTC ISO-8601 with millisecond precision.
- The store file is plain JSONL. You can read it with `jq`, `grep`,
  or anything else; the library never requires you to go through it.

Next: [the event schema](event-schema.md), [how verification works](verification.md),
and the [honest limitations](limitations.md).
