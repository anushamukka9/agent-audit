# Verification

`store.verify()` replays the whole chain from the first line to the
last and checks five things per entry:

1. The line parses as JSON.
2. All required fields are present.
3. The sequence number continues the count. A gap means entries were
   deleted from the middle.
4. `prev_hash` equals the previous entry's hash. A mismatch means the
   entries were reordered or an entry was swapped.
5. `event_hash` equals a fresh SHA-256 over the entry's fields. A
   mismatch means this entry was altered.

Every problem is reported, not just the first, with the 0-based line
number and a reason: `malformed`, `seq_gap`, `broken_link`, or
`hash_mismatch`. The result object carries `valid`, `event_count`,
`problems`, and `head_hash`.

```python
result = store.verify()
if not result.valid:
    for problem in result.problems:
        print(problem.index, problem.reason, problem.detail)
```

## Why you pin the head hash

The chain alone has a blind spot: if someone deletes entries from the
tail, the remaining chain still verifies perfectly. The chain proves
nothing was changed *within* what you have; it cannot prove you have
*all* of it.

That is what pinning is for. After a run, write the head hash
somewhere the log writer cannot reach:

```python
store.pin_head("/secure/vault/run-123.pin")
```

Later, verify against the pin:

```python
result = store.verify_with_pin("/secure/vault/run-123.pin")
```

If the tail was truncated, the chain still verifies but its head no
longer matches the pin, and you get a `pin_mismatch` problem pointing
at the last entry. The pin file is small JSON with the head hash, the
event count, and a timestamp.

The CLI does the same thing:

```bash
agent-audit verify audit.jsonl --pin-out head.pin
agent-audit verify audit.jsonl --pin head.pin
```

## What verification costs

Verification is O(n): it reads and re-hashes every entry. For very
large logs, verify on a schedule (hourly, per run) rather than after
every append, and keep pins per run so you can verify one run's slice
without replaying the whole file.
