# Log verification CLI

`store.verify()` works when your own code holds the store. The
standalone verifier is for the other case: a log file lands in front
of you and you want proof, not trust. A teammate sends you a run log,
CI produces one as an artifact, a customer attaches one to a bug
report. You did not write it and you are not going to open a store on
it. You just want to know whether the chain still adds up.

```bash
agent-audit verify audit.jsonl              # full report, every problem
agent-audit verify audit.jsonl --strict     # stop at the first broken link
agent-audit verify audit.jsonl --format json
agent-audit verify audit.jsonl --verbose    # one ok line per event
agent-audit verify audit.jsonl --pin head.pin
```

In Python, the same walk is `verify_file(path)`, and
`first_broken_link(path)` returns just the first problem, or None.

## What the walk proves

Every line is checked the same way, in file order:

| What happened to the log | How the walk catches it | Reason |
|---|---|---|
| An event was altered | The stored hash no longer matches a fresh hash of the event | `hash_mismatch` |
| An event was dropped | The sequence count jumps, and the next event points at a hash that is not in front of it | `seq_gap`, `broken_link` |
| Events were reordered | The first swapped event carries the wrong sequence number and the wrong previous hash | `seq_gap`, `broken_link` |
| A line was garbled or truncated mid-write | The line does not parse, or required fields are missing | `malformed` |
| An event was replayed or copied in | The same `event_id` shows up twice | `duplicate_id` |
| The tail was cut off | The walk alone cannot see this; the head no longer matches a pin | `pin_mismatch` |

The last row is the honest limit of any hash chain, and it is why
`--pin` exists. Pin the head hash somewhere the log writer cannot
reach when the run finishes, then verify against the pin later. See
[verification.md](verification.md) for the reasoning.

## Strict mode fails loudly

The default walk collects every problem, which is what you want when
you are studying a damaged log. A gate wants the opposite:

```bash
$ agent-audit verify audit.jsonl --strict
events: 2
valid: False
detail: first broken link at line 1: [hash_mismatch] stored event_hash does not match recomputed hash; this entry was altered
head: 9f2c...
  line 1: [hash_mismatch] stored event_hash does not match recomputed hash; this entry was altered
FAIL: line 1: [hash_mismatch] stored event_hash does not match recomputed hash; this entry was altered
```

The walk stops at the first broken link, prints one problem, repeats
it as a `FAIL:` line on stderr, and exits 1. A clean log exits 0.
Because the walk stops early, the `events:` count in strict mode is
the number of events walked up to and including the broken one, not
the file total. On a clean log the two are the same.

Exit codes, all modes: 0 means the chain is intact (and matches the
pin, when one is given), 1 means it is not.

## JSON output for CI

`--format json` prints one JSON object: `valid`, `event_count`,
`head_hash`, `detail`, `first_failure`, and the full `problems` list
with line index, reason, and detail per problem. It composes with
`--strict` and `--pin`.

```yaml
# GitHub Actions: fail the job if the run log was touched
- name: Verify the agent audit log
  run: agent-audit verify audit.jsonl --strict --pin head.pin
```

That one step is the whole gate. If you want the report as a build
artifact as well, add `--format json` and upload the output.

## Cost

The walk is one pass, O(n), re-hashing every event. Measured on this
machine on 2026-11-19, the standalone verifier checked a
10,000-event log at about 36,800 events/sec (median of 3 runs), in
line with `store.verify()`. Verify per run or on a schedule, not
after every append.

## What it cannot prove

- That the writer told the truth. The chain proves the log was not
  altered after writing, nothing about whether the events were
  honest when written.
- That nothing was cut from the tail, without a pin to compare
  against.
- Anything about a log in a different format. The verifier reads
  agent-audit JSONL; other hash-chained formats need their own walk.
