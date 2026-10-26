# agent-audit benchmark results

Measured on: Linux 7.0.0-39-generic (x86_64), Python 3.12.3
Date: 2026-10-01

Appends are single-threaded with fsync per event, which is the
default durability setting. Verification re-hashes the full chain.

| Benchmark | Result |
|---|---|
| Append throughput (1,000 events, single-threaded, fsync) | 49 events/sec |
| Append throughput (10,000 events, single-threaded, fsync) | 56 events/sec |
| Full-chain verification (10,000 events) | 31,875 events/sec |
| Average bytes per event | 480 |
| CSV export (50,000 events) | 1.15 s |


## SIEM export (added 2026-10-26)

Measured on the same machine as above, Python 3.12.3, on 2026-10-26.
Method: the export functions run over 10,000 in-memory events (median
of 3 runs), so these numbers are pure format conversion and file
writing, with no store-read or fsync cost in them. Elastic is slower
because it writes two lines per event (the bulk action line plus the
ECS document).

| Benchmark | Result |
|---|---|
| SIEM export, Splunk HEC envelopes (10,000 events) | 45,720 events/sec |
| SIEM export, Elastic ECS bulk NDJSON (10,000 events) | 32,217 events/sec |
| SIEM export, Datadog log records (10,000 events) | 45,708 events/sec |
