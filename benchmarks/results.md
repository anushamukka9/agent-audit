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

