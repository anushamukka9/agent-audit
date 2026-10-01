"""Benchmarks for agent-audit. Run:  python benchmarks/bench.py [--quick]

Measures single-threaded append throughput, full-chain verification
throughput, average bytes per event, and CSV export time. Writes
benchmarks/results.md. --quick uses small sizes for CI smoke runs and
does not write results.md.
"""

import argparse
import platform
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_audit import AuditStore, export_events  # noqa: E402

HERE = Path(__file__).resolve().parent
WORKDIR = HERE / ".bench-work"

ACTIONS = ["web.search", "file.read", "file.write", "shell.exec", "api.call"]
PARAMS = [
    {"query": "hash chain audit log design"},
    {"path": "/tmp/notes.txt"},
    {"path": "/tmp/notes.txt", "bytes": 128},
    {"cmd": "ls /tmp"},
    {"endpoint": "https://api.example.com/v1", "api_key": "sk-demo-123"},
]


def seed(path: Path, count: int) -> AuditStore:
    store = AuditStore(path)
    for i in range(count):
        action = ACTIONS[i % len(ACTIONS)]
        store.append(
            run_id=f"run-{i // 100}",
            actor="bench",
            agent_id="bench-agent",
            action=action,
            parameters=PARAMS[i % len(PARAMS)],
            policy_decision="deny" if action == "shell.exec" else "allow",
            policy_id="bench-policy",
            human_approval="approved" if action == "file.write" else "skipped",
        )
    return store


def bench_append(count: int) -> float:
    path = WORKDIR / f"append-{count}.jsonl"
    if path.exists():
        path.unlink()
    store = AuditStore(path)
    start = time.perf_counter()
    for i in range(count):
        store.append(
            run_id="run-1",
            actor="bench",
            agent_id="bench-agent",
            action=ACTIONS[i % len(ACTIONS)],
            parameters=PARAMS[i % len(PARAMS)],
            policy_decision="allow",
            policy_id="bench-policy",
        )
    elapsed = time.perf_counter() - start
    return count / elapsed


def bench_verify(count: int) -> tuple[float, int]:
    path = WORKDIR / f"verify-{count}.jsonl"
    if path.exists():
        path.unlink()
    seed(path, count)
    store = AuditStore(path)
    start = time.perf_counter()
    result = store.verify()
    elapsed = time.perf_counter() - start
    assert result.valid
    return count / elapsed, path.stat().st_size


def bench_csv_export(count: int) -> tuple[float, int]:
    src = WORKDIR / f"export-{count}.jsonl"
    if src.exists():
        src.unlink()
    seed(src, count)
    dest = WORKDIR / f"export-{count}.csv"
    if dest.exists():
        dest.unlink()
    start = time.perf_counter()
    written = export_events(src, dest, format="csv")
    elapsed = time.perf_counter() - start
    assert written == count
    return elapsed, dest.stat().st_size


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    WORKDIR.mkdir(parents=True, exist_ok=True)
    try:
        if args.quick:
            append_n = [200]
            verify_n = 500
            export_n = 1000
        else:
            append_n = [1000, 10000]
            verify_n = 10000
            export_n = 50000

        results: dict[str, str] = {}
        append_rates = {}
        for n in append_n:
            rate = bench_append(n)
            append_rates[n] = rate
            results[f"append_{n}"] = f"{rate:,.0f}"
            print(f"append x{n}: {rate:,.0f} events/sec")

        v_rate, v_bytes = bench_verify(verify_n)
        results["verify"] = f"{v_rate:,.0f}"
        avg_bytes = v_bytes / verify_n
        results["avg_bytes"] = f"{avg_bytes:,.0f}"
        print(f"verify x{verify_n}: {v_rate:,.0f} events/sec")
        print(f"avg bytes/event: {avg_bytes:,.0f}")

        csv_secs, csv_bytes = bench_csv_export(export_n)
        results["csv_export"] = f"{csv_secs:.2f}"
        print(f"csv export x{export_n}: {csv_secs:.2f} s ({csv_bytes / 1e6:.1f} MB)")

        if not args.quick:
            machine = (
                f"{platform.system()} {platform.release()} "
                f"({platform.machine()}), Python {platform.python_version()}"
            )
            lines = [
                "# agent-audit benchmark results",
                "",
                f"Measured on: {machine}",
                f"Date: {time.strftime('%Y-%m-%d')}",
                "",
                "Appends are single-threaded with fsync per event, which is the",
                "default durability setting. Verification re-hashes the full chain.",
                "",
                "| Benchmark | Result |",
                "|---|---|",
            ]
            for n in append_n:
                lines.append(
                    f"| Append throughput ({n:,} events, single-threaded, fsync) "
                    f"| {append_rates[n]:,.0f} events/sec |"
                )
            lines.append(
                f"| Full-chain verification ({verify_n:,} events) | {v_rate:,.0f} events/sec |"
            )
            lines.append(f"| Average bytes per event | {avg_bytes:,.0f} |")
            lines.append(f"| CSV export ({export_n:,} events) | {csv_secs:.2f} s |")
            lines.append("")
            (HERE / "results.md").write_text("\n".join(lines) + "\n")
            print("wrote benchmarks/results.md")
    finally:
        shutil.rmtree(WORKDIR, ignore_errors=True)


if __name__ == "__main__":
    main()
