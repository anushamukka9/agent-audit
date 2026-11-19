"""Verify a log you did not write, and watch tampering get caught.

Builds a small clean log, then makes three damaged copies of it: one
event altered, one event dropped, and two events swapped. Each copy
goes through the standalone verifier in fail-fast mode, which stops
at the first broken link and names it.

Run with:  python examples/verify_demo.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_audit import AuditStore, verify_file  # noqa: E402

WORKDIR = Path("/tmp/agent-audit-verify-demo")


def build_clean_log(path: Path) -> None:
    if path.exists():
        path.unlink()
    store = AuditStore(path)
    store.append(
        run_id="demo-run-7",
        actor="anusha",
        agent_id="research-agent",
        action="web.search",
        parameters={"query": "hash chain audit log design"},
        policy_decision="allow",
        policy_id="read-only-tools",
    )
    store.append(
        run_id="demo-run-7",
        actor="anusha",
        agent_id="research-agent",
        action="file.write",
        parameters={"path": "/tmp/notes.txt"},
        policy_decision="allow",
        policy_id="writes-need-approval",
        human_approval="approved",
    )
    store.append(
        run_id="demo-run-7",
        actor="anusha",
        agent_id="research-agent",
        action="shell.exec",
        parameters={"cmd": "rm -rf /tmp/notes"},
        policy_decision="deny",
        policy_id="no-destructive-shell",
    )
    store.append(
        run_id="demo-run-7",
        actor="anusha",
        agent_id="research-agent",
        action="api.call",
        parameters={"endpoint": "https://api.example.com/v1"},
        policy_decision="allow",
        policy_id="read-only-tools",
    )


def show(label: str, path: Path) -> None:
    report = verify_file(path, fail_fast=True)
    if report.valid:
        print(f"{label}: valid, {report.event_count} events, chain intact")
    else:
        first = report.first_failure
        print(f"{label}: INVALID, first broken link at line {first.index}:")
        print(f"  [{first.reason}] {first.detail}")


def main() -> None:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    clean = WORKDIR / "audit.jsonl"
    build_clean_log(clean)
    lines = clean.read_text(encoding="utf-8").splitlines()

    altered = WORKDIR / "altered.jsonl"
    changed = list(lines)
    data = json.loads(changed[1])
    data["action"] = "file.delete"
    changed[1] = json.dumps(data, separators=(",", ":"))
    altered.write_text("\n".join(changed) + "\n", encoding="utf-8")

    dropped = WORKDIR / "dropped.jsonl"
    kept = list(lines)
    del kept[1]
    dropped.write_text("\n".join(kept) + "\n", encoding="utf-8")

    reordered = WORKDIR / "reordered.jsonl"
    swapped = list(lines)
    swapped[1], swapped[2] = swapped[2], swapped[1]
    reordered.write_text("\n".join(swapped) + "\n", encoding="utf-8")

    show("clean    ", clean)
    show("altered  ", altered)
    show("dropped  ", dropped)
    show("reordered", reordered)
    print()
    print("The clean log is the only one that verifies. Each damaged copy")
    print("fails at the first line where the chain stops adding up, which")
    print("is where you start reading. Tail truncation is the one case a")
    print("walk cannot see on its own; pin the head hash for that")
    print("(see docs/log-verification.md).")


if __name__ == "__main__":
    main()
