"""End-to-end demo: log a fake agent run, verify it, export it.

Run with:  python examples/demo_run.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_audit import AuditStore, export_events, filter_events

STORE = Path("/tmp/agent-audit-demo/audit.jsonl")
PIN = Path("/tmp/agent-audit-demo/head.pin")
CSV_OUT = Path("/tmp/agent-audit-demo/audit.csv")

DIFF = """--- a/notes.txt
+++ b/notes.txt
@@ -1,3 +1,4 @@
 meeting notes
+- follow up with priya about the deploy
 action items
"""


def main() -> None:
    for f in (STORE, PIN, CSV_OUT):
        if f.exists():
            f.unlink()

    store = AuditStore(STORE)
    run_id = "demo-run-42"

    store.append(
        run_id=run_id,
        actor="anusha",
        agent_id="research-agent",
        action="web.search",
        parameters={"query": "hash chain audit log design"},
        policy_decision="allow",
        policy_id="read-only-tools",
        human_approval="skipped",
    )
    store.append(
        run_id=run_id,
        actor="anusha",
        agent_id="research-agent",
        action="file.write",
        parameters={"path": "/tmp/agent-audit-demo/notes.txt"},
        policy_decision="allow",
        policy_id="writes-need-approval",
        human_approval="approved",
        diff=DIFF,
    )
    # This one gets denied: the policy says no destructive shell commands.
    store.append(
        run_id=run_id,
        actor="anusha",
        agent_id="research-agent",
        action="shell.exec",
        parameters={"cmd": "rm -rf /tmp/agent-audit-demo"},
        policy_decision="deny",
        policy_id="no-destructive-shell",
        human_approval="skipped",
    )
    # Secrets never make it into the log in the clear.
    store.append(
        run_id=run_id,
        actor="scheduler",
        agent_id="research-agent",
        action="api.call",
        parameters={"endpoint": "https://api.example.com/v1", "api_key": "sk-demo-123"},
        policy_decision="allow",
        policy_id="read-only-tools",
        human_approval="skipped",
    )

    print(f"logged {store.event_count()} events to {STORE}")

    # Pin the head somewhere the writer cannot reach (here, a sibling
    # file stands in for "somewhere else").
    store.pin_head(PIN)
    print(f"pinned head hash to {PIN}")

    result = store.verify_with_pin(PIN)
    print(f"verify: valid={result.valid} ({result.detail})")

    denied = filter_events(store, decision="deny")
    print(f"denied actions in this run: {len(denied)}")
    for event in denied:
        print(f"  - {event.agent_id} tried {event.action}: {event.parameters}")

    count = export_events(store, CSV_OUT, format="csv")
    print(f"exported {count} events to {CSV_OUT}")

    approved = filter_events(store, approval="approved")
    print(f"human-approved writes: {len(approved)}")


if __name__ == "__main__":
    main()
