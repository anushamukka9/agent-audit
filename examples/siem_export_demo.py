"""SIEM export demo: log a fake run, export it three ways, write the dashboard.

Run with:  python examples/siem_export_demo.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_audit import AuditStore, export_siem, write_grafana_dashboard

OUT = Path("/tmp/agent-audit-siem-demo")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    store_path = OUT / "audit.jsonl"
    if store_path.exists():
        store_path.unlink()

    store = AuditStore(store_path)
    store.append(
        run_id="demo-run-7",
        actor="anusha",
        agent_id="research-agent",
        action="web.search",
        parameters={"query": "ecs field mapping"},
        policy_decision="allow",
        policy_id="read-only-tools",
    )
    store.append(
        run_id="demo-run-7",
        actor="anusha",
        agent_id="research-agent",
        action="shell.exec",
        parameters={"cmd": "rm -rf /tmp/demo"},
        policy_decision="deny",
        policy_id="no-destructive-shell",
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

    for fmt, name in (
        ("splunk", "splunk.jsonl"),
        ("elastic", "bulk.ndjson"),
        ("datadog", "datadog.jsonl"),
    ):
        dest = OUT / name
        count = export_siem(store, dest, format=fmt)
        print(f"{fmt}: exported {count} events to {dest}")

    dash = write_grafana_dashboard(OUT / "agent-activity.json")
    panels = len(json.loads(dash.read_text())["panels"])
    print(f"grafana: wrote dashboard with {panels} panels to {dash}")

    first = json.loads((OUT / "splunk.jsonl").read_text().splitlines()[0])
    print(f"first splunk event action: {first['event']['action']}")


if __name__ == "__main__":
    main()
