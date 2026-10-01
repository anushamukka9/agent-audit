"""Command line interface: init, log, verify, export, query."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .export import export_events
from .query import filter_events
from .store import AuditStore


def _json_params(text: str | None) -> dict:
    if not text:
        return {}
    try:
        params = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: --params is not valid JSON: {exc}") from exc
    if not isinstance(params, dict):
        raise SystemExit("error: --params must be a JSON object")
    return params


def cmd_init(args: argparse.Namespace) -> int:
    store = AuditStore(args.path)
    if Path(args.path).exists():
        print(f"store already exists: {args.path}")
    else:
        Path(args.path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.path).touch()
        print(f"initialized empty audit store: {args.path}")
    print(f"events: {store.event_count()}")
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    diff = None
    if args.diff_file:
        diff = Path(args.diff_file).read_text(encoding="utf-8")
    elif args.diff_text:
        diff = args.diff_text
    store = AuditStore(args.path)
    event = store.append(
        run_id=args.run_id,
        actor=args.actor,
        agent_id=args.agent,
        action=args.action,
        parameters=_json_params(args.params),
        policy_decision=args.decision,
        policy_id=args.policy_id,
        human_approval=args.approval,
        diff=diff,
    )
    print(f"logged event {event.event_id} (seq {event.seq})")
    print(f"hash: {event.event_hash}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    store = AuditStore(args.path)
    if args.pin_out:
        head = store.pin_head(args.pin_out)
        print(f"pinned head hash to {args.pin_out}: {head}")
        return 0
    if args.pin:
        result = store.verify_with_pin(args.pin)
    else:
        result = store.verify()
    print(f"events: {result.event_count}")
    print(f"valid: {result.valid}")
    print(f"detail: {result.detail}")
    if result.head_hash:
        print(f"head: {result.head_hash}")
    for problem in result.problems:
        print(f"  line {problem.index}: [{problem.reason}] {problem.detail}")
    return 0 if result.valid else 1


def cmd_export(args: argparse.Namespace) -> int:
    count = export_events(args.path, args.output, format=args.format)
    print(f"exported {count} events to {args.output} ({args.format})")
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    events = filter_events(
        args.path,
        run_id=args.run_id,
        agent_id=args.agent,
        action=args.action,
        decision=args.decision,
        approval=args.approval,
        actor=args.actor,
    )
    for event in events:
        print(json.dumps(event.to_dict(), ensure_ascii=True))
    print(f"{len(events)} event(s) matched", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-audit",
        description="Tamper-evident audit logging for AI agent runs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create an empty audit store")
    p_init.add_argument("path", help="path to the JSONL store file")
    p_init.set_defaults(func=cmd_init)

    p_log = sub.add_parser("log", help="append one event to the store")
    p_log.add_argument("path", help="path to the JSONL store file")
    p_log.add_argument("--run-id", required=True)
    p_log.add_argument("--actor", required=True, help="who initiated: user id or service")
    p_log.add_argument("--agent", required=True, help="which agent acted")
    p_log.add_argument("--action", required=True, help="tool name or operation")
    p_log.add_argument("--params", default=None, help="parameters as a JSON object")
    p_log.add_argument("--decision", default="allow", choices=["allow", "deny"])
    p_log.add_argument("--policy-id", default=None)
    p_log.add_argument("--approval", default="skipped", choices=["approved", "skipped", "pending"])
    p_log.add_argument("--diff-file", default=None, help="file holding a unified diff")
    p_log.add_argument("--diff-text", default=None, help="unified diff as literal text")
    p_log.set_defaults(func=cmd_log)

    p_verify = sub.add_parser("verify", help="re-hash the chain and report problems")
    p_verify.add_argument("path", help="path to the JSONL store file")
    p_verify.add_argument("--pin", default=None, help="compare head against a pin file")
    p_verify.add_argument("--pin-out", default=None, help="write current head hash to a pin file")
    p_verify.set_defaults(func=cmd_verify)

    p_export = sub.add_parser("export", help="export the store to JSONL or CSV")
    p_export.add_argument("path", help="path to the JSONL store file")
    p_export.add_argument("-o", "--output", required=True)
    p_export.add_argument("--format", default="jsonl", choices=["jsonl", "csv"])
    p_export.set_defaults(func=cmd_export)

    p_query = sub.add_parser("query", help="print events matching filters as JSONL")
    p_query.add_argument("path", help="path to the JSONL store file")
    p_query.add_argument("--run-id", default=None)
    p_query.add_argument("--agent", default=None)
    p_query.add_argument("--action", default=None)
    p_query.add_argument("--decision", default=None, choices=["allow", "deny"])
    p_query.add_argument("--approval", default=None, choices=["approved", "skipped", "pending"])
    p_query.add_argument("--actor", default=None)
    p_query.set_defaults(func=cmd_query)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
