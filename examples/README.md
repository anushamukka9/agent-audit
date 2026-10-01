# Examples

## demo_run.py

A complete fake agent run, end to end. It logs four events (a web
search, an approved file write with a diff, a denied destructive shell
command, and an API call whose key gets redacted), pins the head hash,
verifies the chain against the pin, queries the denied actions, and
exports everything to CSV.

Run it:

```bash
python examples/demo_run.py
```

It writes to `/tmp/agent-audit-demo/` so it never touches your real
logs. Read it top to bottom if you want the fastest tour of the API;
every public call the library offers shows up in about sixty lines.
