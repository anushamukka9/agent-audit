# Contributing to agent-audit

Thanks for considering a contribution. This is a small, focused library and
we want to keep it that way.

## What fits here

- Better chain hygiene: cheaper verification, safer append paths,
  smarter truncation handling.
- Export targets people actually need (SQLite, Parquet, a SIEM format)
  with a test proving the round trip.
- Framework adapters that log agent runs with zero extra code on the
  caller's side.
- Docs, examples, and benchmark additions.

## What does not fit

- A network service, a hosted dashboard, or anything that phones home.
- Crypto upgrades that break the "read the source in an afternoon"
  bar. SHA-256 and JSONL are boring on purpose.
- Features that need API keys or large dependencies. The core has zero
  runtime dependencies and it should stay that way.

## How to contribute

1. Fork the repo and create a branch: `git checkout -b fix/short-desc`.
2. Add your change plus tests. Chain behavior needs adversarial tests:
   tamper with a byte, delete a line, truncate the tail, and show that
   `verify()` catches each one.
3. Run the gates: `pytest` and `ruff check` / `ruff format --check`.
   Both must be clean.
4. Write your feature's limitations honestly. Every part of this
   library documents what it cannot do. That is a requirement, not a
   suggestion.
5. Open a PR with a short description: what it does, why, and the test
   evidence. Keep the human voice: plain sentences, no hype.

## A note on example secrets

GitHub's secret scanner blocks pushes containing real provider key
formats, even obviously fake ones. If a test fixture or example needs a
secret-shaped value, keep it clearly fake (`sk-test-NOT-A-REAL-KEY`)
and never in a real provider's exact format. Do not disable push
protection to land a fixture.

## Style

- Python 3.10+, `src/` layout, type hints on public APIs.
- Line length 100, ruff-enforced.
- No em-dashes anywhere. This is a hard rule for this repo.
- Commit messages in imperative mood: `fix: detect tail truncation`,
  not `fixed tail truncation`.
