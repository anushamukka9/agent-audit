# Honest limitations

I built this because I wanted a log I could trust after the fact, and
I want to be upfront about what it does and does not give you.

**A hash chain detects tampering only if the head hash is pinned
somewhere the attacker cannot reach.** Without a pin, anyone who can
rewrite the file can rebuild a valid chain from scratch. Pinning is the
whole game; the chain is just the mechanism that makes the pin small.

**It cannot protect against a compromised logger process.** If the
process calling `append` is owned, it can write lies that verify
perfectly. The chain proves the log was not altered after writing. It
says nothing about whether what was written was true.

**Verification is O(n).** Every verify reads and re-hashes the whole
file. That is fine for thousands of events and gets slow for millions.
Verify per run, keep per-run pins, and do not append to one giant file
forever.

**Clock skew across hosts.** Timestamps come from the writer's clock.
If agents run on multiple machines, do not assume the timestamps order
events precisely. `seq` orders them within one store file; across files
you are on your own.

**Sanitization is a net, not a wall.** Secret-looking keys get
redacted, but a secret under an innocent key name lands in the log in
the clear. Redact before you log if the data is sensitive.

**No concurrency control.** Two processes appending to the same file
can interleave lines. Each line is still valid JSON and each event
still hashes correctly, but the chain links may cross. One writer per
file, or a lock in front of it.

**Diffs are evidence, not proof.** The before/after diff is whatever
the caller passed in. The library does not independently observe the
filesystem. Treat diffs as the agent's claim about what changed.

**JSONL is not encrypted.** Anyone who can read the store file can read
every parameter you logged. If the log holds sensitive data, encrypt
the file at rest yourself.
