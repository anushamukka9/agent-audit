# SIEM export

The JSONL store is the record. The SIEM is where a security team
actually watches things, so this page is about getting events from
the first into the second without losing the parts that matter:
the hashes, the policy decision, and the approval state.

```bash
agent-audit export audit.jsonl -o splunk.jsonl --format splunk
agent-audit export audit.jsonl -o bulk.ndjson --format elastic
agent-audit export audit.jsonl -o datadog.jsonl --format datadog
agent-audit dashboard -o agent-activity.json
```

In Python:

```python
from agent_audit import export_events, export_siem

export_events(store, "splunk.jsonl", format="splunk")
export_siem(store, "bulk.ndjson", format="elastic", index="agent-audit")
```

Three formats, one per platform I get asked about. Each one carries
the complete original event under a predictable key, so a SIEM alert
can always be traced back to a line in the chain file and re-verified
there with `agent-audit verify`.

## Splunk

One HTTP Event Collector (HEC) envelope per line:

```json
{"time": 1790000000.0, "host": "agent-audit", "source": "agent-audit",
 "sourcetype": "agent_audit:event", "event": { "...": "the full event" }}
```

Send it with any HEC client, for example:

```bash
while IFS= read -r line; do
  curl -s -H "Authorization: Splunk $HEC_TOKEN" \
    -d "$line" https://splunk.example.com:8088/services/collector/event
done < splunk.jsonl
```

Or point a Splunk universal forwarder at the file with
`sourcetype = agent_audit:event`. Useful searches once it lands:
`index=agents sourcetype=agent_audit:event event.policy_decision=deny`
for denied actions, and `event.human_approval=pending` for approvals
nobody has resolved yet. Pass `index=` through `export_siem` (or set
your HEC token's default index) if you do not want the token default.

## Elastic

Elasticsearch `_bulk` NDJSON, two lines per event: an `index` action
line, then the document in ECS (Elastic Common Schema) shape. Ship it
with:

```bash
curl -s -H "Content-Type: application/x-ndjson" \
  -XPOST "https://elastic.example.com:9200/_bulk" --data-binary @bulk.ndjson
```

Create the `agent-audit` index (or your `--index` name) from your
index template first if you run with strict mappings; the export
does not create indices or templates for you.

Field mapping, so nobody has to reverse-engineer it:

| agent-audit field | ECS field |
|---|---|
| `timestamp` | `@timestamp` |
| `event_id` | `event.id` |
| `action` | `event.action` |
| `policy_decision` | `event.outcome` (`allow` = success, `deny` = failure) plus `labels.policy_decision` |
| `seq` | `event.sequence` |
| `actor` | `user.name` |
| `agent_id` | `agent.id` and `agent.name` |
| `run_id`, `human_approval`, `policy_id` | `labels.*` |
| everything, verbatim | the `agent_audit` object |

The verbatim `agent_audit` object is the point: ECS gives you the
standard fields dashboards and rules expect, and the original event
is still right there when a rule fires and someone asks "says who".

## Datadog

One JSON log record per line, the shape the Datadog Logs API and the
agent's file tailing both accept:

```json
{"timestamp": "...", "hostname": "agent-audit", "service": "agent-audit",
 "ddsource": "agent-audit", "ddtags": "run_id:...,policy_decision:deny",
 "status": "ERROR", "message": "agent-1 ran tool.1: deny",
 "agent_audit": { "...": "the full event" }}
```

Denied actions get `status: ERROR` so they light up in log monitors
without a custom rule; allowed actions are `OK`. Tail the file from
the Datadog agent with a custom log config (`source: agent-audit`),
or POST the file to the Logs API. Facets worth creating on day one:
`run_id`, `agent_id`, `policy_decision`, `policy_id`.

## Grafana dashboard

`agent-audit dashboard -o agent-activity.json` writes a dashboard
model, also shipped in this repo at `dashboards/agent-activity.json`.
Import it under Dashboards, New, Import, and pick the Elasticsearch
data source that holds the ECS export when Grafana asks.

Panels: events over time, denied actions, pending approvals,
allow-vs-deny split, top agents, top actions, and a detail table of
denied and human-approved events. Template variables filter by agent
and by run. The panel queries use the `agent_audit.*` field names
from the ECS export, so if you rename the index or add a prefix at
ingest time, adjust the queries to match.

## Honest limitations

- This is export, not a shipper. There is no daemon, no retry queue,
  and no checkpointing here on purpose: run the export from cron or
  ship the store file with the agent you already trust (Splunk
  forwarder, Filebeat, Datadog agent), and keep this library boring.
- Exporting does not move the tamper-evidence guarantee into the
  SIEM. The chain proves the store file was not altered. A SIEM copy
  is only as trustworthy as the SIEM and the pipeline that fed it.
  The hashes ride along so any single SIEM event can be checked
  against the store, but nothing here re-verifies the SIEM copy for
  you.
- Re-exporting a store re-sends events it already sent. The Elastic
  export uses the event id as the document `_id`, so a re-export
  overwrites in place there. Splunk and Datadog will happily index
  duplicates; export incrementally (query first, or track your own
  watermark) if duplicates would bother you.
- ECS mapping is a small, documented subset, not the whole schema.
  If your Elastic deployment enforces ECS strictly, validate the
  `agent_audit` object against your template before a big backfill.
