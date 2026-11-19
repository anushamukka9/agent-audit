"""Tests for the standalone log verifier (agent_audit.verify) and the
verify CLI modes built on it: strict fail-fast, JSON output, verbose.
"""

import json

from agent_audit import AuditStore, first_broken_link, verify_file, verify_lines
from agent_audit.cli import main


def make_log(path, count=4):
    store = AuditStore(path)
    for i in range(count):
        store.append(
            run_id="run-1",
            actor="anusha",
            agent_id="agent-1",
            action=f"tool.call.{i}",
            parameters={"n": i},
        )
    return store


def read_lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def write_lines(path, lines):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def tamper(lines, index, **changes):
    data = json.loads(lines[index])
    data.update(changes)
    lines[index] = json.dumps(data, separators=(",", ":"))
    return lines


# -- the walk ------------------------------------------------------------


def test_clean_chain_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = make_log(path, count=4)
    report = verify_file(path)
    assert report.valid
    assert report.event_count == 4
    assert report.problems == ()
    assert report.first_failure is None
    assert report.head_hash == store.head_hash()
    assert report.detail == "chain intact"


def test_missing_and_empty_files_are_valid(tmp_path):
    missing = verify_file(tmp_path / "nope.jsonl")
    assert missing.valid
    assert missing.event_count == 0

    empty = tmp_path / "empty.jsonl"
    empty.touch()
    report = verify_file(empty)
    assert report.valid
    assert report.event_count == 0


def test_altered_event_is_caught_at_its_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=4)
    write_lines(path, tamper(read_lines(path), 1, action="evil.action"))

    report = verify_file(path)
    assert not report.valid
    assert report.first_failure is not None
    assert report.first_failure.index == 1
    assert report.first_failure.reason == "hash_mismatch"
    # The next line links to the original hash, so it breaks too.
    assert any(p.reason == "broken_link" and p.index == 2 for p in report.problems)


def test_dropped_event_is_caught_at_the_gap(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=4)
    lines = read_lines(path)
    del lines[1]
    write_lines(path, lines)

    report = verify_file(path)
    assert not report.valid
    assert report.first_failure is not None
    assert report.first_failure.index == 1
    assert report.first_failure.reason == "seq_gap"
    assert any(p.reason == "broken_link" for p in report.problems)


def test_reordered_events_are_caught_at_the_first_swap(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=4)
    lines = read_lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    write_lines(path, lines)

    report = verify_file(path)
    assert not report.valid
    assert report.first_failure is not None
    assert report.first_failure.index == 1
    assert report.first_failure.reason in ("seq_gap", "broken_link")


def test_malformed_line_is_caught(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=2)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
    report = verify_file(path)
    assert not report.valid
    assert any(p.reason == "malformed" for p in report.problems)


def test_missing_fields_are_caught(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=2)
    lines = read_lines(path)
    data = json.loads(lines[0])
    del data["event_hash"]
    lines[0] = json.dumps(data)
    write_lines(path, lines)

    report = verify_file(path)
    assert not report.valid
    assert report.problems[0].reason == "malformed"
    assert "event_hash" in report.problems[0].detail


def test_duplicate_event_id_is_caught(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=3)
    lines = read_lines(path)
    lines.append(lines[-1])
    write_lines(path, lines)

    report = verify_file(path)
    assert not report.valid
    assert any(p.reason == "duplicate_id" for p in report.problems)


def test_fail_fast_reports_only_the_first_problem(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=4)
    write_lines(path, tamper(read_lines(path), 1, action="evil.action"))

    full = verify_file(path)
    strict = verify_file(path, fail_fast=True)
    assert len(full.problems) >= 2
    assert len(strict.problems) == 1
    assert strict.problems[0] == full.problems[0]
    assert "first broken link at line 1" in strict.detail


def test_first_broken_link_helper(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=3)
    assert first_broken_link(path) is None

    write_lines(path, tamper(read_lines(path), 2, action="evil.action"))
    problem = first_broken_link(path)
    assert problem is not None
    assert problem.index == 2
    assert problem.reason == "hash_mismatch"


def test_verify_lines_in_memory(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=3)
    report = verify_lines(read_lines(path), source="copy.jsonl")
    assert report.valid
    assert report.path == "copy.jsonl"
    assert report.event_count == 3


def test_on_event_fires_only_for_clean_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=3)
    seen = []
    report = verify_file(path, on_event=lambda i, e: seen.append((i, e.seq)))
    assert report.valid
    assert seen == [(0, 0), (1, 1), (2, 2)]


def test_report_to_dict_is_json_ready(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=2)
    write_lines(path, tamper(read_lines(path), 0, action="evil.action"))
    data = verify_file(path).to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["valid"] is False
    assert data["first_failure"]["index"] == 0
    assert data["first_failure"]["reason"] == "hash_mismatch"


# -- pinning through the standalone verifier ------------------------------


def test_pin_round_trip_and_truncation(tmp_path):
    path = tmp_path / "audit.jsonl"
    pin = tmp_path / "head.pin"
    store = make_log(path, count=3)
    store.pin_head(pin)

    assert verify_file(path, pin_path=pin).valid

    lines = read_lines(path)
    write_lines(path, lines[:-1])
    report = verify_file(path, pin_path=pin)
    assert not report.valid
    assert report.problems[0].reason == "pin_mismatch"


def test_unreadable_pin_is_a_failure(tmp_path):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=1)
    report = verify_file(path, pin_path=tmp_path / "nope.pin")
    assert not report.valid
    assert report.problems[0].reason == "pin_mismatch"


# -- CLI modes -------------------------------------------------------------


def test_cli_strict_fails_loudly_with_first_link_only(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=4)
    write_lines(path, tamper(read_lines(path), 1, action="evil.action"))

    assert main(["verify", str(path), "--strict"]) == 1
    captured = capsys.readouterr()
    assert "valid: False" in captured.out
    # Exactly one problem line is printed, even though the full walk
    # finds a second broken link on the following line.
    assert captured.out.count("\n  line ") == 1
    assert "  line 1: [hash_mismatch]" in captured.out
    assert "FAIL: line 1: [hash_mismatch]" in captured.err


def test_cli_strict_passes_a_clean_log(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=2)
    assert main(["verify", str(path), "--strict"]) == 0
    assert "valid: True" in capsys.readouterr().out


def test_cli_json_format(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=3)
    assert main(["verify", str(path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["valid"] is True
    assert data["event_count"] == 3
    assert data["first_failure"] is None

    write_lines(path, tamper(read_lines(path), 0, action="evil.action"))
    assert main(["verify", str(path), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["valid"] is False
    assert data["first_failure"]["reason"] == "hash_mismatch"


def test_cli_json_with_pin_catches_truncation(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    pin = tmp_path / "head.pin"
    make_log(path, count=3).pin_head(pin)
    write_lines(path, read_lines(path)[:-1])

    assert main(["verify", str(path), "--format", "json", "--pin", str(pin)]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["valid"] is False
    assert data["problems"][0]["reason"] == "pin_mismatch"


def test_cli_verbose_prints_ok_lines(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=3)
    assert main(["verify", str(path), "--verbose"]) == 0
    out = capsys.readouterr().out
    assert "ok line 0 seq 0" in out
    assert "ok line 2 seq 2" in out
    assert "valid: True" in out


def test_cli_default_output_is_unchanged(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    make_log(path, count=2)
    assert main(["verify", str(path)]) == 0
    out = capsys.readouterr().out
    assert "events: 2" in out
    assert "valid: True" in out
    assert "detail: chain intact" in out
