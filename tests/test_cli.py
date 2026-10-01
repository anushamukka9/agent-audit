"""Tests for the agent-audit CLI."""

import json

import pytest

from agent_audit import __version__
from agent_audit.cli import main


def run(argv):
    return main(argv)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        run(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_init_creates_store(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    assert run(["init", str(path)]) == 0
    assert path.exists()
    assert "initialized" in capsys.readouterr().out


def test_init_existing_store_is_fine(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    path.touch()
    assert run(["init", str(path)]) == 0
    assert "already exists" in capsys.readouterr().out


def seed(path):
    assert run(["init", str(path)]) == 0
    assert (
        run(
            [
                "log",
                str(path),
                "--run-id",
                "run-1",
                "--actor",
                "anusha",
                "--agent",
                "agent-1",
                "--action",
                "tool.read",
                "--params",
                '{"file": "/etc/hosts"}',
                "--decision",
                "allow",
                "--policy-id",
                "pol-1",
                "--approval",
                "skipped",
            ]
        )
        == 0
    )
    assert (
        run(
            [
                "log",
                str(path),
                "--run-id",
                "run-1",
                "--actor",
                "anusha",
                "--agent",
                "agent-1",
                "--action",
                "shell.exec",
                "--params",
                '{"cmd": "rm -rf /"}',
                "--decision",
                "deny",
                "--policy-id",
                "no-destructive",
                "--approval",
                "skipped",
            ]
        )
        == 0
    )


def test_log_and_verify(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    seed(path)
    out = capsys.readouterr().out
    assert "logged event" in out

    assert run(["verify", str(path)]) == 0
    out = capsys.readouterr().out
    assert "events: 2" in out
    assert "valid: True" in out


def test_verify_fails_on_tampered_store(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    seed(path)
    lines = path.read_text().splitlines()
    data = json.loads(lines[0])
    data["action"] = "evil.action"
    lines[0] = json.dumps(data)
    path.write_text("\n".join(lines) + "\n")

    assert run(["verify", str(path)]) == 1
    out = capsys.readouterr().out
    assert "valid: False" in out
    assert "hash_mismatch" in out


def test_verify_with_pin_flags_truncation(tmp_path):
    path = tmp_path / "audit.jsonl"
    pin = tmp_path / "pin.json"
    seed(path)
    assert run(["verify", str(path), "--pin-out", str(pin)]) == 0
    assert run(["verify", str(path), "--pin", str(pin)]) == 0

    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")
    assert run(["verify", str(path), "--pin", str(pin)]) == 1


def test_log_with_diff_text(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    run(["init", str(path)])
    assert (
        run(
            [
                "log",
                str(path),
                "--run-id",
                "r",
                "--actor",
                "a",
                "--agent",
                "g",
                "--action",
                "file.write",
                "--decision",
                "allow",
                "--approval",
                "approved",
                "--diff-text",
                "--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert run(["export", str(path), "-o", str(tmp_path / "o.jsonl")]) == 0
    data = json.loads((tmp_path / "o.jsonl").read_text().splitlines()[0])
    assert data["diff"].startswith("--- a")
    assert data["human_approval"] == "approved"


def test_log_with_diff_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    diff_file = tmp_path / "change.diff"
    diff_file.write_text("--- a\n+++ b\n")
    run(["init", str(path)])
    assert (
        run(
            [
                "log",
                str(path),
                "--run-id",
                "r",
                "--actor",
                "a",
                "--agent",
                "g",
                "--action",
                "file.write",
                "--diff-file",
                str(diff_file),
            ]
        )
        == 0
    )
    data = json.loads(path.read_text().splitlines()[0])
    assert data["diff"] == "--- a\n+++ b\n"


def test_log_rejects_bad_params_json(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    run(["init", str(path)])
    with pytest.raises(SystemExit) as exc:
        run(
            [
                "log",
                str(path),
                "--run-id",
                "r",
                "--actor",
                "a",
                "--agent",
                "g",
                "--action",
                "act",
                "--params",
                "{not json",
            ]
        )
    assert exc.value.code != 0
    assert "not valid JSON" in str(exc.value)


def test_export_csv(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    seed(path)
    capsys.readouterr()
    out_csv = tmp_path / "out.csv"
    assert run(["export", str(path), "-o", str(out_csv), "--format", "csv"]) == 0
    assert "exported 2 events" in capsys.readouterr().out
    assert out_csv.exists()


def test_export_defaults_to_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    seed(path)
    out = tmp_path / "out.jsonl"
    assert run(["export", str(path), "-o", str(out)]) == 0
    assert len(out.read_text().splitlines()) == 2


def test_query_filters(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    seed(path)
    capsys.readouterr()
    assert run(["query", str(path), "--decision", "deny"]) == 0
    out = capsys.readouterr().out
    assert "shell.exec" in out
    assert "tool.read" not in out


def test_query_no_match(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    seed(path)
    capsys.readouterr()
    assert run(["query", str(path), "--run-id", "nope"]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == ""
    assert "0 event(s) matched" in captured.err


def test_secrets_redacted_through_cli(tmp_path):
    path = tmp_path / "audit.jsonl"
    run(["init", str(path)])
    assert (
        run(
            [
                "log",
                str(path),
                "--run-id",
                "r",
                "--actor",
                "a",
                "--agent",
                "g",
                "--action",
                "login",
                "--params",
                '{"password": "hunter2"}',
            ]
        )
        == 0
    )
    assert "hunter2" not in path.read_text()
