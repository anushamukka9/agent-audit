"""Packaging sanity: version agreement and entry points."""

from pathlib import Path

import tomllib

import agent_audit


def test_version_matches_pyproject():
    pyproject = tomllib.loads(
        (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    )
    assert agent_audit.__version__ == pyproject["project"]["version"]


def test_public_api_is_exported():
    for name in [
        "AuditStore",
        "Event",
        "VerificationResult",
        "filter_events",
        "iter_events",
        "export_csv",
        "export_jsonl",
        "export_events",
        "sanitize_parameters",
    ]:
        assert name in agent_audit.__all__
        assert hasattr(agent_audit, name)
