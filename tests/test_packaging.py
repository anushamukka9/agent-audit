"""Packaging sanity: version agreement and entry points."""

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # tomllib only exists from Python 3.11 onward
    tomllib = None

import agent_audit


def _pyproject_version():
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    if tomllib is not None:
        return tomllib.loads(text)["project"]["version"]
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert match, "version not found in pyproject.toml"
    return match.group(1)


def test_version_matches_pyproject():
    assert agent_audit.__version__ == _pyproject_version()


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
