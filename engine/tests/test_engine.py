"""Unit tests for the engine's pure decision logic (no AWS calls)."""
import importlib
import os
import sys
from pathlib import Path

import pytest

ENV = {
    "AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "us-east-1",
    "ACCOUNT_ID": "111111111111", "TABLE_NAME": "gov-lifecycle", "EVIDENCE_BUCKET": "example-bucket",
    "REGISTRY_ID": "EXAMPLEREGISTRY0", "AUTOMATION_ROLE_ARN": "arn:aws:iam::111111111111:role/GovAutomationRole",
    "ALERT_TOPIC_ARN": "arn:aws:sns:us-east-1:111111111111:gov-alerts",
    "BOUNDARY_ARN": "arn:aws:iam::111111111111:policy/GovAgentBoundary",
    "GUARDRAILS_JSON": "{}",
}


@pytest.fixture(scope="module")
def engine():
    for k, v in ENV.items():
        os.environ.setdefault(k, v)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    return importlib.import_module("engine")


def answers(**on):
    base = dict.fromkeys(["personalData", "customerFacing", "takesActions", "financialImpact", "externalTools", "autonomous"], False)
    base.update(on)
    return base


@pytest.mark.parametrize("flags, classification, tier", [
    ({}, "PUBLIC", "LOW"),
    ({}, "INTERNAL", "LOW"),
    ({}, "CONFIDENTIAL", "MEDIUM"),
    ({}, "RESTRICTED", "HIGH"),
    ({"customerFacing": True}, "INTERNAL", "MEDIUM"),
    ({"externalTools": True}, "INTERNAL", "MEDIUM"),
    ({"personalData": True}, "INTERNAL", "HIGH"),
    ({"financialImpact": True}, "INTERNAL", "HIGH"),
    ({"customerFacing": True, "takesActions": True}, "INTERNAL", "HIGH"),
    ({"autonomous": True, "takesActions": True}, "INTERNAL", "HIGH"),
    ({"autonomous": True}, "INTERNAL", "MEDIUM"),
])
def test_compute_risk(engine, flags, classification, tier):
    got, reasons = engine.compute_risk(answers(**flags), classification)
    assert got == tier
    assert reasons


def test_username(engine):
    assert engine.username("arn:aws:iam::111111111111:user/gov/gov-james") == "gov-james"
    assert engine.username("arn:aws:sts::111111111111:assumed-role/gov-engine-role/gov-engine") == "gov-engine-role"
    assert engine.username(None) == "unknown"


def test_truthy(engine):
    assert engine.truthy("True") and engine.truthy("yes") and engine.truthy(1)
    assert not engine.truthy("false") and not engine.truthy("")


def test_parse_gate_commands():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from github_gate import GateError, parse_command
    assert parse_command("/approve security looks good") == ("approve", "security", "looks good", None)
    assert parse_command("/APPROVE admin run=42 ship it") == ("approve", "admin", "ship it", 42)
    assert parse_command("/reject security requester cannot self-approve") [0:2] == ("reject", "security")
    for bad in ("/reject security", "/approve janitor", "approve security", ""):
        with pytest.raises(GateError):
            parse_command(bad)


def test_github_identity_helpers():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    import github_gate as G
    assert G.role_of_bot("substrai-gov-security[bot]") == "security"
    assert G.role_of_bot("substrai-gov-janitor[bot]") is None
    assert G.role_of_bot("gauravSsinha") is None
    assert G.agent_of_run({"display_title": "intake · catering-order-assistant"}) == "catering-order-assistant"
    assert G.agent_of_run({"display_title": "Update README"}) is None


@pytest.mark.parametrize("env, state, role, blocked", [
    ("gov-intake", {"roles": {"requestedBy": "security"}}, "security", True),
    ("gov-intake", {"roles": {"requestedBy": "developer"}}, "security", False),
    ("gov-release", {"roles": {"owner": "developer"}, "submittedByRole": "security"}, "security", True),
    ("gov-release", {"roles": {"owner": "developer"}, "submittedByRole": "developer"}, "security", False),
    ("gov-change", {"roles": {"owner": "developer"}, "pendingChange": {"requestedByRole": "security"}}, "security", True),
    ("gov-review", {"roles": {"owner": "owner"}}, "owner", True),
    ("gov-review", {"roles": {"owner": "developer"}}, "owner", False),
    ("gov-retire", {"retirement": {"requestedByRole": "admin"}}, "admin", True),
    ("gov-suspend", {"suspensionRequestedByRole": "security"}, "security", True),
    ("gov-build", {"roles": {"requestedBy": "platform"}}, "platform", False),
])
def test_separation_of_duties(env, state, role, blocked):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    import github_gate as G
    assert (role in G.forbidden_roles(env, state)) is blocked
