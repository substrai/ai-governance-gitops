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
