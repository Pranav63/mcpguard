import pytest
from mcpshield.detectors.secrets import scan
from mcpshield.policy.engine import evaluate, load_policy

DEFAULT_POLICY = {
    "policy": {
        "rules": [
            {"detector": "aws_access_key", "action": "block"},
            {"detector": "github_token", "action": "block"},
            {"detector": "high_entropy_string", "action": "flag"},
        ]
    }
}

@pytest.fixture(autouse=True)
def setup_policy():
    load_policy(DEFAULT_POLICY)


def test_aws_key_detected():
    detections = scan("here is my key AKIAIOSFODNN7EXAMPLE and some text")
    assert any(d.rule == "aws_access_key" for d in detections)


def test_aws_key_blocked():
    detections = scan("AKIAIOSFODNN7EXAMPLE")
    violation = evaluate(detections, context="test")
    assert violation is not None
    assert violation.action == "block"


def test_clean_text_passes():
    detections = scan("hello world, nothing sensitive here")
    assert len(detections) == 0


def test_high_entropy_flagged():
    detections = scan("token=aB3xK9mPqR7vLnWjYuEiOcTsDfGhZk2")
    violation = evaluate(detections, context="test")
    assert violation is not None