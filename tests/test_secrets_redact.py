from mcpshield.detectors.secrets import redact
from mcpshield.policy.engine import evaluate_and_redact, load_policy


def test_redact_aws_key():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    redacted, detections = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED-AWS_ACCESS_KEY]" in redacted
    assert len(detections) == 1


def test_policy_redact_secrets():
    load_policy(
        {
            "policy": {
                "rules": [{"detector": "aws_access_key", "action": "redact"}]
            }
        }
    )
    raw = '{"content":"AKIAIOSFODNN7EXAMPLE"}'
    body, violation = evaluate_and_redact(raw, context="test")
    assert violation is not None
    assert violation.action == "redact"
    assert "AKIAIOSFODNN7EXAMPLE" not in body
