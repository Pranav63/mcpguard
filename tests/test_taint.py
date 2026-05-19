import pytest

from mcpshield.proxy.pipeline import init, inspect
from mcpshield.session import taint


@pytest.fixture(autouse=True)
def setup_taint():
    taint.clear()
    init(
        {
            "policy": {"rules": [{"detector": "aws_access_key", "action": "block"}]},
            "taint": {"enabled": True, "min_length": 8},
        }
    )


def test_taint_blocks_reuse():
    secret = "AKIAIOSFODNN7EXAMPLE"
    response = (
        f'{{"jsonrpc":"2.0","id":1,"result":{{"content":"key={secret}"}}}}'
    )
    _, _ = inspect(response, context="resp", record_taint=True)

    request = (
        f'{{"jsonrpc":"2.0","id":2,"method":"tools/call",'
        f'"params":{{"arguments":{{"body":"{secret}"}}}}}}'
    )
    _, violation = inspect(request, context="req")

    assert violation is not None
    assert violation.rule == "taint_leak"
    assert violation.action == "block"


def test_taint_disabled_allows_reuse():
    taint.clear()
    init(
        {
            "policy": {"rules": []},
            "taint": {"enabled": False},
        }
    )
    secret = "supersecretvalue12345"
    taint.mark(secret)
    _, violation = inspect(f'{{"text":"{secret}"}}', context="req")
    assert violation is None
