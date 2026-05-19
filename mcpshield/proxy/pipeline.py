# Shared inspect path for HTTP and stdio transports.

import json

import structlog

from mcpshield.detectors.pii import scan_pii
from mcpshield.detectors.secrets import scan
from mcpshield.policy.engine import evaluate_and_redact, load_policy
from mcpshield.proxy.models import PolicyViolation
from mcpshield.session import taint

log = structlog.get_logger()


def init(cfg: dict) -> None:
    load_policy(cfg)
    taint.configure(cfg)


def _mark_taint_from_body(raw: str) -> None:
    for d in scan(raw):
        taint.mark(d.matched)
    for d in scan_pii(raw):
        taint.mark(d.matched)


def inspect(
    raw: str,
    context: str = "",
    *,
    record_taint: bool = False,
) -> tuple[str, PolicyViolation | None]:
    """
    Scan a JSON-RPC message. Returns (body to send, violation).
    Block violations mean the caller should not forward the message.
    """
    leak = taint.check(raw)
    if leak:
        log.warning("taint_leak", context=context, fragment_len=len(leak))
        return raw, PolicyViolation(
            rule="taint_leak",
            detail=f"Tainted data from a prior tool response blocked in {context}.",
            action="block",
        )

    clean, violation = evaluate_and_redact(raw, context)

    if record_taint:
        _mark_taint_from_body(raw)

    return clean, violation


def block_response(request_id: int | str | None, message: str) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32600, "message": message},
        }
    )


def request_id_from_raw(raw: str) -> int | str | None:
    try:
        return json.loads(raw).get("id")
    except (json.JSONDecodeError, AttributeError):
        return None
