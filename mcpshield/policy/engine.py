import structlog

from mcpshield.detectors.pii import redact as redact_pii
from mcpshield.detectors.pii import scan_pii
from mcpshield.detectors.secrets import Detection, redact as redact_secrets
from mcpshield.detectors.secrets import scan
from mcpshield.proxy.models import PolicyViolation

log = structlog.get_logger()

_policy_rules: dict[str, str] = {}  # rule_name -> action


def load_policy(cfg: dict) -> None:
    global _policy_rules
    rules = cfg.get("policy", {}).get("rules", [])
    _policy_rules = {r["detector"]: r["action"] for r in rules}
    log.info("policy_loaded", rule_count=len(_policy_rules))


def _action_for(rule: str) -> str:
    return _policy_rules.get(rule, "flag")


def evaluate(detections: list[Detection], context: str = "") -> PolicyViolation | None:
    for d in detections:
        if _action_for(d.rule) == "block":
            log.warning("policy_block", rule=d.rule, context=context)
            return PolicyViolation(
                rule=d.rule,
                detail=f"Detected '{d.rule}' in {context}. Request blocked.",
                action="block",
            )

    for d in detections:
        if _action_for(d.rule) == "flag":
            log.info("policy_flag", rule=d.rule, context=context)
            return PolicyViolation(
                rule=d.rule,
                detail=f"Flagged '{d.rule}' in {context}.",
                action="flag",
            )

    return None


def evaluate_and_redact(
    raw: str, context: str = ""
) -> tuple[str, PolicyViolation | None]:
    """Scan secrets and PII; block, redact, or flag per policy."""
    secret_detections = scan(raw)
    secret_violation = evaluate(secret_detections, context)
    if secret_violation and secret_violation.action == "block":
        return raw, secret_violation

    redact_rules = {r for r, a in _policy_rules.items() if a == "redact"}
    block_rules = {r for r, a in _policy_rules.items() if a == "block"}

    body = raw
    if any(d.rule in redact_rules for d in secret_detections):
        body, _ = redact_secrets(body)
        log.info(
            "policy_redact_secrets",
            rules=[d.rule for d in secret_detections],
            context=context,
        )
        return body, PolicyViolation(
            rule="secrets_redacted",
            detail=f"Secrets redacted in {context}.",
            action="redact",
        )

    pii_detections = scan_pii(body)
    for d in pii_detections:
        if d.rule in block_rules:
            log.warning("policy_block_pii", rule=d.rule, context=context)
            return raw, PolicyViolation(
                rule=d.rule,
                detail=f"Detected '{d.rule}' in {context}. Request blocked.",
                action="block",
            )

    if any(d.rule in redact_rules for d in pii_detections):
        body, _ = redact_pii(body)
        log.info(
            "policy_redact_pii",
            rules=[d.rule for d in pii_detections],
            context=context,
        )
        return body, PolicyViolation(
            rule="pii_redacted",
            detail=f"PII redacted in {context}.",
            action="redact",
        )

    if secret_violation:
        return body, secret_violation

    return body, None
