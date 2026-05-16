import math
import re
from dataclasses import dataclass

PATTERNS: dict[str, str] = {
    "aws_access_key":  r"AKIA[0-9A-Z]{16}",
    "github_token":    r"ghp_[a-zA-Z0-9]{36}",
    "openai_key":      r"sk-[a-zA-Z0-9]{48}",
    "anthropic_key":   r"sk-ant-[a-zA-Z0-9\-]{90,}",
    "jwt":             r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
    "private_key_pem": r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    "stripe_live":     r"sk_live_[0-9a-zA-Z]{24}",
    "gcp_api_key":     r"AIza[0-9A-Za-z\-_]{35}",
}

ENTROPY_THRESHOLD = 4.5
MIN_ENTROPY_LEN   = 20


@dataclass(frozen=True)
class Detection:
    rule: str
    matched: str  # never log raw in prod — caller decides


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _high_entropy_tokens(text: str) -> list[Detection]:
    detections = []
    for token in re.split(r"[\s,;\"']+", text):
        if len(token) >= MIN_ENTROPY_LEN and _shannon_entropy(token) >= ENTROPY_THRESHOLD:
            detections.append(Detection(rule="high_entropy_string", matched=token))
    return detections


def scan(text: str) -> list[Detection]:
    detections: list[Detection] = []

    for rule, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text):
            detections.append(Detection(rule=rule, matched=match.group()))

    if not detections:
        detections.extend(_high_entropy_tokens(text))

    return detections