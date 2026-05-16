import re
from dataclasses import dataclass

PII_PATTERNS: dict[str, str] = {
    "email":          r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone_us":       r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "phone_sg":       r"\b(\+65[-.\s]?)?[689]\d{3}[-.\s]?\d{4}\b",
    "nric_sg":        r"\b[STFGM]\d{7}[A-Z]\b",
    "passport":       r"\b[A-Z]{1,2}\d{6,9}\b",
    "credit_card":    r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "ssn_us":         r"\b\d{3}-\d{2}-\d{4}\b",
    "ip_private":     r"\b(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
}


@dataclass(frozen=True)
class PIIDetection:
    rule: str
    matched: str


def scan_pii(text: str) -> list[PIIDetection]:
    detections = []
    for rule, pattern in PII_PATTERNS.items():
        for match in re.finditer(pattern, text):
            detections.append(PIIDetection(rule=rule, matched=match.group()))
    return detections


def redact(text: str) -> tuple[str, list[PIIDetection]]:
    detections = scan_pii(text)
    redacted = text
    for rule, pattern in PII_PATTERNS.items():
        redacted = re.sub(pattern, f"[REDACTED-{rule.upper()}]", redacted)
    return redacted, detections