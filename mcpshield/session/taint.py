#In-memory session taint: block reuse of sensitive values across tool calls.

_tainted: set[str] = set()
_enabled = False
_min_length = 12


def configure(cfg: dict) -> None:
    global _enabled, _min_length
    taint_cfg = cfg.get("taint", {})
    _enabled = bool(taint_cfg.get("enabled", False))
    _min_length = int(taint_cfg.get("min_length", 12))


def mark(value: str) -> None:
    if not _enabled or len(value) < _min_length:
        return
    _tainted.add(value)


def mark_from_text(text: str, min_len: int | None = None) -> None:
    """Mark contiguous non-whitespace tokens that are long enough."""
    threshold = min_len if min_len is not None else _min_length
    if not _enabled:
        return
    for token in text.split():
        if len(token) >= threshold:
            mark(token)


def check(text: str) -> str | None:
    if not _enabled:
        return None
    for value in _tainted:
        if value in text:
            return value
    return None


def clear() -> None:
    _tainted.clear()
