from __future__ import annotations

import re
from typing import Any


def compact_text(value: Any, max_chars: int) -> str:
    txt = " ".join(str(value or "").split())
    if max_chars <= 0:
        return txt
    if len(txt) <= max_chars:
        return txt
    return txt[: max_chars - 3] + "..."


def truthy_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def session_tag(raw: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(raw or "").strip())
    normalized = normalized.strip("._-")
    return normalized or "shared"
