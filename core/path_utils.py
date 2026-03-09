from __future__ import annotations

import glob
import os
from typing import Any, Callable, List


def parse_any_int(value: Any) -> int:
    if isinstance(value, int):
        return int(value)
    text = str(value or "").strip().lower()
    if not text:
        return 0
    try:
        return int(text, 16) if text.startswith("0x") else int(text, 10)
    except Exception:
        return 0


def latest_file_by_patterns(patterns: List[str], *, root_dir: str, repo_rel_fn: Callable[[str], str]) -> str:
    candidates: List[str] = []
    for pattern in patterns:
        if not pattern:
            continue
        candidates.extend(glob.glob(os.path.join(root_dir, pattern)))
    candidates = [path for path in candidates if os.path.isfile(path)]
    if not candidates:
        return ""
    candidates.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    return repo_rel_fn(candidates[0])
