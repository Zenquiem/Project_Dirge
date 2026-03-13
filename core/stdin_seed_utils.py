from __future__ import annotations

import os
import re
from typing import Any, Callable, Dict, Iterable, Tuple

from core.gdb_evidence_utils import cyclic_bytes_lower_triplet, cyclic_bytes_pwntools_lower


CyclicFactory = Callable[[int], bytes]


def resolve_seed_file(path: str, *, root_dir: str = "", search_dirs: Iterable[str] | None = None) -> str:
    raw = str(path or "").strip()
    if not raw:
        return ""
    if os.path.isabs(raw):
        return raw
    cwd_abs = os.path.abspath(raw)
    if os.path.isfile(cwd_abs):
        return cwd_abs
    for base in list(search_dirs or []):
        base = str(base or "").strip()
        if not base:
            continue
        candidate = os.path.abspath(os.path.join(base, raw))
        if os.path.isfile(candidate):
            return candidate
    if root_dir:
        return os.path.abspath(os.path.join(root_dir, raw))
    return cwd_abs


def display_seed_file(path: str, *, resolved: str = "", root_dir: str = "", search_dirs: Iterable[str] | None = None) -> str:
    raw = str(path or "").strip()
    if raw and (not os.path.isabs(raw)):
        return raw
    resolved_abs = str(resolved or "").strip()
    if not resolved_abs:
        resolved_abs = resolve_seed_file(raw, root_dir=root_dir, search_dirs=search_dirs)
    if resolved_abs and root_dir:
        try:
            rel = os.path.relpath(resolved_abs, root_dir)
            if rel and not rel.startswith(".."):
                return rel
        except Exception:
            pass
    return raw or resolved_abs


def detect_cyclic_window(
    stdin_bytes: bytes,
    *,
    cyclic_factory: CyclicFactory,
    pattern_span: int = 8192,
    min_window: int = 4,
) -> Dict[str, Any]:
    data = bytes(stdin_bytes or b"")
    info: Dict[str, Any] = {
        "cyclic_compatible": False,
        "cyclic_offset_start": 0,
        "cyclic_span": 0,
        "cyclic_window_len": 0,
    }
    if len(data) < max(1, int(min_window or 1)):
        return info

    patterns = [cyclic_factory(max(64, int(pattern_span or 0)) + 16)]
    try:
        patterns.append(cyclic_bytes_pwntools_lower(max(64, int(pattern_span or 0)) + 16, subseq_len=4))
    except Exception:
        pass
    try:
        patterns.append(cyclic_bytes_lower_triplet(max(64, int(pattern_span or 0)) + 16))
    except Exception:
        pass
    best_start = -1
    best_len = 0
    data_len = len(data)
    min_required = max(1, int(min_window or 1))

    for pattern in patterns:
        for data_idx in range(data_len):
            byte = data[data_idx : data_idx + 1]
            pat_idx = pattern.find(byte)
            while pat_idx >= 0:
                run = 1
                max_run = min(len(pattern) - pat_idx, data_len - data_idx)
                while run < max_run and pattern[pat_idx + run] == data[data_idx + run]:
                    run += 1
                if run > best_len:
                    best_len = run
                    best_start = pat_idx
                pat_idx = pattern.find(byte, pat_idx + 1)

    if best_start < 0 or best_len < min_required:
        return info

    info["cyclic_compatible"] = True
    info["cyclic_offset_start"] = int(best_start)
    info["cyclic_span"] = int(best_start + best_len)
    info["cyclic_window_len"] = int(best_len)
    return info


def select_seed_input(
    *,
    file_env: str,
    hex_env: str,
    text_env: str,
    auto_len_env: str,
    cyclic_factory: CyclicFactory,
    root_dir: str = "",
    search_dirs: Iterable[str] | None = None,
    error_prefix: str = "stdin",
    auto_len_default: int = 320,
    auto_len_min: int = 32,
    auto_len_max: int = 8192,
) -> Tuple[bytes, str, str, int]:
    stdin_file = str(os.environ.get(file_env, "")).strip()
    if stdin_file:
        resolved = resolve_seed_file(stdin_file, root_dir=root_dir, search_dirs=search_dirs)
        display = display_seed_file(stdin_file, resolved=resolved, root_dir=root_dir, search_dirs=search_dirs)
        try:
            with open(resolved, "rb") as f:
                data = f.read()
            return data, f"file:{display}", "seeded_file", len(data)
        except Exception as e:
            raise RuntimeError(f"{error_prefix}_file_unreadable:{e}") from e

    stdin_hex = str(os.environ.get(hex_env, "")).strip()
    if stdin_hex:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", stdin_hex)
        if (not cleaned) or (len(cleaned) % 2 != 0):
            raise RuntimeError(f"{error_prefix}_hex_invalid")
        try:
            data = bytes.fromhex(cleaned)
            return data, "hex-env", "seeded_hex", len(data)
        except Exception as e:
            raise RuntimeError(f"{error_prefix}_hex_invalid:{e}") from e

    if text_env in os.environ:
        data = os.environ.get(text_env, "").encode("utf-8")
        return data, "text-env", "seeded_text", len(data)

    cyclic_len_raw = str(os.environ.get(auto_len_env, "")).strip()
    cyclic_len = int(auto_len_default)
    if cyclic_len_raw:
        try:
            cyclic_len = max(int(auto_len_min), min(int(auto_len_max), int(cyclic_len_raw)))
        except Exception as e:
            raise RuntimeError(f"{error_prefix}_auto_cyclic_len_invalid:{e}") from e
    data = cyclic_factory(cyclic_len)
    return data, "auto-cyclic", "auto_cyclic", cyclic_len
