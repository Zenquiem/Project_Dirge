#!/usr/bin/env python3
from __future__ import annotations

from typing import Iterable, List


def _ensure_bytes(data: bytes | str) -> bytes:
    if isinstance(data, bytes):
        return data
    return data.encode("latin-1", errors="ignore")


def generate_mutations(seed: bytes | str, max_len: int = 512, limit: int = 32) -> List[bytes]:
    b = _ensure_bytes(seed)
    out: List[bytes] = []

    def add(x: bytes) -> None:
        if len(x) > max_len:
            x = x[:max_len]
        if x not in out:
            out.append(x)

    add(b)
    add(b + b"\n")
    add((b + b"A" * 32)[:max_len])
    add((b + b"A" * 128)[:max_len])
    add((b + b"B" * 256)[:max_len])

    patterns = [b"A", b"B", b"C", b"%p", b"%n", b"\x00", b"\xff"]
    lengths = [8, 16, 32, 64, 128, 256]
    for p in patterns:
        for ln in lengths:
            add((p * ln)[:max_len])
            add(((p * ln) + b"\n")[:max_len])
            if len(out) >= limit:
                return out[:limit]

    return out[:limit]


def write_mutations(paths_prefix: str, corpus: Iterable[bytes]) -> List[str]:
    paths: List[str] = []
    i = 1
    for c in corpus:
        p = f"{paths_prefix}_{i:03d}.bin"
        with open(p, "wb") as f:
            f.write(c)
        paths.append(p)
        i += 1
    return paths
