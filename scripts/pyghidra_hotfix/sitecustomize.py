"""Runtime hotfixes for pyghidra-mcp subprocesses.

This module is auto-imported by Python (via PYTHONPATH) before pyghidra-mcp
starts. It patches chromadb persistent startup failures observed in this
environment and falls back to an in-memory client.
"""

from __future__ import annotations

import os
import sys


def _enabled() -> bool:
    v = str(os.environ.get("PYGHIDRA_CHROMA_FALLBACK", "1")).strip().lower()
    return v not in {"0", "false", "off", "no"}


def _should_fallback(exc: Exception) -> bool:
    msg = str(exc).lower()
    return ("unable to open database file" in msg) or ("(code: 14)" in msg)


def _patch_chromadb() -> None:
    try:
        import chromadb
        from chromadb.config import Settings
    except Exception:
        return

    original = chromadb.PersistentClient

    def patched_persistent_client(*args, **kwargs):
        try:
            return original(*args, **kwargs)
        except Exception as exc:
            if not _should_fallback(exc):
                raise
            try:
                print(
                    "[pyghidra_hotfix] PersistentClient failed, fallback to in-memory Client",
                    file=sys.stderr,
                )
            except Exception:
                pass
            return chromadb.Client(Settings(anonymized_telemetry=False, is_persistent=False))

    chromadb.PersistentClient = patched_persistent_client


if _enabled():
    _patch_chromadb()
