#!/usr/bin/env python3
"""Portable gdb-mcp launcher for runtime-isolated environments.

Why this exists:
- Project Dirge's Codex/OpenClaw wrappers intentionally override HOME/XDG paths
  for runtime isolation.
- The installed `gdb-mcp` console script on this host imports the Python package
  from the real user's `~/.local/lib/pythonX.Y/site-packages`.
- When HOME is redirected to an isolated runtime directory, CPython can stop
  seeing that user-site path, so the server exits before MCP initialize with a
  false `ModuleNotFoundError: gdb_mcp`-style failure.

This launcher restores the uid owner's real user-site import path before
importing `gdb_mcp.server`, mirroring the existing pyghidra launcher approach
without hard-coding one machine's absolute site-packages path.
"""
from __future__ import annotations

import os
import pwd
import re
import site
import sys
from pathlib import Path


def _real_home() -> str:
    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except Exception:
        return os.path.expanduser("~")


def _candidate_user_sites(home: str) -> list[str]:
    ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    candidates = [
        os.path.join(home, ".local", "lib", ver, "site-packages"),
    ]
    try:
        original_home = os.environ.get("HOME")
        os.environ["HOME"] = home
        candidates.append(site.getusersitepackages())
    except Exception:
        pass
    finally:
        if original_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = original_home
    seen: set[str] = set()
    out: list[str] = []
    for raw in candidates:
        p = str(raw or "").strip()
        if not p or p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def _ensure_import_paths() -> None:
    real_home = _real_home()
    for path in reversed(_candidate_user_sites(real_home)):
        if Path(path).exists() and path not in sys.path:
            sys.path.insert(0, path)
    extra = str(os.environ.get("DIRGE_GDB_EXTRA_SITE", "")).strip()
    if extra and Path(extra).exists() and extra not in sys.path:
        sys.path.insert(0, extra)


def main() -> int:
    _ensure_import_paths()
    from gdb_mcp.server import main as gdb_main

    sys.argv[0] = re.sub(r"(-script\.pyw|\.exe)?$", "", sys.argv[0])
    return int(gdb_main())


if __name__ == "__main__":
    raise SystemExit(main())
