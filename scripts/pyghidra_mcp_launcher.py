#!/usr/bin/env python3
"""Portable pyghidra-mcp launcher for runtime-isolated environments.

Why this exists:
- Project Dirge intentionally overrides HOME/XDG paths for Ghidra runtime isolation.
- CPython derives the per-user site-packages path from HOME.
- When HOME is pointed at a repo-local runtime dir, the stock `pyghidra-mcp`
  console-script can stop seeing the package installed in the real user's
  `~/.local/lib/pythonX.Y/site-packages`, causing an immediate
  `ModuleNotFoundError: pyghidra_mcp`.

This launcher restores the real uid owner's user-site path (derived from the
system account database, not the overridden HOME env var) before importing the
package entrypoint. That keeps the runtime portable across hosts without
hard-coding one machine's absolute site-packages path.
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
    # de-dup while preserving order
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
    extra = str(os.environ.get("DIRGE_PYGHIDRA_EXTRA_SITE", "")).strip()
    if extra and Path(extra).exists() and extra not in sys.path:
        sys.path.insert(0, extra)


def main() -> int:
    _ensure_import_paths()
    from pyghidra_mcp.server import main as pyghidra_main

    sys.argv[0] = re.sub(r"(-script\.pyw|\.exe)?$", "", sys.argv[0])
    return int(pyghidra_main())


if __name__ == "__main__":
    raise SystemExit(main())
