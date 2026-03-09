from __future__ import annotations

from typing import Any, Dict, Tuple


def extract_remote_target(state: Dict[str, Any]) -> Tuple[str, int]:
    session = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    remote = session.get("remote", {}) if isinstance(session.get("remote", {}), dict) else {}
    target = remote.get("target", {}) if isinstance(remote.get("target", {}), dict) else {}
    host = str(target.get("host", "")).strip()
    port = int(target.get("port", 0) or 0)
    if host and port > 0:
        return host, port

    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    for key in ("remote", "target"):
        obj = challenge.get(key, {}) if isinstance(challenge.get(key, {}), dict) else {}
        host = str(obj.get("host", "")).strip()
        port = int(obj.get("port", 0) or 0)
        if host and port > 0:
            return host, port

    host = str(challenge.get("remote_host", "")).strip()
    port = int(challenge.get("remote_port", 0) or 0)
    if host and port > 0:
        return host, port
    return "", 0
