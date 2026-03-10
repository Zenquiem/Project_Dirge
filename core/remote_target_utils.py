from __future__ import annotations

from typing import Any, Dict, Tuple


def _parse_port(value: Any) -> int:
    try:
        port = int(value or 0)
    except Exception:
        return 0
    return port if port > 0 else 0


def extract_remote_target(state: Dict[str, Any]) -> Tuple[str, int]:
    session = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    remote = session.get("remote", {}) if isinstance(session.get("remote", {}), dict) else {}
    target = remote.get("target", {}) if isinstance(remote.get("target", {}), dict) else {}
    host = str(target.get("host", "")).strip()
    port = _parse_port(target.get("port", 0))
    if host and port > 0:
        return host, port

    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    for key in ("remote", "target"):
        obj = challenge.get(key, {}) if isinstance(challenge.get(key, {}), dict) else {}
        host = str(obj.get("host", "")).strip()
        port = _parse_port(obj.get("port", 0))
        if host and port > 0:
            return host, port

    host = str(challenge.get("remote_host", "")).strip()
    port = _parse_port(challenge.get("remote_port", 0))
    if host and port > 0:
        return host, port
    return "", 0
