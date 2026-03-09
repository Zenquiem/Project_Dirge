#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except Exception:
        return False


def _resolve_host(host: str) -> Tuple[bool, List[str], str]:
    h = host.strip()
    if not h:
        return False, [], "empty host"
    if _is_ip(h):
        return True, [h], ""
    try:
        infos = socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)
    except Exception as e:
        return False, [], str(e)
    ips: List[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    return bool(ips), ips, ""


def _tcp_probe(host: str, port: int, timeout_sec: float) -> Tuple[bool, str, float]:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=max(0.2, float(timeout_sec))):
            dt = (time.monotonic() - t0) * 1000.0
            return True, "", dt
    except Exception as e:
        dt = (time.monotonic() - t0) * 1000.0
        return False, str(e), dt


def _sanitize_sample(data: bytes, max_chars: int = 120) -> str:
    if not data:
        return ""
    txt = data.decode("utf-8", errors="ignore")
    txt = txt.replace("\r", "\\r").replace("\n", "\\n")
    clean = "".join(ch if (32 <= ord(ch) < 127 or ch in "\\r\\n\\t") else "." for ch in txt)
    return clean[:max_chars]


def _service_probe(host: str, port: int, timeout_sec: float, read_timeout_sec: float) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "attempted": True,
        "connected": False,
        "received_bytes": 0,
        "sample": "",
        "prompt_tokens": {"dollar": False, "hash": False},
        "first_byte_ms": 0.0,
        "fragment_count": 0,
        "max_inter_chunk_ms": 0.0,
        "segmented_prompt": False,
        "suggested_env": {},
        "error": "",
    }
    try:
        with socket.create_connection((host, int(port)), timeout=max(0.2, float(timeout_sec))) as s:
            out["connected"] = True
            slice_timeout = min(0.25, max(0.05, float(read_timeout_sec) / 4.0))
            s.settimeout(slice_timeout)
            data = b""
            t0 = time.monotonic()
            chunk_count = 0
            last_chunk_ts = 0.0
            max_gap_ms = 0.0
            sent_probe = False
            while (time.monotonic() - t0) < max(0.2, float(read_timeout_sec)):
                try:
                    chunk = s.recv(256)
                except socket.timeout:
                    chunk = b""
                except Exception:
                    chunk = b""
                now = time.monotonic()
                if chunk:
                    if chunk_count == 0:
                        out["first_byte_ms"] = round((now - t0) * 1000.0, 3)
                    elif last_chunk_ts > 0.0:
                        max_gap_ms = max(max_gap_ms, (now - last_chunk_ts) * 1000.0)
                    last_chunk_ts = now
                    chunk_count += 1
                    data += chunk
                    if len(data) >= 512:
                        break
                    # After first visible prompt/menu bytes, keep a short grace window to observe fragmentation.
                    sample_low = _sanitize_sample(data, max_chars=240).lower()
                    if any(tok in sample_low for tok in (">>", "menu", "choice", "index:", "name:", "size:", "data:", ": ")):
                        grace_end = time.monotonic() + min(0.20, max(0.05, float(read_timeout_sec) / 3.0))
                        while time.monotonic() < grace_end:
                            try:
                                more = s.recv(256)
                            except socket.timeout:
                                more = b""
                            except Exception:
                                more = b""
                            now_more = time.monotonic()
                            if not more:
                                break
                            max_gap_ms = max(max_gap_ms, (now_more - last_chunk_ts) * 1000.0)
                            last_chunk_ts = now_more
                            chunk_count += 1
                            data += more
                            if len(data) >= 512:
                                break
                        break
                elif (not sent_probe) and (not data) and (time.monotonic() - t0) >= min(0.12, max(0.05, float(read_timeout_sec) / 3.0)):
                    try:
                        s.sendall(b"\n")
                        sent_probe = True
                    except Exception:
                        sent_probe = True
                else:
                    time.sleep(0.02)
            if not data and (not sent_probe):
                try:
                    s.sendall(b"\n")
                except Exception:
                    pass
                try:
                    more = s.recv(256)
                    if more:
                        data += more
                except socket.timeout:
                    pass
                except Exception:
                    pass
            out["received_bytes"] = int(len(data))
            out["sample"] = _sanitize_sample(data)
            sample = str(out.get("sample", ""))
            out["prompt_tokens"] = {
                "dollar": ("$" in sample),
                "hash": ("#" in sample),
            }
            out["fragment_count"] = int(chunk_count)
            out["max_inter_chunk_ms"] = round(max_gap_ms, 3)
            out["segmented_prompt"] = bool(chunk_count >= 2 and max_gap_ms >= 35.0)
            suggested_menu_sync = min(1.8, max(0.55, float(read_timeout_sec) + (max_gap_ms / 1000.0) + 0.12))
            suggested_verify = min(2.5, max(0.85, suggested_menu_sync + 0.30))
            suggested_send_delay = min(0.18, max(0.05, 0.06 + (max_gap_ms / 1000.0) / 2.0))
            out["suggested_env"] = {
                "PWN_REMOTE_MENU_SYNC_RECV_SEC": f"{suggested_menu_sync:.2f}",
                "PWN_VERIFY_RECV_SEC": f"{suggested_verify:.2f}",
                "PWN_SEND_DELAY_SEC": f"{suggested_send_delay:.2f}",
            }
            return out
    except Exception as e:
        out["error"] = str(e)
        return out


def _default_report_path(host: str, port: int) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_host = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in host)[:64] or "unknown"
    return os.path.join("artifacts", "reports", f"remote_preflight_{safe_host}_{port}_{ts}.json")


def _is_env_block_error(msg: str) -> bool:
    low = str(msg or "").strip().lower()
    if not low:
        return False
    markers = [
        "operation not permitted",
        "errno 1",
        "permissionerror",
        "[errno 1]",
        "not permitted",
        "epem",
        "eprem",
    ]
    return any(x in low for x in markers)


def _is_dns_error(msg: str) -> bool:
    low = str(msg or "").strip().lower()
    if not low:
        return False
    markers = [
        "name or service not known",
        "temporary failure in name resolution",
        "nodename nor servname provided",
        "getaddrinfo failed",
    ]
    return any(x in low for x in markers)


def main() -> int:
    ap = argparse.ArgumentParser(description="Remote connectivity preflight (DNS + TCP + service probe + IP fallback)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--timeout-sec", type=float, default=2.5)
    ap.add_argument("--max-ip-candidates", type=int, default=4)
    ap.add_argument("--service-read-timeout-sec", type=float, default=0.9)
    ap.add_argument("--disable-service-probe", action="store_true")
    ap.add_argument("--report", default="")
    args = ap.parse_args()

    host = str(args.host or "").strip()
    port = int(args.port or 0)
    if (not host) or port <= 0:
        print(json.dumps({"ok": False, "error": "invalid host/port"}, ensure_ascii=False, indent=2))
        return 2

    dns_ok, ips, dns_error = _resolve_host(host)
    max_ips = max(1, int(args.max_ip_candidates or 1))
    ips = ips[:max_ips]

    attempts: List[Dict[str, Any]] = []
    candidates: List[str] = []

    ok_host, err_host, ms_host = _tcp_probe(host, port, args.timeout_sec)
    service_host = {
        "attempted": False,
        "connected": False,
        "received_bytes": 0,
        "sample": "",
        "error": "",
    }
    if ok_host and (not bool(args.disable_service_probe)):
        service_host = _service_probe(host, port, args.timeout_sec, float(args.service_read_timeout_sec))
    attempts.append(
        {
            "target": host,
            "kind": "hostname",
            "ok": bool(ok_host),
            "error": err_host,
            "latency_ms": round(ms_host, 3),
            "service_probe": service_host,
        }
    )
    if ok_host:
        candidates.append(host)

    for ip in ips:
        if ip == host:
            continue
        ok_ip, err_ip, ms_ip = _tcp_probe(ip, port, args.timeout_sec)
        service_ip = {
            "attempted": False,
            "connected": False,
            "received_bytes": 0,
            "sample": "",
            "error": "",
        }
        if ok_ip and (not bool(args.disable_service_probe)):
            service_ip = _service_probe(ip, port, args.timeout_sec, float(args.service_read_timeout_sec))
        attempts.append(
            {
                "target": ip,
                "kind": "ip",
                "ok": bool(ok_ip),
                "error": err_ip,
                "latency_ms": round(ms_ip, 3),
                "service_probe": service_ip,
            }
        )
        if ok_ip and ip not in candidates:
            candidates.append(ip)

    if (not candidates) and ips:
        candidates.append(ips[0])

    ok = any(bool(x.get("ok", False)) for x in attempts)
    service_probe_attempted = any(
        bool((x.get("service_probe", {}) if isinstance(x.get("service_probe", {}), dict) else {}).get("attempted", False))
        for x in attempts
    )
    service_live = any(
        bool(x.get("ok", False))
        and int((x.get("service_probe", {}) if isinstance(x.get("service_probe", {}), dict) else {}).get("received_bytes", 0) or 0) > 0
        for x in attempts
    )
    service_silent = bool(ok and service_probe_attempted and (not service_live))
    prompt_dual_hint_seen = any(
        bool(
            (x.get("service_probe", {}) if isinstance(x.get("service_probe", {}), dict) else {})
            .get("prompt_tokens", {})
            .get("dollar", False)
        )
        or bool(
            (x.get("service_probe", {}) if isinstance(x.get("service_probe", {}), dict) else {})
            .get("prompt_tokens", {})
            .get("hash", False)
        )
        for x in attempts
    )

    non_ok_errors = [str(x.get("error", "")).strip() for x in attempts if (not bool(x.get("ok", False)))]
    network_blocked = any(_is_env_block_error(e) for e in non_ok_errors)
    dns_fail_only = (not ok) and bool(non_ok_errors) and all(_is_dns_error(e) for e in non_ok_errors if e)
    block_reason = ""
    if network_blocked:
        for e in non_ok_errors:
            if _is_env_block_error(e):
                block_reason = e
                break
    elif dns_fail_only:
        for e in non_ok_errors:
            if _is_dns_error(e):
                block_reason = e
                break

    best_target = ""
    for item in attempts:
        if not isinstance(item, dict):
            continue
        if not bool(item.get("ok", False)):
            continue
        sp = item.get("service_probe", {}) if isinstance(item.get("service_probe", {}), dict) else {}
        if int(sp.get("received_bytes", 0) or 0) > 0:
            best_target = str(item.get("target", "")).strip()
            break
    if (not best_target) and candidates:
        best_target = candidates[0]

    out: Dict[str, Any] = {
        "generated_utc": utc_now(),
        "ok": bool(ok),
        "host": host,
        "port": port,
        "dns_ok": bool(dns_ok),
        "dns_error": dns_error,
        "resolved_ips": ips,
        "attempts": attempts,
        "candidates": candidates,
        "best_target": best_target,
        "network_blocked": bool(network_blocked),
        "dns_fail_only": bool(dns_fail_only),
        "service_probe_attempted": bool(service_probe_attempted),
        "service_live": bool(service_live),
        "service_silent": bool(service_silent),
        "prompt_dual_hint_seen": bool(prompt_dual_hint_seen),
        "block_reason": block_reason,
    }

    report_rel = str(args.report or "").strip() or _default_report_path(host, port)
    report_abs = report_rel if os.path.isabs(report_rel) else os.path.join(ROOT_DIR, report_rel)
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)
    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    out["report"] = os.path.relpath(report_abs, ROOT_DIR)

    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
