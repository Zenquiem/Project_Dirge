#!/usr/bin/env python3
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Tuple


def cluster_key(ev: Dict[str, Any]) -> Tuple[str, str, str]:
    g = ev.get("gdb", {}) if isinstance(ev.get("gdb", {}), dict) else {}
    sig = str(g.get("signal", ""))
    off = str(g.get("pc_offset", ""))
    rip = str(g.get("rip", g.get("pc", "")))
    stable = off if off else rip
    return (sig, stable, str(ev.get("input_id", "")))


def cluster_evidence(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        buckets[cluster_key(ev)].append(ev)

    out: List[Dict[str, Any]] = []
    for k, items in buckets.items():
        sig, loc, input_id = k
        out.append(
            {
                "cluster_id": f"c_{len(out)+1:04d}",
                "signal": sig,
                "location": loc,
                "input_id": input_id,
                "count": len(items),
                "evidence_ids": [x.get("evidence_id", "") for x in items],
            }
        )
    out.sort(key=lambda x: x.get("count", 0), reverse=True)
    return out
