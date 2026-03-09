#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


TYPE_PRI = {
    "stack_overflow": 100,
    "ret2win": 95,
    "ret2libc": 90,
    "fmt": 85,
    "uaf": 80,
    "heap_related": 70,
    "unknown": 30,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class RankedHypothesis:
    item: Dict[str, Any]
    score: int


class HypothesisEngine:
    def __init__(self, max_active: int = 3, no_progress_drop_threshold: int = 2) -> None:
        self.max_active = max_active
        self.no_progress_drop_threshold = max(1, int(no_progress_drop_threshold))

    def score(self, hypo: Dict[str, Any]) -> int:
        htype = str(hypo.get("type", "unknown"))
        base = TYPE_PRI.get(htype, TYPE_PRI["unknown"])

        wt = hypo.get("what_to_prove", [])
        mt = hypo.get("minimal_test", "")
        confidence = hypo.get("confidence", 0.5)
        bonus = 0

        if isinstance(wt, list):
            bonus += min(10, len(wt) * 2)
        if isinstance(mt, str) and mt.strip():
            bonus += 5
        try:
            cf = float(confidence)
            cf = max(0.0, min(1.0, cf))
            bonus += int(cf * 10)
        except Exception:
            pass

        no_progress_loops = int(hypo.get("no_progress_loops", 0) or 0)
        penalty = min(20, no_progress_loops * 5)
        return base + bonus - penalty

    def rank(self, hypotheses: List[Dict[str, Any]]) -> List[RankedHypothesis]:
        ranked = [RankedHypothesis(item=h, score=self.score(h)) for h in hypotheses if isinstance(h, dict)]
        ranked.sort(key=lambda x: x.score, reverse=True)
        return ranked

    def choose_active(self, hypotheses: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        ranked = self.rank(hypotheses)
        active = [r.item for r in ranked[: self.max_active]]
        dropped = [r.item for r in ranked[self.max_active :]]
        return active, dropped

    def _normalize_hypotheses(self, hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen_ids = set()

        for i, h in enumerate(hypotheses):
            if not isinstance(h, dict):
                continue
            item = dict(h)
            hid = str(item.get("hypothesis_id") or item.get("id") or "").strip()
            if not hid:
                hid = f"h_{i + 1:03d}"
            if hid in seen_ids:
                hid = f"{hid}_{i + 1}"
            seen_ids.add(hid)

            item["hypothesis_id"] = hid
            item.setdefault("status", "active")
            item.setdefault("created_utc", utc_now())
            item.setdefault("updated_utc", utc_now())
            item.setdefault("no_progress_loops", 0)
            item.setdefault("confidence", 0.5)
            item["score"] = self.score(item)
            out.append(item)

        return out

    def apply_to_state(self, state: Dict[str, Any]) -> None:
        static = state.setdefault("static_analysis", {})
        hypos = static.get("hypotheses", [])
        if not isinstance(hypos, list):
            hypos = []

        normalized = self._normalize_hypotheses(hypos)
        active, dropped = self.choose_active(normalized)

        for h in active:
            h["status"] = "active"
            h["updated_utc"] = utc_now()
            h["score"] = self.score(h)

        static["hypotheses"] = active

        global_hypos = state.setdefault("hypotheses", {})
        old_dead = global_hypos.get("dead", [])
        dead = old_dead if isinstance(old_dead, list) else []

        for d in dropped:
            dd = dict(d)
            dd["status"] = "dropped"
            dd["drop_reason"] = "rank_below_top_k"
            dd["updated_utc"] = utc_now()
            dd["score"] = self.score(dd)
            if not any(str(x.get("hypothesis_id", "")) == dd["hypothesis_id"] for x in dead if isinstance(x, dict)):
                dead.append(dd)

        global_hypos["active"] = active
        global_hypos["dead"] = dead

    def update_after_loop(self, state: Dict[str, Any], had_progress: bool) -> None:
        global_hypos = state.setdefault("hypotheses", {})
        active = global_hypos.get("active", []) if isinstance(global_hypos.get("active", []), list) else []
        dead = global_hypos.get("dead", []) if isinstance(global_hypos.get("dead", []), list) else []

        next_active: List[Dict[str, Any]] = []
        for h in active:
            if not isinstance(h, dict):
                continue
            hh = dict(h)
            if had_progress:
                hh["no_progress_loops"] = 0
            else:
                hh["no_progress_loops"] = int(hh.get("no_progress_loops", 0) or 0) + 1

            hh["score"] = self.score(hh)
            hh["updated_utc"] = utc_now()

            if int(hh.get("no_progress_loops", 0)) >= self.no_progress_drop_threshold:
                hh["status"] = "dead"
                hh["drop_reason"] = "no_progress_threshold_reached"
                dead.append(hh)
            else:
                hh["status"] = "active"
                next_active.append(hh)

        ranked = self.rank(next_active)
        next_active = [r.item for r in ranked[: self.max_active]]
        overflow = [r.item for r in ranked[self.max_active :]]
        for h in overflow:
            hh = dict(h)
            hh["status"] = "dropped"
            hh["drop_reason"] = "rank_below_top_k"
            dead.append(hh)

        dedup_dead: List[Dict[str, Any]] = []
        seen = set()
        for h in dead:
            if not isinstance(h, dict):
                continue
            hid = str(h.get("hypothesis_id", "")).strip()
            if not hid or hid in seen:
                continue
            seen.add(hid)
            dedup_dead.append(h)

        global_hypos["active"] = next_active
        global_hypos["dead"] = dedup_dead

        static = state.setdefault("static_analysis", {})
        static["hypotheses"] = next_active

    def active_ids(self, state: Dict[str, Any]) -> List[str]:
        active = state.get("hypotheses", {}).get("active", [])
        if not isinstance(active, list):
            return []
        out = []
        for h in active:
            if not isinstance(h, dict):
                continue
            hid = str(h.get("hypothesis_id", "")).strip()
            if hid:
                out.append(hid)
        return out
