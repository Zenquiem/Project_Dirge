#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _non_empty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def exploit_stage_level(stage: str) -> int:
    s = str(stage).strip().lower()
    if not s.startswith("exploit_l"):
        return -1
    tail = s[len("exploit_l") :]
    return int(tail) if tail.isdigit() else -1


def terminal_exploit_stage(stages: List[str]) -> str:
    best = ""
    best_lv = -1
    for st in stages:
        lv = exploit_stage_level(st)
        if lv > best_lv:
            best_lv = lv
            best = st
    return best if best_lv >= 0 else ""


@dataclass
class ObjectiveEval:
    generated_utc: str
    score: int
    target_achieved: bool
    competition_target_achieved: bool
    competition_reasons: List[str]
    required_stages: List[str]
    missing_stages: List[str]
    stage_completion: Dict[str, bool]
    blockers: List[str]
    capabilities_all_ok: bool
    capabilities_any_ok: bool
    required_capabilities_all: List[str]
    required_capabilities_any: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _stage_completion(state: Dict[str, Any], stage: str, enable_exploit: bool) -> bool:
    protections = state.get("protections", {}) if isinstance(state.get("protections", {}), dict) else {}
    static = state.get("static_analysis", {}) if isinstance(state.get("static_analysis", {}), dict) else {}
    dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
    latest_bases = state.get("latest_bases", {}) if isinstance(state.get("latest_bases", {}), dict) else {}
    exp = state.get("session", {}).get("exp", {}) if isinstance(state.get("session", {}).get("exp", {}), dict) else {}

    if stage == "recon":
        return _non_empty_str(protections.get("arch")) and (protections.get("pie", None) is not None)
    if stage == "ida_slice":
        entrypoints = static.get("entrypoints", []) if isinstance(static.get("entrypoints", []), list) else []
        suspects = static.get("suspects", []) if isinstance(static.get("suspects", []), list) else []
        hypos = static.get("hypotheses", []) if isinstance(static.get("hypotheses", []), list) else []
        return len(entrypoints) > 0 and (len(suspects) > 0 or len(hypos) > 0)
    if stage == "gdb_evidence":
        evid = dynamic.get("evidence", []) if isinstance(dynamic.get("evidence", []), list) else []
        clusters = dynamic.get("clusters", []) if isinstance(dynamic.get("clusters", []), list) else []
        return len(evid) > 0 and _non_empty_str(latest_bases.get("pie_base")) and len(clusters) > 0
    if exploit_stage_level(stage) >= 0:
        if not enable_exploit:
            return True
        status = str(exp.get("status", "")).strip()
        local_verified = bool(exp.get("local_verify_passed", False))
        # Treat exploit stage as completed only after runtime verify succeeds
        # (marker/flag hit), not merely when exp.py is generated.
        return _non_empty_str(exp.get("path")) and status in {"stub_generated", "updated"} and local_verified
    return False


def _capability_checks(state: Dict[str, Any], cfg: Dict[str, Any]) -> tuple[bool, bool, List[str], List[str]]:
    caps = state.get("capabilities", {}) if isinstance(state.get("capabilities", {}), dict) else {}
    target = cfg.get("target", {}) if isinstance(cfg.get("target", {}), dict) else {}
    req_all = target.get("require_capabilities_all", [])
    req_any = target.get("require_capabilities_any", [])
    if not isinstance(req_all, list):
        req_all = []
    if not isinstance(req_any, list):
        req_any = []
    req_all = [str(x) for x in req_all if str(x).strip()]
    req_any = [str(x) for x in req_any if str(x).strip()]

    all_ok = True
    for k in req_all:
        if not bool(caps.get(k, False)):
            all_ok = False
            break

    if not req_any:
        any_ok = True
    else:
        any_ok = any(bool(caps.get(k, False)) for k in req_any)

    return all_ok, any_ok, req_all, req_any


def evaluate_objectives(state: Dict[str, Any], cfg: Dict[str, Any], enable_exploit: bool) -> ObjectiveEval:
    target = cfg.get("target", {}) if isinstance(cfg.get("target", {}), dict) else {}
    required = target.get("require_stage_completion", ["recon", "ida_slice", "gdb_evidence"])
    if not isinstance(required, list):
        required = ["recon", "ida_slice", "gdb_evidence"]
    required_stages = [str(x) for x in required if str(x).strip()]

    require_exp = bool(target.get("require_exploit_when_enabled", False))
    if require_exp and enable_exploit:
        req_exp_stage = str(target.get("require_exploit_stage", "")).strip()
        if not req_exp_stage:
            req_exp_stage = terminal_exploit_stage(required_stages)
        if not req_exp_stage:
            req_exp_stage = "exploit_l3"
        if req_exp_stage not in required_stages:
            required_stages.append(req_exp_stage)

    exploit_stages = [s for s in required_stages if exploit_stage_level(s) >= 0]
    if enable_exploit and not exploit_stages:
        exploit_stages = ["exploit_l3"]
    stage_keys = list(dict.fromkeys(["recon", "ida_slice", "gdb_evidence"] + exploit_stages))
    stage_completion = {s: _stage_completion(state, s, enable_exploit) for s in stage_keys}
    missing = [s for s in required_stages if not stage_completion.get(s, False)]

    all_ok, any_ok, req_all, req_any = _capability_checks(state, cfg)

    blockers: List[str] = []
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    if not _non_empty_str(challenge.get("binary_path")):
        blockers.append("challenge.binary_path missing")
    if not _non_empty_str(challenge.get("workdir")):
        blockers.append("challenge.workdir missing")
    for s in missing:
        blockers.append(f"stage incomplete: {s}")
    if req_all and not all_ok:
        blockers.append("required capabilities(all) not satisfied")
    if req_any and not any_ok:
        blockers.append("required capabilities(any) not satisfied")

    total = max(1, len(required_stages))
    done = len([s for s in required_stages if stage_completion.get(s, False)])
    score = int((done * 100) / total)
    if blockers:
        score = max(0, score - min(20, len(blockers) * 3))

    target_achieved = (
        (len(missing) == 0)
        and all_ok
        and any_ok
        and _non_empty_str(challenge.get("binary_path"))
        and _non_empty_str(challenge.get("workdir"))
    )

    competition_reasons: List[str] = []
    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    remote = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
    caps = state.get("capabilities", {}) if isinstance(state.get("capabilities", {}), dict) else {}
    if bool(remote.get("last_remote_ok", False)):
        competition_reasons.append("session.remote.last_remote_ok=true")
    elif bool(caps.get("exploit_success", False)) and _non_empty_str(remote.get("last_remote_report")):
        competition_reasons.append("capabilities.exploit_success=true + remote report exists")
    competition_target_achieved = bool(competition_reasons)

    return ObjectiveEval(
        generated_utc=utc_now(),
        score=score,
        target_achieved=target_achieved,
        competition_target_achieved=competition_target_achieved,
        competition_reasons=competition_reasons,
        required_stages=required_stages,
        missing_stages=missing,
        stage_completion=stage_completion,
        blockers=[b for b in blockers if b],
        capabilities_all_ok=all_ok,
        capabilities_any_ok=any_ok,
        required_capabilities_all=req_all,
        required_capabilities_any=req_any,
    )


def write_objective_report(
    *,
    root_dir: str,
    session_id: str,
    loop_idx: int,
    pre_eval: ObjectiveEval,
    post_eval: ObjectiveEval,
    planned_stages: List[str],
    executed_stages: List[str],
) -> str:
    rel = f"artifacts/reports/objective_{session_id}_{loop_idx:02d}.json"
    out = os.path.join(root_dir, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": loop_idx,
        "planned_stages": planned_stages,
        "executed_stages": executed_stages,
        "pre": pre_eval.to_dict(),
        "post": post_eval.to_dict(),
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return rel
