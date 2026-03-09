#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_stage_spec(spec_doc: Dict[str, Any], stage: str) -> Dict[str, Any]:
    stages = spec_doc.get("stages", {}) if isinstance(spec_doc.get("stages", {}), dict) else {}
    raw = stages.get(stage, {}) if isinstance(stages.get(stage, {}), dict) else {}
    out: Dict[str, Any] = {
        "mcp_tools": [],
        "required_artifact_keys": [],
        "required_state_paths": [],
        "required_last_evidence_paths": [],
        "required_last_evidence_any_of_paths": [],
        "prompt_contract_lines": [],
    }
    for k in out.keys():
        v = raw.get(k, [])
        if isinstance(v, list):
            out[k] = [str(x) for x in v if str(x).strip()]
    return out


def stage_prompt_contract(spec: Dict[str, Any]) -> str:
    lines = spec.get("prompt_contract_lines", [])
    if not isinstance(lines, list) or not lines:
        return ""
    joined = " ".join(str(x).strip() for x in lines if str(x).strip())
    return joined.strip()


def write_stage_receipt(
    *,
    root_dir: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    spec: Dict[str, Any],
    stage_result: Dict[str, Any],
) -> str:
    rel = f"artifacts/reports/stage_receipt_{session_id}_{loop_idx:02d}_{stage}.json"
    out = os.path.join(root_dir, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": loop_idx,
        "stage": stage,
        "spec": spec,
        "result": stage_result,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return rel


def register_stage_receipt(state: Dict[str, Any], stage: str, receipt_rel: str) -> None:
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["stage_receipt"] = receipt_rel
    latest[f"{stage}_receipt"] = receipt_rel
