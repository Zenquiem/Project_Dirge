from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple


def get_path_value(data: Dict[str, Any], path: str) -> Tuple[bool, Any]:
    current: Any = data
    for key in path.split("."):
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return False, None
    return True, current


def value_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return len(value) > 0
    return True


def _expected_receipt_stage_for_key(key: str) -> str:
    normalized = str(key).strip()
    if normalized == "stage_receipt":
        return ""
    if normalized.endswith("_receipt"):
        return normalized[: -len("_receipt")].strip()
    return ""


def _validate_receipt_artifact(abs_path: str, artifact_key: str) -> List[str]:
    expected_stage = _expected_receipt_stage_for_key(artifact_key)
    if not expected_stage:
        return []
    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            receipt = json.load(f)
    except OSError as exc:
        return [f"required receipt unreadable: latest.paths.{artifact_key} -> {exc}"]
    except json.JSONDecodeError as exc:
        return [f"required receipt invalid json: latest.paths.{artifact_key} -> {exc}"]

    actual_stage = str(receipt.get("stage", "")).strip()
    if actual_stage != expected_stage:
        return [
            f"required receipt stage mismatch: latest.paths.{artifact_key} -> expected {expected_stage}, got {actual_stage or '<empty>'}"
        ]
    return []


def validate_stage_runner_spec(state: Dict[str, Any], stage_spec: Dict[str, Any], *, root_dir: str) -> List[str]:
    errors: List[str] = []
    latest = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
    if not isinstance(latest, dict):
        latest = {}

    for key in stage_spec.get("required_artifact_keys", []):
        artifact_path = str(latest.get(key, "")).strip()
        if not artifact_path:
            errors.append(f"required artifact key missing/empty: latest.paths.{key}")
            continue
        abs_path = os.path.join(root_dir, artifact_path) if not os.path.isabs(artifact_path) else artifact_path
        if not os.path.exists(abs_path):
            errors.append(f"required artifact file not found: latest.paths.{key} -> {artifact_path}")
            continue
        errors.extend(_validate_receipt_artifact(abs_path, str(key)))

    for path in stage_spec.get("required_state_paths", []):
        ok, value = get_path_value(state, str(path))
        if not ok:
            errors.append(f"required state path missing: {path}")
            continue
        if value is None:
            errors.append(f"required state path is null: {path}")
            continue
        if isinstance(value, str) and not value.strip():
            errors.append(f"required state path empty: {path}")
            continue
        if isinstance(value, list) and len(value) == 0:
            errors.append(f"required state path list empty: {path}")
            continue

    req_last_evid = stage_spec.get("required_last_evidence_paths", [])
    req_last_any = stage_spec.get("required_last_evidence_any_of_paths", [])
    has_last_requirements = (
        (isinstance(req_last_evid, list) and bool(req_last_evid))
        or (isinstance(req_last_any, list) and bool(req_last_any))
    )
    if has_last_requirements:
        dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
        evidence = dynamic.get("evidence", []) if isinstance(dynamic.get("evidence", []), list) else []
        if not evidence:
            errors.append("required last evidence missing: dynamic_evidence.evidence is empty")
        else:
            last = evidence[-1] if isinstance(evidence[-1], dict) else {}
            if not isinstance(last, dict):
                errors.append("required last evidence invalid: dynamic_evidence.evidence[-1] is not object")
            else:
                if isinstance(req_last_evid, list):
                    for path in req_last_evid:
                        ok, value = get_path_value(last, str(path))
                        if not ok:
                            errors.append(f"required last evidence path missing: {path}")
                            continue
                        if not value_present(value):
                            errors.append(f"required last evidence path empty: {path}")
                if isinstance(req_last_any, list) and req_last_any:
                    normalized_paths = [str(x).strip() for x in req_last_any if str(x).strip()]
                    any_ok = False
                    for path in normalized_paths:
                        ok, value = get_path_value(last, path)
                        if ok and value_present(value):
                            any_ok = True
                            break
                    if (not any_ok) and normalized_paths:
                        errors.append(
                            "required last evidence any_of not satisfied: " + ", ".join(normalized_paths)
                        )

    return errors
