#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Tuple


def _get_path(data: Dict[str, Any], path: str) -> Tuple[bool, Any]:
    cur: Any = data
    for key in path.split('.'):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return False, None
    return True, cur


def _is_non_empty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0
    return True


def validate_stage_contract(state: Dict[str, Any], stage: str, contracts: Dict[str, Any]) -> List[str]:
    stages = contracts.get('stages', {}) if isinstance(contracts.get('stages', {}), dict) else {}
    contract = stages.get(stage, {}) if isinstance(stages.get(stage, {}), dict) else {}
    if not contract:
        return []

    errors: List[str] = []

    must_equal = contract.get('must_equal', {}) if isinstance(contract.get('must_equal', {}), dict) else {}
    for path, expected in must_equal.items():
        ok, value = _get_path(state, str(path))
        if not ok:
            errors.append(f"missing path for must_equal: {path}")
            continue
        if value != expected:
            errors.append(f"must_equal failed: {path}={value!r} != {expected!r}")

    required_present = contract.get('required_present', []) if isinstance(contract.get('required_present', []), list) else []
    for path in required_present:
        ok, value = _get_path(state, str(path))
        if not ok:
            errors.append(f"required_present missing: {path}")
            continue
        if value is None:
            errors.append(f"required_present is null: {path}")

    required_non_empty = contract.get('required_non_empty', []) if isinstance(contract.get('required_non_empty', []), list) else []
    for path in required_non_empty:
        ok, value = _get_path(state, str(path))
        if not ok:
            errors.append(f"required_non_empty missing: {path}")
            continue
        if not _is_non_empty(value):
            errors.append(f"required_non_empty failed: {path}")

    at_least = contract.get('at_least', {}) if isinstance(contract.get('at_least', {}), dict) else {}
    for path, minimum in at_least.items():
        ok, value = _get_path(state, str(path))
        if not ok:
            errors.append(f"at_least missing: {path}")
            continue
        try:
            if float(value) < float(minimum):
                errors.append(f"at_least failed: {path}={value} < {minimum}")
        except Exception:
            errors.append(f"at_least not numeric: {path}={value!r}")

    max_items = contract.get('max_items', {}) if isinstance(contract.get('max_items', {}), dict) else {}
    for path, mx in max_items.items():
        ok, value = _get_path(state, str(path))
        if not ok:
            errors.append(f"max_items missing: {path}")
            continue
        if not isinstance(value, list):
            errors.append(f"max_items expects list: {path}")
            continue
        try:
            lim = int(mx)
            if len(value) > lim:
                errors.append(f"max_items failed: {path} has {len(value)} > {lim}")
        except Exception:
            errors.append(f"max_items invalid limit: {path} -> {mx!r}")

    any_of_non_empty = contract.get('any_of_non_empty', []) if isinstance(contract.get('any_of_non_empty', []), list) else []
    for group in any_of_non_empty:
        paths = group if isinstance(group, list) else [group]
        good = False
        for p in paths:
            ok, value = _get_path(state, str(p))
            if ok and _is_non_empty(value):
                good = True
                break
        if not good:
            errors.append(f"any_of_non_empty failed: {paths}")

    return errors
