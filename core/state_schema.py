#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any, Dict, List


_JSON_TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def _type_ok(expected: Any, value: Any) -> bool:
    if expected is None:
        return True
    if isinstance(expected, list):
        return any(_type_ok(x, value) for x in expected)
    if isinstance(expected, str):
        py_t = _JSON_TYPE_MAP.get(expected)
        if py_t is None:
            return True
        if expected == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        return isinstance(value, py_t)
    return True


def _validate(schema: Dict[str, Any], value: Any, path: str, errors: List[str]) -> None:
    expected_type = schema.get("type")
    if expected_type is not None and not _type_ok(expected_type, value):
        errors.append(f"{path}: type mismatch, expected {expected_type}, got {type(value).__name__}")
        return

    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        errors.append(f"{path}: value {value!r} not in enum {enum!r}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and value < minimum:
            errors.append(f"{path}: value {value} < minimum {minimum}")

    if isinstance(value, list):
        max_items = schema.get("maxItems")
        min_items = schema.get("minItems")
        if isinstance(max_items, int) and len(value) > max_items:
            errors.append(f"{path}: items {len(value)} > maxItems {max_items}")
        if isinstance(min_items, int) and len(value) < min_items:
            errors.append(f"{path}: items {len(value)} < minItems {min_items}")

        items_schema = schema.get("items")
        if isinstance(items_schema, dict):
            for i, item in enumerate(value):
                _validate(items_schema, item, f"{path}[{i}]", errors)

    if isinstance(value, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    errors.append(f"{path}: missing required key '{key}'")

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, sub_schema in properties.items():
                if key in value and isinstance(sub_schema, dict):
                    _validate(sub_schema, value[key], f"{path}.{key}", errors)

        additional = schema.get("additionalProperties", True)
        if additional is False and isinstance(properties, dict):
            for key in value.keys():
                if key not in properties:
                    errors.append(f"{path}: additional property '{key}' not allowed")


def validate_state_data(schema: Dict[str, Any], data: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(schema, dict):
        return ["schema root is not an object"]
    if not isinstance(data, dict):
        return ["state root is not an object"]
    _validate(schema, data, "$", errors)
    return errors


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
