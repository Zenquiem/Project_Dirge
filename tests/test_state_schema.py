#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest

from core.state_schema import load_json, validate_state_data


class StateSchemaTests(unittest.TestCase):
    def test_validate_state_data_accepts_valid_document(self) -> None:
        schema = {
            "type": "object",
            "required": ["name", "count"],
            "properties": {
                "name": {"type": "string", "enum": ["dirge"]},
                "count": {"type": "integer", "minimum": 1},
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 2,
                    "items": {"type": ["string", "null"]},
                },
            },
            "additionalProperties": False,
        }
        data = {"name": "dirge", "count": 2, "items": ["x", None]}
        self.assertEqual([], validate_state_data(schema, data))

    def test_validate_state_data_reports_common_schema_violations(self) -> None:
        schema = {
            "type": "object",
            "required": ["name", "count"],
            "properties": {
                "name": {"type": "string", "enum": ["dirge"]},
                "count": {"type": "integer", "minimum": 1},
                "items": {
                    "type": "array",
                    "minItems": 2,
                    "items": {"type": "number"},
                },
            },
            "additionalProperties": False,
        }
        data = {"name": "wrong", "count": 0, "items": [True], "extra": 1}
        errors = validate_state_data(schema, data)
        self.assertTrue(any("not in enum" in e for e in errors))
        self.assertTrue(any("< minimum" in e for e in errors))
        self.assertTrue(any("< minItems" in e for e in errors))
        self.assertTrue(any("type mismatch" in e for e in errors))
        self.assertTrue(any("additional property 'extra'" in e for e in errors))

    def test_validate_state_data_rejects_bad_roots_and_load_json_reads_dict(self) -> None:
        self.assertEqual(["schema root is not an object"], validate_state_data([], {}))
        self.assertEqual(["state root is not an object"], validate_state_data({}, []))

        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as f:
            json.dump({"ok": True}, f)
            f.flush()
            self.assertEqual({"ok": True}, load_json(f.name))


if __name__ == "__main__":
    unittest.main()
