#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from typing import List

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")
DEFAULT_SCHEMA = os.path.join(ROOT_DIR, "state", "schema.json")

sys.path.insert(0, ROOT_DIR)

from core.state_schema import load_json, validate_state_data  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate state/state.json against state/schema.json")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.state):
        print(f"[validate_state] state not found: {args.state}", file=sys.stderr)
        return 2
    if not os.path.exists(args.schema):
        print(f"[validate_state] schema not found: {args.schema}", file=sys.stderr)
        return 2

    try:
        state = load_json(args.state)
    except Exception as e:
        print(f"[validate_state] failed to load state: {e}", file=sys.stderr)
        return 2

    try:
        schema = load_json(args.schema)
    except Exception as e:
        print(f"[validate_state] failed to load schema: {e}", file=sys.stderr)
        return 2

    errors: List[str] = validate_state_data(schema, state)
    if errors:
        if not args.quiet:
            print("== validate_state report ==")
            print(f"schema: {args.schema}")
            print(f"state:  {args.state}")
            print("Errors:")
            for err in errors:
                print(f" - {err}")
            print("[validate_state] FAIL")
        return 1

    if not args.quiet:
        print("== validate_state report ==")
        print(f"schema: {args.schema}")
        print(f"state:  {args.state}")
        print("[validate_state] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
