#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")
DEFAULT_CONTRACTS = os.path.join(ROOT_DIR, "policy", "stage_contracts.yaml")

sys.path.insert(0, ROOT_DIR)

from core.stage_contracts import validate_stage_contract  # noqa: E402


def load_json(path: str):
    import json

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: str):
    import yaml  # type: ignore

    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate current state against stage contract")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--contracts", default=DEFAULT_CONTRACTS)
    ap.add_argument("--stage", default="", help="stage name; default uses progress.stage")
    args = ap.parse_args()

    if not os.path.exists(args.state):
        print(f"[check_stage_contracts] state not found: {args.state}", file=sys.stderr)
        return 2
    if not os.path.exists(args.contracts):
        print(f"[check_stage_contracts] contracts not found: {args.contracts}", file=sys.stderr)
        return 2

    state = load_json(args.state)
    contracts = load_yaml(args.contracts)
    stage = args.stage or str(state.get("progress", {}).get("stage", "")).strip()
    if not stage:
        print("[check_stage_contracts] stage empty", file=sys.stderr)
        return 2

    errors = validate_stage_contract(state, stage, contracts)
    print(f"== stage contract check ==\nstage: {stage}\nstate: {args.state}\ncontracts: {args.contracts}\n")
    if errors:
        print("Errors:")
        for e in errors:
            print(f" - {e}")
        print("[check_stage_contracts] FAIL")
        return 1

    print("[check_stage_contracts] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
