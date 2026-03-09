#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _inside_repo(path: str) -> bool:
    try:
        return os.path.commonpath([ROOT_DIR, os.path.abspath(path)]) == ROOT_DIR
    except Exception:
        return False


def _repo_rel(path: str) -> str:
    return os.path.relpath(os.path.abspath(path), ROOT_DIR)


def _parse_json_payload(raw: str) -> Any:
    try:
        return json.loads(raw)
    except Exception as e:
        raise ValueError(f"invalid json payload: {e}") from e


def main() -> int:
    ap = argparse.ArgumentParser(description="Write artifact via unified python writer (json/text)")
    ap.add_argument("--path", required=True, help="artifact output path (repo-relative or absolute)")
    ap.add_argument("--format", choices=["json", "text"], required=True)
    ap.add_argument("--json", default="", help="json string payload when --format json")
    ap.add_argument("--json-file", default="", help="json file payload when --format json")
    ap.add_argument("--text", default="", help="text payload when --format text")
    ap.add_argument("--text-file", default="", help="text file payload when --format text")
    ap.add_argument("--ensure-parent", action="store_true", default=True)
    args = ap.parse_args()

    out_abs = args.path if os.path.isabs(args.path) else os.path.abspath(os.path.join(ROOT_DIR, args.path))
    if not _inside_repo(out_abs):
        print(json.dumps({"ok": False, "error": f"output path outside repo: {out_abs}"}, ensure_ascii=False, indent=2))
        return 2

    if args.ensure_parent:
        os.makedirs(os.path.dirname(out_abs), exist_ok=True)

    try:
        if args.format == "json":
            if bool(args.json) == bool(args.json_file):
                raise ValueError("json mode requires exactly one of --json / --json-file")
            if args.json_file:
                src = args.json_file if os.path.isabs(args.json_file) else os.path.abspath(os.path.join(ROOT_DIR, args.json_file))
                with open(src, "r", encoding="utf-8") as f:
                    payload = json.load(f)
            else:
                payload = _parse_json_payload(args.json)
            with open(out_abs, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        else:
            if bool(args.text) == bool(args.text_file):
                raise ValueError("text mode requires exactly one of --text / --text-file")
            if args.text_file:
                src = args.text_file if os.path.isabs(args.text_file) else os.path.abspath(os.path.join(ROOT_DIR, args.text_file))
                with open(src, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            else:
                text = args.text
            with open(out_abs, "w", encoding="utf-8") as f:
                f.write(text)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False, indent=2))
        return 1

    print(
        json.dumps(
            {
                "ok": True,
                "path": _repo_rel(out_abs),
                "generated_utc": utc_now(),
                "format": args.format,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
