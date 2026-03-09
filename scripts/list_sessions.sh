#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSIONS_DIR="$ROOT_DIR/sessions"
RICH=0
LIMIT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rich) RICH=1; shift ;;
    --limit) LIMIT="${2:-0}"; shift 2 ;;
    *) echo "[list_sessions] ERROR: unknown arg: $1" >&2; exit 1 ;;
  esac
done

mkdir -p "$SESSIONS_DIR"

python3 - "$SESSIONS_DIR" "$ROOT_DIR" "$RICH" "$LIMIT" <<'PY'
import glob, json, os, sys
root = os.path.abspath(sys.argv[1])
repo = os.path.abspath(sys.argv[2])
rich = bool(int(sys.argv[3]))
limit = int(sys.argv[4] or 0)
items = []
for p in glob.glob(os.path.join(root, "*", "meta.json")):
    try:
        with open(p, "r", encoding="utf-8") as f:
            m = json.load(f)
        items.append(m)
    except Exception:
        continue

items.sort(key=lambda x: x.get("created_utc", ""), reverse=True)

if limit > 0:
    items = items[:limit]

if not rich:
    print(json.dumps(items, ensure_ascii=False, indent=2))
    raise SystemExit(0)

out = []
for m in items:
    sid = str(m.get("session_id", "")).strip()
    metrics = {}
    if sid:
        mp = os.path.join(repo, "sessions", sid, "metrics.json")
        if os.path.exists(mp):
            try:
                with open(mp, "r", encoding="utf-8") as f:
                    metrics = json.load(f)
            except Exception:
                metrics = {}
    out.append({
        "session_id": sid,
        "created_utc": m.get("created_utc", ""),
        "status": m.get("status", ""),
        "challenge": m.get("challenge", {}),
        "exp": m.get("exp", {}),
        "latest_run": m.get("latest_run", {}),
        "metrics_brief": {
            "runs_total": metrics.get("runs_total", 0),
            "loops_total": metrics.get("loops_total", 0),
            "objective_score_latest": metrics.get("objective_score_latest", 0),
            "objective_target_hits": metrics.get("objective_target_hits", 0),
            "stage_retries": metrics.get("stage_retries", 0),
            "timeout_circuit_activations": metrics.get("timeout_circuit_activations", 0),
            "timeout_circuit_skips": metrics.get("timeout_circuit_skips", 0),
            "remote_connect_attempts": metrics.get("remote_connect_attempts", 0),
            "self_stop_blocked": metrics.get("self_stop_blocked", 0),
            "autofix_rounds_total": metrics.get("autofix_rounds_total", 0),
        },
    })

print(json.dumps(out, ensure_ascii=False, indent=2))
PY
