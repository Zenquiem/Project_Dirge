#!/usr/bin/env bash
set -euo pipefail

die(){ echo "[get_session] ERROR: $*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSIONS_DIR="$ROOT_DIR/sessions"

SESSION_ID="${1:-}"
RICH=0
if [[ "${2:-}" == "--rich" ]]; then
  RICH=1
fi
[[ -n "$SESSION_ID" ]] || die "usage: scripts/get_session.sh <session_id> [--rich]"

META_JSON="$SESSIONS_DIR/$SESSION_ID/meta.json"
[[ -f "$META_JSON" ]] || die "session not found: $SESSION_ID"

if [[ "$RICH" -eq 0 ]]; then
  cat "$META_JSON"
  exit 0
fi

python3 - "$ROOT_DIR" "$SESSION_ID" <<'PY'
import glob
import json
import os
import sys

root = os.path.abspath(sys.argv[1])
sid = sys.argv[2]

meta_path = os.path.join(root, "sessions", sid, "meta.json")
with open(meta_path, "r", encoding="utf-8") as f:
    meta = json.load(f)

metrics_path = os.path.join(root, "sessions", sid, "metrics.json")
latest = meta.get("latest_run", {}) if isinstance(meta.get("latest_run", {}), dict) else {}
if isinstance(latest.get("metrics"), str) and latest.get("metrics"):
    p = latest["metrics"]
    metrics_path = p if os.path.isabs(p) else os.path.join(root, p)
metrics = {}
if os.path.exists(metrics_path):
    try:
        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics = json.load(f)
    except Exception:
        metrics = {}

tx_dir = os.path.join(root, "sessions", sid, "transactions")
recent = []
if os.path.isdir(tx_dir):
    metas = sorted(glob.glob(os.path.join(tx_dir, "*.meta.json")))
    for p in metas[-8:]:
        try:
            with open(p, "r", encoding="utf-8") as f:
                t = json.load(f)
            if isinstance(t, dict):
                t["meta_path"] = os.path.relpath(p, root)
                recent.append(t)
        except Exception:
            continue

state_path = os.path.join(root, "state", "state.json")
state = {}
if os.path.exists(state_path):
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            s = json.load(f)
        cur = s.get("session", {}) if isinstance(s.get("session", {}), dict) else {}
        if str(cur.get("session_id", "")) == sid:
            state = s
    except Exception:
        pass

out = {
    "meta": meta,
    "metrics": metrics,
    "state_brief": {
        "progress": state.get("progress", {}),
        "objective": state.get("progress", {}).get("objectives", {}) if isinstance(state.get("progress", {}), dict) else {},
        "artifacts_latest": state.get("artifacts_index", {}).get("latest", {}) if isinstance(state.get("artifacts_index", {}), dict) else {},
    },
    "recent_transactions": recent,
}
print(json.dumps(out, ensure_ascii=False, indent=2))
PY
