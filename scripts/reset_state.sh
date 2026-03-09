#!/usr/bin/env bash
set -euo pipefail

die(){ echo "[reset_state] ERROR: $*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_FILE="$ROOT_DIR/state/state.json"
ART_DIR="$ROOT_DIR/artifacts"

KEEP_CHALLENGE=1
MAKE_BACKUP=1
CLEAN_INPUTS=1

usage(){
  cat <<USAGE
Usage:
  scripts/reset_state.sh [options]

Options:
  --drop-challenge   reset and clear state.challenge
  --keep-inputs      keep artifacts/inputs/*
  --no-backup        do not backup state/state.json before overwrite
  -h, --help         show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --drop-challenge) KEEP_CHALLENGE=0; shift ;;
    --keep-inputs) CLEAN_INPUTS=0; shift ;;
    --no-backup) MAKE_BACKUP=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

mkdir -p "$ROOT_DIR/state"
mkdir -p "$ART_DIR"/{gdb,ida,logs,reports,cores,inputs,tmp}

if [[ "$MAKE_BACKUP" -eq 1 && -f "$STATE_FILE" ]]; then
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  cp "$STATE_FILE" "$ROOT_DIR/state/state.json.bak.${TS}"
  echo "[reset_state] backup: state/state.json.bak.${TS}"
fi

rm -rf "$ART_DIR"/gdb/* "$ART_DIR"/ida/* "$ART_DIR"/logs/* "$ART_DIR"/reports/* "$ART_DIR"/cores/* "$ART_DIR"/tmp/*
if [[ "$CLEAN_INPUTS" -eq 1 ]]; then
  rm -rf "$ART_DIR"/inputs/*
fi

python3 - "$STATE_FILE" "$KEEP_CHALLENGE" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

state_path = sys.argv[1]
keep_challenge = bool(int(sys.argv[2]))

old = {}
if os.path.exists(state_path):
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            old = json.load(f)
    except Exception:
        old = {}

old_ch = old.get("challenge", {}) if isinstance(old.get("challenge", {}), dict) else {}

if keep_challenge:
    challenge = {
        "name": old_ch.get("name", ""),
        "binary_path": old_ch.get("binary_path", ""),
        "workdir": old_ch.get("workdir", "."),
        "notes": old_ch.get("notes", ""),
        "import_meta": old_ch.get("import_meta", {}) if isinstance(old_ch.get("import_meta", {}), dict) else {},
    }
else:
    challenge = {
        "name": "",
        "binary_path": "",
        "workdir": ".",
        "notes": "",
        "import_meta": {},
    }

state = {
    "version": 1.0,
    "project": {
        "mode": "mcp_only",
        "notes": "",
        "features": {
            "enable_exploit": True,
            "exploit_plugin": "l3_default",
            "allow_remote_exp": True,
        },
    },
    "challenge": challenge,
    "env": {
        "require_container": False,
        "fingerprint": {
            "id": "",
            "container_image": "",
            "kernel": "",
            "arch": "",
            "libc": {"path": "", "sha256": ""},
            "ld": {"path": "", "sha256": ""},
            "aslr": None,
        },
    },
    "protections": {
        "arch": "",
        "bits": None,
        "endian": "",
        "nx": None,
        "pie": None,
        "relro": "",
        "canary": None,
    },
    "io_profile": {
        "mode": "",
        "prompt_style": "",
        "expects_newline": None,
        "notes": "",
    },
    "capabilities": {
        "has_crash": False,
        "crash_stable": False,
        "rip_control": "unknown",
        "stack_smash_suspected": False,
        "has_leak": "unknown",
        "write_primitive": "unknown",
        "notes": "",
        "control_rip": False,
        "offset_to_rip": 0,
        "ret2win_path_verified": False,
        "system_call_observed": False,
        "exploit_success": False,
    },
    "progress": {
        "stage": "init",
        "run_seq": 0,
        "loop_seq": 0,
        "decision": {
            "adaptive_stage_order": True,
            "no_progress_loops": 0,
            "last_stage_plan": [],
            "last_decision_report": "",
            "last_active_hypothesis_ids": [],
            "last_loop_had_progress": False,
        },
        "objectives": {
            "score": 0,
            "target_achieved": False,
            "required_stages": [],
            "missing_stages": [],
            "blockers": [],
            "last_objective_report": "",
            "last_eval_utc": "",
        },
        "counters": {
            "total_runs": 0,
            "recon_runs": 0,
            "ida_calls": 0,
            "gdb_runs": 0,
            "exploit_runs": 0,
        },
        "last_updated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    },
    "artifacts_index": {
        "runs": [],
        "latest": {
            "run_id": "",
            "paths": {},
        },
    },
    "static_analysis": {
        "entrypoints": [],
        "suspects": [],
        "hypotheses": [],
    },
    "hypotheses": {
        "active": [],
        "dead": [],
    },
    "dynamic_evidence": {
        "inputs": [],
        "evidence": [],
        "clusters": [],
    },
    "latest_bases": {
        "pie_base": "",
        "libc_base": "",
    },
    "summary": {
        "current_best_guess": "",
        "blockers": [],
        "next_actions": [],
    },
    "session": {
        "session_id": "",
        "created_utc": "",
        "status": "init",
        "codex_enabled": False,
        "codex_pid": None,
        "challenge_source_dir": "",
        "challenge_work_dir": "",
        "conversation_log": "",
        "prompt_file": "",
        "exp": {
            "path": "",
            "status": "enabled",
            "generated_utc": "",
            "strategy": "",
            "plan_report": "",
            "local_verify_passed": False,
        },
        "remote": {
            "ask_pending": False,
            "request_file": "",
            "requested_utc": "",
            "answer": "",
            "answered_utc": "",
            "target": {"host": "", "port": 0},
            "last_preflight_report": "",
            "last_remote_report": "",
            "last_remote_ok": False,
        },
    },
}

with open(state_path, "w", encoding="utf-8") as f:
    json.dump(state, f, ensure_ascii=False, indent=2)

print("[reset_state] wrote", state_path)
print("[reset_state] challenge_kept=", keep_challenge)
print("[reset_state] challenge.binary_path=", state["challenge"].get("binary_path", ""))
PY

echo "[reset_state] artifacts cleaned."
