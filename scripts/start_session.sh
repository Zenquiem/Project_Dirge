#!/usr/bin/env bash
set -euo pipefail

die(){ echo "[start_session] ERROR: $*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_FILE="$ROOT_DIR/state/state.json"
RESET_SCRIPT="$ROOT_DIR/scripts/reset_state.sh"
SESSIONS_DIR="$ROOT_DIR/sessions"
CHALLENGE_ROOT="$ROOT_DIR/challenge"

CHALLENGE_DIR=""
BINARY_PATH=""
SESSION_ID=""
SESSION_NAME=""
START_CODEX=1
AUTO_SOLVE=1
FOREGROUND_SOLVE=0
INTERACTIVE_CODEX=0
DO_RESET=1
ENABLE_EXP=1
BLIND_MODE=0
USER_PROMPT=""
USER_PROMPT_FILE=""
CODEX_BIN="${CODEX_BIN:-$ROOT_DIR/scripts/codex_with_mcp.sh}"
FORCE_MCP_WRAPPER="${FORCE_MCP_WRAPPER:-1}"
CODEX_DEFAULT_MODEL="${CODEX_DEFAULT_MODEL:-gpt-5.3-codex}"
CODEX_DEFAULT_REASONING_EFFORT="${CODEX_DEFAULT_REASONING_EFFORT:-xhigh}"

if [[ "$FORCE_MCP_WRAPPER" == "1" && -x "$ROOT_DIR/scripts/codex_with_mcp.sh" ]]; then
  CODEX_BIN="$ROOT_DIR/scripts/codex_with_mcp.sh"
fi

resolve_bin_ok=0
if [[ "$CODEX_BIN" == */* ]]; then
  if [[ -x "$CODEX_BIN" ]]; then
    resolve_bin_ok=1
  fi
else
  if command -v "$CODEX_BIN" >/dev/null 2>&1; then
    resolve_bin_ok=1
  fi
fi

if [[ "$resolve_bin_ok" -ne 1 ]]; then
  for _fb in "$ROOT_DIR/scripts/codex_with_mcp.sh" "$HOME/.npm-global/bin/codex" "$HOME/.local/bin/codex"; do
    if [[ -x "$_fb" ]]; then
      CODEX_BIN="$_fb"
      resolve_bin_ok=1
      break
    fi
  done
fi

usage(){
  cat <<USAGE
Usage:
  scripts/start_session.sh --challenge-dir <dir> [options]

Options:
  --challenge-dir <dir>   题目目录（必填）
  --binary <path>         二进制路径（可选；相对 challenge-dir 或绝对路径）
  --session-id <id>       自定义会话 ID（可选）
  --name <name>           自定义题目名（可选）
  --no-codex              仅创建会话与状态，不自动启动 solve
  --no-auto-solve         创建会话后启动 codex exec（旧模式，不推荐）
  --foreground-solve      前台执行 solve（CLI 实时输出，不走后台 nohup）
  --interactive-codex     前台进入 Codex 交互式 CLI（可实时输入指令）
  --no-exp                本次会话禁用 exp 生成
  --no-reset              不执行 reset_state（默认会 reset）
  --prompt <text>         自定义启动 prompt（可选）
  --prompt-file <file>    从文件读取启动 prompt（可选）
  -h, --help              显示帮助

Env:
  CODEX_BIN               codex 可执行名/路径（默认: scripts/codex_with_mcp.sh）
  FORCE_MCP_WRAPPER       1=强制使用 scripts/codex_with_mcp.sh（默认），0=允许 CODEX_BIN 覆盖
  CODEX_DEFAULT_MODEL     默认模型（默认: gpt-5.3-codex）
  CODEX_DEFAULT_REASONING_EFFORT 默认推理强度（默认: xhigh）
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --challenge-dir) CHALLENGE_DIR="${2:-}"; shift 2 ;;
    --binary) BINARY_PATH="${2:-}"; shift 2 ;;
    --session-id) SESSION_ID="${2:-}"; shift 2 ;;
    --name) SESSION_NAME="${2:-}"; shift 2 ;;
    --no-codex) START_CODEX=0; AUTO_SOLVE=0; shift ;;
    --no-auto-solve) AUTO_SOLVE=0; shift ;;
    --foreground-solve) FOREGROUND_SOLVE=1; AUTO_SOLVE=1; START_CODEX=1; shift ;;
    --interactive-codex) INTERACTIVE_CODEX=1; AUTO_SOLVE=0; START_CODEX=1; shift ;;
    --no-exp) ENABLE_EXP=0; shift ;;
    --no-reset) DO_RESET=0; shift ;;
    --prompt) USER_PROMPT="${2:-}"; shift 2 ;;
    --prompt-file) USER_PROMPT_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

if [[ "$FOREGROUND_SOLVE" -eq 1 && "$START_CODEX" -eq 0 ]]; then
  die "--foreground-solve cannot be used with --no-codex"
fi
if [[ "$FOREGROUND_SOLVE" -eq 1 && "$AUTO_SOLVE" -eq 0 ]]; then
  die "--foreground-solve cannot be used with --no-auto-solve"
fi
if [[ "$INTERACTIVE_CODEX" -eq 1 && "$START_CODEX" -eq 0 ]]; then
  die "--interactive-codex cannot be used with --no-codex"
fi
if [[ "$INTERACTIVE_CODEX" -eq 1 && "$FOREGROUND_SOLVE" -eq 1 ]]; then
  die "--interactive-codex cannot be used with --foreground-solve"
fi

[[ -n "$CHALLENGE_DIR" ]] || die "--challenge-dir is required"
[[ -d "$CHALLENGE_DIR" ]] || die "challenge dir not found: $CHALLENGE_DIR"
[[ -f "$RESET_SCRIPT" ]] || die "missing reset script: $RESET_SCRIPT"
[[ -f "$STATE_FILE" ]] || die "missing state file: $STATE_FILE"

if [[ -n "$USER_PROMPT" && -n "$USER_PROMPT_FILE" ]]; then
  die "--prompt and --prompt-file are mutually exclusive"
fi
if [[ -n "$USER_PROMPT_FILE" ]]; then
  [[ -f "$USER_PROMPT_FILE" ]] || die "prompt file not found: $USER_PROMPT_FILE"
fi

if [[ -z "$SESSION_ID" ]]; then
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  SESSION_ID="sess_${TS}_$RANDOM"
fi
if [[ ! "$SESSION_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
  die "invalid session id: $SESSION_ID"
fi

mkdir -p "$SESSIONS_DIR" "$CHALLENGE_ROOT"
SESSION_DIR="$SESSIONS_DIR/$SESSION_ID"
[[ ! -e "$SESSION_DIR" ]] || die "session already exists: $SESSION_ID"
mkdir -p "$SESSION_DIR/exp"

META_JSON="$SESSION_DIR/meta.json"
CONV_LOG="$SESSION_DIR/conversation.log"
PROMPT_TXT="$SESSION_DIR/prompt.txt"
STATE_INIT_SNAPSHOT="$SESSION_DIR/state.initial.json"
EXP_PATH_REL="sessions/$SESSION_ID/exp/exp.py"

# 始终先创建 conversation.log，避免 UI/计时链路引用到不存在文件。
: > "$CONV_LOG"

ABS_SRC_DIR="$(python3 - <<PY
import os
print(os.path.abspath("$CHALLENGE_DIR"))
PY
)"

INSIDE_REPO="$(python3 - <<PY
import os
root=os.path.abspath("$ROOT_DIR")
src=os.path.abspath("$ABS_SRC_DIR")
try:
    print("1" if os.path.commonpath([root, src])==root else "0")
except Exception:
    print("0")
PY
)"

if [[ "$INSIDE_REPO" == "1" ]]; then
  ABS_WORK_DIR="$ABS_SRC_DIR"
  IMPORT_MODE="inplace"
else
  ABS_WORK_DIR="$CHALLENGE_ROOT/$SESSION_ID"
  IMPORT_MODE="copied"
  mkdir -p "$ABS_WORK_DIR"
  cp -a "$ABS_SRC_DIR"/. "$ABS_WORK_DIR"/
fi

ABS_BIN_PATH=""
if [[ -n "$BINARY_PATH" ]]; then
  if [[ "$BINARY_PATH" = /* ]]; then
    ABS_BIN_PATH="$BINARY_PATH"
  else
    ABS_BIN_PATH="$ABS_WORK_DIR/$BINARY_PATH"
  fi
  [[ -f "$ABS_BIN_PATH" ]] || die "binary not found: $ABS_BIN_PATH"
else
  ABS_BIN_PATH="$(python3 - "$ABS_WORK_DIR" <<'PY'
import os
import stat
import sys

root=os.path.abspath(sys.argv[1])
best=None
best_score=None
max_depth=4

def _looks_loader_name(name: str) -> bool:
    low = str(name or "").strip().lower()
    if not low:
        return False
    if low in {"ld.so", "ld-linux.so.2", "ld-linux-x86-64.so.2"}:
        return True
    if low.startswith("ld-linux") and ".so" in low:
        return True
    if low.startswith("ld-") and ".so" in low:
        return True
    return False

def _looks_libc_name(name: str) -> bool:
    low = str(name or "").strip().lower()
    if not low:
        return False
    if low == "libc.so.6":
        return True
    if low.startswith("libc") and ".so" in low:
        return True
    return False

def _score_candidate(path: str, rel: str, depth: int, st_mode: int) -> int:
    name = os.path.basename(path).strip().lower()
    score = 0
    if _looks_loader_name(name):
        score += 400
    if _looks_libc_name(name):
        score += 360
    if (name.endswith(".so") or (".so." in name)):
        score += 180
    if name.startswith("lib") and (".so" in name):
        score += 120
    if not (st_mode & stat.S_IXUSR):
        score += 40
    if name in {"chall", "challenge", "pwn", "main", "bin", "timu", "vuln", "a.out"}:
        score -= 20
    score += max(0, int(depth)) * 8
    score += min(len(rel), 220)
    return int(score)

for cur, dirs, files in os.walk(root):
    rel_dir=os.path.relpath(cur, root)
    depth=0 if rel_dir=='.' else rel_dir.count(os.sep)+1
    if depth>max_depth:
        dirs[:] = []
        continue
    for fn in files:
        p=os.path.join(cur, fn)
        try:
            st=os.stat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            with open(p,'rb') as f:
                magic=f.read(4)
            if magic!=b'\x7fELF':
                continue
            rel=os.path.relpath(p, root)
            score=_score_candidate(p, rel, depth, int(st.st_mode))
            if best_score is None or score < best_score:
                best_score=score
                best=p
        except Exception:
            continue

print(best or "")
PY
)"
  if [[ -z "$ABS_BIN_PATH" ]]; then
    BLIND_MODE=1
  fi
fi

if [[ "$BLIND_MODE" -eq 0 ]]; then
  [[ -f "$ABS_BIN_PATH" ]] || die "resolved binary does not exist: $ABS_BIN_PATH"
fi

BIN_SELECTION_JSON="$(python3 - "$ABS_WORK_DIR" "$ABS_BIN_PATH" <<'PY'
import json
import os
import stat
import sys

root = os.path.abspath(sys.argv[1])
chosen = os.path.abspath(sys.argv[2])

def _looks_loader_name(name: str) -> bool:
    low = str(name or "").strip().lower()
    if not low:
        return False
    if low in {"ld.so", "ld-linux.so.2", "ld-linux-x86-64.so.2"}:
        return True
    if low.startswith("ld-linux") and ".so" in low:
        return True
    if low.startswith("ld-") and ".so" in low:
        return True
    return False

def _looks_libc_name(name: str) -> bool:
    low = str(name or "").strip().lower()
    if not low:
        return False
    if low == "libc.so.6":
        return True
    if low.startswith("libc") and ".so" in low:
        return True
    return False

def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False

def _score_candidate(path: str, rel: str, depth: int, st_mode: int) -> int:
    name = os.path.basename(path).strip().lower()
    score = 0
    if _looks_loader_name(name):
        score += 400
    if _looks_libc_name(name):
        score += 360
    if (name.endswith(".so") or (".so." in name)):
        score += 180
    if name.startswith("lib") and (".so" in name):
        score += 120
    if not (st_mode & stat.S_IXUSR):
        score += 40
    if name in {"chall", "challenge", "pwn", "main", "bin", "timu", "vuln", "a.out"}:
        score -= 20
    score += max(0, int(depth)) * 8
    score += min(len(rel), 220)
    return int(score)

def _is_suspicious(path: str) -> bool:
    name = os.path.basename(path).strip().lower()
    if _looks_loader_name(name) or _looks_libc_name(name):
        return True
    if (name.endswith(".so") or (".so." in name)):
        return True
    return False

best = ""
best_score = None
max_depth = 4

if os.path.isdir(root):
    for cur, dirs, files in os.walk(root):
        rel_dir = os.path.relpath(cur, root)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        if depth > max_depth:
            dirs[:] = []
            continue
        for fn in files:
            p = os.path.join(cur, fn)
            try:
                st = os.stat(p)
            except Exception:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if not _is_elf(p):
                continue
            rel = os.path.relpath(p, root)
            score = _score_candidate(p, rel, depth, int(st.st_mode))
            if best_score is None or score < best_score:
                best_score = score
                best = p

chosen_exists = bool(chosen and os.path.isfile(chosen))
chosen_elf = _is_elf(chosen) if chosen_exists else False
chosen_rel = os.path.relpath(chosen, root) if (chosen_exists and chosen.startswith(root + os.sep)) else os.path.basename(chosen)
chosen_score = _score_candidate(chosen, chosen_rel, 0, os.stat(chosen).st_mode) if chosen_exists else 10**9
chosen_suspicious = _is_suspicious(chosen) if chosen_exists else True

selected = chosen
note = ""
corrected = False

if best and os.path.abspath(best) != os.path.abspath(chosen):
    if (not chosen_exists) or (not chosen_elf) or chosen_suspicious:
        selected = best
        corrected = True
        note = f"binary_path suspicious ({os.path.basename(chosen)}), auto-corrected to {os.path.basename(best)}"
    elif best_score is not None and int(best_score) + 220 < int(chosen_score):
        selected = best
        corrected = True
        note = f"binary_path heuristic preferred {os.path.basename(best)} over {os.path.basename(chosen)}"

print(json.dumps({
    "selected": os.path.abspath(selected) if selected else "",
    "corrected": bool(corrected),
    "note": note,
    "chosen": os.path.abspath(chosen),
    "best": os.path.abspath(best) if best else "",
}, ensure_ascii=False))
PY
)"

ABS_BIN_PATH="$(python3 - "$BIN_SELECTION_JSON" <<'PY'
import json
import os
import sys
raw = str(sys.argv[1] if len(sys.argv) > 1 else "").strip()
try:
    obj = json.loads(raw) if raw else {}
except Exception:
    obj = {}
print(os.path.abspath(str(obj.get("selected", "")).strip()) if str(obj.get("selected", "")).strip() else "")
PY
)"
if [[ "$BLIND_MODE" -eq 0 ]]; then
  [[ -n "$ABS_BIN_PATH" ]] || die "resolved binary selection is empty"
  [[ -f "$ABS_BIN_PATH" ]] || die "resolved binary selection does not exist: $ABS_BIN_PATH"
fi
BIN_SELECTION_NOTE="$(python3 - "$BIN_SELECTION_JSON" <<'PY'
import json
import sys
raw = str(sys.argv[1] if len(sys.argv) > 1 else "").strip()
try:
    obj = json.loads(raw) if raw else {}
except Exception:
    obj = {}
print(str(obj.get("note", "")).strip())
PY
)"
if [[ "$BLIND_MODE" -eq 1 ]]; then
  ABS_BIN_PATH=""
  BIN_SELECTION_NOTE="blind mode: no local ELF provided"
fi

REL_WORK_DIR="$(python3 - <<PY
import os
print(os.path.relpath(os.path.abspath("$ABS_WORK_DIR"), os.path.abspath("$ROOT_DIR")))
PY
)"
REL_BIN_PATH="$(python3 - <<PY
import os
root = os.path.abspath("$ROOT_DIR")
bin_path = str("$ABS_BIN_PATH").strip()
if not bin_path:
    print("")
else:
    print(os.path.relpath(os.path.abspath(bin_path), root))
PY
)"

if [[ "$REL_WORK_DIR" == .* ]]; then
  die "resolved work dir is outside repository: $ABS_WORK_DIR"
fi
if [[ -n "$REL_BIN_PATH" && "$REL_BIN_PATH" == .* ]]; then
  die "resolved binary is outside repository: $ABS_BIN_PATH"
fi

if [[ -z "$SESSION_NAME" ]]; then
  if [[ "$IMPORT_MODE" == "copied" ]]; then
    SESSION_NAME="$(basename "$ABS_SRC_DIR")"
  else
    SESSION_NAME="$(basename "$ABS_WORK_DIR")"
  fi
fi
if [[ -z "$SESSION_NAME" || "$SESSION_NAME" == "/" || "$SESSION_NAME" == "." ]]; then
  SESSION_NAME="$SESSION_ID"
fi

if [[ "$DO_RESET" -eq 1 ]]; then
  "$RESET_SCRIPT" --drop-challenge --no-backup >/dev/null
fi

CREATED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EXP_STATUS="enabled"
if [[ "$ENABLE_EXP" -eq 0 ]]; then
  EXP_STATUS="disabled_by_user"
fi
if [[ "$BLIND_MODE" -eq 1 ]]; then
  EXP_STATUS="disabled_blind_mode"
fi

export START_ROOT_DIR="$ROOT_DIR"
export START_STATE_FILE="$STATE_FILE"
export START_META_JSON="$META_JSON"
export START_SESSION_ID="$SESSION_ID"
export START_SESSION_NAME="$SESSION_NAME"
export START_CREATED_UTC="$CREATED_UTC"
export START_SRC_DIR="$ABS_SRC_DIR"
export START_WORK_DIR_REL="$REL_WORK_DIR"
export START_WORK_DIR_ABS="$ABS_WORK_DIR"
export START_BIN_REL="$REL_BIN_PATH"
export START_BIN_ABS="$ABS_BIN_PATH"
export START_BIN_NOTE="$BIN_SELECTION_NOTE"
export START_BLIND_MODE="$BLIND_MODE"
export START_IMPORT_MODE="$IMPORT_MODE"
export START_CONV_LOG_REL="sessions/$SESSION_ID/conversation.log"
export START_PROMPT_REL="sessions/$SESSION_ID/prompt.txt"
export START_STATE_INIT_REL="sessions/$SESSION_ID/state.initial.json"
export START_EXP_REL="$EXP_PATH_REL"
export START_EXP_STATUS="$EXP_STATUS"
export START_CODEX_ENABLED="$START_CODEX"
export START_ENABLE_EXP="$ENABLE_EXP"
export CODEX_BIN

python3 - <<'PY'
import json
import os

state_path = os.environ["START_STATE_FILE"]
meta_path = os.environ["START_META_JSON"]

def ensure(d, k, default):
    if k not in d or d[k] is None:
        d[k] = default
    return d[k]

with open(state_path, "r", encoding="utf-8") as f:
    state = json.load(f)

project = ensure(state, "project", {})
project["mode"] = "mcp_only"
features = ensure(project, "features", {})
features["enable_exploit"] = bool(int(os.environ.get("START_ENABLE_EXP", "1")))
features["exploit_plugin"] = "l3_default"
features["allow_remote_exp"] = True

challenge = ensure(state, "challenge", {})
challenge["name"] = os.environ["START_SESSION_NAME"]
challenge["binary_path"] = os.environ["START_BIN_REL"]
challenge["workdir"] = os.environ["START_WORK_DIR_REL"]
challenge["notes"] = "session-managed"
meta = ensure(challenge, "import_meta", {})
meta["session_id"] = os.environ["START_SESSION_ID"]
meta["source_dir"] = os.environ["START_SRC_DIR"]
meta["import_mode"] = os.environ["START_IMPORT_MODE"]
meta["imported_utc"] = os.environ["START_CREATED_UTC"]
meta["binary_selection_note"] = os.environ.get("START_BIN_NOTE", "")
meta["blind_mode"] = bool(int(os.environ.get("START_BLIND_MODE", "0")))

session = {
    "session_id": os.environ["START_SESSION_ID"],
    "created_utc": os.environ["START_CREATED_UTC"],
    "status": "initialized",
    "codex_enabled": bool(int(os.environ.get("START_CODEX_ENABLED", "1"))),
    "codex_pid": None,
    "challenge_source_dir": os.environ["START_SRC_DIR"],
    "challenge_work_dir": os.environ["START_WORK_DIR_REL"],
    "conversation_log": os.environ["START_CONV_LOG_REL"],
    "prompt_file": os.environ["START_PROMPT_REL"],
    "exp": {
        "path": os.environ["START_EXP_REL"],
        "status": os.environ["START_EXP_STATUS"],
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
}
state["session"] = session

with open(state_path, "w", encoding="utf-8") as f:
    json.dump(state, f, ensure_ascii=False, indent=2)

meta_doc = {
    "version": 1,
    "session_id": os.environ["START_SESSION_ID"],
    "created_utc": os.environ["START_CREATED_UTC"],
    "status": "initialized",
    "challenge": {
        "name": os.environ["START_SESSION_NAME"],
        "source_dir": os.environ["START_SRC_DIR"],
        "work_dir": os.environ["START_WORK_DIR_REL"],
        "binary_path": os.environ["START_BIN_REL"],
        "import_mode": os.environ["START_IMPORT_MODE"],
        "blind_mode": bool(int(os.environ.get("START_BLIND_MODE", "0"))),
    },
    "paths": {
        "session_dir": os.path.relpath(os.path.dirname(meta_path), os.environ["START_ROOT_DIR"]),
        "meta_json": os.path.relpath(meta_path, os.environ["START_ROOT_DIR"]),
        "state_json": os.path.relpath(state_path, os.environ["START_ROOT_DIR"]),
        "state_initial_snapshot": os.environ["START_STATE_INIT_REL"],
        "artifacts_dir": "artifacts",
        "conversation_log": os.environ["START_CONV_LOG_REL"],
        "prompt_file": os.environ["START_PROMPT_REL"],
    },
    "exp": {
        "path": os.environ["START_EXP_REL"],
        "status": os.environ["START_EXP_STATUS"],
        "generated_utc": "",
        "strategy": "",
        "plan_report": "",
        "local_verify_passed": False,
        "last_error": None,
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
    "codex": {
        "enabled": bool(int(os.environ.get("START_CODEX_ENABLED", "1"))),
        "bin": os.environ.get("CODEX_BIN", "scripts/codex_with_mcp.sh"),
        "pid": None,
        "last_error": None,
    },
}

with open(meta_path, "w", encoding="utf-8") as f:
    json.dump(meta_doc, f, ensure_ascii=False, indent=2)
PY

cp "$STATE_FILE" "$STATE_INIT_SNAPSHOT"

if [[ -n "$USER_PROMPT_FILE" ]]; then
  cp "$USER_PROMPT_FILE" "$PROMPT_TXT"
elif [[ -n "$USER_PROMPT" ]]; then
  printf "%s\n" "$USER_PROMPT" > "$PROMPT_TXT"
else
  if [[ "$INTERACTIVE_CODEX" -eq 1 ]]; then
    if [[ "$BLIND_MODE" -eq 1 ]]; then
      FLOW_HINT="当前是交互式会话（盲打模式）：先询问用户“是否盲打题目”；若是，继续询问远程地址（host:port），然后执行 remote-answer 记录目标。不要自动执行 solve。"
    elif [[ "$ENABLE_EXP" -eq 1 ]]; then
      FLOW_HINT="当前是交互式会话：先等待用户指令，再按用户要求执行 L0/L1/L2/L3/L4。不要自动执行 solve。"
    else
      FLOW_HINT="当前是交互式会话（禁用 exp）：先等待用户指令，再按用户要求执行 L0/L1/L2。不要自动执行 solve。"
    fi
    if [[ "$BLIND_MODE" -eq 1 ]]; then
      SOLVE_HINT="如果用户确认盲打并给出 host:port，执行：python3 scripts/session_api.py remote-answer $SESSION_ID --yes --host <host> --port <port>。"
    else
      SOLVE_HINT="先回复你已就绪，并等待用户下一条命令。"
    fi
  else
    if [[ "$ENABLE_EXP" -eq 1 ]]; then
      FLOW_HINT="请一次性自动推进：L0 Recon -> L1 Static Slice（Ghidra MCP） -> L2 GDB Evidence -> L3 Exploit -> L4 Exploit（当前终点）。不要在 L2 停下并等待“继续”。"
      SOLVE_HINT="优先直接执行: python3 scripts/session_api.py solve --session-id $SESSION_ID --fast 。若未到 terminal exploit stage，再自动继续直到达成或触发 stopping condition。"
    else
      FLOW_HINT="请一次性自动推进：L0 Recon -> L1 Static Slice（Ghidra MCP） -> L2 GDB Evidence（本次会话禁用 exp）。"
      SOLVE_HINT="优先直接执行: python3 scripts/session_api.py solve --session-id $SESSION_ID --fast 。"
    fi
  fi
  if [[ "$BLIND_MODE" -eq 1 ]]; then
    EXP_HINT="盲打模式：未生成本地 exp 脚本，待确认远程目标后再按需创建。"
  elif [[ "$ENABLE_EXP" -eq 1 ]]; then
    EXP_HINT="默认启用 exp 写入，路径: $EXP_PATH_REL（支持 PWN_REMOTE_HOST/PWN_REMOTE_PORT 远程参数）"
  else
    EXP_HINT="本次会话已禁用 exp 写入（--no-exp）"
  fi
  cat > "$PROMPT_TXT" <<PROMPT
你现在处于会话 $SESSION_ID。
$FLOW_HINT
$SOLVE_HINT
题目目录: $REL_WORK_DIR
题目二进制: ${REL_BIN_PATH:-<blind mode / not provided>}
${BIN_SELECTION_NOTE:+二进制选择: $BIN_SELECTION_NOTE}
$EXP_HINT
请将关键证据写入 artifacts，并同步更新 state/state.json。
PROMPT
fi

if [[ "$ENABLE_EXP" -eq 1 && "$BLIND_MODE" -eq 0 ]]; then
  python3 - <<'PY'
import json
import os
import sys

root = os.environ["START_ROOT_DIR"]
state_path = os.environ["START_STATE_FILE"]
meta_path = os.environ["START_META_JSON"]
session_id = os.environ["START_SESSION_ID"]
exp_rel = os.environ["START_EXP_REL"]
exp_abs = os.path.abspath(os.path.join(root, exp_rel))

sys.path.insert(0, root)

try:
    from core.plugins.exploit_l3 import generate_exp_stub
except Exception as e:
    with open(state_path, "r", encoding="utf-8") as f:
        state = json.load(f)
    state.setdefault("session", {}).setdefault("exp", {})["status"] = "error"
    state["session"]["exp"]["last_error"] = f"import plugin failed: {e}"
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    meta.setdefault("exp", {})["status"] = "error"
    meta["exp"]["last_error"] = f"import plugin failed: {e}"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    raise SystemExit(0)

with open(state_path, "r", encoding="utf-8") as f:
    state = json.load(f)

try:
    info = generate_exp_stub(exp_abs, state, session_id, root_dir=root)
    state.setdefault("session", {}).setdefault("exp", {})["status"] = info.get("exp_status", "stub_generated")
    state["session"]["exp"]["generated_utc"] = info.get("generated_utc", "")
    state["session"]["exp"]["strategy"] = info.get("strategy", "")
    state["session"]["exp"]["plan_report"] = info.get("plan_report", "")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    meta.setdefault("exp", {})["status"] = info.get("exp_status", "stub_generated")
    meta["exp"]["generated_utc"] = info.get("generated_utc", "")
    meta["exp"]["strategy"] = info.get("strategy", "")
    meta["exp"]["plan_report"] = info.get("plan_report", "")
    meta["exp"]["last_error"] = None
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
except Exception as e:
    state.setdefault("session", {}).setdefault("exp", {})["status"] = "error"
    state["session"]["exp"]["last_error"] = str(e)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    meta.setdefault("exp", {})["status"] = "error"
    meta["exp"]["last_error"] = str(e)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
PY
fi

update_meta_status(){
  local status="$1"
  local pid="${2:-}"
  local err="${3:-}"
  export META_STATUS="$status"
  export META_PID="$pid"
  export META_ERR="$err"
  export META_JSON_PATH="$META_JSON"
  export META_STATE_PATH="$STATE_FILE"
  python3 - <<'PY'
import json
import os

meta_path = os.environ["META_JSON_PATH"]
state_path = os.environ["META_STATE_PATH"]
status = os.environ.get("META_STATUS", "initialized")
pid = os.environ.get("META_PID", "").strip()
err = os.environ.get("META_ERR", "").strip() or None

with open(meta_path, "r", encoding="utf-8") as f:
    meta = json.load(f)
meta["status"] = status
meta.setdefault("codex", {})["enabled"] = meta.get("codex", {}).get("enabled", True)
meta["codex"]["pid"] = int(pid) if pid.isdigit() else None
meta["codex"]["last_error"] = err
with open(meta_path, "w", encoding="utf-8") as f:
    json.dump(meta, f, ensure_ascii=False, indent=2)

with open(state_path, "r", encoding="utf-8") as f:
    state = json.load(f)
state.setdefault("session", {})["status"] = status
if isinstance(state["session"], dict):
    if pid.isdigit():
        state["session"]["codex_pid"] = int(pid)
    if err:
        state["session"]["last_error"] = err
with open(state_path, "w", encoding="utf-8") as f:
    json.dump(state, f, ensure_ascii=False, indent=2)
PY
}

CODEX_MODEL_ARGS=()
if [[ -n "${CODEX_DEFAULT_MODEL:-}" ]]; then
  CODEX_MODEL_ARGS+=(-m "$CODEX_DEFAULT_MODEL")
fi
if [[ -n "${CODEX_DEFAULT_REASONING_EFFORT:-}" ]]; then
  CODEX_MODEL_ARGS+=(-c "model_reasoning_effort=\"$CODEX_DEFAULT_REASONING_EFFORT\"")
fi

if [[ "$START_CODEX" -eq 1 ]]; then
  if [[ "$INTERACTIVE_CODEX" -eq 1 ]]; then
    code_bin_ok=0
    if [[ "$CODEX_BIN" == */* ]]; then
      [[ -x "$CODEX_BIN" ]] && code_bin_ok=1
    else
      command -v "$CODEX_BIN" >/dev/null 2>&1 && code_bin_ok=1
    fi
    if [[ "$code_bin_ok" -ne 1 ]]; then
      update_meta_status "codex_unavailable" "" "codex command not found: $CODEX_BIN"
      cat "$META_JSON"
      echo "[start_session] ERROR: codex command not found: $CODEX_BIN" >&2
      exit 3
    fi

    update_meta_status "running_interactive" "" ""
    echo "[start_session] entering interactive codex CLI..."
    echo "[start_session] session_id=$SESSION_ID"
    if [[ "$BLIND_MODE" -eq 1 ]]; then
      echo "[start_session] binary=<blind mode / not provided>"
    else
      echo "[start_session] binary=$REL_BIN_PATH"
    fi
    if [[ -n "$BIN_SELECTION_NOTE" ]]; then
      echo "[start_session] binary_note=$BIN_SELECTION_NOTE"
    fi
    echo "[start_session] prompt_file=sessions/$SESSION_ID/prompt.txt"

    set +e
    (
      cd "$ROOT_DIR"
      "$CODEX_BIN" "${CODEX_MODEL_ARGS[@]}" -a never --sandbox workspace-write "$(cat "$PROMPT_TXT")"
    )
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
      update_meta_status "finished" "" ""
    else
      update_meta_status "finished_with_errors" "" "interactive codex exit rc=$rc"
    fi
    cat "$META_JSON"
    exit $rc
  fi

  if [[ "$AUTO_SOLVE" -eq 1 ]]; then
    if [[ "$FOREGROUND_SOLVE" -eq 1 ]]; then
      update_meta_status "running" "" ""
      set +e
      {
        cd "$ROOT_DIR"
        python3 scripts/session_api.py solve --session-id "$SESSION_ID" --fast
      } 2>&1 | tee "$CONV_LOG"
      rc="${PIPESTATUS[0]:-1}"
      if [[ ! "$rc" =~ ^[0-9]+$ ]]; then
        rc=1
      fi
      set -e
      if [[ $rc -ne 0 ]]; then
        update_meta_status "finished_with_errors" "" "foreground solve exit rc=$rc"
      fi
      cat "$META_JSON"
      exit $rc
    fi

    set +e
    (
      cd "$ROOT_DIR"
      nohup python3 scripts/session_api.py solve --session-id "$SESSION_ID" --fast > "$CONV_LOG" 2>&1 &
      echo $! > "$SESSION_DIR/codex.pid"
    )
    rc=$?
    set -e

    if [[ $rc -ne 0 ]]; then
      update_meta_status "solve_start_failed" "" "failed to spawn session_api solve"
      cat "$META_JSON"
      echo "[start_session] ERROR: failed to start session_api solve" >&2
      exit 4
    fi

    SOLVE_PID="$(cat "$SESSION_DIR/codex.pid" 2>/dev/null || true)"
    update_meta_status "running" "$SOLVE_PID" ""
    cat "$META_JSON"
    exit 0
  fi

  code_bin_ok=0
  if [[ "$CODEX_BIN" == */* ]]; then
    [[ -x "$CODEX_BIN" ]] && code_bin_ok=1
  else
    command -v "$CODEX_BIN" >/dev/null 2>&1 && code_bin_ok=1
  fi
  if [[ "$code_bin_ok" -ne 1 ]]; then
    update_meta_status "codex_unavailable" "" "codex command not found: $CODEX_BIN"
    cat "$META_JSON"
    echo "[start_session] ERROR: codex command not found: $CODEX_BIN (可用 --no-codex 仅初始化会话)" >&2
    exit 3
  fi

  set +e
  (
    cd "$ROOT_DIR"
    nohup "$CODEX_BIN" "${CODEX_MODEL_ARGS[@]}" -a never exec --skip-git-repo-check --sandbox workspace-write "$(cat "$PROMPT_TXT")" > "$CONV_LOG" 2>&1 &
    echo $! > "$SESSION_DIR/codex.pid"
  )
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    update_meta_status "codex_start_failed" "" "failed to spawn codex exec"
    cat "$META_JSON"
    echo "[start_session] ERROR: failed to start codex exec" >&2
    exit 4
  fi

  CODEX_PID="$(cat "$SESSION_DIR/codex.pid" 2>/dev/null || true)"
  update_meta_status "running" "$CODEX_PID" ""
else
  update_meta_status "initialized" "" ""
  python3 - <<PY
import json
mp="$META_JSON"
sp="$STATE_FILE"
with open(mp,"r",encoding="utf-8") as f:
    m=json.load(f)
m.setdefault("codex",{})["enabled"]=False
with open(mp,"w",encoding="utf-8") as f:
    json.dump(m,f,ensure_ascii=False,indent=2)
with open(sp,"r",encoding="utf-8") as f:
    s=json.load(f)
s.setdefault("session",{})["codex_enabled"]=False
with open(sp,"w",encoding="utf-8") as f:
    json.dump(s,f,ensure_ascii=False,indent=2)
PY
fi

cat "$META_JSON"
