#!/usr/bin/env bash
set -euo pipefail

# =======================
# pwn-recon (robust)
# - Multi-probe IO detection to reduce "unknown"
# - checksec PIE parsing including "No PIE (0x400000)" base extraction
# - Safe state update via python3 (avoids jq escaping pitfalls)
# =======================

die() { echo "[pwn-recon] ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1; }

utc_now_file() { date -u +"%Y%m%dT%H%M%SZ"; }
utc_now_iso()  { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_FILE="$ROOT_DIR/state/state.json"
[[ -f "$STATE_FILE" ]] || die "state file not found: $STATE_FILE"
need_cmd python3 || die "python3 is required for robust JSON state update"

# ---- read binary_path/workdir from state (robust) ----
read_state_field() {
  # 允许两种方式：read_state_field challenge.binary_path  或  FIELD=challenge.binary_path read_state_field
  local field="${1:-}"
  if [[ -z "$field" ]]; then
    field="${FIELD:-}"
  fi
  [[ -n "$field" ]] || die "read_state_field: missing field path (e.g. challenge.binary_path)"

  python3 - "$STATE_FILE" "$field" <<'PY'
import json,sys
state_path, field = sys.argv[1], sys.argv[2]
with open(state_path, 'r', encoding='utf-8') as f:
    s = json.load(f)

cur = s
for k in field.split('.'):
    if not isinstance(cur, dict) or k not in cur:
        print("")
        sys.exit(0)
    cur = cur[k]

# dict/list 输出成 JSON，其他直接输出字符串/数字
if isinstance(cur, (dict, list)):
    print(json.dumps(cur, ensure_ascii=False))
else:
    print(cur)
PY
}


FIELD="challenge.binary_path" BIN_PATH="$(FIELD="$FIELD" read_state_field)"
FIELD="challenge.workdir" WORKDIR="$(FIELD="$FIELD" read_state_field)"

[[ -n "$BIN_PATH" ]] || die "state.challenge.binary_path is empty"
[[ -f "$BIN_PATH" ]] || die "binary not found: $BIN_PATH"
if [[ -z "$WORKDIR" ]]; then WORKDIR="$ROOT_DIR"; fi

# ---- determine next run_id based on state.progress.run_seq ----
RUN_SEQ="$(python3 - "$STATE_FILE" <<'PY'
import json,sys
s=json.load(open(sys.argv[1],'r',encoding='utf-8'))
v=s.get("progress",{}).get("run_seq",0)
try: v=int(v)
except: v=0
print(v)
PY
)"
RUN_SEQ=$((RUN_SEQ + 1))
RUN_ID=$(printf "run_%04d" "$RUN_SEQ")
TS_FILE="$(utc_now_file)"
TS_ISO="$(utc_now_iso)"

# ---- artifacts paths ----
ART_LOG_DIR="$ROOT_DIR/artifacts/logs"
ART_REP_DIR="$ROOT_DIR/artifacts/reports"
mkdir -p "$ART_LOG_DIR" "$ART_REP_DIR"

LOG_PATH="$ART_LOG_DIR/recon_${TS_FILE}_${RUN_ID}.log"
REP_PATH="$ART_REP_DIR/recon_${TS_FILE}_${RUN_ID}.md"

# ---- log header ----
{
  echo "[pwn-recon] run_id=$RUN_ID utc=$TS_ISO"
  echo "[pwn-recon] binary=$BIN_PATH"
  echo "[pwn-recon] workdir=$WORKDIR"
  echo
  echo "== file =="
  file "$BIN_PATH" || true
  echo
  echo "== sha256 =="
  if need_cmd sha256sum; then sha256sum "$BIN_PATH" || true; fi
  echo
} | tee "$LOG_PATH" >/dev/null

FILE_OUT="$(file "$BIN_PATH" 2>/dev/null || true)"

# ---- parse arch/bits/endian (best-effort) ----
ARCH=""
BITS=""
ENDIAN=""

if echo "$FILE_OUT" | grep -qi "x86-64"; then ARCH="x86_64"; BITS="64"; fi
if echo "$FILE_OUT" | grep -qiE "Intel 80386|i386"; then ARCH="x86"; BITS="32"; fi
if echo "$FILE_OUT" | grep -qiE "aarch64|ARM aarch64"; then ARCH="aarch64"; BITS="64"; fi
if echo "$FILE_OUT" | grep -qiE "ARM"; then
  [[ -z "$ARCH" ]] && ARCH="arm"
  [[ -z "$BITS" ]] && BITS="32"
fi

if echo "$FILE_OUT" | grep -qi "LSB"; then ENDIAN="little"; fi
if echo "$FILE_OUT" | grep -qi "MSB"; then ENDIAN="big"; fi

# ---- protections defaults (tri-state in strings: true/false/null) ----
NX="null"
PIE="null"
CANARY="null"
RELRO=""
NO_PIE_BASE=""  # e.g. 0x400000 if available

# ---- helper: extract 0x... from string ----
extract_hex() {
  # prints first 0x... match or empty
  grep -Eo '0x[0-9a-fA-F]+' | head -n1 || true
}

# ---- checksec parsing (robust-ish across variants) ----
CHECKSEC_OUT=""
if need_cmd checksec; then
  {
    echo "== checksec =="
    checksec --file="$BIN_PATH" 2>&1 | tee -a "$LOG_PATH" >/dev/null
    echo
  } >> "$LOG_PATH"
  CHECKSEC_OUT="$(checksec --file="$BIN_PATH" 2>&1 || true)"

  # NX
  if echo "$CHECKSEC_OUT" | grep -qiE 'NX[^A-Za-z0-9]*enabled|NX[^A-Za-z0-9]*ENABLED'; then NX="true"; fi
  if echo "$CHECKSEC_OUT" | grep -qiE 'NX[^A-Za-z0-9]*disabled|NX[^A-Za-z0-9]*DISABLED'; then NX="false"; fi

  # Canary
  if echo "$CHECKSEC_OUT" | grep -qiE 'Canary[^A-Za-z0-9]*found|Stack Canary[^A-Za-z0-9]*found|Canary[^A-Za-z0-9]*FOUND'; then CANARY="true"; fi
  if echo "$CHECKSEC_OUT" | grep -qiE 'Canary[^A-Za-z0-9]*not found|No Canary|Canary[^A-Za-z0-9]*NOT FOUND'; then CANARY="false"; fi

  # RELRO
  if echo "$CHECKSEC_OUT" | grep -qi 'Full RELRO'; then RELRO="Full"; fi
  if echo "$CHECKSEC_OUT" | grep -qi 'Partial RELRO'; then RELRO="Partial"; fi
  if echo "$CHECKSEC_OUT" | grep -qiE 'No RELRO|RELRO[^A-Za-z0-9]*No'; then RELRO="None"; fi

  # PIE + base (handle: "No PIE (0x400000)")
  if echo "$CHECKSEC_OUT" | grep -qiE 'No PIE'; then
    PIE="false"
    # try extract base from the same line containing "No PIE"
    NO_PIE_BASE="$(echo "$CHECKSEC_OUT" | grep -i 'No PIE' | extract_hex)"
  fi
  if echo "$CHECKSEC_OUT" | grep -qiE 'PIE[^A-Za-z0-9]*enabled|PIE[^A-Za-z0-9]*ENABLED'; then
    PIE="true"
  fi
else
  echo "[pwn-recon] checksec not found; falling back to readelf heuristics" | tee -a "$LOG_PATH" >/dev/null
fi

# ---- readelf fallback/augment ----
if need_cmd readelf; then
  READELF_H="$(readelf -h "$BIN_PATH" 2>/dev/null || true)"
  {
    echo "== readelf -h =="
    echo "$READELF_H"
    echo
  } >> "$LOG_PATH"

  # PIE inference from ELF type if still unknown
  if [[ "$PIE" == "null" ]]; then
    if echo "$READELF_H" | grep -q "Type:[[:space:]]*DYN"; then PIE="true"; fi
    if echo "$READELF_H" | grep -q "Type:[[:space:]]*EXEC"; then PIE="false"; fi
  fi

  READELF_L="$(readelf -W -l "$BIN_PATH" 2>/dev/null || true)"
  {
    echo "== readelf -l =="
    echo "$READELF_L"
    echo
  } >> "$LOG_PATH"

  # NX from GNU_STACK
  if [[ "$NX" == "null" ]]; then
    if echo "$READELF_L" | grep -q "GNU_STACK.*RWE"; then NX="false"; fi
    if echo "$READELF_L" | grep -q "GNU_STACK.*RW"; then NX="true"; fi
  fi

  # RELRO from GNU_RELRO + BIND_NOW
  if [[ -z "$RELRO" ]]; then
    if echo "$READELF_L" | grep -q "GNU_RELRO"; then RELRO="Partial"; fi
    READELF_D="$(readelf -d "$BIN_PATH" 2>/dev/null || true)"
    {
      echo "== readelf -d =="
      echo "$READELF_D"
      echo
    } >> "$LOG_PATH"
    if echo "$READELF_D" | grep -q "BIND_NOW"; then
      if [[ "$RELRO" == "Partial" ]]; then RELRO="Full"; fi
    fi
  fi

  # Canary heuristic: __stack_chk_fail symbol
  if [[ "$CANARY" == "null" ]]; then
    if readelf -Ws "$BIN_PATH" 2>/dev/null | grep -q "__stack_chk_fail"; then CANARY="true"; fi
  fi

  # No PIE base fallback: infer from LOAD segment min VirtAddr
  if [[ "$PIE" == "false" && -z "$NO_PIE_BASE" ]]; then
    NO_PIE_BASE="$(echo "$READELF_L" | awk '
      $1=="LOAD" {
        v=$3
        if (v ~ /^0x/) {
          # strip 0x and convert
          sub(/^0x/,"",v)
          val=strtonum("0x" v)
          if (min=="" || val<min) min=val
        }
      }
      END {
        if (min!="") printf "0x%x\n", min
      }' 2>/dev/null || true)"
    # If awk strtonum not supported (busybox awk), fallback to common 0x400000
    if [[ -z "$NO_PIE_BASE" ]]; then NO_PIE_BASE="0x400000"; fi
  fi
fi

# ---- IO probe (multi-probe to avoid unknown) ----
RUN_TIMEOUT="${PWN_RUN_TIMEOUT:-3}"
RUN_ARGS="${PWN_RUN_ARGS:-}"
SAMPLE_INPUT="${PWN_SAMPLE_INPUT:-}"  # if set, we will include it early

# Use stdbuf if available to reduce buffering issues
RUNNER_PREFIX=()
if need_cmd stdbuf; then RUNNER_PREFIX=(stdbuf -o0 -e0); fi

run_probe() {
  local label="$1"
  local input_data="$2"
  local out rc

  {
    echo "== run probe: $label =="
    echo "[pwn-recon] timeout=${RUN_TIMEOUT}s args='${RUN_ARGS}'"
  } >> "$LOG_PATH"

  set +e
  if [[ -n "$input_data" ]]; then
    out="$(
      (cd "$WORKDIR" && printf "%b" "$input_data" | timeout "${RUN_TIMEOUT}"s "${RUNNER_PREFIX[@]}" "$BIN_PATH" $RUN_ARGS) 2>&1
    )"
  else
    out="$(
      (cd "$WORKDIR" && timeout "${RUN_TIMEOUT}"s "${RUNNER_PREFIX[@]}" "$BIN_PATH" $RUN_ARGS) 2>&1
    )"
  fi
  rc=$?
  set -e

  {
    echo "[pwn-recon] probe rc=$rc"
    echo "----- probe output begin -----"
    echo "$out"
    echo "----- probe output end -----"
    echo
  } >> "$LOG_PATH"

  # Return output via stdout (caller captures)
  printf "%s" "$out"
}

# Define probe list
declare -a PROBE_LABELS=()
declare -a PROBE_INPUTS=()

PROBE_LABELS+=("no-input"); PROBE_INPUTS+=("")
if [[ -n "$SAMPLE_INPUT" ]]; then
  PROBE_LABELS+=("sample-input"); PROBE_INPUTS+=("$SAMPLE_INPUT")
fi
PROBE_LABELS+=("newline"); PROBE_INPUTS+=($'\n')
PROBE_LABELS+=("menu-1");  PROBE_INPUTS+=("1\n")
PROBE_LABELS+=("letter-A"); PROBE_INPUTS+=("A\n")
PROBE_LABELS+=("AAAA"); PROBE_INPUTS+=("AAAA\n")

BEST_OUT=""
BEST_LABEL=""

for i in "${!PROBE_LABELS[@]}"; do
  o="$(run_probe "${PROBE_LABELS[$i]}" "${PROBE_INPUTS[$i]}")"
  # pick first probe that produces non-whitespace output
  if [[ -z "$BEST_OUT" ]]; then
    if [[ -n "$(echo "$o" | tr -d ' \t\r\n')" ]]; then
      BEST_OUT="$o"
      BEST_LABEL="${PROBE_LABELS[$i]}"
    fi
  fi
done

IO_MODE="unknown"
PROMPT_STYLE="unknown"
EXPECTS_NEWLINE="null"
IO_NOTES=""

if [[ -n "$BEST_OUT" ]]; then
  if echo "$BEST_OUT" | grep -qiE "1\)|2\)|3\)|choice|select|menu|option"; then
    IO_MODE="menu"
    PROMPT_STYLE="numbered_menu"
    EXPECTS_NEWLINE="true"
    IO_NOTES="Detected menu-like prompts from probe '${BEST_LABEL}'."
  elif echo "$BEST_OUT" | grep -qiE "Enter|Input|Name|Password|Size|Length|index|addr"; then
    IO_MODE="line"
    PROMPT_STYLE="custom"
    EXPECTS_NEWLINE="true"
    IO_NOTES="Detected line-input prompts from probe '${BEST_LABEL}'."
  else
    IO_MODE="unknown"
    PROMPT_STYLE="unknown"
    EXPECTS_NEWLINE="null"
    IO_NOTES="Probe '${BEST_LABEL}' produced output but pattern not recognized; keep unknown."
  fi
else
  IO_MODE="unknown"
  PROMPT_STYLE="unknown"
  EXPECTS_NEWLINE="null"
  IO_NOTES="All probes produced empty output (likely blocks on read without prompt). Consider interactive/manual probe."
fi

# ---- write short report ----
{
  echo "# Recon Report"
  echo
  echo "- run_id: \`$RUN_ID\`"
  echo "- time_utc: \`$TS_ISO\`"
  echo "- binary: \`$BIN_PATH\`"
  echo
  echo "## Protections"
  echo "- arch: \`$ARCH\`"
  echo "- bits: \`${BITS:-}\`"
  echo "- endian: \`$ENDIAN\`"
  echo "- NX: \`$NX\`"
  echo "- PIE: \`$PIE\`"
  if [[ -n "$NO_PIE_BASE" ]]; then
    echo "- No-PIE base (if applicable): \`$NO_PIE_BASE\`"
  fi
  echo "- RELRO: \`$RELRO\`"
  echo "- Canary: \`$CANARY\`"
  echo
  echo "## IO Profile"
  echo "- mode: \`$IO_MODE\`"
  echo "- prompt_style: \`$PROMPT_STYLE\`"
  echo "- expects_newline: \`$EXPECTS_NEWLINE\`"
  echo "- notes: $IO_NOTES"
  echo
  echo "## Next"
  echo "- recommended: pwn-ida-slice"
} > "$REP_PATH"

# ---- safe state update via python3 (no escaping issues) ----
# Pass all values via env; python converts to correct JSON types.
export UPD_RUN_SEQ="$RUN_SEQ"
export UPD_RUN_ID="$RUN_ID"
export UPD_TS_ISO="$TS_ISO"
export UPD_BIN_PATH="$BIN_PATH"
export UPD_WORKDIR="$WORKDIR"
export UPD_LOG_PATH="$LOG_PATH"
export UPD_REP_PATH="$REP_PATH"

export UPD_ARCH="$ARCH"
export UPD_BITS="${BITS:-}"
export UPD_ENDIAN="$ENDIAN"
export UPD_NX="$NX"
export UPD_PIE="$PIE"
export UPD_RELRO="$RELRO"
export UPD_CANARY="$CANARY"

export UPD_IO_MODE="$IO_MODE"
export UPD_PROMPT_STYLE="$PROMPT_STYLE"
export UPD_EXPECTS_NEWLINE="$EXPECTS_NEWLINE"
export UPD_IO_NOTES="$IO_NOTES"

export UPD_NO_PIE_BASE="$NO_PIE_BASE"

python3 - "$STATE_FILE" <<'PY'
import json, os, sys
from datetime import datetime

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
  s = json.load(f)

def ensure(d, key, default):
  if key not in d or d[key] is None:
    d[key] = default
  return d[key]

def as_tristate(v):
  # "true"/"false"/"null" -> True/False/None
  v = (v or "").strip().lower()
  if v == "true": return True
  if v == "false": return False
  return None

def as_int_or_none(v):
  v = (v or "").strip()
  if not v: return None
  try: return int(v)
  except: return None

# Ensure top-level structures
challenge = ensure(s, "challenge", {})
env = ensure(s, "env", {})
prot = ensure(s, "protections", {})
io = ensure(s, "io_profile", {})
progress = ensure(s, "progress", {})
counters = ensure(progress, "counters", {})
artidx = ensure(s, "artifacts_index", {})
runs = ensure(artidx, "runs", [])
latest = ensure(artidx, "latest", {})
latest_paths = ensure(latest, "paths", {})
summary = ensure(s, "summary", {})
latest_bases = ensure(s, "latest_bases", {})

# Read env inputs
run_seq = int(os.environ.get("UPD_RUN_SEQ","0"))
run_id = os.environ.get("UPD_RUN_ID","")
ts = os.environ.get("UPD_TS_ISO","")

bin_path = os.environ.get("UPD_BIN_PATH","")
workdir = os.environ.get("UPD_WORKDIR","")
log_path = os.environ.get("UPD_LOG_PATH","")
rep_path = os.environ.get("UPD_REP_PATH","")

arch = os.environ.get("UPD_ARCH","")
bits = as_int_or_none(os.environ.get("UPD_BITS",""))
endian = os.environ.get("UPD_ENDIAN","")

nx = as_tristate(os.environ.get("UPD_NX","null"))
pie = as_tristate(os.environ.get("UPD_PIE","null"))
canary = as_tristate(os.environ.get("UPD_CANARY","null"))
relro = os.environ.get("UPD_RELRO","")

io_mode = os.environ.get("UPD_IO_MODE","unknown")
prompt_style = os.environ.get("UPD_PROMPT_STYLE","unknown")
expects_newline = as_tristate(os.environ.get("UPD_EXPECTS_NEWLINE","null"))
io_notes = os.environ.get("UPD_IO_NOTES","")

no_pie_base = os.environ.get("UPD_NO_PIE_BASE","").strip()

# Update challenge
if bin_path: challenge["binary_path"] = bin_path
if workdir:  challenge["workdir"] = workdir

# Update protections
prot["arch"] = arch
prot["bits"] = bits
prot["endian"] = endian
prot["nx"] = nx
prot["pie"] = pie
prot["relro"] = relro
prot["canary"] = canary

# Update IO profile
io["mode"] = io_mode
io["prompt_style"] = prompt_style
io["expects_newline"] = expects_newline
io["notes"] = io_notes

# Update progress
progress["run_seq"] = run_seq
progress["stage"] = "recon"
counters["recon_runs"] = int(counters.get("recon_runs", 0) or 0) + 1
counters["total_runs"] = int(counters.get("total_runs", 0) or 0) + 1
progress["last_updated_utc"] = ts

# Update artifacts index
latest["run_id"] = run_id
latest_paths["recon_log"] = log_path
latest_paths["recon_report"] = rep_path

runs.append({
  "run_id": run_id,
  "stage": "recon",
  "created_utc": ts,
  "paths": {"recon_log": log_path, "recon_report": rep_path}
})

# Next actions
summary["next_actions"] = ["pwn-ida-slice"]

# If No PIE and base known, set latest_bases.pie_base for convenience
# (Stage 3 will still compute mapping-based base for PIE=true.)
if pie is False and no_pie_base:
  latest_bases["pie_base"] = no_pie_base

with open(path, 'w', encoding='utf-8') as f:
  json.dump(s, f, ensure_ascii=False, indent=2)
PY

echo "[pwn-recon] OK: wrote $LOG_PATH and updated state."
