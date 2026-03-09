#!/usr/bin/env bash
set -euo pipefail

die() { echo "[pwn-gdb-evidence] ERROR: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

utc_now_file() { date -u +"%Y%m%dT%H%M%SZ"; }
utc_now_iso()  { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_FILE="$ROOT_DIR/state/state.json"
[[ -f "$STATE_FILE" ]] || die "state file not found: $STATE_FILE"

need_cmd python3 || die "python3 required"
GDB_BIN="${GDB_BIN:-gdb}"
need_cmd "$GDB_BIN" || die "gdb not found: $GDB_BIN"
need_cmd timeout || die "timeout required"

# ---- read state fields ----
py_get() {
  local field="$1"
  FIELD="$field" python3 - "$STATE_FILE" <<'PY'
import json,sys,os
s=json.load(open(sys.argv[1],'r',encoding='utf-8'))
field=os.environ.get("FIELD","")
cur=s
for k in field.split("."):
  if not k: continue
  if isinstance(cur, dict) and k in cur:
    cur=cur[k]
  else:
    cur=""
    break
if cur is None: cur=""
print(cur if isinstance(cur,str) else cur)
PY
}

BIN_PATH="$(py_get "challenge.binary_path")"
WORKDIR="$(py_get "challenge.workdir")"
PIE_STATE="$(py_get "protections.pie")"
LAST_PIE_BASE="$(py_get "latest_bases.pie_base")"
[[ -n "$BIN_PATH" ]] || die "state.challenge.binary_path is empty"
[[ -f "$BIN_PATH" ]] || die "binary not found: $BIN_PATH"
[[ -n "$WORKDIR" ]] || WORKDIR="$ROOT_DIR"

PIE_TRI="$(python3 - <<PY
v = """$PIE_STATE""".strip().lower()
if v in ("true","1","yes"): print("true")
elif v in ("false","0","no"): print("false")
else: print("null")
PY
)"

# ---- run id from state.progress.run_seq ----
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
ART_GDB_DIR="$ROOT_DIR/artifacts/gdb/$RUN_ID"
ART_IN_DIR="$ROOT_DIR/artifacts/inputs"
mkdir -p "$ART_GDB_DIR" "$ART_IN_DIR"

RAW_TXT="$ART_GDB_DIR/raw.txt"
SUMMARY_JSON="$ART_GDB_DIR/summary.json"
GDB_CMDS_USED="$ART_GDB_DIR/gdb_cmds.used.txt"

BASE_CMDS="$ROOT_DIR/skills/pwn-gdb-evidence/gdb_cmds.txt"
[[ -f "$BASE_CMDS" ]] || die "missing base gdb_cmds.txt: $BASE_CMDS"

# ---- input handling ----
PWN_INPUT_FILE="${PWN_INPUT_FILE:-}"
PWN_INPUT_TEXT="${PWN_INPUT_TEXT:-}"
PWN_RUN_ARGS="${PWN_RUN_ARGS:-}"
PWN_GDB_TIMEOUT="${PWN_GDB_TIMEOUT:-20}"

INPUT_TMP=""
if [[ -n "$PWN_INPUT_FILE" ]]; then
  [[ -f "$PWN_INPUT_FILE" ]] || die "PWN_INPUT_FILE not found: $PWN_INPUT_FILE"
  INPUT_TMP="$PWN_INPUT_FILE"
elif [[ -n "$PWN_INPUT_TEXT" ]]; then
  INPUT_TMP="$ART_GDB_DIR/input.txt"
  printf "%s" "$PWN_INPUT_TEXT" > "$INPUT_TMP"
else
  INPUT_TMP="$ART_GDB_DIR/input.txt"
  printf "\n" > "$INPUT_TMP"
fi

INPUT_SHA256="$(python3 - "$INPUT_TMP" <<'PY'
import hashlib,sys
p=sys.argv[1]
h=hashlib.sha256()
with open(p,'rb') as f:
  for ch in iter(lambda: f.read(1<<20), b''):
    h.update(ch)
print(h.hexdigest())
PY
)"

INPUT_ID_AND_PATH="$(python3 - "$STATE_FILE" "$INPUT_SHA256" "$ART_IN_DIR" "$TS_FILE" <<'PY'
import json,sys,os
state_path, sha, in_dir, ts = sys.argv[1:5]
s=json.load(open(state_path,'r',encoding='utf-8'))
dyn=s.get("dynamic_evidence",{})
inputs=dyn.get("inputs",[]) if isinstance(dyn.get("inputs",[]), list) else []
for it in inputs:
  if isinstance(it, dict) and it.get("sha256","") == sha:
    print(it.get("input_id",""), it.get("path",""))
    raise SystemExit
n=len(inputs)+1
input_id=f"in_{n:04d}"
dst=os.path.join(in_dir, f"{input_id}_{ts}.bin")
print(input_id, dst)
PY
)"
INPUT_ID="$(echo "$INPUT_ID_AND_PATH" | awk '{print $1}')"
INPUT_DST="$(echo "$INPUT_ID_AND_PATH" | awk '{print $2}')"

if [[ -n "$INPUT_DST" && ! -f "$INPUT_DST" ]]; then
  cp -f "$INPUT_TMP" "$INPUT_DST"
fi

ABS_INPUT_DST="$(python3 - <<PY
import os
print(os.path.abspath("$INPUT_DST"))
PY
)"
ABS_BIN_PATH="$(python3 - <<PY
import os
print(os.path.abspath("$BIN_PATH"))
PY
)"
ABS_WORKDIR="$(python3 - <<PY
import os
print(os.path.abspath("$WORKDIR"))
PY
)"

# ---- build gdb commands used ----
{
  echo "set pagination off"
  echo "set confirm off"
  echo "set verbose off"
  echo "set print elements 0"
  echo "set print repeats 0"
  echo "set print pretty off"
  echo "set disassemble-next-line on"
  echo "set width 0"
  echo "set height 0"
  echo "set disable-randomization off"
  echo "handle SIGALRM pass nostop noprint"
  echo "handle SIGPIPE pass nostop noprint"
  echo ""
  echo "cd $ABS_WORKDIR"
  echo ""
    # --- prelude: get PIE base while process is alive ---
  echo "echo ==[evidence] pre_starti ==\\n"
  echo "starti"
  echo "echo ==[evidence] mappings ==\\n"
  echo "info proc mappings"
  echo "echo ==[evidence] info files ==\\n"
  echo "info files"
  echo "kill"
  echo ""

  # --- run with input (may crash or exit) ---
  echo "echo \\n==[evidence] run ==\\n"
  echo "run < $ABS_INPUT_DST"
  echo ""

  # --- post-run evidence (regs/bt etc.) ---
  cat "$BASE_CMDS"

  echo ""
  echo "echo \\n==[evidence] done ==\\n"
  echo "quit"
} > "$GDB_CMDS_USED"

# ---- run gdb ----
{
  echo "[pwn-gdb-evidence] run_id=$RUN_ID utc=$TS_ISO"
  echo "[pwn-gdb-evidence] pie=$PIE_TRI"
  echo "[pwn-gdb-evidence] bin=$ABS_BIN_PATH"
  echo "[pwn-gdb-evidence] workdir=$ABS_WORKDIR"
  echo "[pwn-gdb-evidence] input_id=$INPUT_ID sha256=$INPUT_SHA256 path=$INPUT_DST"
  echo "[pwn-gdb-evidence] gdb_timeout=${PWN_GDB_TIMEOUT}s args='${PWN_RUN_ARGS}'"
  echo
  echo "== gdb_cmds.used =="
  sed -n '1,200p' "$GDB_CMDS_USED"
  echo "== /gdb_cmds.used =="
  echo
} > "$RAW_TXT"

set +e
timeout -k 1s "${PWN_GDB_TIMEOUT}s" \
  "$GDB_BIN" -q -nx -batch \
  -x "$GDB_CMDS_USED" \
  --args "$ABS_BIN_PATH" $PWN_RUN_ARGS \
  >> "$RAW_TXT" 2>&1
GDB_RC=$?
set -e

echo "" >> "$RAW_TXT"
echo "[pwn-gdb-evidence] gdb_rc=$GDB_RC" >> "$RAW_TXT"

# ---- parse raw transcript -> summary.json
# - mappings tolerant parse
# - PIE base fallback: auxv (AT_PHDR - e_phoff) -> info files + readelf .text
# - libc base fallback: info sharedlibrary
# - compute pc_offset for PIE-stable comparisons
python3 - "$RAW_TXT" "$SUMMARY_JSON" "$ABS_BIN_PATH" "$PIE_TRI" "$LAST_PIE_BASE" "$TS_ISO" "$RUN_ID" "$INPUT_ID" <<'PY'
import re,sys,json,os,subprocess

raw_path, out_path, bin_path, pie_tri, last_pie_base, ts, run_id, input_id = sys.argv[1:9]
bin_base = os.path.basename(bin_path)
raw_lines = open(raw_path,'r',errors='ignore').read().splitlines()

def section_between(marker):
  out=[]
  inside=False
  for ln in raw_lines:
    if ln.strip() == marker:
      inside=True
      continue
    if inside and ln.strip().startswith("==[evidence]") and ln.strip()!=marker:
      break
    if inside:
      out.append(ln)
  return out

def first_match(pattern, lines):
  r=re.compile(pattern)
  for ln in lines:
    m=r.search(ln)
    if m:
      return m
  return None

def hex_ok(x): return bool(re.fullmatch(r'0x[0-9a-fA-F]+', (x or "").strip()))

def readelf_e_phoff(path):
  # from: "Start of program headers:          64 (bytes into file)"
  try:
    out = subprocess.check_output(["readelf","-h",path], stderr=subprocess.DEVNULL, text=True)
  except Exception:
    return None
  m = re.search(r'Start of program headers:\s*([0-9]+)\s*\(bytes into file\)', out)
  if not m: return None
  try: return int(m.group(1))
  except: return None

def readelf_text_sh_addr(path):
  # readelf -WS line: [ 1] .text PROGBITS 0000000000001130 ...
  try:
    out = subprocess.check_output(["readelf","-WS",path], stderr=subprocess.DEVNULL, text=True)
  except Exception:
    return None
  for ln in out.splitlines():
    if re.search(r'\]\s+\.text\s', ln):
      m = re.search(r'\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s', ln)
      if m:
        try: return int(m.group(1),16)
        except: return None
  return None

# -------- signal / regs --------
sig = ""
m = first_match(r'Program received signal\s+([A-Z0-9]+)', raw_lines)
if m: sig = m.group(1)

pc = ""; sp = ""; cr2 = ""
reg_re = re.compile(r'^\s*([a-zA-Z0-9_]+)\s+0x([0-9a-fA-F]+)\b')
for ln in raw_lines:
  m = reg_re.match(ln)
  if not m: 
    continue
  name = m.group(1).lower()
  val = "0x" + m.group(2).lower()
  if name in ("rip","eip","pc"): pc = val
  if name in ("rsp","esp","sp"): sp = val
  if name == "cr2": cr2 = val

# -------- bt --------
bt=[]
bt_lines = section_between("==[evidence] backtrace ==")
for ln in bt_lines[:60]:
  if ln.strip().startswith("#"):
    bt.append(ln.strip())

# -------- info proc mappings (tolerant) --------
maps=[]
maps_lines = section_between("==[evidence] mappings ==")
for ln in maps_lines:
  if not re.match(r'^\s*0x[0-9a-fA-F]+', ln):
    continue
  m = re.match(r'^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b(.*)$', ln)
  if not m:
    continue
  start=m.group(1).lower()
  end=m.group(2).lower()
  tail=(m.group(3) or "").strip()
  # best-effort obj path: last token resembling path/so/binary
  obj=""
  toks=tail.split()
  for t in toks[::-1]:
    tt=t.strip()
    if not tt: continue
    if "/" in tt or tt.endswith(".so") or ".so." in tt or tt.endswith(bin_base) or bin_base in tt:
      obj=tt
      break
  maps.append({"start":start,"end":end,"obj":obj})

def pick_binary_map(maps):
  cand=[]
  for it in maps:
    obj=(it.get("obj") or "")
    if not obj: 
      continue
    if obj.endswith("/"+bin_base) or obj==bin_base or obj.endswith(bin_base) or ("/"+bin_base) in obj:
      cand.append(it)
  if not cand:
    return None
  cand.sort(key=lambda x:int(x["start"],16))
  return cand[0], cand[-1]

def pick_libc_map(maps):
  cand=[]
  for it in maps:
    obj=(it.get("obj") or "").lower()
    if "libc" in obj and ".so" in obj:
      cand.append(it)
  if not cand:
    return None
  cand.sort(key=lambda x:int(x["start"],16))
  return cand[0], cand[-1]

pie_base=""
bin_range=["",""]
bm=pick_binary_map(maps)
if bm:
  lo,hi=bm
  pie_base=lo["start"]
  bin_range=[lo["start"], hi["end"]]

libc_base=""
libc_range=["",""]
lm=pick_libc_map(maps)
if lm:
  lo,hi=lm
  libc_base=lo["start"]
  libc_range=[lo["start"], hi["end"]]

# -------- info sharedlibrary fallback (for libc) --------
if not libc_base:
  sh_lines = section_between("==[evidence] sharedlibrary ==")
  # example: 0x7ffff7dd7000  0x7ffff7dfd000  Yes (*)     /lib/x86_64-linux-gnu/libc.so.6
  for ln in sh_lines:
    if "libc" not in ln.lower() or ".so" not in ln.lower():
      continue
    m = re.search(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+.*\s(\/\S+libc\S*\.so\S*)', ln)
    if m:
      libc_base = m.group(1).lower()
      libc_range = [m.group(1).lower(), m.group(2).lower()]
      break
    m2 = re.search(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+.*\s(\/\S+)', ln)
    if m2:
      # weaker: accept any path if it contains libc
      if "libc" in m2.group(3).lower():
        libc_base = m2.group(1).lower()
        libc_range = [m2.group(1).lower(), m2.group(2).lower()]
        break

# -------- info auxv fallback (for PIE base) --------
auxv_lines = section_between("==[evidence] auxv ==")
at_phdr = ""
for ln in auxv_lines:
  m = re.search(r'AT_PHDR.*(0x[0-9a-fA-F]+)', ln)
  if m:
    at_phdr = m.group(1).lower()
    break

# -------- info files + readelf .text fallback (for PIE base) --------
info_files_lines = section_between("==[evidence] info files ==")
runtime_text_start = ""
for ln in info_files_lines:
  # gdb typically: 0x... - 0x... is .text
  m = re.match(r'^\s*(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)\s+is\s+\.text\b', ln.strip())
  if m:
    runtime_text_start = m.group(1).lower()
    break

# -------- decide PIE base via multi-source --------
pie_tri = pie_tri.strip().lower()

if pie_tri == "true" and not pie_base:
  # 1) auxv AT_PHDR - e_phoff
  e_phoff = readelf_e_phoff(bin_path)
  if at_phdr and e_phoff is not None and hex_ok(at_phdr):
    try:
      base = int(at_phdr,16) - int(e_phoff)
      if base > 0:
        pie_base = f"0x{base:x}"
    except Exception:
      pass

if pie_tri == "true" and not pie_base:
  # 2) runtime .text start - static .text sh_addr
  static_text = readelf_text_sh_addr(bin_path)
  if runtime_text_start and static_text is not None and hex_ok(runtime_text_start):
    try:
      base = int(runtime_text_start,16) - int(static_text)
      if base > 0:
        pie_base = f"0x{base:x}"
    except Exception:
      pass

# No PIE rule normalization
if pie_tri == "false":
  if not pie_base:
    last=(last_pie_base or "").strip()
    if hex_ok(last):
      pie_base = last.lower()
    else:
      pie_base = "0x400000"

# PIE true hard requirement: if still empty, last resort = page-align pc (better than empty)
if pie_tri == "true" and not pie_base and hex_ok(pc):
  # coarse: align down to page (won't be perfect but avoids null)
  pie_base = f"0x{(int(pc,16) & ~0xfff):x}"

# fault addr
fault_addr=""
if sig=="SIGSEGV" and cr2:
  fault_addr=cr2

# pc_offset
pc_offset=""
if hex_ok(pc) and hex_ok(pie_base):
  try:
    off=int(pc,16)-int(pie_base,16)
    pc_offset = f"0x{off:x}" if off>=0 else f"-0x{(-off):x}"
  except Exception:
    pc_offset=""

# rip_control heuristic (very conservative)
rip_control="unknown"
if pc and any(pat in pc.lower() for pat in ("0x41414141","0x61616161","0x42424242")):
  rip_control="yes"

out = {
  "run_id": run_id,
  "input_id": input_id,
  "created_utc": ts,
  "gdb": {
    "signal": sig,
    "pc": pc,
    "sp": sp,
    "pc_offset": pc_offset,
    "fault_addr": fault_addr,
    "bt_top": bt[:10]
  },
  "mappings": {
    "pie_base": pie_base,
    "binary_range": bin_range,
    "libc_base": libc_base,
    "libc_range": libc_range
  },
  "sources": {
    "has_proc_mappings": bool(maps_lines),
    "has_auxv": bool(auxv_lines),
    "has_info_files": bool(info_files_lines),
    "has_sharedlibrary": bool(section_between("==[evidence] sharedlibrary =="))
  },
  "heuristics": {
    "rip_control": rip_control
  }
}

with open(out_path,'w',encoding='utf-8') as f:
  json.dump(out,f,ensure_ascii=False,indent=2)
PY

# ---- update state safely via python (PIE-stable crash_stable) ----
export UPD_RUN_SEQ="$RUN_SEQ"
export UPD_RUN_ID="$RUN_ID"
export UPD_TS_ISO="$TS_ISO"
export UPD_INPUT_ID="$INPUT_ID"
export UPD_INPUT_SHA256="$INPUT_SHA256"
export UPD_INPUT_PATH="$INPUT_DST"

export UPD_RAW_TXT="$RAW_TXT"
export UPD_SUMMARY_JSON="$SUMMARY_JSON"
export UPD_GDB_CMDS="$GDB_CMDS_USED"

python3 - "$STATE_FILE" "$SUMMARY_JSON" <<'PY'
import json, os, sys, re

state_path = sys.argv[1]
summary_path = sys.argv[2]

s=json.load(open(state_path,'r',encoding='utf-8'))
summ=json.load(open(summary_path,'r',encoding='utf-8'))

def ensure(d,k,default):
  if k not in d or d[k] is None:
    d[k]=default
  return d[k]

prot = ensure(s,"protections",{})
is_pie = prot.get("pie", None)

progress = ensure(s,"progress",{})
counters = ensure(progress,"counters",{})
artidx = ensure(s,"artifacts_index",{})
runs = ensure(artidx,"runs",[])
latest = ensure(artidx,"latest",{})
latest_paths = ensure(latest,"paths",{})
dyn = ensure(s,"dynamic_evidence",{})
inputs = ensure(dyn,"inputs",[])
evids = ensure(dyn,"evidence",[])
latest_bases = ensure(s,"latest_bases",{})
caps = ensure(s,"capabilities",{})
stability = s.get("stability",{}) if isinstance(s.get("stability",{}), dict) else {}
summary = ensure(s,"summary",{})

run_seq = int(os.environ.get("UPD_RUN_SEQ","0"))
run_id = os.environ.get("UPD_RUN_ID","")
ts = os.environ.get("UPD_TS_ISO","")

input_id = os.environ.get("UPD_INPUT_ID","")
sha256 = os.environ.get("UPD_INPUT_SHA256","")
input_path = os.environ.get("UPD_INPUT_PATH","")

raw_txt = os.environ.get("UPD_RAW_TXT","")
summary_json = os.environ.get("UPD_SUMMARY_JSON","")
gdb_cmds = os.environ.get("UPD_GDB_CMDS","")

# inputs dedupe by sha256
existing_id = None
for it in inputs:
  if isinstance(it, dict) and it.get("sha256","") == sha256 and sha256:
    existing_id = it.get("input_id")
    break
if not existing_id:
  inputs.append({
    "input_id": input_id,
    "sha256": sha256,
    "path": input_path,
    "description": "gdb evidence input",
    "created_utc": ts
  })
else:
  input_id = existing_id

evidence_id = f"ev_{len(evids)+1:04d}"

g = summ.get("gdb",{})
m = summ.get("mappings",{})

evids.append({
  "evidence_id": evidence_id,
  "run_id": run_id,
  "input_id": input_id,
  "env_fingerprint_id": s.get("env",{}).get("fingerprint",{}).get("id",""),
  "mappings": {
    "pie_base": m.get("pie_base",""),
    "binary_range": m.get("binary_range",["",""]),
    "libc_base": m.get("libc_base",""),
    "libc_range": m.get("libc_range",["",""])
  },
  "gdb": {
    "signal": g.get("signal",""),
    "rip": g.get("pc",""),
    "sp": g.get("sp",""),
    "pc_offset": g.get("pc_offset",""),
    "fault_addr": g.get("fault_addr",""),
    "bt_top": g.get("bt_top",[])
  },
  "paths": {
    "raw_log": raw_txt,
    "summary_json": summary_json,
    "gdb_cmds": gdb_cmds
  },
  "created_utc": ts
})

progress["run_seq"] = run_seq
progress["stage"] = "gdb_evidence"
counters["gdb_runs"] = int(counters.get("gdb_runs",0) or 0) + 1
counters["total_runs"] = int(counters.get("total_runs",0) or 0) + 1
progress["last_updated_utc"] = ts

latest["run_id"] = run_id
latest_paths["gdb_raw"] = raw_txt
latest_paths["gdb_summary"] = summary_json
latest_paths["gdb_cmds"] = gdb_cmds
runs.append({
  "run_id": run_id,
  "stage": "gdb_evidence",
  "created_utc": ts,
  "paths": {
    "gdb_raw": raw_txt,
    "gdb_summary": summary_json,
    "gdb_cmds": gdb_cmds
  }
})

pie_base = (m.get("pie_base","") or "").strip()
libc_base = (m.get("libc_base","") or "").strip()
if pie_base:
  latest_bases["pie_base"] = pie_base
if libc_base:
  latest_bases["libc_base"] = libc_base

sig = (g.get("signal","") or "").strip()
pc  = (g.get("pc","") or "").strip()
pc_off = (g.get("pc_offset","") or "").strip()
rip_control = (summ.get("heuristics",{}) or {}).get("rip_control","unknown")

if sig:
  caps["has_crash"] = True
if rip_control:
  caps["rip_control"] = rip_control

need = int(stability.get("crash_repro_runs", 3) or 3)

def hex_ok(x): return bool(re.fullmatch(r'0x[0-9a-fA-F]+', (x or "").strip()))

def norm_pc_from_ev(ev):
  eg = (ev.get("gdb",{}) or {})
  em = (ev.get("mappings",{}) or {})
  pc = (eg.get("rip","") or "").strip()
  if is_pie is True:
    off = (eg.get("pc_offset","") or "").strip()
    if off:
      return off
    base = (em.get("pie_base","") or "").strip()
    if hex_ok(pc) and hex_ok(base):
      try:
        return f"0x{(int(pc,16)-int(base,16))&0xffffffffffffffff:x}"
      except:
        return ""
    return ""
  else:
    return pc

norm_now = pc_off if (is_pie is True and pc_off) else (pc if is_pie is not True else "")
same = 0
if sig and (norm_now or pc):
  for ev in evids:
    eg = (ev.get("gdb",{}) or {})
    if (eg.get("signal","") or "").strip() != sig:
      continue
    if is_pie is True:
      if norm_pc_from_ev(ev) == norm_now and norm_now:
        same += 1
    else:
      if (eg.get("rip","") or "").strip() == pc and pc:
        same += 1

caps["crash_stable"] = (same >= need) if sig else False

if caps.get("has_crash") and not caps.get("crash_stable"):
  summary["next_actions"] = ["pwn-gdb-evidence"]
else:
  summary["next_actions"] = []

with open(state_path,'w',encoding='utf-8') as f:
  json.dump(s,f,ensure_ascii=False,indent=2)
PY

echo "[pwn-gdb-evidence] OK: wrote $RAW_TXT / $SUMMARY_JSON and updated state."
