#!/usr/bin/env bash
set -euo pipefail

die() { echo "[pwn-ida-slice] ERROR: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

utc_now_file() { date -u +"%Y%m%dT%H%M%SZ"; }
utc_now_iso()  { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_FILE="$ROOT_DIR/state/state.json"
[[ -f "$STATE_FILE" ]] || die "state file not found: $STATE_FILE"
need_cmd python3 || die "python3 required"

# --- read state fields (robust) ---
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
[[ -n "$BIN_PATH" ]] || die "state.challenge.binary_path is empty"
[[ -f "$BIN_PATH" ]] || die "binary not found: $BIN_PATH"
[[ -n "$WORKDIR" ]] || WORKDIR="$ROOT_DIR"

# --- run id from state.progress.run_seq ---
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

ART_DIR="$ROOT_DIR/artifacts/ida/$RUN_ID"
mkdir -p "$ART_DIR"
RAW_LOG="$ART_DIR/raw.log"
SLICE_JSON="$ART_DIR/slice.json"
SLICE_MD="$ART_DIR/slice.md"

PROVIDER="${IDA_SLICE_PROVIDER:-ida_mcp}"   # ida_mcp | fallback
DEPTH="${IDA_SLICE_DEPTH:-5}"
MAX_SINKS="${IDA_MAX_SINKS:-20}"

echo "[pwn-ida-slice] run_id=$RUN_ID utc=$TS_ISO provider=$PROVIDER" | tee "$RAW_LOG" >/dev/null
echo "[pwn-ida-slice] binary=$BIN_PATH workdir=$WORKDIR depth=$DEPTH max_sinks=$MAX_SINKS" >> "$RAW_LOG"

# =====================
# 1) Try IDA MCP (placeholder adapter)
# =====================
IDA_OK=0
if [[ "$PROVIDER" == "ida_mcp" ]]; then
  echo "" >> "$RAW_LOG"
  echo "== ida_mcp attempt ==" >> "$RAW_LOG"

  # Option A: CLI wrapper
  #   export IDA_MCP_CLI="/path/to/ida_mcp_cli"
  #   "$IDA_MCP_CLI" slice --binary "$BIN_PATH" --depth "$DEPTH" --max-sinks "$MAX_SINKS" --out "$SLICE_JSON"
  #
  # Option B: HTTP adapter (not implemented here)
  #   export IDA_MCP_URL="http://127.0.0.1:xxxx"
  #
  if [[ -n "${IDA_MCP_CLI:-}" ]] && [[ -x "${IDA_MCP_CLI:-}" ]]; then
    echo "[pwn-ida-slice] using IDA_MCP_CLI=${IDA_MCP_CLI}" >> "$RAW_LOG"
    set +e
    "${IDA_MCP_CLI}" slice \
      --binary "$BIN_PATH" \
      --depth "$DEPTH" \
      --max-sinks "$MAX_SINKS" \
      --out "$SLICE_JSON" >> "$RAW_LOG" 2>&1
    rc=$?
    set -e
    if [[ $rc -eq 0 && -s "$SLICE_JSON" ]]; then IDA_OK=1; fi
  elif [[ -n "${IDA_MCP_URL:-}" ]]; then
    echo "[pwn-ida-slice] IDA_MCP_URL set but HTTP adapter not implemented in MVP; fallback will be used." >> "$RAW_LOG"
  else
    echo "[pwn-ida-slice] IDA MCP not configured (no IDA_MCP_CLI / IDA_MCP_URL)." >> "$RAW_LOG"
  fi
fi

# =====================
# 2) Fallback static slice via objdump (robust parser)
# =====================
if [[ $IDA_OK -ne 1 ]]; then
  echo "" >> "$RAW_LOG"
  echo "== fallback slice: objdump ==" >> "$RAW_LOG"
  need_cmd objdump || die "objdump required for fallback"

  DISASM="$ART_DIR/objdump.txt"
  objdump -d -w "$BIN_PATH" > "$DISASM" 2>>"$RAW_LOG" || true
  echo "[pwn-ida-slice] wrote disasm: $DISASM" >> "$RAW_LOG"

  python3 - "$DISASM" "$SLICE_JSON" "$DEPTH" "$MAX_SINKS" >>"$RAW_LOG" 2>&1 <<'PY'
import re, sys, json, collections

disasm_path, out_path, depth_s, max_sinks_s = sys.argv[1:5]
DEPTH = int(depth_s)
MAX_SINKS = int(max_sinks_s)

# 常见高危/关键 sink（可按需扩展）
SINKS = [
  "system", "execve", "execl", "execlp", "execle", "execv", "execvp", "popen",
  "gets", "fgets", "scanf", "__isoc99_scanf", "read",
  "strcpy", "strncpy", "strcat", "strncat",
  "sprintf", "snprintf", "vsprintf", "vsnprintf",
  "printf", "fprintf", "dprintf", "vprintf", "vfprintf",
  "memcpy", "memmove", "bcopy",
  "malloc", "calloc", "realloc", "free"
]

# 用于 hypothesis 去偏/优先级（printf 多也不会占满 3 条）
SINK_SCORE = {
  "execve": 100, "execv": 100, "execvp": 100, "execl": 100, "execlp": 100, "execle": 100,
  "system": 95, "popen": 90,
  "gets": 90, "strcpy": 85, "strcat": 85, "sprintf": 85, "vsprintf": 85,
  "scanf": 70, "__isoc99_scanf": 70, "fgets": 60, "read": 60,
  "printf": 55, "fprintf": 55, "dprintf": 55, "vprintf": 55, "vfprintf": 55, "snprintf": 45, "vsnprintf": 45,
  "memcpy": 40, "memmove": 40, "bcopy": 40,
  "free": 35, "malloc": 20, "calloc": 20, "realloc": 20
}

def norm_sym(sym: str) -> str:
  """
  清洗 objdump 符号名：
  - printf@plt / printf@plt.sec / printf@got.plt -> printf
  - printf@@GLIBC_2.2.5 / printf@GLIBC_2.2.5 -> printf
  - foo_plt / foo.plt -> foo
  """
  if not sym:
    return ""
  s = sym.strip()

  # 去版本后缀：@@GLIBC_2.2.5 / @GLIBC_2.2.5
  s = re.sub(r'@@?GLIBC_[0-9.]+', '', s)

  # 常见链接后缀
  s = s.replace("@plt.sec", "@plt")
  s = re.sub(r'@got(\.plt)?', '', s)
  s = re.sub(r'@plt', '', s)

  # 其他变体
  s = re.sub(r'(\.plt|_plt)$', '', s)

  # 再清一次尾部 @...（有些工具链奇怪 suffix）
  s = re.sub(r'@.+$', '', s)

  return s.strip()

# 函数头：更宽松，允许奇怪符号名（直到 >）
func_re = re.compile(r'^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$')

# call：支持直接 call 与 GOT 间接 call
#  callq  401030 <printf@plt>
#  callq *0x404018 <printf@@GLIBC_2.2.5>
call_re = re.compile(r'\bcall[q]?\s+\*?\s*([0-9a-fA-Fx]+)\s*(?:<([^>]+)>)?\s*$')

current_func = None
func_addrs = {}                         # function name -> addr
edges = collections.defaultdict(set)    # caller -> {callee_sym}
reverse_edges = collections.defaultdict(set)  # callee_sym -> {caller_func}
sink_callsites = []

with open(disasm_path, 'r', errors='ignore') as f:
  for line in f:
    m = func_re.match(line)
    if m:
      addr = "0x" + m.group(1).lower()
      current_func = m.group(2).strip()
      func_addrs[current_func] = addr
      continue

    m = call_re.search(line)
    if m and current_func:
      callsite_addr = line.strip().split(":")[0]
      callee_sym = (m.group(2) or "").strip()

      # 记录调用边（如果有符号）
      if callee_sym:
        edges[current_func].add(callee_sym)
        reverse_edges[callee_sym].add(current_func)

      base = norm_sym(callee_sym)
      if base in SINKS:
        sink_callsites.append({
          "sink": base,
          "callee": callee_sym,
          "callsite": "0x" + callsite_addr.lower(),
          "caller": current_func,
          "caller_addr": func_addrs.get(current_func, ""),
          "score": SINK_SCORE.get(base, 10)
        })

# 按危险度排序并截断
sink_callsites.sort(key=lambda x: (-x.get("score", 0), x.get("sink",""), x.get("caller","")))
sink_callsites = sink_callsites[:MAX_SINKS]

# entrypoints：优先 main/_start
entry = None
for cand in ("main", "_start"):
  if cand in func_addrs:
    entry = cand
    break
if entry is None and func_addrs:
  entry = next(iter(func_addrs.keys()))

entrypoints = []
if entry:
  entrypoints.append({"name": entry, "addr": func_addrs.get(entry,""), "reason": "preferred entrypoint"})

# BFS 寻路：entry -> caller-of-sink
def find_path(src, dst, max_depth):
  if not src or not dst:
    return None
  q = collections.deque([(src, [src])])
  seen = set([src])
  while q:
    node, path = q.popleft()
    if node == dst:
      return path
    if len(path) >= max_depth:
      continue
    for nxt in edges.get(node, []):
      # 这里 nxt 是符号名，若恰好是函数名（非 @plt），就能形成函数间路径
      if nxt not in seen:
        seen.add(nxt)
        q.append((nxt, path + [nxt]))
  return None

call_chains = []
for sc in sink_callsites:
  dst = sc["caller"]
  path = find_path(entry, dst, DEPTH)
  if path:
    call_chains.append({
      "from": entry,
      "to": dst,
      "path": [{"name": n, "addr": func_addrs.get(n,"")} for n in path]
    })
call_chains = call_chains[:3]

# callers_of_caller：best-effort（fallback 局限：只有直接 call <func> 的情况才可靠）
for sc in sink_callsites:
  caller = sc["caller"]
  # 如果别的函数直接 call <caller>，reverse_edges 会记录到
  callers = sorted(list(reverse_edges.get(caller, [])))[:20]
  sc["callers_of_caller"] = [{"name": c, "addr": func_addrs.get(c,"")} for c in callers]

# suspects
suspects = []
for sc in sink_callsites:
  suspects.append({
    "where": {"function": sc["caller"], "addr": sc.get("caller_addr",""), "callsite": sc.get("callsite","")},
    "sink": sc["sink"],
    "reason": f"calls {sc['sink']} at {sc.get('callsite','')}",
    "callers_of_caller": sc.get("callers_of_caller", [])
  })

# hypotheses：去偏/去重/按危险度优先
hypotheses = []
used_callers = set()
used_types = set()

def htype_from_sink(s):
  if s in ("gets","strcpy","strcat","sprintf","vsprintf"):
    return "stack_overflow"
  if s in ("printf","fprintf","dprintf","vprintf","vfprintf","snprintf","vsnprintf"):
    return "fmt"
  if s in ("free","malloc","calloc","realloc"):
    return "heap_related"
  if s in ("system","execve","execv","execvp","execl","execlp","execle","popen"):
    return "code_execution_sink"
  return "unknown"

hid = 1
for sc in sink_callsites:
  if len(hypotheses) >= 3:
    break

  caller = sc["caller"]
  if caller in used_callers:
    continue

  sname = sc["sink"]
  t = htype_from_sink(sname)

  # 类型多样化（可选）：第 3 条尽量不重复 type
  if len(hypotheses) >= 2 and t in used_types:
    continue

  used_callers.add(caller)
  used_types.add(t)

  waddr = sc.get("caller_addr","")
  if t == "stack_overflow":
    what = ["Find controllable length input reaching this sink",
            "Confirm crash RIP/RSP behavior in GDB evidence stage"]
    test = "Try long cyclic input; see if crash occurs near the sink caller"
  elif t == "fmt":
    what = ["Check if user input flows into format string position",
            "Look for %p/%n behavior in output"]
    test = "Input '%p %p %p' and observe output / crash"
  elif t == "heap_related":
    what = ["Check for UAF/double-free patterns around this call",
            "Confirm object lifetime mismatches in dynamic evidence"]
    test = "Exercise allocate/free paths twice; observe crashes or inconsistencies"
  elif t == "code_execution_sink":
    what = ["Check reachability of this sink from entry via IO",
            "Identify arguments/source data for system/exec*"]
    test = "Try to reach this call path; collect GDB evidence and observe callsite context"
  else:
    what = ["Confirm reachability from entry via IO",
            "Collect GDB evidence with minimal triggering input"]
    test = "Try minimal interaction to reach caller; then vary input length/content"

  hypotheses.append({
    "hypothesis_id": f"h_{hid:04d}",
    "where": {"function": caller, "addr": waddr},
    "type": t,
    "what_to_prove": what,
    "minimal_test": test
  })
  hid += 1

out = {
  "provider": "fallback_objdump",
  "entrypoints": entrypoints,
  "call_chains": call_chains,
  "sink_callsites": sink_callsites,
  "suspects": suspects,
  "hypotheses": hypotheses
}

with open(out_path, "w", encoding="utf-8") as f:
  json.dump(out, f, ensure_ascii=False, indent=2)
PY

  [[ -s "$SLICE_JSON" ]] || die "fallback slice failed to produce slice.json"
fi

# =====================
# 3) Write slice.md summary (short)
# =====================
python3 - "$SLICE_JSON" "$SLICE_MD" <<'PY'
import json,sys
j=json.load(open(sys.argv[1],'r',encoding='utf-8'))
md=sys.argv[2]

lines=[]
lines.append("# IDA Slice Report (L1)")
lines.append("")
lines.append(f"- provider: `{j.get('provider','')}`")
eps=j.get("entrypoints",[])
if eps:
  lines.append(f"- entrypoint: `{eps[0].get('name','')}` {eps[0].get('addr','')}")
lines.append("")
lines.append("## Call Chains (sample)")
chains=j.get("call_chains",[])
if not chains:
  lines.append("- (none found)")
else:
  for c in chains[:3]:
    path=" -> ".join([n.get("name","") for n in c.get("path",[])])
    lines.append(f"- {path}")
lines.append("")
lines.append("## Sink Callsites (top)")
scs=j.get("sink_callsites",[])
if not scs:
  lines.append("- (none)")
else:
  for sc in scs[:10]:
    lines.append(f"- `{sc.get('sink')}` in `{sc.get('caller')}` at {sc.get('callsite')}")
lines.append("")
lines.append("## Hypotheses (<=3)")
hs=j.get("hypotheses",[])
if not hs:
  lines.append("- (none)")
else:
  for h in hs:
    w=h.get("where",{})
    lines.append(f"- `{h.get('hypothesis_id')}` {h.get('type')} at `{w.get('function','')}` {w.get('addr','')}")
    for it in h.get("what_to_prove",[])[:3]:
      lines.append(f"  - prove: {it}")

open(md,"w",encoding="utf-8").write("\n".join(lines))
PY

# =====================
# 4) Update state safely via python
# =====================
export UPD_RUN_SEQ="$RUN_SEQ"
export UPD_RUN_ID="$RUN_ID"
export UPD_TS_ISO="$TS_ISO"
export UPD_SLICE_JSON="$SLICE_JSON"
export UPD_SLICE_MD="$SLICE_MD"
export UPD_RAW_LOG="$RAW_LOG"

python3 - "$STATE_FILE" "$SLICE_JSON" <<'PY'
import json, os, sys

state_path = sys.argv[1]
slice_path = sys.argv[2]

s=json.load(open(state_path,'r',encoding='utf-8'))
sl=json.load(open(slice_path,'r',encoding='utf-8'))

def ensure(d, k, default):
  if k not in d or d[k] is None:
    d[k]=default
  return d[k]

progress = ensure(s,"progress",{})
counters = ensure(progress,"counters",{})
artidx = ensure(s,"artifacts_index",{})
runs = ensure(artidx,"runs",[])
latest = ensure(artidx,"latest",{})
latest_paths = ensure(latest,"paths",{})
static = ensure(s,"static_analysis",{})
summary = ensure(s,"summary",{})

run_seq = int(os.environ.get("UPD_RUN_SEQ","0"))
run_id = os.environ.get("UPD_RUN_ID","")
ts = os.environ.get("UPD_TS_ISO","")

slice_json = os.environ.get("UPD_SLICE_JSON","")
slice_md   = os.environ.get("UPD_SLICE_MD","")
raw_log    = os.environ.get("UPD_RAW_LOG","")

# progress
progress["run_seq"] = run_seq
progress["stage"] = "ida_slice"
counters["ida_calls"] = int(counters.get("ida_calls",0) or 0) + 1
counters["total_runs"] = int(counters.get("total_runs",0) or 0) + 1
progress["last_updated_utc"] = ts

# artifacts index
latest["run_id"] = run_id
latest_paths["ida_slice_json"] = slice_json
latest_paths["ida_slice_md"] = slice_md
latest_paths["ida_raw_log"] = raw_log
runs.append({
  "run_id": run_id,
  "stage": "ida_slice",
  "created_utc": ts,
  "paths": {
    "ida_slice_json": slice_json,
    "ida_slice_md": slice_md,
    "ida_raw_log": raw_log
  }
})

# static_analysis（L1：用本次结果覆盖即可）
static["entrypoints"] = sl.get("entrypoints",[])
static["suspects"] = sl.get("suspects",[])
static["hypotheses"] = sl.get("hypotheses",[])

# next action
summary["next_actions"] = ["pwn-gdb-evidence"]

with open(state_path,'w',encoding='utf-8') as f:
  json.dump(s,f,ensure_ascii=False,indent=2)
PY

echo "[pwn-ida-slice] OK: wrote $SLICE_JSON and updated state."
