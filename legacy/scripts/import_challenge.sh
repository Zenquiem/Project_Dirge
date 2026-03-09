#!/usr/bin/env bash
set -euo pipefail

die(){ echo "[import_challenge] ERROR: $*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_FILE="$ROOT_DIR/state/state.json"
[[ -f "$STATE_FILE" ]] || die "missing state: $STATE_FILE"

[[ $# -ge 1 ]] || die "usage: scripts/import_challenge.sh <path_to_binary> [name]"
SRC="$1"
[[ -f "$SRC" ]] || die "binary not found: $SRC"
NAME="${2:-$(basename "$SRC")}"

DEST_DIR="$ROOT_DIR/challenge"
mkdir -p "$DEST_DIR"
DEST="$DEST_DIR/$NAME"
TMP="$DEST_DIR/.tmp_${NAME}_$$"

# 如果已有旧文件且只读，先尽量移除（删除取决于目录权限，不取决于文件只读位，但先 chmod 保险）
if [[ -e "$DEST" || -L "$DEST" ]]; then
  chmod u+w "$DEST" 2>/dev/null || true
  rm -f "$DEST" || die "failed to remove existing dest: $DEST (check permissions of $DEST_DIR)"
fi

# 先拷贝到临时文件，再原子替换
cp -f "$SRC" "$TMP"
mv -f "$TMP" "$DEST"

# 确保可执行（A），再设只读（但保留 x）
chmod a+rx "$DEST" || true
chmod a-w "$DEST" || true

# 计算 sha256/size
SHA256="$(python3 - "$DEST" <<'PY'
import hashlib,sys,os
p=sys.argv[1]
h=hashlib.sha256()
with open(p,'rb') as f:
  for ch in iter(lambda: f.read(1<<20), b''):
    h.update(ch)
print(h.hexdigest())
PY
)"
SIZE_BYTES="$(python3 - "$DEST" <<'PY'
import os,sys
print(os.path.getsize(sys.argv[1]))
PY
)"
IMPORTED_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# update state: binary_path/workdir + metadata（C）
python3 - "$STATE_FILE" "$DEST" "$SHA256" "$SIZE_BYTES" "$IMPORTED_UTC" <<'PY'
import json,sys,os
state_path,dest_path,sha,size,ts = sys.argv[1:6]

s = json.load(open(state_path,'r',encoding='utf-8')) if os.path.exists(state_path) else {}

def ensure(d,k,default):
  if k not in d or d[k] is None:
    d[k]=default
  return d[k]

repo_root = os.path.abspath(os.path.join(os.path.dirname(state_path), ".."))
rel = os.path.relpath(dest_path, repo_root)

ch = ensure(s,"challenge",{})
ch["binary_path"] = rel
ch["workdir"] = "."
ch["name"] = os.path.basename(rel)

meta = ensure(ch,"import_meta",{})
meta["sha256"] = sha
meta["size_bytes"] = int(size)
meta["imported_utc"] = ts

with open(state_path,'w',encoding='utf-8') as f:
  json.dump(s,f,ensure_ascii=False,indent=2)

print("updated state.challenge.binary_path =", ch["binary_path"])
print("updated state.challenge.import_meta.sha256 =", sha)
PY

echo "[import_challenge] copied -> $DEST (a+rx, a-w) and updated state."
