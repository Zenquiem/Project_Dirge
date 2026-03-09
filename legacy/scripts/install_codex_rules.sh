#!/usr/bin/env bash
set -euo pipefail

die(){ echo "[install_codex_rules] ERROR: $*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_RULES="$ROOT_DIR/rules/default.rules"
[[ -f "$SRC_RULES" ]] || die "missing source rules: $SRC_RULES"

CODEX_DIR="${CODEX_DIR:-$HOME/.codex}"
DEST_DIR="$CODEX_DIR/rules"
DEST_RULES="$DEST_DIR/default.rules"

MODE="link"   # link | copy
FORCE=0
DRY=0

usage(){
  cat <<EOF
Usage:
  scripts/install_codex_rules.sh [--link|--copy] [--force] [--dry-run]

Defaults:
  --link   (symlink ~/.codex/rules/default.rules -> <repo>/rules/default.rules)

Env:
  CODEX_DIR=~/.codex
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --link) MODE="link"; shift ;;
    --copy) MODE="copy"; shift ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

# D: CODEX_DIR sanity
if [[ -e "$CODEX_DIR" && ! -d "$CODEX_DIR" ]]; then
  die "CODEX_DIR exists but is not a directory: $CODEX_DIR"
fi

if [[ "$DRY" -eq 1 ]]; then
  echo "[dry-run] mkdir -p '$DEST_DIR'"
else
  mkdir -p "$DEST_DIR"
fi

# If already linked to same file, no-op (unless force)
if [[ "$MODE" == "link" && -L "$DEST_RULES" ]]; then
  CUR="$(readlink "$DEST_RULES" || true)"
  if [[ -n "$CUR" ]]; then
    # normalize relative link
    CUR_ABS="$(python3 - <<PY
import os
print(os.path.abspath(os.path.join(os.path.dirname("$DEST_RULES"), "$CUR")))
PY
)"
    SRC_ABS="$(python3 - <<PY
import os
print(os.path.abspath("$SRC_RULES"))
PY
)"
    if [[ "$CUR_ABS" == "$SRC_ABS" && "$FORCE" -ne 1 ]]; then
      echo "[install_codex_rules] already installed (same symlink): $DEST_RULES -> $CUR"
      exit 0
    fi
  fi
fi

backup_if_needed(){
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    local ts
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    local bak="${path}.bak.${ts}"
    if [[ "$FORCE" -ne 1 ]]; then
      die "destination exists: $path (use --force; would backup to $bak)"
    fi
    if [[ "$DRY" -eq 1 ]]; then
      echo "[dry-run] mv '$path' '$bak'"
    else
      mv "$path" "$bak"
      echo "[install_codex_rules] backed up: $path -> $bak"
    fi
  fi
}

backup_if_needed "$DEST_RULES"

if [[ "$MODE" == "link" ]]; then
  if [[ "$DRY" -eq 1 ]]; then
    echo "[dry-run] ln -s '$SRC_RULES' '$DEST_RULES'"
  else
    ln -s "$SRC_RULES" "$DEST_RULES"
  fi
  echo "[install_codex_rules] installed (symlink): $DEST_RULES -> $SRC_RULES"
elif [[ "$MODE" == "copy" ]]; then
  TMP="$DEST_DIR/.tmp_default.rules.$$"
  if [[ "$DRY" -eq 1 ]]; then
    echo "[dry-run] cp '$SRC_RULES' '$TMP' && mv '$TMP' '$DEST_RULES'"
  else
    cp "$SRC_RULES" "$TMP"
    mv "$TMP" "$DEST_RULES"
  fi
  echo "[install_codex_rules] installed (copy): $DEST_RULES"
else
  die "invalid MODE: $MODE"
fi

echo "[install_codex_rules] done."
