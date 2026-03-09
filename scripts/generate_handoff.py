#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATE_PATH = os.path.join(ROOT_DIR, "state", "state.json")
SESSIONS_DIR = os.path.join(ROOT_DIR, "sessions")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json_or(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _repo_rel(path: str) -> str:
    ap = os.path.abspath(path)
    try:
        if os.path.commonpath([ROOT_DIR, ap]) == ROOT_DIR:
            return os.path.relpath(ap, ROOT_DIR)
    except Exception:
        pass
    return ap


def _iter_session_ids() -> List[str]:
    out: List[str] = []
    if not os.path.isdir(SESSIONS_DIR):
        return out
    for name in os.listdir(SESSIONS_DIR):
        sid = str(name).strip()
        if not sid.startswith("sess_"):
            continue
        if os.path.isdir(os.path.join(SESSIONS_DIR, sid)):
            out.append(sid)
    return sorted(out)


def _parse_utc_ts(raw: str) -> float:
    s = str(raw or "").strip()
    if not s:
        return 0.0
    try:
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return 0.0


def _latest_session_id(state: Dict[str, Any]) -> str:
    cur_sid = str((state.get("session", {}) or {}).get("session_id", "")).strip()
    if cur_sid and os.path.isfile(os.path.join(SESSIONS_DIR, cur_sid, "meta.json")):
        return cur_sid
    best_sid = ""
    best_ts = -1.0
    for sid in _iter_session_ids():
        meta = _read_json_or(os.path.join(SESSIONS_DIR, sid, "meta.json"), {})
        ts = _parse_utc_ts(str(meta.get("created_utc", "")).strip())
        if ts <= 0:
            try:
                ts = os.path.getmtime(os.path.join(SESSIONS_DIR, sid))
            except Exception:
                ts = 0.0
        if ts > best_ts:
            best_ts = ts
            best_sid = sid
    return best_sid


def _collect_stage_rows(metrics: Dict[str, Any]) -> List[Tuple[str, float, float]]:
    stage_wall = metrics.get("stage_wall_sec", {}) if isinstance(metrics.get("stage_wall_sec", {}), dict) else {}
    rows: List[Tuple[str, float, float]] = []
    total = float(metrics.get("stage_wall_total_sec", 0.0) or 0.0)
    for k, v in stage_wall.items():
        name = str(k).strip()
        if not name:
            continue
        sec = float(v or 0.0)
        pct = (sec / total * 100.0) if total > 0 else 0.0
        rows.append((name, sec, pct))
    rows.sort(key=lambda x: x[1], reverse=True)
    return rows


def _collect_latest_artifacts(
    sid: str,
    state: Dict[str, Any],
    meta: Dict[str, Any],
) -> Dict[str, str]:
    out: Dict[str, str] = {}
    state_sid = str((state.get("session", {}) or {}).get("session_id", "")).strip()
    if sid and sid == state_sid:
        latest = ((state.get("artifacts_index", {}) or {}).get("latest", {}) or {}).get("paths", {})
        if isinstance(latest, dict):
            for k, v in latest.items():
                ks = str(k).strip()
                vs = str(v).strip()
                if ks and vs:
                    out[ks] = vs
    meta_latest = meta.get("latest_artifacts", {}) if isinstance(meta.get("latest_artifacts", {}), dict) else {}
    if isinstance(meta_latest, dict):
        for k, v in meta_latest.items():
            ks = str(k).strip()
            vs = str(v).strip()
            if ks and vs:
                out.setdefault(ks, vs)
    return out


def _fallback_reports_for_sid(sid: str) -> List[str]:
    if not sid:
        return []
    patt = os.path.join(ROOT_DIR, "artifacts", "reports", f"*{sid}*")
    paths = sorted(glob.glob(patt))
    return [_repo_rel(p) for p in paths[-12:]]


def _render_markdown(
    *,
    sid: str,
    meta: Dict[str, Any],
    state: Dict[str, Any],
    metrics: Dict[str, Any],
    artifacts: Dict[str, str],
    fallback_reports: List[str],
) -> str:
    challenge = meta.get("challenge", {}) if isinstance(meta.get("challenge", {}), dict) else {}
    remote = meta.get("remote", {}) if isinstance(meta.get("remote", {}), dict) else {}
    exp = meta.get("exp", {}) if isinstance(meta.get("exp", {}), dict) else {}
    objective = meta.get("objective", {}) if isinstance(meta.get("objective", {}), dict) else {}
    stage_rows = _collect_stage_rows(metrics)
    stage_total = float(metrics.get("stage_wall_total_sec", 0.0) or 0.0)
    target = remote.get("target", {}) if isinstance(remote.get("target", {}), dict) else {}
    host = str(target.get("host", "")).strip()
    port = int(target.get("port", 0) or 0)
    blind_mode = bool(challenge.get("blind_mode", False))
    stage_attempts = metrics.get("stage_attempts", {}) if isinstance(metrics.get("stage_attempts", {}), dict) else {}
    stage_failures = metrics.get("stage_failures", {}) if isinstance(metrics.get("stage_failures", {}), dict) else {}

    lines: List[str] = []
    lines.append(f"# Next Session Handoff - {sid}")
    lines.append("")
    lines.append(f"- Generated UTC: {utc_now()}")
    lines.append(f"- Session ID: `{sid}`")
    lines.append(f"- Status: `{meta.get('status', '-')}`")
    lines.append(f"- Created UTC: `{meta.get('created_utc', '-')}`")
    lines.append(f"- Challenge Name: `{challenge.get('name', '-')}`")
    lines.append(f"- Challenge Dir: `{challenge.get('work_dir', '-')}`")
    lines.append(f"- Binary Path: `{challenge.get('binary_path', '') or '<empty>'}`")
    lines.append(f"- Blind Mode: `{blind_mode}`")
    lines.append(f"- Remote Target: `{host}:{port}`" if host and port > 0 else "- Remote Target: `<unset>`")
    lines.append(f"- EXP Status: `{exp.get('status', '-')}`")
    lines.append(f"- Objective Achieved: `{objective.get('competition_target_achieved', False)}`")
    lines.append("")

    lines.append("## Stage Metrics")
    lines.append("")
    lines.append(f"- loops_total: `{int(metrics.get('loops_total', 0) or 0)}`")
    lines.append(f"- codex_calls/codex_errors: `{int(metrics.get('codex_calls', 0) or 0)}/{int(metrics.get('codex_errors', 0) or 0)}`")
    lines.append(f"- stage_wall_total_sec: `{stage_total:.2f}`")
    if stage_rows:
        lines.append("")
        lines.append("| Stage | Sec | % | attempts | failures |")
        lines.append("|---|---:|---:|---:|---:|")
        for st, sec, pct in stage_rows:
            a = int(stage_attempts.get(st, 0) or 0)
            f = int(stage_failures.get(st, 0) or 0)
            lines.append(f"| {st} | {sec:.2f} | {pct:.1f}% | {a} | {f} |")
    lines.append("")

    lines.append("## Key Artifacts")
    lines.append("")
    if artifacts:
        for k in sorted(artifacts.keys()):
            lines.append(f"- `{k}`: `{artifacts[k]}`")
    else:
        lines.append("- `<none>`")
    if fallback_reports:
        lines.append("")
        lines.append("### Recent Reports (fallback)")
        for p in fallback_reports:
            lines.append(f"- `{p}`")
    lines.append("")

    lines.append("## New Session Bootstrap Commands")
    lines.append("")
    lines.append("```bash")
    lines.append("cd /mnt/Project_Dirge")
    lines.append("python3 scripts/session_api.py overview --limit 10")
    lines.append(f"python3 scripts/session_api.py inspect {sid} --tail 30")
    lines.append(f"python3 scripts/session_api.py timeline {sid} --limit 50")
    lines.append("```")
    lines.append("")

    lines.append("## Prompt Template (paste into next Codex session)")
    lines.append("")
    lines.append("```text")
    lines.append("继续维护 Project_Dirge + DirgeUI。")
    lines.append("项目根：/mnt/Project_Dirge")
    lines.append("UI根：/home/zenduk/桌面/DirgeUI")
    lines.append("")
    lines.append("先只做理解，不改代码：")
    lines.append(f"1) 阅读 artifacts/reports/next_session_handoff_{sid}.md")
    lines.append("2) 阅读 /home/zenduk/桌面/DirgeUI/PROJECT_OVERVIEW_CN.md")
    lines.append("3) 阅读 /mnt/Project_Dirge/policy/agent.yaml")
    lines.append("4) 阅读 /mnt/Project_Dirge/scripts/run_session.py 和 start_session.sh")
    lines.append("5) 输出：架构摘要 + 当前瓶颈Top3 + 本轮改动计划（按收益排序）")
    lines.append("```")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a compact handoff markdown for next Codex session")
    ap.add_argument("--session-id", default="", help="session id; default auto-select current/latest")
    ap.add_argument(
        "--output",
        default="",
        help="output markdown path (absolute or repo-relative); default artifacts/reports/next_session_handoff_<sid>.md",
    )
    args = ap.parse_args()

    state = _read_json_or(STATE_PATH, {})
    if not isinstance(state, dict):
        state = {}
    sid = str(args.session_id or "").strip() or _latest_session_id(state)
    if not sid:
        print(json.dumps({"ok": False, "error": "no session found"}, ensure_ascii=False, indent=2))
        return 2
    meta_path = os.path.join(SESSIONS_DIR, sid, "meta.json")
    meta = _read_json_or(meta_path, {})
    if not isinstance(meta, dict):
        meta = {}
    metrics_path = os.path.join(SESSIONS_DIR, sid, "metrics.json")
    metrics = _read_json_or(metrics_path, {})
    if not isinstance(metrics, dict):
        metrics = {}

    artifacts = _collect_latest_artifacts(sid, state, meta)
    fallback_reports = _fallback_reports_for_sid(sid)
    md = _render_markdown(
        sid=sid,
        meta=meta,
        state=state,
        metrics=metrics,
        artifacts=artifacts,
        fallback_reports=fallback_reports,
    )

    out_path = str(args.output or "").strip()
    if not out_path:
        out_path = os.path.join(ROOT_DIR, "artifacts", "reports", f"next_session_handoff_{sid}.md")
    elif not os.path.isabs(out_path):
        out_path = os.path.abspath(os.path.join(ROOT_DIR, out_path))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)

    print(
        json.dumps(
            {
                "ok": True,
                "session_id": sid,
                "output": _repo_rel(out_path),
                "metrics_path": _repo_rel(metrics_path) if os.path.isfile(metrics_path) else "",
                "meta_path": _repo_rel(meta_path) if os.path.isfile(meta_path) else "",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

