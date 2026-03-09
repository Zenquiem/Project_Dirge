#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class SessionMetrics:
    session_id: str
    created_utc: str = field(default_factory=utc_now)
    updated_utc: str = field(default_factory=utc_now)
    stage_attempts: Dict[str, int] = field(default_factory=dict)
    stage_success: Dict[str, int] = field(default_factory=dict)
    stage_failures: Dict[str, int] = field(default_factory=dict)
    codex_errors: int = 0
    verifier_failures: int = 0
    validate_state_failures: int = 0
    codex_calls: int = 0
    prompt_chars_total: int = 0
    stage_wall_total_sec: float = 0.0
    stage_wall_sec: Dict[str, float] = field(default_factory=dict)
    wall_time_sec: float = 0.0
    runs_total: int = 0
    loops_total: int = 0
    evidence_added: int = 0
    mutations_generated: int = 0
    crash_clusters: int = 0
    hypotheses_added: int = 0
    no_progress_loops: int = 0
    stage_retries: int = 0
    recoverable_failures: int = 0
    stop_requests: int = 0
    timeout_circuit_activations: int = 0
    timeout_circuit_skips: int = 0
    capability_updates: int = 0
    objective_score_latest: int = 0
    objective_target_hits: int = 0
    exploit_attempts: int = 0
    exploit_success: int = 0
    remote_connect_attempts: int = 0
    self_stop_blocked: int = 0
    autofix_rounds_total: int = 0
    notes: List[str] = field(default_factory=list)

    @classmethod
    def load_or_new(cls, path: str, session_id: str) -> "SessionMetrics":
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return cls.from_dict(data)
            except Exception:
                pass
        return cls(session_id=session_id)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionMetrics":
        raw_stage_wall_sec = data.get("stage_wall_sec", {})
        if not isinstance(raw_stage_wall_sec, dict):
            raw_stage_wall_sec = {}
        return cls(
            session_id=str(data.get("session_id", "")),
            created_utc=str(data.get("created_utc", utc_now())),
            updated_utc=str(data.get("updated_utc", utc_now())),
            stage_attempts=dict(data.get("stage_attempts", {})),
            stage_success=dict(data.get("stage_success", {})),
            stage_failures=dict(data.get("stage_failures", {})),
            codex_errors=int(data.get("codex_errors", 0)),
            verifier_failures=int(data.get("verifier_failures", 0)),
            validate_state_failures=int(data.get("validate_state_failures", 0)),
            codex_calls=int(data.get("codex_calls", 0)),
            prompt_chars_total=int(data.get("prompt_chars_total", 0)),
            stage_wall_total_sec=float(data.get("stage_wall_total_sec", 0.0) or 0.0),
            stage_wall_sec={str(k): float(v) for k, v in raw_stage_wall_sec.items()},
            wall_time_sec=float(data.get("wall_time_sec", 0.0) or 0.0),
            runs_total=int(data.get("runs_total", 0)),
            loops_total=int(data.get("loops_total", 0)),
            evidence_added=int(data.get("evidence_added", 0)),
            mutations_generated=int(data.get("mutations_generated", 0)),
            crash_clusters=int(data.get("crash_clusters", 0)),
            hypotheses_added=int(data.get("hypotheses_added", 0)),
            no_progress_loops=int(data.get("no_progress_loops", 0)),
            stage_retries=int(data.get("stage_retries", 0)),
            recoverable_failures=int(data.get("recoverable_failures", 0)),
            stop_requests=int(data.get("stop_requests", 0)),
            timeout_circuit_activations=int(data.get("timeout_circuit_activations", 0)),
            timeout_circuit_skips=int(data.get("timeout_circuit_skips", 0)),
            capability_updates=int(data.get("capability_updates", 0)),
            objective_score_latest=int(data.get("objective_score_latest", 0)),
            objective_target_hits=int(data.get("objective_target_hits", 0)),
            exploit_attempts=int(data.get("exploit_attempts", 0)),
            exploit_success=int(data.get("exploit_success", 0)),
            remote_connect_attempts=int(data.get("remote_connect_attempts", 0)),
            self_stop_blocked=int(data.get("self_stop_blocked", 0)),
            autofix_rounds_total=int(data.get("autofix_rounds_total", 0)),
            notes=list(data.get("notes", [])),
        )

    def to_dict(self) -> Dict[str, Any]:
        avg_stage_sec = 0.0
        if self.runs_total > 0:
            avg_stage_sec = float(self.stage_wall_total_sec) / float(self.runs_total)
        return {
            "session_id": self.session_id,
            "created_utc": self.created_utc,
            "updated_utc": self.updated_utc,
            "stage_attempts": self.stage_attempts,
            "stage_success": self.stage_success,
            "stage_failures": self.stage_failures,
            "codex_errors": self.codex_errors,
            "verifier_failures": self.verifier_failures,
            "validate_state_failures": self.validate_state_failures,
            "codex_calls": self.codex_calls,
            "prompt_chars_total": self.prompt_chars_total,
            "stage_wall_total_sec": self.stage_wall_total_sec,
            "stage_wall_sec": self.stage_wall_sec,
            "avg_stage_sec": avg_stage_sec,
            "wall_time_sec": self.wall_time_sec,
            "runs_total": self.runs_total,
            "loops_total": self.loops_total,
            "evidence_added": self.evidence_added,
            "mutations_generated": self.mutations_generated,
            "crash_clusters": self.crash_clusters,
            "hypotheses_added": self.hypotheses_added,
            "no_progress_loops": self.no_progress_loops,
            "stage_retries": self.stage_retries,
            "recoverable_failures": self.recoverable_failures,
            "stop_requests": self.stop_requests,
            "timeout_circuit_activations": self.timeout_circuit_activations,
            "timeout_circuit_skips": self.timeout_circuit_skips,
            "capability_updates": self.capability_updates,
            "objective_score_latest": self.objective_score_latest,
            "objective_target_hits": self.objective_target_hits,
            "exploit_attempts": self.exploit_attempts,
            "exploit_success": self.exploit_success,
            "remote_connect_attempts": self.remote_connect_attempts,
            "self_stop_blocked": self.self_stop_blocked,
            "autofix_rounds_total": self.autofix_rounds_total,
            "notes": self.notes,
        }

    def bump_stage_attempt(self, stage: str) -> None:
        self.stage_attempts[stage] = int(self.stage_attempts.get(stage, 0)) + 1
        self.runs_total += 1
        self.updated_utc = utc_now()

    def bump_stage_success(self, stage: str) -> None:
        self.stage_success[stage] = int(self.stage_success.get(stage, 0)) + 1
        self.updated_utc = utc_now()

    def bump_stage_failure(self, stage: str) -> None:
        self.stage_failures[stage] = int(self.stage_failures.get(stage, 0)) + 1
        self.updated_utc = utc_now()

    def record_stage_wall(self, stage: str, sec: float) -> None:
        v = max(0.0, float(sec))
        self.stage_wall_total_sec += v
        self.stage_wall_sec[stage] = float(self.stage_wall_sec.get(stage, 0.0) or 0.0) + v
        self.updated_utc = utc_now()

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.updated_utc = utc_now()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)


def write_global_kpi(path: str, all_metrics: List[SessionMetrics]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    sessions = [m.to_dict() for m in all_metrics]
    summary = {
        "sessions": len(sessions),
        "runs_total": sum(s.get("runs_total", 0) for s in sessions),
        "codex_errors": sum(s.get("codex_errors", 0) for s in sessions),
        "verifier_failures": sum(s.get("verifier_failures", 0) for s in sessions),
        "validate_state_failures": sum(s.get("validate_state_failures", 0) for s in sessions),
        "codex_calls": sum(s.get("codex_calls", 0) for s in sessions),
        "prompt_chars_total": sum(s.get("prompt_chars_total", 0) for s in sessions),
        "stage_wall_total_sec": round(sum(float(s.get("stage_wall_total_sec", 0.0) or 0.0) for s in sessions), 3),
        "wall_time_sec": round(sum(float(s.get("wall_time_sec", 0.0) or 0.0) for s in sessions), 3),
        "mutations_generated": sum(s.get("mutations_generated", 0) for s in sessions),
        "crash_clusters": sum(s.get("crash_clusters", 0) for s in sessions),
        "no_progress_loops": sum(s.get("no_progress_loops", 0) for s in sessions),
        "stage_retries": sum(s.get("stage_retries", 0) for s in sessions),
        "recoverable_failures": sum(s.get("recoverable_failures", 0) for s in sessions),
        "stop_requests": sum(s.get("stop_requests", 0) for s in sessions),
        "timeout_circuit_activations": sum(s.get("timeout_circuit_activations", 0) for s in sessions),
        "timeout_circuit_skips": sum(s.get("timeout_circuit_skips", 0) for s in sessions),
        "capability_updates": sum(s.get("capability_updates", 0) for s in sessions),
        "objective_target_hits": sum(s.get("objective_target_hits", 0) for s in sessions),
        "exploit_attempts": sum(s.get("exploit_attempts", 0) for s in sessions),
        "exploit_success": sum(s.get("exploit_success", 0) for s in sessions),
        "remote_connect_attempts": sum(s.get("remote_connect_attempts", 0) for s in sessions),
        "self_stop_blocked": sum(s.get("self_stop_blocked", 0) for s in sessions),
        "autofix_rounds_total": sum(s.get("autofix_rounds_total", 0) for s in sessions),
    }
    runs_total = int(summary.get("runs_total", 0) or 0)
    stage_wall_total_sec = float(summary.get("stage_wall_total_sec", 0.0) or 0.0)
    summary["avg_stage_sec"] = round(stage_wall_total_sec / runs_total, 4) if runs_total > 0 else 0.0
    out = {
        "updated_utc": utc_now(),
        "summary": summary,
        "sessions": sessions,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
