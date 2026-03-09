#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from dataclasses import field
from typing import Dict, List

from .base import MCPAdapter, StageRequest, StageResult


@dataclass
class CodexCLIAdapter(MCPAdapter):
    codex_bin: str = "codex"
    retries: int = 0
    retry_on_nonzero: bool = False
    model: str = ""
    stage_model: Dict[str, str] = field(default_factory=dict)
    model_reasoning_effort: str = ""
    stage_model_reasoning_effort: Dict[str, str] = field(default_factory=dict)
    extra_args: List[str] = field(default_factory=lambda: ["--skip-git-repo-check", "--sandbox", "workspace-write"])

    name = "codex_cli"
    _TOOL_LINE_RE = re.compile(r"^\s*tool\s+([a-zA-Z0-9_.:-]+)\(", re.MULTILINE)

    def _effective_reasoning_effort(self, stage: str) -> str:
        raw = str(self.stage_model_reasoning_effort.get(stage, "")).strip()
        if not raw:
            raw = str(self.model_reasoning_effort).strip()
        if not raw:
            return ""
        low = raw.lower()
        if low in {"minimal", "low", "medium", "high", "xhigh"}:
            return low
        return ""

    def _effective_model(self, stage: str) -> str:
        raw = str(self.stage_model.get(stage, "")).strip()
        if not raw:
            raw = str(self.model).strip()
        return raw

    def _tail_text(self, path: str, max_bytes: int = 24000) -> str:
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                n = min(size, max(1024, int(max_bytes)))
                if n > 0:
                    f.seek(-n, os.SEEK_END)
                    buf = f.read(n)
                else:
                    buf = b""
            return buf.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _early_abort_signature(self, log_path: str) -> str:
        txt = self._tail_text(log_path, max_bytes=32000).lower()
        if not txt:
            return ""
        needles = [
            ("mcp startup: no servers", "mcp startup: no servers"),
            ("transport closed", "mcp transport closed"),
            ("handshaking", "mcp handshaking failed"),
            ("initialize response", "mcp initialize response failed"),
            ("mcp: pyghidra-mcp failed", "pyghidra startup failed"),
            ("mcp startup: ready: gdb; failed: pyghidra-mcp", "pyghidra startup failed"),
            ("failed to load configuration", "codex config load failed"),
            ("unable to lock project", "ghidra project lock"),
            ("lockexception", "ghidra project lock"),
        ]
        hits: List[str] = []
        for needle, tag in needles:
            if needle in txt:
                hits.append(tag)
        if not hits:
            return ""
        dedup: List[str] = []
        seen = set()
        for h in hits:
            if h in seen:
                continue
            seen.add(h)
            dedup.append(h)
        return "; ".join(dedup[:3])

    def _match_tool_pattern(self, tool: str, pattern: str) -> bool:
        p = str(pattern or "").strip()
        if not p:
            return False
        if p.endswith("*"):
            return tool.startswith(p[:-1])
        return tool == p

    def _tool_in_patterns(self, tool: str, patterns: List[str]) -> bool:
        for p in patterns:
            if self._match_tool_pattern(tool, p):
                return True
        return False

    def _scan_new_tool_calls(self, log_path: str, cursor: int) -> tuple[int, List[str]]:
        try:
            size = os.path.getsize(log_path)
        except Exception:
            return cursor, []
        if size < 0:
            return cursor, []
        if cursor < 0:
            cursor = 0
        if size < cursor:
            cursor = 0
        if size == cursor:
            return cursor, []
        try:
            with open(log_path, "rb") as f:
                f.seek(cursor, os.SEEK_SET)
                chunk = f.read(size - cursor)
            txt = chunk.decode("utf-8", errors="ignore")
            tools = [m.group(1).strip() for m in self._TOOL_LINE_RE.finditer(txt) if m.group(1).strip()]
            return size, tools
        except Exception:
            return size, []

    def run_stage(self, req: StageRequest) -> StageResult:
        os.makedirs(os.path.dirname(req.output_log), exist_ok=True)

        attempts = max(1, int(self.retries) + 1)
        last_rc = 0
        last_err = None

        for i in range(attempts):
            try:
                cmd = [self.codex_bin, "-a", "never", "exec", *self.extra_args]
                model = self._effective_model(req.stage)
                if model:
                    cmd.extend(["-m", model])
                effort = self._effective_reasoning_effort(req.stage)
                if effort:
                    cmd.extend(["-c", f'model_reasoning_effort="{effort}"'])
                cmd.append(req.prompt)
                with open(req.output_log, "a", encoding="utf-8") as log:
                    log.write(f"\n=== stage={req.stage} adapter={self.name} ===\n")
                    log.write(f"[adapter] attempt={i + 1}/{attempts} timeout={req.timeout_sec}s\n")
                    log.write(f"[adapter] cmd={' '.join(cmd[:-1])} <prompt>\n")
                    try:
                        # Only count tool calls generated by this attempt.
                        # The output log is append-only across retries.
                        log.flush()
                        log_cursor = os.path.getsize(req.output_log)
                    except Exception:
                        log_cursor = 0
                    p = subprocess.Popen(  # noqa: S603
                        cmd,
                        cwd=req.workdir,
                        env={
                            **os.environ,
                            **{
                                str(k): str(v)
                                for k, v in (req.env or {}).items()
                                if str(k).strip()
                            },
                        },
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    deadline = time.monotonic() + max(1, int(req.timeout_sec))
                    poll_gap = 0.4
                    early_abort_reason = ""
                    tool_calls = 0
                    allowed_tools = [str(x).strip() for x in req.allowed_tools if str(x).strip()]
                    blocked_tools = [str(x).strip() for x in req.blocked_tools if str(x).strip()]
                    max_tool_calls = max(0, int(req.max_tool_calls or 0))
                    while True:
                        rc = p.poll()
                        if rc is not None:
                            last_rc = int(rc)
                            break
                        log_cursor, new_tools = self._scan_new_tool_calls(req.output_log, log_cursor)
                        if new_tools:
                            for tool in new_tools:
                                tool_calls += 1
                                if blocked_tools and self._tool_in_patterns(tool, blocked_tools):
                                    early_abort_reason = f"blocked tool call: {tool}"
                                    break
                                if allowed_tools and (not self._tool_in_patterns(tool, allowed_tools)):
                                    early_abort_reason = f"disallowed tool call: {tool}"
                                    break
                                if max_tool_calls > 0 and tool_calls > max_tool_calls:
                                    early_abort_reason = f"tool call budget exceeded: {tool_calls}>{max_tool_calls}"
                                    break
                            if early_abort_reason:
                                log.write(f"[adapter] early-abort guard: {early_abort_reason}\n")
                                try:
                                    p.terminate()
                                    p.wait(timeout=1.5)
                                except Exception:
                                    try:
                                        p.kill()
                                    except Exception:
                                        pass
                                last_rc = 125
                                break
                        sig = self._early_abort_signature(req.output_log)
                        if sig:
                            early_abort_reason = sig
                            log.write(f"[adapter] early-abort signature: {sig}\n")
                            try:
                                p.terminate()
                                p.wait(timeout=1.5)
                            except Exception:
                                try:
                                    p.kill()
                                except Exception:
                                    pass
                            last_rc = 125
                            break
                        if time.monotonic() >= deadline:
                            early_abort_reason = ""
                            try:
                                p.terminate()
                                p.wait(timeout=1.5)
                            except Exception:
                                try:
                                    p.kill()
                                except Exception:
                                    pass
                            last_rc = 124
                            break
                        time.sleep(poll_gap)
                if last_rc == 125 and early_abort_reason:
                    last_err = f"early abort: {early_abort_reason}"
                    break
                if last_rc != 0:
                    tail_low = self._tail_text(req.output_log, max_bytes=32000).lower()
                    if (
                        last_rc == 1
                        and ("failed to shutdown rollout recorder" in tail_low)
                        and ("mcp startup: ready:" in tail_low)
                    ):
                        # 已知 Codex 客户端偶发尾阶段 recorder 错误，业务执行通常已完成。
                        # 这里放行为“软成功”，后续由 stage contract / state 校验决定是否通过。
                        with open(req.output_log, "a", encoding="utf-8") as log:
                            log.write("[adapter] tolerate rc=1 due to rollout-recorder shutdown error\n")
                        last_rc = 0
                if last_rc == 0:
                    return StageResult(
                        ok=True,
                        stage=req.stage,
                        return_code=last_rc,
                        output_log=req.output_log,
                    )
                last_err = f"codex return code={last_rc}"
                # External recovery loop controls retries; avoid hidden retries by default.
                if (not self.retry_on_nonzero) or (i >= attempts - 1):
                    break
            except FileNotFoundError:
                last_rc = 127
                last_err = f"codex command not found: {self.codex_bin}"
                break
            except subprocess.TimeoutExpired:
                last_rc = 124
                last_err = f"stage timeout ({req.timeout_sec}s)"
                # Timeout retry can double wall time; let outer recovery decide.
                break

        return StageResult(
            ok=False,
            stage=req.stage,
            return_code=last_rc,
            output_log=req.output_log,
            error=last_err,
        )
