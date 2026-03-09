#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Dict, List, Optional


@dataclass
class StageRequest:
    session_id: str
    stage: str
    prompt: str
    timeout_sec: int
    workdir: str
    output_log: str
    allowed_tools: List[str] = field(default_factory=list)
    blocked_tools: List[str] = field(default_factory=list)
    max_tool_calls: int = 0
    env: Dict[str, str] = field(default_factory=dict)


@dataclass
class StageResult:
    ok: bool
    stage: str
    return_code: int
    output_log: str
    error: Optional[str] = None


class AdapterError(RuntimeError):
    pass


class MCPAdapter:
    name = "mcp_adapter"

    def run_stage(self, req: StageRequest) -> StageResult:
        raise NotImplementedError

    def build_prompt(self, context: Dict[str, str]) -> str:
        raise NotImplementedError
