# Skill: pwn-ida-slice (MCP-only)

## Purpose
L1 静态切片（以输入链为中心）并输出可验证假设。

要求：
- 至少 1 条调用链：入口 -> 输入点 -> 可疑 sink
- 每个 sink callsite 给出：函数、地址、上游调用者/xrefs

## Inputs
来自 `state/state.json`：
- `challenge.binary_path`（必填）

仅允许 Ghidra MCP 路径（`pyghidra-mcp`）；不使用 `objdump` fallback。
说明：阶段名仍为 `ida_slice`，仅为兼容历史字段与脚本命名。

## Outputs
- `artifacts/ida/<run_id>/slice.json`
- `artifacts/ida/<run_id>/slice.md`
- `artifacts/ida/<run_id>/raw.log`

## Required State Updates
- `progress.stage = "ida_slice"`
- `progress.run_seq += 1`
- `progress.counters.ida_calls += 1`
- `progress.counters.total_runs += 1`
- `static_analysis.entrypoints[]`
- `static_analysis.suspects[]`
- `static_analysis.hypotheses[]`（<=3）
- `artifacts_index.latest.paths.ida_slice_json`
- `artifacts_index.latest.paths.ida_slice_md`
- `artifacts_index.latest.paths.ida_raw_log`
- `summary.next_actions = ["pwn-gdb-evidence"]`

## Acceptance
- `artifacts/ida/` 有本轮切片产物
- `suspects` 或 `hypotheses` 至少 1 条
