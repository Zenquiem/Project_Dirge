# Skill: pwn-gdb-evidence (MCP-only)

## Purpose
L2 动态采证：
- signal / PC / SP
- backtrace 前几帧
- mappings 与 PIE base
- 固定栈窗口

仅允许 GDB MCP 路径，不使用本地 gdb 批处理脚本作为主流程。

## Inputs
来自 `state/state.json`：
- `challenge.binary_path`（必填）
- `protections.pie`（建议已知）

## Outputs
- `artifacts/gdb/<run_id>/raw.txt`
- `artifacts/gdb/<run_id>/summary.json`

## Required State Updates
- `progress.stage = "gdb_evidence"`
- `progress.run_seq += 1`
- `progress.counters.gdb_runs += 1`
- `progress.counters.total_runs += 1`
- `dynamic_evidence.inputs[]`
- `dynamic_evidence.evidence[]`
- `latest_bases.pie_base`（必填）
- `artifacts_index.latest.paths.gdb_raw`
- `artifacts_index.latest.paths.gdb_summary`

## PIE Rule
- PIE=true：`pie_base` 必须来自运行时映射
- PIE=false：`pie_base` 必须填固定基址（映射起始或 0x400000）
- `pie_base` 不允许为空

## Acceptance
- `artifacts/gdb/<run_id>/raw.txt` 存在
- `artifacts/gdb/<run_id>/summary.json` 存在
- `state.latest_bases.pie_base` 非空
