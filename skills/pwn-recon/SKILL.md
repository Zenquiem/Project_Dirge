# Skill: pwn-recon (MCP-only)

## Purpose
L0 基础侦察：
- protections（arch/bits/endian/nx/pie/relro/canary）
- IO 形态初判（menu/line/unknown）

本技能仅允许 MCP 路径，不使用本地 `checksec/readelf/objdump/gdb` 作为主流程。

## MCP Inputs
来自 `state/state.json`：
- `challenge.binary_path`（必填）
- `challenge.workdir`（可选）

建议 MCP 信息源：
- Ghidra MCP（pyghidra-mcp）：ELF 基本属性、入口函数与导入函数
- GDB MCP：运行时映射与基址补充（必要时）

## Outputs
- `artifacts/logs/recon_<run_id>.log`
- `artifacts/reports/recon_<run_id>.md`

## Required State Updates
- `progress.stage = "recon"`
- `progress.run_seq += 1`
- `progress.counters.recon_runs += 1`
- `progress.counters.total_runs += 1`
- `protections.*`
- `io_profile.*`
- `artifacts_index.latest.paths.recon_log`
- `artifacts_index.latest.paths.recon_report`
- `summary.next_actions = ["pwn-ida-slice"]`

## Acceptance
- `protections.arch` 非空
- `protections.pie` 已判定（true/false/null）
- recon 证据已落盘并登记索引
