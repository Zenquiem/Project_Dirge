# PWN Agent (MCP-First) Guide

本仓库目标：
- 基于 Codex + MCP（Ghidra MCP / GDB MCP）完成 L0 -> L2 证据闭环
- 所有结论可追溯到 `artifacts/` 与 `state/state.json`
- 在证据充分时，支持 L3/L4 exploit 自动推进（本地优先写入/更新 `exp`，可显式参数化远程目标）

---

## Hard Rules (必须遵守)

1. 纯 MCP 主流程
- L0/L1/L2 仅允许 MCP 取证路径。
- 禁止把本地 `checksec/readelf/objdump/gdb` 当主流程。
- 禁止使用容器 pipeline 作为解题主路径（旧方案在 `legacy/`）。

2. 证据优先
- 静态结论引用 `artifacts/ida/...`
- 动态结论引用 `artifacts/gdb/...`
- 不允许无证据推断

3. 结构化落盘
- 每轮更新 `state/state.json`
- 原始输出写入 `artifacts/`
- 在 `state.artifacts_index` 登记路径

4. PIE Bridge 必须可用
- 每条动态证据必须有 `mappings.pie_base`
- 同步更新 `state.latest_bases.pie_base`

5. 预算与熔断
- 遵循 `policy/budget.yaml`
- 发生死循环/输出爆炸时熔断并记录原因

6. 安全边界
- 只在仓库内读写
- 联网能力由策略控制（见 `policy/budget.yaml::safety.allow_network`），默认按当前策略执行

7. L3 边界
- 默认先生成/更新本地 `exp` 文件；可按策略开启远程参数化模板
- 是否执行真实远程利用由调用方显式控制，不在自动主循环里隐式放开。

8. 自动推进默认行为
- 当 `project.features.enable_exploit=true` 时，自动入口（`session_api solve` / `run_session.py` / `start_session.sh` 默认提示）应一次性推进到 terminal exploit stage（当前为 `exploit_l4`）。
- 不应在 L2 停止并等待用户额外回复“继续”，除非触发 stopping condition（预算/无进展/MCP 不可用/schema 失败）。

---

## Directory Contract

- `state/state.json`：状态机与索引
- `state/schema.json`：状态结构约束
- `artifacts/inputs/`：输入样本
- `artifacts/logs/`：通用日志
- `artifacts/ida/`：静态切片证据
- `artifacts/gdb/`：动态证据（raw + summary）
- `artifacts/reports/`：阶段报告/KPI
- `policy/budget.yaml`：预算/熔断策略
- `policy/agent.yaml`：自动化行为开关（含 `enable_exploit`）
- `policy/stage_contracts.yaml`：阶段字段契约（每阶段必填/约束）
- `policy/stage_runner.yaml`：阶段执行规范（MCP tools / artifact keys / prompt contract）
- `skills/*`：阶段技能说明（MCP-only）
- `sessions/*`：会话元数据与对话日志（供 UI 展示）
  - `sessions/<id>/control/run.lock`：会话运行锁（防并发重复运行）
  - `sessions/<id>/control/stop.requested.json`：停止请求信号（供 UI/CLI 停止）
- `scripts/reset_state.sh`：一键重置状态与 artifacts
- `scripts/start_session.sh`：创建会话、写入 challenge、生成 exp stub、可选启动 codex
- `scripts/run_session.py`：自动编排 L0 -> L2 -> (可选) L3/L4（`enable_exploit=true` 时默认推进到 terminal exploit stage）
- `scripts/session_api.py`：统一会话 API（start/list/get/overview/inspect/health/run/cleanup/repair-state/reset/stop）
- `scripts/session_api.py timeline <id>`：阶段时间线（供 UI 展示）
- `scripts/session_api.py artifacts <id>`：会话最新产物索引（供 UI 展示）
- `scripts/check_stage_contracts.py`：按阶段契约校验当前 state
- `scripts/validate_state.py`：按 `state/schema.json` 校验
- `scripts/verifier.py`：证据规则/预算/MCP-only 合规校验
- `scripts/health_check_mcp.py`：MCP 健康检查（codex + mcp server 列表）
- `scripts/verify_local_exp.py`：L3 本地 exp 校验（语法/可选执行）并写报告
- `scripts/list_sessions.sh`：列出现有会话（JSON）
- `scripts/get_session.sh`：读取单个会话元数据（JSON）
- `scripts/list_sessions.sh --rich`：UI 友好的增强会话列表（含 metrics brief）
- `scripts/get_session.sh <id> --rich`：UI 友好的增强会话详情（含 recent transactions）
- `scripts/replay_benchmarks.py`：回放基准用例
- `scripts/cleanup_artifacts.py`：按 keep-last 策略清理 artifacts（支持 dry-run）
- `scripts/repair_state.py`：修复 `state/state.json` 结构污染并落盘报告
- `legacy/*`：历史脚本（非主路径）

---

## Workflow (L0 -> L2 -> L3/L4)

### Stage 0: Init
目标：确定题目路径并初始化状态。

必填：
- `state.progress.stage = "init"`
- `state.challenge.binary_path`
- `state.challenge.workdir`

### Stage 1: Recon (`skills/pwn-recon`)
目标：收集 protections 与 IO 轮廓。

必更字段：
- `state.protections.*`
- `state.io_profile.*`
- `state.progress.counters.recon_runs += 1`
- `state.progress.stage = "recon"`
- `state.summary.next_actions`

### Stage 2: Static Slice (`skills/pwn-ida-slice`, Ghidra MCP)
目标：围绕输入链输出函数关系、sink callsite、调用链、可验证假设。

必更字段：
- `state.static_analysis.entrypoints[]`
- `state.static_analysis.suspects[]`
- `state.static_analysis.hypotheses[]`（<=3）
- `state.progress.counters.ida_calls += 1`
- `state.progress.stage = "ida_slice"`

### Stage 3: GDB Evidence (`skills/pwn-gdb-evidence`)
目标：采集寄存器/回溯/映射/栈窗口并抽取 `pie_base`。

必更字段：
- `state.dynamic_evidence.inputs[]`
- `state.dynamic_evidence.evidence[]`
- `state.latest_bases.pie_base`
- `state.progress.counters.gdb_runs += 1`
- `state.progress.stage = "gdb_evidence"`
- `state.dynamic_evidence.clusters[]`

### Stage 4: Exploit L3/L4（自动模式默认推进到 terminal exploit stage）
目标：在已有证据基础上生成/更新本地优先的 `exp` 脚本（可预留远程参数）。

必更字段：
- `state.session.exp.path`
- `state.session.exp.status`（`enabled`/`stub_generated`/`updated`/`disabled_by_user`）
- `state.session.exp.local_verify_passed`
- `state.progress.counters.exploit_runs += 1`
- `state.progress.stage = "exploit_l3"`

---

## Stopping Condition

满足任一条件应停止自动推进并写报告到 `artifacts/reports/`。
例外：当 terminal exploit rewrite 已开始且尚未拿到 shell/flag 时，`hint gate`、`timeout/no-evidence gate`、连续无进展这类软门不应直接停机，只写报告并继续推进；仅硬故障/硬预算条件允许中断：
- 达到预算上限
- 连续无进展（仅限非 terminal exploit rewrite 阶段）
- 环境不稳定/证据不可复现
- MCP 不可用
- state schema 校验失败

---

## Output Style

- 输出短、可审计、证据驱动
- 结论必须引用 evidence_id 或 artifact 路径
- 大日志写文件，不在对话中贴大段原文
- 若启用 L3，报告里必须给出 `exp` 路径与生成状态
- 自动编排每阶段会写入 `sessions/<id>/transactions/` 的 before/after 快照与 meta
- 自动编排每轮会写入 `artifacts/reports/decision_<session>_<loop>.json`（阶段计划与策略说明）
- 自动编排每轮会写入 `artifacts/reports/objective_<session>_<loop>.json`（目标完成度与缺口）
- 自动编排每阶段会写入 `artifacts/reports/stage_receipt_<session>_<loop>_<stage>.json`（执行回执）
- 自动编排每轮会写入 `artifacts/reports/capabilities_<session>_<loop>.json`（能力推断）
- L3 自动写 exp 会生成 `artifacts/reports/exp_plan_<session>.json`（策略、能力快照、脚本路径）
- L3 自动校验 exp 会生成 `artifacts/reports/exp_verify_<session>_<loop>.json`（校验结果）
- 运行前可选 MCP 健康检查，写 `artifacts/reports/health_mcp_<session>.json`
- 自动编排支持恢复策略：可恢复错误（如 timeout / MCP 瞬时异常）按 `policy/agent.yaml::automation.recovery` 重试
