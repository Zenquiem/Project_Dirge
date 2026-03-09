# Sessions

该目录保存 UI 发起的解题会话元数据与会话日志。

约定：
- 每次会话落盘到 `sessions/<session_id>/`
- 核心文件：
  - `meta.json`：会话元数据（题目位置、对话日志路径、exp 路径与状态）
  - `conversation.log`：Codex 会话输出日志
  - `prompt.txt`：本次启动 prompt
  - `state.initial.json`：会话启动时状态快照
  - `exp/exp.py`：默认生成的本地 exp stub
  - `transactions/*.before.json|after.json|meta.json`：阶段事务快照与结果
  - `control/run.lock`：会话运行锁
  - `control/stop.requested.json`：停止请求标记（由 `session_api.py stop` 写入）

说明：
- 主流程仍是 MCP-only 取证（L0/L1/L2）。
- 默认启用 exp 写入，占位脚本会在会话创建时生成。
- exp 模板为本地优先，支持通过环境变量 `PWN_REMOTE_HOST/PWN_REMOTE_PORT` 显式切换远程目标。
- `meta.json` 与 `state.session.exp` 会同步记录 exp 状态。
- 自动编排会在 `artifacts/inputs/` 生成 mutation corpus，并在 `artifacts/reports/` 生成每轮 decision 报告。
- 自动编排会在 `artifacts/reports/` 生成每轮 objective 报告（目标完成度与缺口）。
- 自动编排会在 `artifacts/reports/` 生成阶段回执（stage_receipt）与能力推断报告（capabilities）。
- L3 自动写本地 exp 时会生成 `artifacts/reports/exp_plan_<session>.json`（策略与证据快照）。
- L3 自动校验本地 exp 时会生成 `artifacts/reports/exp_verify_<session>_<loop>.json`（语法/执行校验结果）。

常用脚本：
- `scripts/start_session.sh --challenge-dir <dir> [--no-codex] [--no-exp]`
- `scripts/list_sessions.sh`
- `scripts/get_session.sh <session_id>`
- `scripts/list_sessions.sh --rich [--limit N]`
- `scripts/get_session.sh <session_id> --rich`
- `scripts/run_session.py --session-id <id>`
- `scripts/session_api.py timeline <session_id> [--limit N]`
- `scripts/session_api.py artifacts <session_id>`
- `scripts/session_api.py <start|list|get|overview|inspect|timeline|artifacts|health|run|cleanup|repair-state|reset|stop> ...`

停止机制：
- `scripts/session_api.py stop <session_id>` 会先写入 stop 请求，再尝试终止本地 codex 进程。
- `scripts/run_session.py` 会在每轮/每阶段开始前检查 stop 请求并优雅结束，会话状态写为 `stopped`。
