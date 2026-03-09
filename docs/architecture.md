# Project Dirge Architecture

## 当前结构

### 主编排入口
- `scripts/run_session.py`
  - 负责会话生命周期、阶段循环、状态落盘、策略拼装
  - 目标是逐步收敛成“orchestrator”，而不是继续承载大量工具函数

### 已抽离的辅助模块
- `core/text_utils.py`：文本压缩、flag 判断、session tag
- `core/path_utils.py`：路径匹配、整数解析
- `core/state_utils.py`：状态路径读取、stage runner spec 校验
- `core/stage_flow_utils.py`：stage level / terminal stage / counter progress
- `core/stage_prompt_builder.py`：各阶段 prompt 构造
- `core/stage_plan_utils.py`：bundle 阶段计划检测
- `core/decision_report_utils.py`：决策报告写盘
- `core/decision_config.py`：hint/route/blind/timeout 配置解析
- `core/session_plan_config.py`：stage order / unified / terminal stage 配置解析

### 循环与策略模块
- `scripts/session_loop_policy.py`
  - stop / gate / stage failure 等纯决策逻辑
- `scripts/session_strategy_route.py`
  - strategy route switch 逻辑
- `scripts/session_loop_finalize.py`
  - 每轮结束后的 decision state 落盘与 stop 判定

## 当前改造方向

1. 继续缩小 `run_session.py` 的职责面
2. 将“配置解析 / 纯决策 / 报告写盘 / prompt 构造”与 orchestrator 分离
3. 为后续修改停止条件、阶段编排和 agent 协作预留清晰边界

## 下一阶段建议

- 引入更明确的 orchestrator context/runtime state 对象
- 将 exploit rewrite / remote preflight / runtime guard 进一步模块化
- 对 loop finalize 的大参数面做结构化收敛（在现有测试护栏下进行）
