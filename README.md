# Project Dirge

一个面向 CTF/Pwn 场景的会话编排框架：以 `state.json` 为核心状态，驱动 `recon -> ida_slice -> gdb_evidence -> exploit` 多阶段自动化流程。

> 当前仓库偏「工程内核 + 策略系统」，不是单一 exploit 脚本集合。

---

## 仓库结构（核心）

- `scripts/run_session.py`：主编排入口（会话循环、阶段调度、恢复与收敛）
- `core/`：状态/能力/策略等核心模块
- `policy/`：运行策略（阶段顺序、恢复、预算、health、autofix 等）
- `state/`：状态模板与 schema
- `scripts/`：各阶段执行与后处理脚本
- `tests/`：会话编排相关单元测试
- `benchmarks/`：回放与回归基线

---

## 快速开始

### 1) 克隆

```bash
git clone git@github.com:Zenquiem/Project_Dirge.git
cd Project_Dirge
```

### 2) 准备状态文件

默认入口读取：

- `state/state.json`
- `state/schema.json`
- `policy/agent.yaml`

可按模板初始化：

```bash
cp state/state.template.jsonc state/state.json
```

### 3) 运行会话

```bash
python3 scripts/run_session.py
```

常用参数：

```bash
python3 scripts/run_session.py --max-loops 2
python3 scripts/run_session.py --skip-validate --skip-verifier
python3 scripts/run_session.py --allow-codex-missing
```

---

## 测试

当前测试文件：`tests/test_session_orchestrators.py`

```bash
python3 -m unittest tests.test_session_orchestrators -q
```

---

## Benchmark / 回归

```bash
python3 scripts/replay_benchmarks.py
python3 scripts/replay_benchmarks.py --write-baseline benchmarks/baseline/latest.json
python3 scripts/replay_benchmarks.py --baseline benchmarks/baseline/latest.json --gate
```

---

## 安全与仓库卫生

已忽略（不要入库）：

- `.codex_runtime/`
- `.codex_runtime_link/`
- `*.core`

如果本地误追踪了运行时文件，请执行：

```bash
git rm -r --cached .codex_runtime .codex_runtime_link || true
git rm --cached *.core || true
```

---

## 下一步建议（工程化）

1. 拆分 `scripts/run_session.py`（超大文件）为 orchestrator + runtime helpers。
2. 增加 `requirements-dev.txt` 或 `pyproject.toml` 统一开发依赖。
3. 增加 CI：至少跑 `unittest` + 基础 lint。
4. 给 `policy/*.yaml` 增加配置说明文档（默认值与风险说明）。
