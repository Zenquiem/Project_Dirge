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

快速跑全部单元测试：

```bash
python3 -m unittest discover -s tests -q
```

如果只想跑核心编排测试：

```bash
python3 -m unittest tests.test_session_orchestrators -q
```

## 开发依赖

```bash
python3 -m pip install -r requirements-dev.txt
```

可选检查：

```bash
python3 -m ruff check tests
python3 -m compileall core scripts tests
```

也可以直接用：

```bash
make dev-install
make check
```

仓库已附带 GitHub Actions CI：push / pull request 时会自动执行 `python -m ruff check tests` 与 `python -m unittest discover -s tests -q`。

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

## 工程结构补充

- 架构说明：`docs/architecture.md`

## 下一步建议（工程化）

1. 继续拆分 `scripts/run_session.py`（超大文件）为 orchestrator + runtime helpers。
2. 给 `policy/*.yaml` 增加配置说明文档（默认值、联动关系、风险说明）。
3. 增加更细的测试覆盖：尤其是 `run_session.py` 周边的配置归并、fail-open / rewrite / fuse 分支。
4. 视需要补充本地开发规范（例如 `make check`、提交前检查、最小 Python 环境约束）。
