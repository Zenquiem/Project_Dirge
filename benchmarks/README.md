# Benchmarks

该目录用于回放会话编排脚本的基准用例。

结构：
- `cases/*.json`：单题配置（题目目录、二进制、循环次数等）

执行：
- `python3 scripts/replay_benchmarks.py`
- 若当前环境无 `codex`，可加 `--allow-codex-missing` 做离线 smoke。
- 写入 baseline：`python3 scripts/replay_benchmarks.py --write-baseline benchmarks/baseline/latest.json`
- 回归门禁：`python3 scripts/replay_benchmarks.py --baseline benchmarks/baseline/latest.json --gate`
