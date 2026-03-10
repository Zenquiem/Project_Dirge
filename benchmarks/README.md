# Benchmarks

该目录用于回放会话编排脚本的基准用例。

结构：
- `cases/*.json`：单题配置（题目目录、二进制、循环次数等）

Case 字段（常用）：
- `challenge_dir`：题目目录（必填）
- `binary`：题目二进制（可选）
- `max_loops`：传给 `run_session.py --max-loops`
- `allow_codex_missing`：是否允许 `run_session.py --allow-codex-missing`
- `ensure_binary_executable`：若为 `true`，benchmark 在启动前会为 case binary 补齐 owner execute bit；适合导入题目包时丢失执行位的 host-side / CI 场景
- `clear_cached_artifacts`：若为 `true`，benchmark 会在启动前清掉该 binary sha 对应的 stage/exploit cache，避免“靠旧缓存冒绿”
- `start_no_codex`：是否在 `start_session.sh` 阶段固定加 `--no-codex`；默认 `true`
- `start_session_args`：附加到 `start_session.sh` 的参数数组
- `run_session_args`：附加到 `run_session.py` 的参数数组
- `env`：执行 `start_session.sh` / `run_session.py` 时注入的环境变量对象（例如 `CODEX_BIN`、`CODEX_DEFAULT_MODEL`）
  - 对 no-Codex 本地 gdb benchmark，可用 `DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING=1` 搭配 `DIRGE_LOCAL_GDB_STDIN_TEXT` / `DIRGE_LOCAL_GDB_STDIN_HEX` / `DIRGE_LOCAL_GDB_STDIN_FILE` 显式描述触发崩溃的输入
- `expect`：可选结果断言。用于把“benchmark 成功”从单纯 `run_rc == 0` 提升为更接近真实 challenge / regression 的成功定义

`expect` 支持的字段：
- `run_rc`：要求 `replay_benchmarks.py` 内部执行 `run_session.py` 的进程返回码
- `final_exit_code`：要求 `run_session.py` 最终 JSON 输出里的 `exit_code`
- `acceptance_passed`：要求最终 acceptance 结果
- `min_objective_score`：要求 `metrics.objective_score_latest >= N`
- `required_success_stages`：这些 stage 必须至少有一次 `ok=true`
- `stage_sequence`：要求本轮 `stage_results[*].stage` 的实际执行顺序精确匹配；适合锁住可移植编排流，防止 case 因为多跑/乱序 stage 还“假绿”
- `forbid_stage_cache_hits`：这些 stage 本轮不允许 `stage_cache_hit=true`，用于要求 fresh execution 而不是复用旧缓存
- `metrics_min`：对 metrics.json 中的计数器做下限检查，例如 `{"exploit_success": 1}`
- `state_paths`：对最终 state.json 做点路径精确匹配，例如 `{"session.status": "finished"}`；支持简单数组索引，如 `{"dynamic_evidence.evidence[0].gdb.signal": "SIGSEGV"}`
- `report_paths`：对 `run_session.py` 最终 JSON 输出里的路径字段做存在性断言；值可为 `"file"` / `"dir"` / `"exists"`，例如 `{"report": "file", "stage_results[0].stage_receipt": "file"}`
- `report_path_contains`：对 `run_session.py` 输出里的路径字段做子串断言，适合要求产物路径明确属于当前 benchmark session；支持 `{{SESSION_ID}}` 占位符，例如 `{"report": "{{SESSION_ID}}"}`
- `report_json_paths`：先取 `run_session.py` 输出里的某个 JSON 文件路径，再对该 JSON 内部字段做点路径精确匹配；适合验证 stage receipt / acceptance report / summary report 的嵌入身份没有串线，例如 `{"stage_results[0].stage_receipt": {"session_id": "{{SESSION_ID}}", "stage": "recon"}}`
- `notes_contains`：要求最终 `run_session.py` 输出里的 `notes[]` 至少包含这些子串；适合锁定“到底走了哪条 runtime-adapter / recovery path”，避免 benchmark 绿了但其实已经悄悄退回别的实现面
- `notes_absent`：要求最终 `notes[]` 不得包含这些子串；适合明确禁止某些 OpenClaw 特化、旧 fallback、或你不想再看到的退化路径

说明：
- 默认仍走 `start_session.sh --no-codex` + `run_session.py`，适合当前开发/重构环境。
- 若要更贴近 host-side Codex CLI，可在 case 中显式设置 `env`、`run_session_args`，并按需关闭 `start_no_codex`。
- 对 smoke / regression case，推荐把 `clear_cached_artifacts=true` 与 `expect.forbid_stage_cache_hits` 一起用，避免缓存把真实回归掩盖掉。
- 如果 case 写了 `expect`，该 case 的 `ok` 将由断言结果决定，而不再只是看 `run_rc == 0`。
- 这让 benchmark case 自己描述运行面和结果面，减少对 OpenClaw 当前环境的硬编码依赖，也更适合后续真实题目回归。

执行：
- `python3 scripts/replay_benchmarks.py`
- 若当前环境无 `codex`，可加 `--allow-codex-missing` 做离线 smoke。
- 写入 baseline：`python3 scripts/replay_benchmarks.py --write-baseline benchmarks/baseline/latest.json`
- 回归门禁：`python3 scripts/replay_benchmarks.py --baseline benchmarks/baseline/latest.json --gate`

Gate 行为：
- 不只看总分板（success_rate / codex_errors / stage_retries），还会对 baseline 中记录过的每个 case 做逐项回归检查
- 如果 baseline 里的某个 case 在当前运行里缺失，或 baseline 原本为 `ok=true` 但当前退化为失败，gate 会直接失败
- `run_rc` 会按 case 逐项比较，避免“总分还能过，但某个真实 challenge-like case 已经悄悄坏掉”
- 新写入的 baseline 还会携带 `final_exit_code`、`acceptance_passed`、`success_stages`、`stage_sequence`；gate 会把这些也当作 case 级不变量，防止 benchmark 因为走了更弱/不同的成功路径、额外乱跑 stage 或编排顺序漂移而“冒绿”
- baseline 还会记录每个 case 的“执行合同”哈希（来自 challenge/runtime knobs/env/expect 等规范化字段）；如果有人通过偷偷改弱 case 配置或 expectation 来换取假绿，`--gate` 会直接把这种 benchmark-contract 漂移报出来
