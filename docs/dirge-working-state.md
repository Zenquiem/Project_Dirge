# Dirge Working State

This file is a short handoff/state snapshot for recurring isolated iteration runs.
Keep it brief, current, and action-biased.

## Current Mission
Maintain Project_Dirge as a dual-entry pwn framework that can run through both:
- OpenClaw
- host-side Codex CLI

Do not hard-bind the project to only one of those entry paths.
Prefer a shared capability core with thinner runtime-specific adapters.

Clarification guardrail:
- Codex CLI is a supported execution path, not a required auth gate for core project progress.
- Missing Codex auth must not block replay, benchmark, local fallback, direct gdb probe, or OpenClaw-driven execution.

## Current High-Priority Themes
1. Preserve and improve real pwn solve capability on challenge-like workflows.
2. Keep benchmark/replay contracts portable across host machines and non-root `cwd` launches.
3. Continue reducing drift between:
   - local gdb fallback
   - direct gdb probe
   - wrapper/runtime adapter behavior
4. Keep OpenClaw and Codex CLI both viable as execution paths.

## 当前迭代原则（中文约束）
1. 底盘类修复可以继续做，但前提是它们确实提升以下至少一项：
   - benchmark / replay 真实性
   - 真实 challenge 运行一致性
   - solve 结果或证据质量
2. 如果某个 portability / runtime / env / wrapper 问题不会明显影响以上目标，则不要长期把它排在最高优先级。
3. 后续迭代应逐步把重点从“持续底盘修补”转向“solve 能力提升”和“challenge 结果改进”。
4. 每轮重要迭代都应尽量回答一件事：这次改动对解题能力、成功率、失败类型减少、或人工接管需求下降有什么实际帮助。
5. 不要为了追求表面整洁而制造高 churn；当当前 gate 与关键验证切片为绿色时，应优先等待下一个真实复现的 seam，再决定是否继续改底盘。
6. 定时迭代在通过关键 gate 或形成清晰阶段成果后，应及时整理为小粒度本地 commit，避免大量改动长期堆积在工作区。
7. 未经用户明确授权，不要自动 push 到 GitHub 远端仓库；默认只做本地 commit，由用户决定何时统一 push。
8. 定时迭代应将“通过关键 gate 或形成清晰阶段成果后进行本地 commit”视为默认执行动作，而不是可做可不做的附加步骤。

## Current Environment Facts
- `pyghidra-mcp` installed at: `/home/ubuntu/.local/bin/pyghidra-mcp`
- `gdb-mcp` installed at: `/home/ubuntu/.local/bin/gdb-mcp`
- Repo launcher `scripts/gdb_mcp_launcher.py` now preserves real user-site imports for Codex/OpenClaw runtime-isolated launches, so host-style `codex_with_mcp.sh exec` no longer loses `gdb-mcp` during MCP initialize just because wrapper `HOME` points at the isolated Ghidra runtime home.
- Ghidra exists at: `/home/ubuntu/tools/ghidra/ghidra_12.0.4_PUBLIC`
- Repo launcher `scripts/pyghidra_mcp_launcher.py` now preserves real user-site imports even when runtime isolation overrides `HOME`, so the old `ModuleNotFoundError: pyghidra_mcp` false failure is gone.
- Repo-local `.ghidra-current` on this host now points at `/home/ubuntu/tools/ghidra/ghidra_12.0.4_PUBLIC` instead of the stale bundled 11.4 tree.
- Host Java has now been remediated to OpenJDK 21 at `/usr/lib/jvm/java-21-openjdk-amd64`; the earlier Ghidra-12/JDK-17 blocker is gone on this machine.
- Wrapper/health-check Java handling is now more portable: both `scripts/codex_with_mcp.sh` and `scripts/health_check_mcp.py` auto-discover usable Java homes from env, repo-local `.tools/{java,jdk}`, common user-local install roots, and standard system locations, then forward `JAVA_HOME`/`JDK_HOME` into pyghidra runtime/probes when available.
- Pyghidra runtime env normalization is now more transferable across direct config, bridge, and health-probe launches: relative `HOME` / `XDG_*` / `GHIDRA_INSTALL_DIR` style config values are repo-anchored before backend launch, avoiding false failures like `XDG_CACHE_HOME is not an absolute path`.
- Health-probe / MCP-bridge env normalization is now better aligned with replay/runtime contracts for repo-relative `CODEX_{HOME,RUNTIME_HOME}`, `GHIDRA_{MCP_BIN,RUNTIME_ROOT,SESSION_ROOT,MCP_HOME,MCP_XDG_*}`, launcher-script, extra-site, Java-home, `PYTHON_BIN`, and `MCP_JSONLINE_BRIDGE` overrides, reducing another place where direct functional probes could drift from benchmarked wrapper behavior.
- Replay, health-check, and MCP-bridge normalization now also carry the wrapper's `GHIDRA_MCP_XDG_DATA_HOME` contract, so repo-relative pyghidra data-home isolation stays aligned across benchmark summaries, functional probes, and real wrapper launches instead of only being correct on `codex_with_mcp.sh`.
- Health-check / MCP-bridge normalization now also treats `PATH` and `PYGHIDRA_MCP_PYTHONPATH` as path-list contracts rather than opaque strings, so helper-launch/import-path behavior stays closer to replay under non-root `cwd` and portable repo-relative env setups.
- Replay contract/env normalization now also treats wrapper-style `HOME` / `XDG_CONFIG_HOME` / `XDG_CACHE_HOME` / `XDG_DATA_HOME` overrides as path-like values, so repo-local runtime-home isolation remains benchmark-honest across checkout roots and non-root `cwd` runs.
- Repo wrapper `scripts/codex_with_mcp.sh` now carries that same `XDG_DATA_HOME` runtime-isolation contract into real launches: it derives a repo-portable pyghidra data-home under the isolated runtime home, repo-anchors relative overrides, creates the directory, exports it, and forwards it into the pyghidra MCP env block instead of leaving data-home handling to ambient host defaults.
- Replay now also normalizes `PYTHONPATH` / `PYGHIDRA_MCP_PYTHONPATH`-style path lists, closing another import-path seam where non-root `cwd` runs could otherwise look benchmark-green while real launcher injection paths had drifted.
- Replay, health-check, and MCP-bridge env normalization now also treat `LD_LIBRARY_PATH` as a repo-relative path-list contract, reducing another loader/libc portability seam for host-style challenge runs that rely on custom library search roots.
- That same shared env-normalization layer now also carries exploit runtime bundle vars `PWN_LOADER`, `PWN_LIBC_PATH`, and `PWN_LD_LIBRARY_PATH`, so replay, health probes, and bridge-backed launches stay aligned with `run_session.py` on repo-relative loader/libc contracts.
- Standalone MCP health checks now respect server `startup_timeout_sec` during functional probing, so real pyghidra cold start on this host no longer false-fails at the old 12s probe ceiling.
- `codex` is now installed on PATH at: `/home/ubuntu/.npm-global/bin/codex` (`@openai/codex`, verified `codex --version`)
- Repo wrapper `scripts/codex_with_mcp.sh` now auto-discovers a valid Ghidra install from repo-local/system candidates when stale defaults like `/opt/ghidra/current` are wrong, and it now prefers repo-local `.ghidra-current` before the stale bundled `.tools/ghidra` tree, so live wrapper-backed Codex/OpenClaw MCP startup no longer regresses onto Ghidra 11.4 on this host.
- Health-check parsing now treats Codex's `No MCP servers configured yet...` banner as an empty registry instead of a fake server named `No`.
- `scripts/health_check_mcp.py` now repo-anchors `--config`, functional-probe `cwd` / `GHIDRA_MCP_PROJECT_PATH`, falls back to `tomli` on Python 3.10, treats stale machine-private `gdb` launcher config as recoverable when portable `gdb-mcp` exists on PATH, rejects pyghidra bridge-style launcher configs whose repo-relative `./scripts/mcp_jsonline_bridge.py` path has drifted, has a real stdio gdb functional probe (`initialize` + `tools/list`), and now defaults standalone `authority=project_config` checks to functional probing unless `--no-functional-probe` is passed.
- On this host, launcher discovery for `pyghidra-mcp` is no longer trustworthy as a health signal by itself: the current PATH launcher fails functional probe with `ModuleNotFoundError: No module named 'pyghidra_mcp'`.
- Repo wrapper `scripts/codex_with_mcp.sh` is executable again (`100755`) and now auto-discovers portable `gdb-mcp` on PATH when no explicit `DIRGE_GDB_MCP_CMD` / legacy checkout is present; that PATH-discovered path now also defaults `mcp_servers.gdb.cwd` to repo root instead of an empty string, so real `codex_with_mcp.sh exec` no longer dies at MCP spawn time with ENOENT on this host.
- `scripts/run_session.py` now repo-anchors path-style `codex.bin` values before adapter execution, closing another non-root-`cwd` launcher seam between config validation and real Codex invocation.
- `scripts/gdb_direct_probe.py` now repo-anchors `--state` before loading state, can launch a PATH-discovered `gdb-mcp` without requiring a fake non-empty cwd, adapts at runtime between legacy `gdb_start` / `gdb_terminate` and modern `start_binary` / `stop_session` MCP tool surfaces, and its remaining legacy fallback now derives from `$HOME` instead of hard-coding one user's home directory.
- Direct `gdb_direct_probe` discovery is now less shell-fragile on this host: when PATH lookup misses, it also falls back to executable user-local installs like `~/.local/bin/gdb-mcp`, so stripped/non-login cron-style environments no longer falsely report gdb-mcp as unavailable.
- On this host, the installed `/home/ubuntu/.local/bin/gdb-mcp` (`1.26.0`) exposes `start_binary`, `gdb_command`, and `stop_session`; a real direct probe now succeeds against that live PATH binary instead of failing on the older `gdb_start` assumption.
- `scripts/run_session.py` now prevents fast-profile missing-Codex runs from silently overriding `DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING=1` with opportunistic direct GDB probe; host-like non-root-`cwd` local-fallback benchmarks are green again while explicit `--no-fast` direct-probe benchmarks stay on the real probe path.
- Codex runtime home handling is now less temp-dir-fragile: wrapper default `CODEX_RUNTIME_HOME` is repo-local under `artifacts/codex/runtime-home/<session>`, and `scripts/codex_with_mcp.sh` now always exports `CODEX_HOME` there even when no source auth/config files were copied, avoiding real direct-wrapper drift into temporary Ghidra `HOME/.codex` state on this host.
- Direct `scripts/run_session.py` session isolation is now closer to the wrapper contract too: `configure_session_mcp_env()` now exports per-session `XDG_CONFIG_HOME` / `XDG_CACHE_HOME` / `XDG_DATA_HOME`, keeps the explicit `GHIDRA_MCP_XDG_*` vars aligned to those same directories, aligns `CODEX_HOME` to `CODEX_RUNTIME_HOME`, and repo-anchors pre-set relative `GHIDRA_RUNTIME_ROOT` / `CODEX_RUNTIME_HOME` overrides so non-root-`cwd` direct launches do not drift onto caller-relative runtime dirs.
- When needed, ensure `~/.local/bin` and `~/.npm-global/bin` are on PATH for runtime checks.

## Current Working Assumptions
- Isolated cron runs should rely on repository/log state, not conversational memory.
- `docs/dirge-iteration-log.md` is the primary rolling narrative log.
- Important failures and blocked conditions should be written to the iteration log, not only successes.
- Before editing high-churn files, re-read latest contents from disk.

## Likely Next Valuable Directions
- Keep auditing the remaining direct host/runtime seams where replay may still be masking cwd/path/env drift after the recent `start_session.sh`, wrapper, and `run_session.py` entrypoint fixes.
- Continue making dependency/runtime remediation explicit, logged, and transferable.
- Improve OpenClaw/Codex dual-entry compatibility without forking the core solve logic.
- Prefer benchmark-visible fixes over hidden/internal polish.

## Immediate Watch Items
- Codex CLI availability/pathing for any flow that still assumes `codex` exists.
- `run_session.py` now has direct startup-path regression coverage proving session-level `codex_enabled=false` suppresses MCP hard-preflight / self-heal / health bootstrap even when the machine-level Codex runtime exists, and missing-Codex fallback notes now distinguish intentional session-level Codex disablement from an actually missing/broken Codex binary; later-stage gates should still be replayed to catch any deeper regressions against that session runtime contract.
- The checked-in `.codex/config.toml` now keeps repo-local/PATH-oriented MCP defaults (`./scripts/mcp_jsonline_bridge.py`, `./scripts/pyghidra_mcp_launcher.py`, `./scripts/gdb_mcp_launcher.py`, `./.ghidra-current`) instead of stale `/mnt/Project_Dirge` and `/home/zenduk/...` machine-private entries; keep that contract clean and avoid reintroducing host-private paths.
- Targeted replay debugging is now less noisy: `replay_benchmarks.py --gate --only <substring>` filters baseline case-comparison down to the selected case set instead of reporting unrelated missing baseline cases, and current unit coverage for that baseline-slice behavior is green.
- Recent isolated-run edit failures were concentrated in high-churn test files; stable edit-anchor comments were added in `tests/test_codex_with_mcp.py` and `tests/test_replay_benchmarks.py` to make future focused patches less brittle.
- Any remaining places where replay succeeds only because the harness normalizes something that the real direct entrypoints still mishandle.
- Watch for any remaining real Codex CLI behaviors that still implicitly key off `HOME` instead of the wrapper-exported `CODEX_HOME`; later-stage spot-checking already found and fixed one direct `exec` seam (empty PATH-`gdb-mcp` cwd causing ENOENT), and bare health-check gdb stdio probe is now green against the live PATH server.
- Pyghidra import-path, Java-version, and wrapper Ghidra-selection blockers are now cleared on this host; real `codex_with_mcp.sh exec` startup reaches MCP-ready state, and the wrapper now preflights obvious missing-auth cases locally (`exit 2`) instead of burning time on repeated Codex-side `401` reconnect churn.
- Shared Codex adapter still fast-aborts on unmistakable auth failures (`401` / missing bearer / invalid API key), and the direct wrapper path now has a matching missing-auth preflight contract when no `auth.json` / OpenAI auth env is present; keep future Codex-backed session loops aligned with that fail-fast behavior.
- Keep replaying the direct-probe path against the real installed `gdb-mcp`, not only the fake shim, so future direct-entry changes do not regress the now-working `tools/list`-driven compatibility path.
- Live PATH `gdb-mcp` output on this host is JSON-wrapped (`{"output": ...}`) for `gdb_command` responses; `scripts/gdb_direct_probe.py` now normalizes that wrapper before parsing mappings/registers/stack, and the checked-in real-path benchmark `demo_direct_gdb_path_nonpie` is now part of the replay baseline.
- Replay cases can now declare `required_commands`; use that instead of ad-hoc notes when adding real-path benchmarks that depend on host-installed tools such as `gdb-mcp` or local `gdb`, so dependency gaps show up as explicit skips rather than noisy runtime failures. The local-gdb replay cases now explicitly declare `required_commands: ["gdb"]`, and `summarize_case_contract()` omits empty `required_commands` from the hashed contract so default-empty schema growth does not create false full-suite baseline drift.
- `replay_benchmarks.py` required-command preflight now resolves cwd-relative PATH entries against the case's real `cwd` before calling `shutil.which()`, closing a skip-only portability seam where host-like cases could run successfully yet still be preflight-marked as missing because PATH contained `./bin`-style entries.
- Command-style launcher normalization now correctly skips interpreter flags that consume following values (for example `python3 -W ignore -X dev script.py`, `python3 --check-hash-based-pycs always script.py`, or `bash -O extglob script.sh`) before repo-anchoring the real script path, and explicit `./` / `../` command-script components in replay env launchers now preserve caller-`cwd` semantics instead of being silently rewritten to repo-root paths; keep future launcher portability work aligned with that richer host-side contract.
- `scripts/health_check_mcp.py` and `scripts/mcp_jsonline_bridge.py` now also normalize `DIRGE_GDB_MCP_CMD` correctly for `env -S "python3 ... ./script.py"` and interpreter-flag forms, closing another replay-vs-real-entry drift window around repo-relative launcher commands.
- `scripts/start_session.sh` now accepts `--flag=value` spellings for its path/value-bearing CLI options (`--challenge-dir`, `--binary`, `--session-id`, `--name`, `--prompt`, `--prompt-file`), and direct challenge-dir resolution now also prefers caller `cwd` before repo root for dotted/host-style launches such as `--challenge-dir=.` from inside `challenge/...`; keep other direct entrypoints aligned with the same mixed CLI contract.
- Full replay baseline was refreshed again on 2026-03-12 to include `demo_direct_gdb_file_nonpie_cwd_dotfile`; the latest full `--gate` run passed green with 24 total cases / 23 executed / 1 skipped, and direct-probe cwd-relative seeded-file replay (`DIRGE_GDB_DIRECT_STDIN_FILE=./...` from challenge cwd) is now baseline-enforced instead of only spot-checked.
- Shared JSON state I/O is now more concurrency-tolerant in `scripts/run_session.py` and `scripts/gdb_direct_probe.py`: state saves use temp-file + `os.replace`, and loads retry brief transient decode failures. This was prompted by a real parallel-run `JSONDecodeError: Extra data` race on `state/state.json`; serial replay remained green after the hardening.
- `scripts/run_session.py` JSON loads now also retry transient empty-file windows instead of only partial/extra-data decode failures. This was prompted by a real host-like direct-gdb replay failure (`demo_direct_gdb_file_nonpie_cwd`) where stage-spec validation briefly read an empty `state/state.json`; the targeted replay slice is green again after the hardening.
- Replay expectation evaluation now prefers session-scoped transaction snapshots over shared `state/state.json`, but still uses the shared state when its `session.session_id` matches the current benchmark case so finalized fields like `session.status=finished` are preserved. This closes a real baseline-regression seam where serial replay could falsely fail by reading another case's shared state or by asserting against a pre-finalize transaction snapshot.
- `scripts/replay_benchmarks.py` JSON loads now also retry brief transient decode/empty-file windows instead of failing open to `{}` immediately. This was prompted by a real replay-only false regression where the direct-gdb seeded-file cwd case had valid transaction snapshots on disk but expectation evaluation briefly read them mid-write and asserted against empty state; targeted replay gate is green again after the hardening.
- Replay expectations now support `{{SESSION_ID}}` expansion inside `expect.state_paths`, so state assertions can lock embedded session identity directly instead of only checking filenames/report payloads.
- Fresh targeted replay no longer shows the previous local no-Codex gdb evidence drift: `demo_local_offset`, `demo_local_nonpie_sendline`, `demo_local_nocontrol`, and `demo_local_gdb_stale_nocontrol` are green again after capability inference stopped trusting stale top-level RIP-control state over fresh gdb evidence.
- Full replay baseline was refreshed again on 2026-03-12 after verifying the only remaining gate delta was stale baseline data for `demo_local_file_nonpie_cwd_dotfile` (`run_rc/final_exit_code` old `1` -> current `0`); `python3 scripts/replay_benchmarks.py --allow-codex-missing --gate` is green again.
- `python3 -m unittest discover -s tests -q` is not a green baseline right now: current failures are concentrated in older Codex wrapper / health-check / start-session drift (`tests.test_codex_with_mcp`, `tests.test_health_check_mcp`, `tests.test_codex_cli_adapter`, `tests.test_start_session`) rather than the repaired local-gdb replay seam.
- `tests.test_gdb_direct_probe` is green again after re-aligning `scripts/gdb_direct_probe.py` with the shared ABI/stack/stdin helpers plus modern `gdb-mcp` tool-surface compatibility (`gdb_start`/`gdb_terminate` and `start_binary`/`stop_session`).
- Fresh single-case replay `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_direct_gdb_nonpie` is currently still red because `run_session.py --allow-codex-missing --no-fast` stops after `recon` instead of reaching `gdb_evidence`; treat that as the next benchmark-facing seam instead of more unit-only adapter polishing.

## Update Rule
When priorities materially change, update this file in a small, direct way.
Do not let it turn into a long historical log; history belongs in `docs/dirge-iteration-log.md`.
