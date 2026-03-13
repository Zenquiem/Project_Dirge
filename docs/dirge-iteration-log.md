# Project Dirge Iteration Log

This file tracks ongoing autonomous iteration work on Project_Dirge.

## 2026-03-13 10:06 CST — Iteration summary refreshed, old detailed log cleared

### Current overall status

Project_Dirge iteration is active and making real progress.
The project has moved out of the earlier "stabilize the replay/runtime plumbing" phase and into a more solve-facing phase, while keeping the benchmark gate green.

### Confirmed current progress

- Full unit slice is green in the latest recorded run (`233 tests` passing).
- Full replay benchmark gate is green again under `--allow-codex-missing`.
- The expanded no-Codex benchmark matrix is currently stable and baseline-aligned.
- `bench_ret2win` is now green across the three important missing-Codex paths:
  - local gdb fallback: `recon -> gdb_evidence -> exploit_l3`
  - direct gdb probe: `recon -> gdb_evidence -> exploit_l3`
  - real PATH `gdb-mcp` direct path: `recon -> gdb_evidence -> exploit_l3`

### What improved across the recent iteration window

1. Replay / benchmark gating became trustworthy again
- baseline drift was cleaned up
- stronger contracts are now enforced instead of older weaker expectations
- direct-gdb and local-gdb benchmark paths were re-aligned with current runtime behavior

2. Local-gdb and direct-gdb evidence behavior was brought closer together
- cyclic offset recovery logic was unified into shared helpers
- capability inference is more consistent across adapters
- direct-probe and local fallback now expose a more similar artifact/capability surface

3. Ret2win solve capability improved materially
- local exploit verify now survives more realistic success patterns
- ret2win replay is benchmarked end-to-end
- shared capability state now carries useful offset hints such as:
  - `fault_offset_candidate=65`
  - `static_offset_candidate=72`
- exploit generation can consume those shared hints without depending only on adapter-local `state.gdb`

4. Host portability continued improving
- replay/runtime path normalization was tightened
- mixed CLI flag forms (`--flag value` and `--flag=value`) were normalized more consistently
- machine-private path assumptions were reduced in wrapper/runtime handling

### Current best understanding of project phase

The project is no longer mainly blocked on broad replay/gate instability.
Those foundations are in a much better place now.
Current priority should stay on solve capability and challenge-facing evidence quality, not on more generic cleanup unless a real seam reappears.

### Current next seam

A new missing-Codex / missing-gdb route has been opened in planning:
- when Codex is missing,
- and no usable local gdb or direct-gdb path exists,
- and local exploit is allowed,
- the planner can now degrade to `recon -> exploit_l3`

However, a real stripped-PATH validation run showed the next unresolved seam:
- runtime did not actually enter the missing-Codex planner path
- instead it kept the full stage plan and treated the configured Codex runner as unavailable
- so the new route is unit-tested, but not yet fully validated in a real no-gdb/no-codex runtime simulation

### Recommended next focus

- Make the true no-gdb/no-codex classification path benchmarkable
- Ensure real runtime routing matches the new planner behavior
- Continue spending iteration budget on solve/evidence improvements rather than baseline bookkeeping, unless a fresh regression appears

## 2026-03-13 10:14 CST — Fixed one host-style no-Codex planner classification seam

### What changed

- Tightened `scripts/run_session.py::choose_missing_codex_stage_order()` so `challenge.binary_path` is no longer treated as repo-root-relative only when deciding whether local recon / local exploit fallback is possible.
- Added `_resolve_state_relative_path()` and taught the missing-Codex planner to resolve relative binary paths against:
  - repo root,
  - the state file directory,
  - and challenge-relative directories such as `challenge.workdir` / `work_dir` / `source_dir`.

### Why it mattered

A real stripped-PATH validation had shown an adapter seam where the runtime could log:
- `configured codex runner unavailable: scripts/codex_with_mcp.sh`
- `codex 缺失，但保持完整 stage plan（失败后继续由策略层处理）`

instead of entering the intended portable missing-Codex planner path.
One plausible cause was that the planner failed to recognize a valid local binary when the state used host-style relative paths outside the repo-root assumption.

### Verification

- `python3 -m pytest tests/test_run_session_missing_codex.py -q` → `32 passed`
- Added regression coverage for a temp state outside the repo with:
  - `challenge.binary_path = "chall"`
  - `challenge.workdir = "challenge"`
- Lightweight spot-check with `PYTHONPATH="$PWD:$PWD/scripts" python3 - <<'PY' ...` now returns:
  - `{'stage_order': ['recon'], 'mode': 'local_recon_only'}`
  for that host-style relative-path scenario.

### Remaining follow-up

- This fixes one concrete classification seam, but the full end-to-end no-gdb/no-codex runtime path is still not benchmark-enforced yet.
- Next useful step is a replayable or scripted run that proves the real runtime now reaches `local_recon_exploit` (or another intended degraded plan) under stripped tool availability, not just the planner helper in isolation.

## 2026-03-13 10:36 CST — Reinserted recon for terminal-only no-gdb/no-codex helper plans; deeper runtime seam still present

### What changed

- Relaxed `scripts/run_session.py::choose_missing_codex_stage_order()` so local missing-Codex fallback no longer requires the incoming stage order to already contain `recon` before it can choose a portable local route.
- This means terminal-heavy/cached plans like `['exploit_l4']` can now still degrade to `['recon', 'exploit_l3']` when:
  - a real local binary exists,
  - `DIRGE_ALLOW_LOCAL_EXP_ON_CODEX_MISSING=1`,
  - and no usable local/direct gdb path is available.
- Added regression coverage in `tests/test_run_session_missing_codex.py` for that exact terminal-only case.

### Why it mattered

A real stripped-PATH run can arrive at missing-Codex handling after runtime heuristics/cache pressure have already collapsed the live plan toward exploit-only stages.
The old helper logic silently refused portable local fallback in that situation because it insisted `recon` already be present in the incoming order.
That was too brittle for host-like degraded runtime paths.

### Verification

- `python3 -m pytest tests/test_run_session_missing_codex.py -q` → `33 passed`
- Direct helper spot-check with current saved state now returns `(['recon', 'exploit_l3'], 'local_recon_exploit')` even for incoming stage orders like:
  - `['exploit_l4']`
  - `['exploit_l3', 'exploit_l4']`

### Real-runtime validation result

A fresh scripted stripped-PATH run (symlink farm PATH excluding `gdb`, `gdb-mcp`, and `codex`) against `challenge/bench_ret2win` showed partial improvement but also exposed a deeper seam:

- `start_session.sh --no-codex` succeeded under the stripped PATH.
- `run_session.py --allow-codex-missing` now really executed `recon` before exploit stages, instead of staying fully exploit-only.
- But the live run still logged:
  - `codex 缺失，但保持完整 stage plan（失败后继续由策略层处理）`
- and still continued into `exploit_l4`, ending with repeated:
  - `exploit_l3 失败，但继续推进到 exploit_l4`

Observed live stage sequence in that stripped-tool run:
- loop 1: `recon -> exploit_l3 -> exploit_l4`
- loop 2: `recon -> exploit_l3 -> exploit_l4`

### Current interpretation

The planner helper itself is now capable of the intended `local_recon_exploit` degradation on the saved state, but the full runtime path is still not consistently surfacing that planner decision in the live orchestration layer.
This suggests another seam remains around pre-call stage-order mutation, runtime note/report selection, or post-planner exploit rewrite/terminal forcing.

### Next useful follow-up

- Trace why the live stripped-PATH route still emits the `keep_full_plan` note even though the helper now resolves the same saved state to `local_recon_exploit`.
- Then add a replayable or scripted regression that locks the real runtime contract to the intended no-gdb/no-codex route.

## 2026-03-13 11:01 CST — Fixed missing `local_recon_exploit` orchestration branch; stripped-PATH runtime now degrades to `recon -> exploit_l3`

### What changed

- Fixed the main missing-Codex handling branch in `scripts/run_session.py` so the planner result `local_recon_exploit` is handled explicitly instead of falling through to the generic `keep_full_plan` path.
- The new branch now applies the same runtime-policy adjustments as the other portable local fallback modes:
  - emit plan notes,
  - keep local exploit enabled,
  - clear terminal-stage forcing,
  - disable exploit-rewrite extra-loop machinery for this degraded path,
  - and defer objective stop until the local exploit stage gets one real run.

### Why it mattered

The earlier helper fixes were real, but the live stripped-PATH runtime still kept going to `exploit_l4` because the orchestrator never had a case for `local_recon_exploit`.
That meant:
- `choose_missing_codex_stage_order()` correctly returned `(['recon', 'exploit_l3'], 'local_recon_exploit')`,
- but the outer runtime handler treated it like an unknown plan,
- logged `codex 缺失，但保持完整 stage plan（失败后继续由策略层处理）`,
- and preserved the terminal exploit forcing that reintroduced `exploit_l4`.

### Verification

- `python3 -m pytest tests/test_run_session_missing_codex.py -q` → `33 passed`
- Direct helper spot-check under stripped PATH still returns:
  - `(['recon', 'exploit_l3'], 'local_recon_exploit')`
- Fresh scripted stripped-PATH runtime validation against `challenge/bench_ret2win` now shows the intended degraded live contract:
  - decision report stage plan: `['recon', 'exploit_l3']`
  - session summary notes include:
    - `codex missing: prefer portable local recon + local exploit plugin`
    - `direct gdb probe: off`
    - `gdb evidence unavailable: exploit after recon`
    - `local exploit plugin: on`
  - timeline contains only:
    - loop 1: `recon -> exploit_l3`
  - `exploit_l4` is no longer executed on that stripped-tool path.

### Remaining follow-up

- The routing bug is fixed; the next seam is exploit quality on the true no-gdb/no-codex path.
- In the fresh stripped-PATH validation, `exploit_l3` still failed local verify with:
  - `autofix skipped: missing prerequisites (evidence=0, pie_base=no)`
- Next useful step is to improve the recon-only ret2win/no-gdb exploit path so it can use static recon artifacts more effectively instead of stalling on missing dynamic-evidence prerequisites.

## 2026-03-13 11:24 CST — Fixed recon stage-cache loss of ret2win-facing static facts

### What changed

- Expanded `scripts/run_session.py::extract_stage_cache_patch()` for `stage == "recon"`.
- Recon cache entries no longer preserve only:
  - `protections`
  - `io_profile`
- They now also carry the portable static facts that matter for no-gdb/no-codex ret2win generation:
  - `static_analysis`
  - `capabilities.static_offset_candidate` (when present)
- Added regression coverage in `tests/test_run_session_missing_codex.py` proving a recon cache round-trip preserves those hints.

### Why it mattered

While inspecting the latest stripped-PATH no-gdb/no-codex failure state, the generated exploit had already regressed to:
- `strategy: fuzz_probe`
- `RET2WIN_ADDR = 0`
- `STATIC_OFFSET_CANDIDATE = 0`

That was inconsistent with the stronger local recon path already implemented for ret2win binaries.
The root cause was not only exploit verify logic: on a recon cache hit, the state could silently lose the exact portable recon facts that should have driven `exploit_l3` into a static ret2win plan.
So the degraded path was weaker than intended even before verify/autofix logic had a chance to help.

### Verification

- `python3 -m pytest tests/test_run_session_missing_codex.py -q` → `34 passed`
- Spot-check with `PYTHONPATH="$PWD:$PWD/scripts" python3 - <<'PY' ...`:
  - saved a synthetic recon cache carrying ret2win symbol/offset hints
  - restored a fresh state via `apply_stage_cache("recon", ...)`
  - generated an exploit stub from that restored state
  - observed `{"strategy": "ret2win", "written": true}`

### Current interpretation

The true no-gdb/no-codex seam is now narrower and more honest:
- before this fix, cache-hit runs could drop ret2win-static recon knowledge and fail from a degraded `fuzz_probe` starting point
- after this fix, recon cache reuse should preserve the portable facts needed for ret2win-oriented `exploit_l3` generation across both OpenClaw and host-side Codex-style entry flows

### Remaining follow-up

- Re-run the stripped-PATH real runtime validation against `challenge/bench_ret2win`.
- If it still fails, the remaining issue is more likely in exploit execution / local verify policy than in recon-state retention.

## 2026-03-13 12:05 CST — Fixed ret2win local-verify semantics for recon-only no-gdb/no-codex exploit passes

### What changed

- Patched `core/plugins/exploit_l3.py` so generated local exploit stubs no longer require a post-exploit shell marker as the only successful verify outcome.
- Added a lightweight success-marker bridge for banner-style wins:
  - `_verify_success_markers()` derives a small banner token set from the generated strategy/reasons
  - `_has_success_marker()` recognizes ret2win/banner output such as `DIRGE_RET2WIN_OK`
  - `_verify_shell(io, preflight_data=...)` now accepts success observed in pre-shell output, or in merged preflight+post-echo output, before demanding an interactive shell marker
- Also fixed `_send_payload()` to return the full stage output window (including `drain_post_send` / clear-buffer data), because the ret2win success banner was often printed before the old return value captured anything.
- Updated verify-mode offset bruteforce in the generated stub to pass that stage output into `_verify_shell(io, out)`.
- Added regression coverage in `tests/test_exploit_l3.py` ensuring:
  - generated ret2win stubs recognize banner success before shell verification
  - generated verify-mode code actually passes preflight output into `_verify_shell(...)`

### Why it mattered

A fresh real stripped-PATH no-gdb/no-codex run had already improved recon/exploit generation correctly:
- stage plan: `['recon', 'exploit_l3']`
- exploit strategy: `ret2win`
- static offset hint: `72`
- ret2win symbol/address present

But the live exploit still failed local verify with a timeout-only false negative.
The root cause was that verify-mode bounded offset probing treated success as “shell marker or bust”, while `bench_ret2win` is a classic banner-style ret2win that:
- prints `DIRGE_RET2WIN_OK`
- exits cleanly via `_exit(0)`
- never produces `__PWN_VERIFY_OK__`

So the exploit was actually succeeding, but verify kept iterating offsets until the outer timeout expired.

### Verification

- `python3 -m pytest tests/test_exploit_l3.py tests/test_run_session_missing_codex.py -q` → `38 passed`
- Manual spot-check of the generated ret2win stub:
  - plain local run prints `bye` + `DIRGE_RET2WIN_OK`
- Fresh real stripped-PATH runtime validation (symlink-farm PATH with binutils preserved, `gdb`/`gdb-mcp`/`codex` absent) against `challenge/bench_ret2win` now shows:
  - stage plan: `['recon', 'exploit_l3']`
  - `session.exp.strategy = 'ret2win'`
  - `session.exp.local_verify_passed = true`
  - `capabilities.exploit_success = true`
  - `session.status = 'finished'`

### Current interpretation

The real no-gdb/no-codex ret2win path is now green in a more honest way:
- recon cache reuse preserves ret2win/static offset facts
- `exploit_l3` generation selects a real ret2win plan instead of regressing to `fuzz_probe`
- local verify now accepts legitimate banner-style exploit success rather than forcing a shell-only contract

This strengthens both supported runtime entries:
- OpenClaw can execute the degraded recon-only ret2win path directly
- host-side Codex CLI retains the same shared exploit/verify core without requiring a Codex auth gate for this class of local benchmark progress

### Remaining follow-up

- Reduce reliance on bounded local verify/offset bruteforce for recon-only ret2win cases by promoting more deterministic offset/control contracts into the shared exploit plan when evidence exists.
- Keep future benchmark additions focused on portable exploit outcome semantics (banner success, flag success, shell success) rather than overfitting verify to one interaction style.

## 2026-03-13 12:29 CST — Revalidated ret2win exploit slices on both portable missing-Codex paths

### What changed

- Re-ran the focused verification slice after the exploit-verify/cache fixes landed, instead of trusting only the earlier ad-hoc stripped-PATH run.
- Verified both benchmark-facing missing-Codex ret2win exploit routes that matter for dual-entry runtime support:
  - local gdb fallback path
  - direct PATH `gdb-mcp` probe path

### Verification

- `python3 -m pytest tests/test_exploit_l3.py tests/test_run_session_missing_codex.py -q` → `38 passed`
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_local_ret2win_exploit` → case passes (`recon -> gdb_evidence -> exploit_l3`, `exp_verify_ok=true`)
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_direct_gdb_path_ret2win_exploit` → case passes (`recon -> gdb_evidence -> exploit_l3`, `gdb.mode=gdb_direct_probe`, `exp_verify_ok=true`)

### Why it mattered

The earlier fixes were already promising, but this rerun matters because it reconfirms the shared exploit/verify core on both supported entry styles:
- OpenClaw-compatible local-gdb flow is still green
- host-like direct-gdb/MCP adapter flow is also still green

So the current tree is not merely "fixed for one degraded path"; the portable ret2win exploit contract is holding across both runtime-adapter shapes.

### Current next seam

- The main remaining weakness is still determinism, not outright success:
  - current ret2win success can still depend on bounded local verify/offset bruteforce when `offset_to_rip` is not promoted cleanly enough
- Next high-value work should focus on promoting stronger shared offset/control facts into exploit planning, rather than doing more generic runtime/plumbing cleanup.

## 2026-03-13 13:05 CST — Baseline-enforced the true stripped-tool no-gdb/no-codex ret2win route

### What changed

- Added replay-side `path_block_commands` support to `scripts/replay_benchmarks.py`.
  - For a given case, replay now builds a temporary PATH view from the current host PATH while omitting selected commands.
  - This keeps the rest of the host tool surface intact instead of relying on machine-private symlink farms or one-off shell surgery.
- Documented the new case contract in `benchmarks/README.md`.
- Added unit coverage in `tests/test_replay_benchmarks.py` for:
  - case parsing/contract hashing of `path_block_commands`
  - temporary PATH view construction that actually removes blocked commands
- Added a new benchmark case: `benchmarks/cases/demo_nogdb_nocodex_ret2win_exploit.json`
  - blocks `gdb`, `gdb-mcp`, and `codex` from PATH
  - requires binutils-style local recon commands only
  - asserts the portable degraded path stays `recon -> exploit_l3`
  - asserts `session.exp.strategy=ret2win`, `local_verify_passed=true`, and `capabilities.exploit_success=true`

### Verification

- `python3 -m pytest tests/test_replay_benchmarks.py -q` → `15 passed`
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_nogdb_nocodex_ret2win_exploit` → passes
  - stage sequence: `['recon', 'exploit_l3']`
  - `path_block_commands = ['gdb', 'gdb-mcp', 'codex']`
  - `recon.mode = 'local_recon_fallback'`
  - `session.exp.strategy = 'ret2win'`
  - `session.exp.local_verify_passed = true`
  - `capabilities.static_offset_candidate = 72`
  - `capabilities.ret2win_path_verified = true`
  - `capabilities.exploit_success = true`

### Why it mattered

Previously the stripped-tool route was only spot-checked manually. That left a portability gap: the project could be green on the richer local/direct-gdb matrix while the real `no-gdb/no-codex` degraded route silently drifted.

This change makes that route part of the benchmark contract without hard-binding Dirge to OpenClaw-specific behavior:
- the runtime core stays the same (`recon` facts feeding `exploit_l3` verify)
- OpenClaw remains a valid execution environment
- host-side Codex CLI compatibility is preserved because the case explicitly models *absence* of Codex/GDB rather than special-casing OpenClaw

### Current follow-up

- Now that the stripped-tool route is benchmarked, the next valuable seam is still exploit determinism rather than more benchmark plumbing:
  - reduce dependence on bounded local verify/offset bruteforce for recon-only ret2win success
  - promote stronger shared offset/control facts from recon/gdb evidence into exploit planning when evidence is good enough
