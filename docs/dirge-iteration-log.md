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

## 2026-03-13 13:31 CST — Persisted real auto-hit ret2win offsets from local verify instead of throwing them away

### What changed

- Fixed a concrete generated-stub bug in `core/plugins/exploit_l3.py`:
  - successful verify-mode ret2win runs used to print
    - `[auto-offset] hit={off} align={int(bool(align))}`
    as a literal string because the generated f-string escaped the braces.
  - the stub now prints the actual discovered values, e.g. `hit=72 align=1`.
- Added `scripts/verify_local_exp.py::_extract_auto_offset_hit()`.
  - verify reports now parse the real auto-hit line from runtime output and store it as `auto_offset_hit`.
- Successful local verify now also projects that discovered hit back into state:
  - `capabilities.control_rip=true`
  - `capabilities.offset_to_rip=<hit>`
  - `session.exp.selected_offset=<hit>`
  - `session.exp.selected_align_ret=<0|1>`

### Why it mattered

The recent ret2win improvements made the recon-only no-gdb/no-codex route succeed, but one determinism seam remained:
- success could still depend on verify-mode bounded offset scanning,
- and even when that scan found the correct offset, the runtime mostly threw the discovery away.

That meant future reruns still had to rediscover the same local offset rather than reusing a now-proven session fact.
This was especially wasteful on the portable stripped-tool ret2win path, where the whole point is to preserve useful capability knowledge even without Codex or gdb.

### Verification

- `python3 -m pytest tests/test_exploit_l3.py tests/test_verify_local_exp.py -q` → `10 passed`
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_nogdb_nocodex_ret2win_exploit` → passes
- Fresh verify report now contains a real parsed hit instead of a dead literal placeholder:
  - `artifacts/reports/exp_verify_bench_demo_nogdb_nocodex_ret2win_exploit_20260313T053054Z_01_01.json`
  - `auto_offset_hit.offset_to_rip = 72`
  - `auto_offset_hit.align_ret = 1`

### Current interpretation

This is not a giant solve-engine change, but it meaningfully improves exploit determinism and evidence retention:
- the shared exploit core now keeps a proven offset discovered during local verify,
- OpenClaw and host-side Codex-style runtimes both benefit because the behavior lives in the shared verify/report/state path,
- and later reruns/autofix loops have a better chance of starting from `offset_to_rip` instead of re-bruteforcing a known-good ret2win offset.

### Remaining follow-up

- Re-run a stronger ret2win slice that exercises a second pass/rerun on the same session and confirm it now prefers the persisted `offset_to_rip` path over verify-time scanning.
- If that holds, extend the same “capture discovered exploit facts instead of discarding them” pattern to other exploit families where local verify learns deterministic runtime facts.

## 2026-03-13 17:02 CST — Added a real replayable direct-execve exploit slice and fixed two shared non-ret2win seams

### What changed

- Added a new challenge-like local fixture under `challenge/bench_direct_execve/`:
  - non-PIE amd64 overflow binary
  - real helper target `run_cmd_execve()` that calls `execve("/bin/sh", ...)`
  - seeded crash input `cyclic88.txt`
  - short README documenting that this is meant to exercise the shared `direct_execve_shell` path rather than another ret2win-only proof
- Added a new replay case `benchmarks/cases/demo_local_direct_execve_exploit.json`.
  - It asserts the portable missing-Codex path stays `recon -> gdb_evidence -> exploit_l3`
  - It requires `session.exp.strategy = direct_execve_shell`
  - It requires successful local verify / `capabilities.exploit_success = true`
- Tightened shared exploit-family routing in `core/exploit_strategy.py`.
  - Before this change, an execve-like helper symbol plus clean RIP control still fell through too easily unless the binary also exposed extra `/bin/sh`/`int 0x80`-style hints.
  - The shared strategy picker now treats `execve`-like target symbols + proven RIP control as sufficient to prefer `direct_execve_shell` with lower confidence, instead of collapsing back to `rip_control_probe`.
- Tightened shared direct-execve stub target selection in `core/plugins/exploit_l3.py`.
  - Before this change, generated direct-execve stubs only looked for a narrow hard-coded symbol set like `execve`, `get_shell`, `win`, etc.
  - That missed realistic helper names such as `run_cmd_execve`, so the strategy could be correct while the generated stub still had no usable target and local verify failed.
  - The stub now falls back to any symbol whose name contains `execve` or ends in `shell` / `_shell` when the explicit symbol list misses.
- Added focused regression coverage:
  - `tests/test_exploit_strategy.py` proves execve-like helper symbols with RIP control select `direct_execve_shell`
  - `tests/test_exploit_l3.py` proves the generated direct-execve stub can pick an execve-like helper symbol name outside the older fixed allowlist

### Notable failure trail

- The first fixture attempt used a 72-byte seeded file and `gdb_evidence` exited normally; that was a real benchmark-design mistake, because 72 bytes only reached saved RBP on this frame shape and did not actually corrupt RIP.
- After switching the seeded crash input to `cyclic88.txt`, `gdb_evidence` recovered `offset_to_rip = 72` correctly, but `exploit_l3` still failed for two more concrete reasons:
  1. strategy routing degraded to `rip_control_probe` because execve hints were under-weighted
  2. after fixing routing, the direct-execve stub still failed to locate `run_cmd_execve`
- Keeping those failures in the loop mattered because they exposed two shared-core seams rather than a benchmark-only issue:
  - exploit-family classification was too ret2win-/shell-name-biased
  - direct-execve target selection was too dependent on a tiny fixed symbol vocabulary

### Verification

- `python3 -m pytest tests/test_exploit_strategy.py tests/test_exploit_l3.py tests/test_verify_local_exp.py tests/test_session_exploit_runtime.py -q` → passes (`23 passed`)
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_local_direct_execve_exploit` → passes
  - stage sequence: `['recon', 'gdb_evidence', 'exploit_l3']`
  - `recon.mode = 'local_recon_fallback'`
  - `gdb.mode = 'local_gdb_fallback'`
  - `capabilities.offset_to_rip = 72`
  - `session.exp.strategy = 'direct_execve_shell'`
  - `session.exp.local_verify_passed = true`
  - `capabilities.exploit_success = true`

### Why it mattered

This closes the previously explicit benchmark gap around non-ret2win/non-ret2libc exploit proof.
Project_Dirge now has a replayable challenge-like slice proving that the shared portable core can:
- recover RIP control via local gdb fallback in a missing-Codex run
- classify the exploit family as direct-execve rather than generic probe/ret2win
- generate a usable helper-target exploit stub
- complete local shell verification through the shared `exploit_l3` path

That moves the project one step closer to a real dual-entry runtime contract where both OpenClaw and host-side Codex CLI can drive the same solve core without hard-coding success around only ret2win fixtures.

### Current follow-up

- Add a similarly replayable multi-stage exploit slice (likely leak + ret2libc or equivalent) so the benchmark matrix covers at least one family beyond single-hop ret2win/direct-execve control-flow redirection.
- Audit whether generic `shell` substring bias still leaks into other strategy branches now that the execve-family path is stronger.

## 2026-03-13 13:58 CST — Made rerun exploit stubs consume persisted ret2win offset/alignment facts

### What changed

- Tightened `core/plugins/exploit_l3.py::generate_exp_stub()` so regenerated exploit templates no longer rely only on `capabilities.offset_to_rip`.
- The shared stub now also consumes persisted verify-learned session facts when present:
  - `session.exp.selected_offset`
  - `session.exp.selected_align_ret`
- For ret2win stubs this changes two concrete runtime contracts:
  - `OFFSET_TO_RIP` now falls back to `selected_offset` when capability state is sparse or stale
  - `_align_modes()` now honors persisted `selected_align_ret` before defaulting back to generic `auto/always/never` behavior
- Added focused regression coverage in `tests/test_exploit_l3.py` proving regenerated stubs:
  - reuse `selected_offset` as the primary offset when `capabilities.offset_to_rip` is missing
  - reuse `selected_align_ret` to stay on the verified align branch instead of retrying the opposite branch first

### Why it mattered

The previous iteration taught local verify to *record* a real ret2win auto-hit, but one determinism seam remained in the shared exploit generation path:
- reruns could still regenerate a template that only trusted top-level capability offset state
- and align choice could drift back to generic x64 `auto => [True, False]` ordering even after verify had already proven `align=0` or `align=1`

That meant some second-pass flows could still waste time rediscovering what local verify had already learned, especially on stripped-tool ret2win paths where these persisted facts are the main portable substitute for debugger evidence.

### Verification

- `python3 -m pytest tests/test_exploit_l3.py tests/test_verify_local_exp.py -q` → `12 passed`
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_nogdb_nocodex_ret2win_exploit` → passes after the stub-regeneration change

### Current interpretation

This is a modest but real determinism improvement in the shared exploit core:
- OpenClaw and host-side Codex-style runtimes both benefit because the reuse logic lives in common stub generation rather than a runtime-specific adapter
- successful local verify now feeds a more reusable second-pass exploit template instead of only enriching the report/state for humans
- the remaining validation gap is mostly orchestration-level proof, not missing shared-core support

### Remaining follow-up

- Add or script a same-session rerun proof that demonstrates the orchestration loop regenerates/uses the persisted ret2win facts end-to-end rather than only at the stub unit-contract level.
- If that holds, generalize the same persisted-fact reuse pattern to other exploit families where local verify learns deterministic runtime choices.

## 2026-03-13 15:00 CST — Closed the verify-sync seam that could drop learned ret2win rerun facts

### What changed

- Patched `scripts/session_exploit_runtime.py::sync_exp_verify_artifacts()` so verify-report synchronization now also projects deterministic ret2win facts learned during local verify, not just the coarse pass/fail bit.
- When a verify report contains `auto_offset_hit` and `run_result_ok=true`, sync now carries back into the owning session state:
  - `capabilities.control_rip=true`
  - `capabilities.offset_to_rip=<hit>`
  - `session.exp.selected_offset=<hit>`
  - `session.exp.selected_align_ret=<0|1>`
- Added a stronger integration test in `tests/test_session_exploit_runtime.py` that covers the host/OpenClaw-shared edge case where the main shared `state/state.json` belongs to another session and the current session must sync verify results from a report + base-state snapshot.
- That new test then regenerates `sessions/<sid>/exp/exp.py` from the synced state and proves the ret2win stub reuses the synchronized facts directly (`OFFSET_TO_RIP=72`, `_offset_candidates() -> [72]`, `_align_modes() -> [True]`) instead of reopening bounded rediscovery.

### Why it mattered

The previous two iterations fixed only half of the determinism chain:
- local verify could discover and record a real auto-hit offset/alignment
- regenerated stubs could reuse persisted `selected_offset` / `selected_align_ret`

But a real orchestration seam remained when verify ran against a temp snapshot or when shared state drifted to another session:
- `verify_local_exp.py` wrote `auto_offset_hit` into the report and into the state it directly touched
- `sync_exp_verify_artifacts()` only synchronized `local_verify_passed`, report path, and `exploit_success`
- so the precise rerun facts could still be lost before the owning session regenerated its next stub

That would have left OpenClaw and host-style orchestration more dependent on accidental same-file state ownership than on the intended shared report/state contract.

### Verification

- `python3 -m pytest tests/test_session_exploit_runtime.py tests/test_exploit_l3.py tests/test_verify_local_exp.py -q` → `14 passed`
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_nogdb_nocodex_ret2win_exploit` → passes

### Current interpretation

This closes the specific rerun-proof gap called out in the last iteration:
- same-session ret2win rerun facts now survive the verify-report sync boundary,
- regenerated exploit templates can deterministically stay on the proven offset/alignment branch,
- and the fix lives in shared orchestration/state-sync code rather than an OpenClaw-only or Codex-only adapter.

### Remaining follow-up

- Move from ret2win-specific deterministic fact retention toward other exploit families where verify learns reusable runtime choices.
- Look for the next real challenge-like seam where shared evidence can be promoted into exploit planning before bounded verify/bruteforce is needed.

## 2026-03-13 15:29 CST — Extended verify-learned auto-offset retention to direct_execve_shell stubs

### What changed

- Fixed the generated `direct_execve_shell` verify-mode template in `core/plugins/exploit_l3.py` so successful auto-offset discovery now prints real values:
  - before: `print(f"[auto-offset] hit={{off}} align={{int(bool(align))}}")`
  - after: `print(f"[auto-offset] hit={off} align={int(bool(align))}")`
- Added focused regression coverage in `tests/test_exploit_l3.py` proving the generated `direct_execve_shell` stub now emits the same parseable auto-offset line shape already used by the ret2win path.

### Why it mattered

The previous iterations had already taught the shared verify/report/sync pipeline to preserve deterministic ret2win facts learned during bounded local verify.
But one nearby exploit family still had a silent portability/determinism gap:
- `direct_execve_shell` also does verify-time offset scanning when `OFFSET_TO_RIP` is unknown
- `verify_local_exp.py` already knows how to parse `[auto-offset] hit=<n> align=<0|1>`
- yet the generated stub printed literal braces instead of numeric values, so any successful discovered offset could not flow into verify reports or back into session state

That meant the shared reuse pipeline was stronger for ret2win than for another RIP-control exploit family that should benefit from the same contract across both OpenClaw and host-style Codex entry paths.

### Verification

- `python3 -m pytest tests/test_exploit_l3.py tests/test_verify_local_exp.py tests/test_session_exploit_runtime.py -q` → `15 passed`
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_nogdb_nocodex_ret2win_exploit` → passes after the shared-template fix (regression guard on the already-green stripped-tool route)

### Current interpretation

This is a small change, but it pushes the deterministic-fact retention contract one step beyond ret2win-specific plumbing:
- direct execve-style RIP-control templates can now emit parseable verify-learned offset/alignment facts
- the existing shared verify/report/state-sync machinery is positioned to preserve those facts without adding an OpenClaw-only or Codex-only fork
- the remaining gap is now less about string-format bugs and more about finding the next real benchmark/challenge slice where non-ret2win exploit families can prove the same end-to-end reuse contract

### Remaining follow-up

- Add a benchmarkable or scripted proof for a non-ret2win exploit family (likely direct-execve or ret2libc-oriented) that demonstrates discovered verify-time runtime facts survive into a useful rerun path.
- Continue promoting reusable exploit facts through the shared core rather than adding runtime-specific fallback behavior.

## 2026-03-13 16:08 CST — Extended verify-learned rerun determinism from ret2win offsets to ret2libc template choice

### What changed

- Extended the shared verify/report/state-sync pipeline so a successful ret2libc verify run can now preserve which stage-2 ROP template actually worked.
- `scripts/verify_local_exp.py` now parses runtime lines of the form:
  - `[rop-template] hit=<idx>/<count> order=<n>`
  and records that as `rop_template_hit` in both the verify report and `run_detail`.
- `scripts/session_exploit_runtime.py::sync_exp_verify_artifacts()` now syncs that portable fact back into the owning session as:
  - `session.exp.selected_rop_template_idx`
- `core/plugins/exploit_l3.py` now carries that shared session fact into generated stubs as:
  - `SELECTED_ROP_TEMPLATE_IDX`
  and uses it to prefer the known-good ret2libc payload ordering on rerun instead of always reopening from payload #1.
- Also fixed two nearby evidence-quality bugs in the ret2libc template body:
  - `[rop-template] hit=...` now prints real numeric values instead of literal braces
  - libc profile source strings now emit `profile:<name>` instead of the stale literal `profile:{name}`

### Why it mattered

The previous iterations had already made ret2win/direct-execve reruns more deterministic by preserving auto-discovered offset/alignment facts from local verify.
But ret2libc still had a nearby shared-core gap:

- a verify run could discover that payload template #2 or #3 worked,
- yet the useful choice was not preserved across the verify-report/sync boundary,
- and the next generated stub would still default back to the first template.

That was wasteful and made non-ret2win reruns less transferable across both supported runtime entries.
This cycle moves the same general contract one step wider without adding an OpenClaw-only or Codex-only fork.

### Verification

- `python3 -m pytest tests/test_exploit_l3.py tests/test_verify_local_exp.py tests/test_session_exploit_runtime.py -q` → `20 passed`
- Added focused regression coverage proving:
  - ret2libc generated stubs emit parseable `[rop-template] hit=2/3 order=1`-style output
  - verify parsing ignores the old literal-brace placeholder form
  - synced `selected_rop_template_idx` survives a foreign-shared-state scenario
  - regenerated ret2libc stubs reuse that synced template preference via `_selected_payload_order()`

### Current interpretation

This is a modest but real solve-facing determinism improvement in the shared exploit core:

- it broadens reusable verify-learned facts beyond ret2win-only offset/alignment retention,
- improves evidence readability for ret2libc runs,
- and keeps the behavior portable across OpenClaw and host-side Codex CLI entry shapes.

### Remaining follow-up

- Add a benchmarkable or scripted non-ret2win exploit slice that exercises the new ret2libc template-preference reuse end-to-end, rather than proving it only through focused integration tests.
- Keep looking for other exploit families where local verify learns stable runtime choices that should become first-class shared session facts.

## 2026-03-13 16:32 CST — Closed this cycle with green validation; next gap remains a real non-ret2libc replay slice

### What changed

- No additional core logic changes were needed after the ret2libc template-choice work.
- This cycle focused on validating and tightening the landing zone for the already-staged shared-core changes in:
  - `core/plugins/exploit_l3.py`
  - `scripts/verify_local_exp.py`
  - `scripts/session_exploit_runtime.py`
- The main goal was to confirm the new verify-learned fact retention work did not regress the currently important no-Codex/no-gdb ret2win path while the repo still lacks a true replay-enforced non-ret2libc exploit slice.

### Verification

- `python3 -m pytest tests/test_exploit_l3.py tests/test_verify_local_exp.py tests/test_session_exploit_runtime.py -q` → `20 passed`
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_nogdb_nocodex_ret2win_exploit` → passes

### Why it mattered

The ret2libc rerun-determinism improvement is shared-core work, but right now the repository still has stronger replay coverage for ret2win than for non-ret2libc exploit families.
Before stacking more changes on top, it was useful to prove two things:

- the shared verify/report/sync edits are green in focused integration coverage
- the strongest stripped-tool portability benchmark (`demo_nogdb_nocodex_ret2win_exploit`) still stays green after the exploit-core changes

That keeps the current branch honest: solve-facing determinism improved, and the already-hard-won portable no-Codex/no-gdb ret2win route did not regress.

### Current interpretation

- This cycle was a deliberate validation/containment pass, not a new benchmark expansion pass.
- The shared exploit core is in a better state than before for carrying forward verify-discovered runtime facts.
- The next valuable move is still to find or build a replayable non-ret2libc exploit slice that can prove the same end-to-end reuse contract under a real challenge-like run, rather than only via focused tests.

### Remaining follow-up

- Add a real challenge-like replay or scripted harness for a non-ret2libc exploit family (ret2libc or direct-execve are the most obvious candidates).
- Prefer a fixture/session seed that already reaches exploit generation, so the next cycle spends effort on evidence/verify reuse rather than re-opening broad planner/runtime plumbing.

## 2026-03-13 17:32 CST — Baseline-enforced the new direct-execve slice and refreshed the full replay gate

### What changed

- Took the already-green `challenge/bench_direct_execve` + `demo_local_direct_execve_exploit` path from “targeted proof” to full benchmark baseline coverage.
- Refreshed `benchmarks/baseline/latest.json` from a fresh full replay run so the new non-ret2win slice is part of the checked regression surface instead of living only in focused logs/tests.
- Kept the shared-core focus narrow: this cycle did not add more exploit logic, it locked in the previous direct-execve work as a first-class regression contract.

### Verification

- `python3 -m pytest tests/test_exploit_strategy.py tests/test_exploit_l3.py tests/test_verify_local_exp.py tests/test_session_exploit_runtime.py -q` → `22 passed`
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_local_direct_execve_exploit` → passes
- `python3 scripts/replay_benchmarks.py --allow-codex-missing --gate --write-baseline benchmarks/baseline/latest.json` → passes
  - fresh scoreboard: `30 total / 29 executed / 1 skipped`
  - `exploit_success_total = 5`
  - `demo_local_direct_execve_exploit` now lives inside the refreshed baseline

### Why it mattered

The direct-execve work from the previous cycle was valuable, but until it was in the full replay baseline it still had a soft spot:
- targeted replay could stay green,
- while a later broad refresh could accidentally omit or drift the case without immediately surfacing it.

This cycle closes that gap.
Project_Dirge now has a baseline-enforced non-ret2win exploit slice in the normal replay gate, which is a better fit for the project charter:
- benchmark-facing,
- challenge-like,
- portable across OpenClaw and host-side Codex-style entry paths,
- and not dependent on OpenClaw-only behavior.

### Current interpretation

- The project now has replay-enforced exploit proofs across three distinct portable classes:
  - stripped-tool recon-only ret2win
  - local/direct-gdb ret2win
  - local-gdb direct-execve
- That is a healthier benchmark surface than the earlier ret2win-heavy matrix.
- The next meaningful family gap is no longer “any non-ret2win proof exists?” but specifically “where is the replayable multi-stage leak/ret2libc proof?”

### Remaining follow-up

- Build a real challenge-like ret2libc or comparable multi-stage leak benchmark slice, ideally one that can eventually prove verify-learned template choice reuse end-to-end rather than only in focused tests.
- Prefer improvements that move leak acquisition / libc-closure / stage-2 payload selection forward in the shared core, instead of adding more benchmark-only scaffolding.
