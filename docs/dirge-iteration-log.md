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
