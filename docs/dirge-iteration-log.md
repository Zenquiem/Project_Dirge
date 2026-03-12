# Project Dirge Iteration Log

This file tracks ongoing autonomous iteration work on Project_Dirge.

## 2026-03-10 20:34 CST — Iteration system initialized

- Repository cloned to `/home/ubuntu/.openclaw/workspace/Project_Dirge`
- Baseline local test run completed: `67 tests`, all passing
- Continuous iteration cron job created
- Current cadence: every 10 minutes
- Push permission granted by user, but changes should still be grouped into coherent tested commits

### Current phase

Phase 1 — audit and baseline tightening

### Immediate goals

1. Audit architecture, state flow, and session orchestration
2. Identify top bottlenecks hurting solve quality
3. Propose prioritized iteration plan
4. Start first low-risk implementation pass with tests

### How to verify work is continuing

- Check this file for appended progress entries
- Check `git log --oneline -n 10`
- Check `git status`
- Check repository timestamps / remote commits if pushes occur

## 2026-03-10 21:07 CST — Stage receipt validation tightened

- Audited stage receipt / state validation path in `core/stage_runner.py`, `core/state_utils.py`, and finalize flow
- Hardened `validate_stage_runner_spec()` so required `*_receipt` artifacts are not only present, but also parsed and checked to match the expected stage name
- Added regression coverage for stale/mismatched receipt wiring in `tests/test_state_utils.py`
- Verification: `python3 -m unittest discover -s tests -q` → `68 tests`, passing; `python3 -m compileall core scripts tests` passing
- Why this matters: reduces false-positive stage readiness when `artifacts_index.latest.paths` accidentally points at an old or wrong-stage receipt

## 2026-03-10 21:18 CST — Meta/state sync drift guard aligned

- Audited `scripts/session_state_sync.py` against the CLI sync path in `scripts/sync_state_meta.py`
- Hardened in-process meta sync so session-scoped fields only update when `state.session.session_id` matches the target session, avoiding cross-session metadata drift during orchestration/recovery flows
- Synced objective projection to carry `competition_reasons` and preserve `latest_run` updates independently of session-scoped syncing
- Added regression tests in `tests/test_session_state_sync.py` for both mismatch guarding and objective reason propagation
- Verification: `python3 -m unittest discover -s tests -q` → `70 tests`, passing; `python3 -m compileall core scripts tests` passing
- Why this matters: keeps UI/session metadata consistent with the canonical state owner, and makes evidence/verification success reasons survive meta sync instead of being silently dropped

## 2026-03-10 21:24 CST — Receipt identity checks tightened

- Audited `core/state_utils.py` receipt validation in the stage-spec enforcement path
- Hardened required `*_receipt` validation to also verify embedded `session_id` and `loop` against the canonical `stage_receipt_<session>_<loop>_<stage>.json` path, not just the stage field
- Added regression coverage in `tests/test_state_utils.py` for stale/cross-session receipt aliasing where the path points at one run but the JSON payload belongs to another
- Verification: `python3 -m unittest discover -s tests -q` and `python3 -m compileall core scripts tests`
- Why this matters: reduces false-positive verification when `artifacts_index.latest.paths.*_receipt` drifts across sessions/loops during retries, recovery, or manual repair flows

## 2026-03-10 21:42 CST — Meta sync objective reasons aligned across code paths

- Audited the two meta-sync paths: in-process helper `scripts/session_state_sync.py` and CLI sync `scripts/sync_state_meta.py`
- Fixed CLI sync drift so `progress.objectives.competition_reasons` is preserved in `sessions/<sid>/meta.json.objective`, matching the in-process path instead of silently dropping evidence/verification rationale
- Added regression coverage in `tests/test_sync_state_meta.py` to exercise the CLI entrypoint and confirm remote-verification status promotion still coexists with retained competition reasons
- Verification: `python3 -m unittest discover -s tests -q` → `72 tests`, passing; `python3 -m compileall core scripts tests` passing
- Why this matters: keeps downstream status/meta consumers from losing *why* a competition target was considered achieved, which is important for evidence review, dashboards, and post-run debugging

## 2026-03-10 21:51 CST — Receipt path validation fixed for underscore stage names

- Audited `core/state_utils.py` receipt-path identity parsing after noticing the canonical filename format includes stage names like `gdb_evidence` and `exploit_l4`
- Fixed `_parse_receipt_path_expectations()` so `stage_receipt_<session>_<loop>_<stage>.json` correctly parses stages containing underscores, instead of silently skipping path/session/loop consistency checks for those receipts
- Added regression coverage in `tests/test_state_utils.py` to prove `exploit_l4_receipt` now trips session/loop mismatch errors just like single-token stages already did
- Verification: `python3 -m unittest discover -s tests -q` → `73 tests`, passing; `python3 -m compileall core scripts tests` passing
- Why this matters: closes a false-negative hole in the evidence/verification flow where later-stage receipts could drift across sessions/loops without being flagged, despite earlier hardening intended to catch exactly that

## 2026-03-10 22:00 CST — CLI meta sync now preserves challenge provenance

- Audited drift between in-process `scripts/session_state_sync.py` and CLI `scripts/sync_state_meta.py`
- Fixed CLI sync so it creates/populates `sessions/<sid>/meta.json.challenge` from state when missing, instead of only mutating pre-existing challenge metadata
- Synced `challenge.import_meta.source_dir` into meta, matching the in-process path and preserving imported challenge provenance for dashboards and post-run review
- Added regression coverage in `tests/test_sync_state_meta.py` for challenge metadata creation/population while keeping the earlier competition-reason path intact
- Verification: `python3 -m unittest tests.test_sync_state_meta -q`, `python3 -m unittest discover -s tests -q` → `74 tests`, and `python3 -m compileall core scripts tests` passing
- Why this matters: removes another state/meta divergence where non-orchestrator syncs could silently drop binary/workdir/source provenance, weakening evidence review and session introspection

## 2026-03-10 22:18 CST — Failure-context verifier evidence compacted

- Audited `scripts/session_stage_post.py` failure reporting path used after stage execution / verifier handoff
- Compacted embedded verifier `stage_evidence` before writing failure-context JSON so reports keep stable summary fields and a short event tail instead of copying arbitrarily large/raw verifier payloads verbatim
- Added regression coverage in `tests/test_session_stage_post.py` to lock the compacted schema and prove truncation/signal preservation for verifier findings
- Verification: `python3 -m unittest tests.test_session_stage_post -q`, `python3 -m unittest discover -s tests -q` → `75 tests`, and `python3 -m compileall core scripts tests` passing
- Why this matters: keeps evidence/verification flow reviewable during exploit failures, reduces report bloat, and makes downstream failure triage consume a more stable verifier summary

## 2026-03-10 22:24 CST — In-process meta sync now shares remote-verification promotion

- Audited drift between in-process `scripts/session_state_sync.py` and CLI `scripts/sync_state_meta.py` around remote verification promotion
- Extracted shared remote-report success heuristics into `core/meta_sync_utils.py` and wired both sync paths to use the same promotion logic
- In-process sync now promotes `sessions/<sid>/meta.json` to `remote_verified` when remote verification artifacts prove success, even if `state.session.remote.last_remote_ok` has not been flipped yet
- Added regression coverage in `tests/test_session_state_sync.py` for report-driven promotion, while preserving the earlier mismatch guard and competition-reason sync behavior
- Verification: `python3 -m unittest tests.test_session_state_sync tests.test_sync_state_meta -q`, `python3 -m unittest discover -s tests -q` → `76 tests`, and `python3 -m compileall core scripts tests` passing
- Why this matters: removes another CLI vs orchestrator drift point in the evidence/state/verification flow, so dashboards and post-run review see the same remote-verification outcome regardless of which sync path ran last

## 2026-03-10 22:58 CST — Benchmark replay now carries portable runtime knobs

- Audited `scripts/replay_benchmarks.py` and noticed benchmark execution was hard-wired to `start_session.sh --no-codex` plus a fixed `run_session.py` invocation, which underfit the stated host-side Codex CLI target runtime
- Refactored benchmark case execution so each case can now describe transferable runtime knobs directly: `start_no_codex`, `start_session_args`, `run_session_args`, and injected `env` (for host-side `CODEX_BIN`, model, and runtime-alignment env like `PWN_*`)
- Added `build_case_commands()` plus strict case-shape validation to keep the replay harness simple but explicit, instead of hiding OpenClaw-specific assumptions inside the driver
- Extended replay reports to record effective start/run commands and env key names per case, making benchmark failures easier to map back to the intended host-like runtime surface
- Updated `benchmarks/README.md` and `benchmarks/cases/template.json` so new cases can encode Codex portability/runtime-adapter expectations instead of relying on repo-local defaults
- Added regression coverage in `tests/test_replay_benchmarks.py` for default init-only behavior, host-like override behavior, and invalid case-shape rejection
- Verification: `python3 -m unittest tests.test_replay_benchmarks -q`, `python3 -m unittest discover -s tests -q` → `79 tests`, and `python3 -m compileall core scripts tests` passing
- Why this matters: moves the benchmark loop closer to the eventual host Codex CLI runtime, keeps the harness portable/adaptable without OpenClaw-specific wiring, and creates a cleaner place to drive future real-challenge benchmark variants from explicit runtime assumptions

## 2026-03-10 23:19 CST — Benchmark success criteria made challenge-facing

- Audited `scripts/replay_benchmarks.py` again and found benchmark success was still mostly `run_session.py` process return code, which is too weak for real pwn/regression work
- Added optional case-level `expect` assertions so each benchmark can declare the minimum acceptable outcome surface: `run_rc`, `final_exit_code`, `acceptance_passed`, `min_objective_score`, `required_success_stages`, `metrics_min`, and exact `state_paths`
- Replay reports now include `expectation_result` with per-check diagnostics, so failures are easier to map to orchestration regressions vs challenge-facing outcome regressions
- Updated `benchmarks/README.md`, `benchmarks/cases/template.json`, and `benchmarks/cases/demo_local.json` to document/use the new expectation model instead of relying on implicit success semantics
- Added regression coverage in `tests/test_replay_benchmarks.py` for expectation parsing, pass/fail evaluation, and invalid expectation shapes
- While smoke-running the benchmark, found two portability/runtime issues that were hidden by the old harness assumptions:
  - `scripts/start_session.sh` invoked `reset_state.sh` directly and failed on hosts where execute bits are missing; fixed by explicitly running it via `bash`
  - `scripts/run_session.py --allow-codex-missing` still hit startup MCP hard-preflight/health gates before the Codex-missing fallback could take effect; adjusted startup flow to skip those Codex-specific gates when the runtime is intentionally absent
- Verification: `python3 -m unittest discover -s tests -q` → `81 tests`, and `python3 -m compileall core scripts tests` passing
- Benchmark finding: `python3 scripts/replay_benchmarks.py --only demo_local --allow-codex-missing` still does not complete quickly in this environment, so the next iteration should inspect where the no-Codex fallback loop is stalling rather than treating the harness as “done”
- Why this matters: benchmark cases now encode solve-facing expectations directly, and the smoke run immediately exposed host-portability / no-Codex recovery flaws that are more valuable than generic framework polish

## 2026-03-10 23:26 CST — No-Codex benchmark fallback is now bounded instead of effectively unending

- Re-ran `python3 scripts/replay_benchmarks.py --only demo_local --allow-codex-missing` to chase the concrete stall from the previous iteration, and confirmed the session was collapsing to terminal-only `exploit_l4` while `exploit_rewrite.until_success=true` expanded the loop budget toward the hard cap
- Extracted loop-budget shaping into `adjust_loop_budget_for_missing_codex()` in `scripts/run_session.py`
- New behavior: when the user explicitly chooses `--allow-codex-missing` and Codex is actually unavailable, terminal exploit rewrite is forcibly downgraded from `until_success` to a tiny bounded retry budget (`extra_loops<=1` by default) instead of inheriting the huge rewrite cap
- Added focused regression coverage in `tests/test_run_session_missing_codex.py` to lock both sides of the behavior: bounded fallback when Codex is missing, unchanged unbounded behavior when Codex is available
- Verification: `python3 -m unittest tests.test_run_session_missing_codex tests.test_replay_benchmarks -q` and `python3 -m compileall scripts tests`
- Benchmark result after fix: the same replay now exits quickly with a normal failure report instead of hanging; the remaining blocker is challenge-facing and concrete (`challenge/demo/chall_true` permission denied, plus no-Codex fallback still skips recon/IDA), which is a much better next-step target than debugging an effectively infinite orchestration loop
- Why this matters: this is a portability/stability win for the host-side benchmark loop — missing Codex now produces fast, inspectable failure evidence instead of pathological rewrite churn that hides the real challenge/runtime problem

## 2026-03-10 23:38 CST — Benchmark harness can now repair missing execute bits explicitly

- Chased the concrete `Permission denied` failure from the previous smoke replay instead of treating it as fixture noise
- Added explicit case-level runtime knob `ensure_binary_executable` to `scripts/replay_benchmarks.py`; when enabled, the harness now preflights the declared case binary and adds owner execute permission before session start if the bit was lost during import/extraction
- Replay results now record `binary_preflight` (path, before/after execute status, whether chmod was applied, error text), so benchmark failures distinguish challenge-package hygiene from orchestration/runtime regressions
- Updated `benchmarks/cases/demo_local.json` to opt into this repair path and documented the knob in `benchmarks/README.md` / `benchmarks/cases/template.json`
- Added regression coverage in `tests/test_replay_benchmarks.py` for both command construction and the execute-bit repair helper
- Verification: `python3 -m unittest tests.test_replay_benchmarks tests.test_run_session_missing_codex -q`, `python3 -m unittest discover -s tests -q` → `84 tests`, `python3 -m compileall core scripts tests`, and `python3 scripts/replay_benchmarks.py --only demo_local --allow-codex-missing`
- Benchmark finding after fix: the replay no longer fails on binary exec permission; it now reaches the real challenge-facing failure surface (`exploit_l4` unsolved because no-Codex fallback still bypasses recon/IDA evidence), which is a much better next target
- Why this matters: this keeps the benchmark loop portable to host-side Codex/CI runs where challenge archives often lose execute bits, while making the remaining failures more representative of actual solve-capability gaps instead of packaging noise

## 2026-03-10 23:50 CST — Missing-Codex benchmark path now prefers portable local recon and passes demo replay

- Chased the next concrete blocker from the smoke benchmark instead of polishing around it: when Codex was intentionally absent, orchestration still collapsed toward terminal exploit, which hid the useful challenge-facing evidence path and kept `demo_local` red
- Added `choose_missing_codex_stage_order()` in `scripts/run_session.py` so the missing-Codex path can prefer a transferable local-recon-only plan when a local binary is present, instead of defaulting straight to terminal exploit
- Added `run_local_recon_fallback()` in `scripts/run_session.py` to generate a real recon receipt/report from portable host tools (`file`, `readelf`, `nm`) and update state/protections/io-profile without depending on OpenClaw-specific runtime behavior
- Wired the no-Codex negative-stage execution path so `recon` succeeds through the new local fallback instead of hard-failing as `codex missing, skipped stage recon`
- When the planner chooses the local-recon-only path, orchestration now disables exploit/rewrite forcing for that run, which keeps the smoke benchmark aligned with the actual available runtime surface instead of manufacturing downstream exploit failures from missing prerequisites
- Fixed a separate finalize-path persistence bug in `scripts/session_run_finalize.py`: final `session.status` is now saved before later reloads, so successful early-stop / recon-only runs do not regress back to stale `running:*` status on disk
- Added regression coverage in `tests/test_run_session_missing_codex.py` for missing-Codex stage-plan selection and the local recon fallback, plus `tests/test_session_run_finalize.py` for final-status persistence across finalize reloads
- Verification:
  - `python3 -m unittest tests.test_session_run_finalize tests.test_run_session_missing_codex tests.test_replay_benchmarks -q`
  - `python3 -m unittest discover -s tests -q` → `87 tests`, passing
  - `python3 scripts/replay_benchmarks.py --only demo_local --allow-codex-missing` → `cases_ok=1`, `success_rate=1.0`
- Benchmark result after fix: `benchmarks/cases/demo_local.json` now passes under the intentional no-Codex smoke path with `recon` success, `exit_code=0`, and `session.status=finished`
- Why this matters: this is a direct host-portability / benchmark-loop improvement, not OpenClaw polish — missing Codex now yields a bounded, inspectable, challenge-facing recon run that can transfer to host CLI/CI environments and serve as a better baseline for the next real capability step (e.g. local gdb evidence or richer static fallback)

## 2026-03-10 23:59 CST — Benchmark replay can now force fresh execution instead of cache-green runs

- Audited the supposedly-green `demo_local` replay output and found the previous pass was actually satisfied via `stage_cache_hit=true` on `recon`, which is a weak benchmark signal for real regression work
- Added case-level preflight knob `clear_cached_artifacts` to `scripts/replay_benchmarks.py`; when enabled, the harness now removes binary-sha-scoped stage/exploit cache artifacts before the run so smoke/replay cases can demand a fresh solve path
- Added expectation field `expect.forbid_stage_cache_hits` so a case can explicitly fail if specific stages succeed only by replaying cached patches instead of executing this run’s runtime surface
- Replay reports now include `cache_preflight` (binary sha + removed cache files), making it obvious whether a case exercised a cold path or leaned on prior artifacts
- Updated `benchmarks/README.md`, `benchmarks/cases/template.json`, and `benchmarks/cases/demo_local.json` so the demo smoke case now clears its binary-scoped cache and asserts that `recon` must complete without a stage-cache hit
- Added regression coverage in `tests/test_replay_benchmarks.py` for cache clearing and no-cache-hit expectation evaluation
- Verification:
  - `python3 -m unittest tests.test_replay_benchmarks -q`
  - `python3 -m unittest discover -s tests -q` → `88 tests`, passing
  - `python3 -m compileall scripts tests`
  - `python3 scripts/replay_benchmarks.py --only demo_local --allow-codex-missing`
- Benchmark result after fix: `demo_local` still passes, but now with `cache_preflight.removed=[..._recon.json]` and `stage_results[0].stage_cache_hit=false`, so the green result reflects a real portable local-recon execution instead of a stale cache replay
- Why this matters: this tightens the benchmark loop around actual host-portable behavior, exposes cache-masked regressions earlier, and keeps future challenge-facing iterations honest without adding OpenClaw-specific machinery

## 2026-03-11 00:15 CST — Missing-Codex path can now capture portable local gdb crash evidence

- Continued from the host-portability benchmark work instead of adding more framework polish: audited the remaining no-Codex negative-stage path in `scripts/run_session.py` and found `gdb_evidence` was still hard-skipped even when a host had a local binary plus plain `gdb`
- Added `run_local_gdb_fallback()` plus small parsers for signal/register/mapping extraction so the missing-Codex path can now use stock host tooling (`gdb -batch`) to collect crash evidence, derive `mappings.pie_base` / `gdb.pc_offset`, and write the required portable artifacts (`gdb_raw`, `gdb_summary`, `gdb_clusters`, `capabilities_report`)
- Wired the stage executor so `gdb_evidence` now attempts this local fallback before declaring the stage skipped when Codex is unavailable; this keeps the runtime-adapter boundary cleaner by preserving stage semantics while swapping in a host-portable evidence source
- Added regression coverage in `tests/test_run_session_missing_codex.py` for both the success path (evidence/artifacts/state updated from mocked `gdb` output) and the bounded failure path (`gdb_no_crash_signal` when the probe exits normally)
- Verification:
  - `python3 -m unittest tests.test_run_session_missing_codex -q`
  - `python3 -m unittest discover -s tests -q` → `90 tests`, passing
  - `python3 -m compileall scripts tests`
  - `python3 scripts/replay_benchmarks.py --only demo_local --allow-codex-missing` still passes (`cases_ok=1`)
- Why this matters: it expands real host-side recoverability/capability in the exact place the charter cares about — when Codex CLI is absent or intentionally disabled, Dirge can now still harvest transferable dynamic evidence with plain local tooling instead of collapsing to “stage skipped”, which is a better substrate for future crash-driven benchmark cases and exploit synthesis loops

## 2026-03-11 00:37 CST — Cold benchmark now exercises fresh local recon + gdb evidence, and exposed/fixed a real gdb invocation bug

- Pushed the benchmark loop one step closer to a real host-side challenge workflow instead of stopping at recon: added explicit local-gdb stdin seeding via `DIRGE_LOCAL_GDB_STDIN_TEXT` / `HEX` / `FILE`, and taught `choose_missing_codex_stage_order()` to prefer `recon + gdb_evidence` when the operator explicitly asks for that portable path
- While validating the new case, found a concrete runtime bug the mocked unit tests had missed: `run_local_gdb_fallback()` was building `gdb -batch` as `... --args <bin> -ex ...`, which meant gdb never executed the scripted commands in the intended order and produced false `gdb_no_crash_signal` failures on a real host
- Fixed the command construction so all `-ex` commands are emitted before `--args <bin>`, matching stock host `gdb` behavior and making the fallback genuinely transferable to the user’s eventual Codex-CLI runtime
- Added a new benchmark fixture under `challenge/bench_local_gdb/` plus `benchmarks/cases/demo_local_gdb.json`; it is intentionally small but challenge-like enough to require a real crash-triggering stdin seed and produce fresh `recon` + `gdb_evidence` artifacts without Codex
- Extended regression coverage in `tests/test_run_session_missing_codex.py` for seeded local-gdb stage-plan selection, stdin-source parsing, and the real command ordering contract passed into `_run_capture_quick()`
- Updated `benchmarks/README.md` and `benchmarks/cases/template.json` so future cases can encode crash-triggering local gdb inputs directly instead of hiding them in ad-hoc wrapper scripts
- Verification:
  - `python3 -m unittest tests.test_run_session_missing_codex tests.test_replay_benchmarks tests.test_session_run_finalize -q`
  - `python3 scripts/replay_benchmarks.py --only demo_local_gdb --allow-codex-missing` → `cases_ok=1`, `success_rate=1.0`, with required successful stages `recon` + `gdb_evidence` and no cache hits on either stage
- Why this matters: the benchmark loop now covers real dynamic-evidence collection on a cold no-Codex path, and it already paid for itself by surfacing/fixing a portability bug that would have broken host-side Codex CLI runs despite the earlier synthetic tests being green

## 2026-03-11 01:42 CST — Full regression and cold local-gdb benchmark reconfirmed clean

- Re-ran the full suite after the portability-oriented benchmark/fallback changes to make sure the branch is coherent instead of only locally green on targeted tests
- Verification:
  - `python3 -m unittest discover -s tests -q` → `93 tests`, passing
  - `python3 scripts/replay_benchmarks.py --only demo_local_gdb --allow-codex-missing` → passing again with expectation checks satisfied (`recon` + `gdb_evidence`, no cache hits, `session.status=finished`)
- Also cleaned this iteration log by removing an accidentally duplicated `00:15 CST` section so the progress trail stays audit-friendly
- Why this matters: this converts the current work from “likely good” into a cold-path-verified portability slice that is easier to trust, bisect, and carry over to the eventual host-side Codex CLI runtime

## 2026-03-11 01:52 CST — Benchmark expectations now assert concrete crash evidence, not just stage green-ness

- Tightened `scripts/replay_benchmarks.py` so `expect.state_paths` supports simple array indexing (for example `dynamic_evidence.evidence[0].gdb.signal`), instead of only flat dotted object lookups
- Upgraded the cold no-Codex gdb benchmark case in `benchmarks/cases/demo_local_gdb.json` to assert concrete portable evidence surfaced by the run: `capabilities.has_crash=true`, first crash signal `SIGSEGV`, and first recorded stdin source `text-env`
- Extended `tests/test_replay_benchmarks.py` to lock the new indexed state-path expectation behavior against synthetic `dynamic_evidence` state
- Updated `benchmarks/README.md` to document indexed `state_paths` assertions for future challenge-like cases
- Verification:
  - `python3 -m unittest tests.test_replay_benchmarks tests.test_run_session_missing_codex tests.test_session_run_finalize -q`
  - `python3 -m unittest discover -s tests -q` → `93 tests`, passing
  - `python3 scripts/replay_benchmarks.py --only demo_local_gdb --allow-codex-missing` → passing with expectation checks now proving crash evidence fields, not only `recon`/`gdb_evidence` stage success

## 2026-03-11 03:11 CST — Benchmark harness now proves artifacts belong to the current session, not just “some existing file”

- Audited `scripts/replay_benchmarks.py` expectation coverage again and found a remaining false-green hole: `expect.report_paths` only verified that a path existed, so a replay could still pass while pointing at stale or cross-session artifacts if the path field was wrong but happened to exist
- Added `expect.report_path_contains` to `scripts/replay_benchmarks.py`; benchmark cases can now assert that specific output paths contain a required substring, with `{{SESSION_ID}}` placeholder expansion for the current replay session
- Upgraded `benchmarks/cases/demo_local_gdb.json` and `benchmarks/cases/template.json` so the benchmark loop can require summary/acceptance/timeline/stage-receipt paths to carry the live session id, making cold-path greens harder to fake via stale artifact references
- Extended `tests/test_replay_benchmarks.py` for placeholder parsing, positive path-substring checks, and invalid empty `report_path_contains` shapes
- Verification:
  - `python3 -m unittest tests.test_replay_benchmarks -q`
  - `python3 -m unittest discover -s tests -q` → `96 tests`, passing
  - `python3 scripts/replay_benchmarks.py --only demo_local_gdb --allow-codex-missing` → passing, with expectation output now explicitly showing report/stage-receipt paths contain the fresh `bench_demo_local_gdb_<ts>` session id
- Why this matters: it tightens the real benchmark loop around recoverability and evidence correctness, not just process success — Dirge now checks that the artifacts it claims as proof of progress were actually produced for this run, which is exactly the kind of session-flow integrity a host-side Codex CLI runtime will need

## 2026-03-11 03:21 CST — Benchmark expectations now verify artifact payload identity, not only filenames

- Audited the still-green cold benchmark output and found one more evidence-integrity gap: `expect.report_path_contains` proved paths looked fresh, but it still could not catch a path pointing at a JSON artifact whose embedded `session_id` / `stage` / `loop` payload was stale or mismatched
- Added `expect.report_json_paths` to `scripts/replay_benchmarks.py`; benchmark cases can now point at a JSON-valued artifact path from `run_session.py` output and assert dotted/indexed fields inside that artifact, with the same `{{SESSION_ID}}` placeholder expansion used elsewhere
- Upgraded `benchmarks/cases/demo_local_gdb.json` so the cold portable benchmark now verifies embedded identity in the acceptance report and both stage receipts (`session_id`, `loop`, `stage`, `result.ok`), not just the outer filenames
- Updated `benchmarks/README.md` and `benchmarks/cases/template.json` so future challenge-like cases can lock receipt/report payload identity directly instead of only checking path existence or substrings
- Extended `tests/test_replay_benchmarks.py` for valid/invalid `report_json_paths` parsing plus positive expectation evaluation against synthetic summary/receipt JSON files
- Verification:
  - `python3 -m unittest tests.test_replay_benchmarks -q`
  - `python3 -m unittest discover -s tests -q` → `98 tests`, passing
  - `python3 scripts/replay_benchmarks.py --only demo_local_gdb --allow-codex-missing` → passing with acceptance/receipt payload identity checks satisfied
- Why this matters: this closes another false-green lane in the benchmark harness by requiring the evidence payload itself to belong to the current run, which is directly useful for recoverability, debugging, and future host-side regression gating

## 2026-03-12 22:18 CST — State-path benchmark expectations now lock session identity, and fresh replay exposed two live local-gdb regressions

- Audited `scripts/replay_benchmarks.py` again for remaining false-green seams and found that `expect.state_paths` still compared raw literals only, unlike `report_path_contains` / `report_json_paths`; that meant benchmark cases could lock artifact filenames/payloads to the current session but still could not assert that the loaded state itself belonged to the current replay session.
- Updated `scripts/replay_benchmarks.py` so `expect.state_paths` also expands `{{SESSION_ID}}`, and now records both the expanded value and original raw expectation in per-check diagnostics.
- Extended `tests/test_replay_benchmarks.py` synthetic state coverage to assert `session.session_id` and `challenge.import_meta.session_id` through the new placeholder path.
- Upgraded `benchmarks/cases/demo_local_gdb.json`, `benchmarks/cases/template.json`, and `benchmarks/README.md` so the benchmark contract can explicitly require state-level session identity, not just fresh-looking report filenames.
- Verification:
  - `python3 -m unittest tests.test_replay_benchmarks` → passing
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_local_gdb` → passing with new `state_paths.session.session_id == {{SESSION_ID}}` / `challenge.import_meta.session_id == {{SESSION_ID}}` checks satisfied
- While refreshing replay, found a more important benchmark-facing issue that should not be hidden: targeted no-Codex local-gdb cases `demo_local_nonpie_sendline` and `demo_local_offset` now reproduce expectation failures on this host even though stage execution itself still returns green. Current evidence shape regresses to `capabilities.offset_to_rip=0` / missing `gdb.offset_to_rip` / missing seeded-input metadata, and the non-PIE sendline case also reports `pie_base=0x401170` with `pc_offset=0x0` instead of the expected base+offset split.
- Reproduced failures with:
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --only local_nonpie_sendline`
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --only local_offset`
- Why this matters: the new placeholder support tightens replay honesty for both OpenClaw and host-side Codex-style runs, and the newly surfaced offset/control regressions are exactly the kind of real challenge-facing evidence bug the next cycle should chase instead of papering over with broader baseline assumptions.

## 2026-03-11 04:02 CST — Benchmark contract now locks the chosen runtime-adapter path via `notes[]`

- Audited the current cold benchmark again and found one remaining portability blind spot: even with stage/evidence/receipt checks, the replay harness still could not assert *which runtime-adapter path* produced the green result
- Added `expect.notes_contains` and `expect.notes_absent` to `scripts/replay_benchmarks.py`, so cases can now fail if `run_session.py` stops emitting the expected portable-path notes or starts advertising a forbidden/legacy runtime path
- Upgraded `benchmarks/cases/demo_local.json`, `benchmarks/cases/demo_local_gdb.json`, and `benchmarks/cases/template.json` to lock the intentional no-Codex portable paths (`portable local recon fallback`, `portable local recon + local gdb evidence fallback`) and explicitly forbid a placeholder OpenClaw-specific fallback string
- Extended `tests/test_replay_benchmarks.py` for parsing, positive evaluation, and invalid-shape rejection of the new `notes[]` expectations
- Refreshed `benchmarks/baseline/latest.json` after the stricter contract change, then re-ran `python3 scripts/replay_benchmarks.py --allow-codex-missing --gate` to confirm the updated baseline still passes cleanly
- Verification:
  - `python3 -m unittest tests.test_replay_benchmarks -q`
  - `python3 -m unittest discover -s tests -q` → `98 tests`, passing
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --write-baseline benchmarks/baseline/latest.json`
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --gate` → gate passing with the stricter contract
- Why this matters: the benchmark loop now guards not just outputs, but also the portability-critical routing decision that produced them, which should make future host-Codex migration regressions show up earlier instead of quietly “passing” through a different execution surface

## 2026-03-11 04:09 CST — `until_success` rewrite mode no longer bypasses hard stop conditions

- Audited the newly touched loop-finalize path and found a real recoverability/stability bug: when `exploit_rewrite.until_success=true`, `evaluate_loop_stop()` skipped `evaluate_exploit_rewrite_stop()` entirely, so hard stop guards like rewrite wall-time and same-error streak could be silently bypassed
- Tightened `scripts/session_loop_finalize.py` so terminal-unsolved rewrite loops always evaluate the hard stop policy; `until_success` now only disables the extra-loop budget check by forcing an unbounded synthetic budget, instead of suppressing the whole stop evaluator
- Added/updated regression coverage in `tests/test_session_loop_finalize.py` and `tests/test_session_orchestrators.py` to prove the intended behavior on both sides: `until_success` still continues past normal extra-loop budget pressure, but now stops once hard rewrite guards (for example wall-time limit) fire
- Verification:
  - `python3 -m unittest tests.test_replay_benchmarks tests.test_session_loop_finalize tests.test_session_orchestrators -q`
  - `python3 -m unittest discover -s tests -q` → `98 tests`, passing
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --gate` → passing
- Why this matters: this is a direct host-runtime stability fix, not framework polish — exploit rewrite can still stay aggressive when asked, but it no longer has an accidental infinite/unsafe tail when the portable runtime has already proven it is stuck

## 2026-03-12 22:34 CST — Local no-Codex gdb fallback now restores seeded-input metadata and non-PIE offset evidence

- Chased the concrete replay regressions surfaced in the previous cycle instead of relaxing the benchmark contract: `demo_local_nonpie_sendline` and `demo_local_offset` were stage-green but still failing expectation checks because `run_local_gdb_fallback()` had drifted from the shared seed/gdb parsing logic.
- Root causes found in `scripts/run_session.py`:
  - local fallback parsed `pie_base` from the whole combined gdb transcript, so non-PIE runs could latch onto a backtrace/register address (`0x401170`) instead of the binary mapping base (`0x400000`)
  - local fallback still used its own minimal stdin selector and never emitted shared seed metadata (`stdin_kind`, cyclic-window fields), so replay could not prove how the crash was triggered
  - local fallback never issued a stack probe or recovered `offset_to_rip` from cyclic input + stack words, so capability/state summaries stayed at `offset_to_rip=0` even when the crash clearly showed control on the stack
- Fixed `run_local_gdb_fallback()` to reuse the shared capability core instead of another one-off parser:
  - switched seed selection to `core.stdin_seed_utils.select_seed_input()`
  - added shared cyclic-window detection and persisted `kind`, `stdin_source`, `cyclic_compatible`, `cyclic_window_len`, and `cyclic_span` into `dynamic_evidence.inputs[]`
  - added ABI-aware stack probing via `core.gdb_evidence_utils.stack_probe_command()`
  - parsed mappings/registers with the shared gdb helpers and restricted `parse_pie_base()` to the mappings block, fixing the non-PIE base/offset split
  - recovered `offset_to_rip` from cyclic-compatible seeded input plus stack/rip words and propagated it into `dynamic_evidence.evidence[].gdb`, `state.gdb`, `capabilities`, and `latest_bases`
- Added regression coverage in `tests/test_run_session_missing_codex.py` for:
  - seeded-text metadata persistence on the local fallback path
  - a synthetic non-PIE cyclic-sendline crash that now proves `pie_base=0x400000`, `pc_offset=0x1170`, and `offset_to_rip=88`
- Verification:
  - `python3 -m unittest tests.test_run_session_missing_codex -q`
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --only local_nonpie_sendline`
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --only local_offset`
  - `python3 -m unittest tests.test_run_session_missing_codex tests.test_replay_benchmarks -q`
- Result: both previously red targeted local-gdb no-Codex replay cases are green again with the stronger benchmark contract still intact.
- Important failure visibility / deferred follow-up:
  - `python3 -m unittest tests.test_run_session_missing_codex tests.test_replay_benchmarks tests.test_gdb_direct_probe -q` currently fails before running the direct-probe tests because `tests.test_gdb_direct_probe` imports `_abi_info` from `scripts.gdb_direct_probe`, but that symbol is not currently exported there. This appears to be a pre-existing direct-probe/unit-test drift, not a regression introduced by the local-fallback fix.
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --gate` is still red against the checked-in baseline, but not because the two local offset/sendline regressions remain. The current gate deltas are: `demo_local_file_nonpie_cwd_dotfile` improved relative to the stale baseline (`run_rc/final_exit_code` now `0` instead of `1`), while `demo_local_gdb_stale_nocontrol` and `demo_local_nocontrol` still regress. Those remaining `nocontrol` cases are the next concrete benchmark-facing seam.
- Why this matters: this directly improves real challenge-facing evidence quality on the portable no-Codex runtime path used by both OpenClaw and eventual host-side Codex CLI runs. The framework now preserves *how* a crash was triggered and whether control/offset evidence was actually recovered, instead of only marking the stage green.

## 2026-03-12 22:49 CST — Capability inference now lets fresh no-control gdb evidence clear stale RIP-control state

- Reproduced the remaining benchmark seam instead of refreshing the baseline blindly:
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --only local_nocontrol`
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --only local_gdb_stale_nocontrol`
- Both cases were failing for the same real reason: the local fallback had already written `gdb.control_rip=false` / `gdb.offset_to_rip=0`, but top-level `state.capabilities` still stayed at stale `control_rip=true` / `rip_control=yes`.
- Root cause was in `core/capability_engine.py`, not the fallback collector itself:
  - `_find_control_rip()` trusted pre-existing top-level `capabilities.control_rip` before looking at fresh `dynamic_evidence`
  - it also treated any non-zero `gdb.pc_offset` as proof of RIP control, which is wrong for plain crashes because code-location offset and saved-return-address control are not the same thing
  - once `control_rip` dropped false, `offset_to_rip` was not being cleared from the inferred capability snapshot
- Fixed `core/capability_engine.py` so capability inference now:
  - prefers fresh `dynamic_evidence.evidence[].gdb` over stale top-level capability state whenever dynamic evidence exists
  - only infers RIP control from explicit `gdb.control_rip` or positive `gdb.offset_to_rip`, not from mere `pc_offset`
  - clears stale `capabilities.offset_to_rip` when fresh evidence says control was not recovered
- Verification:
  - `python3 -m unittest tests.test_capability_engine tests.test_run_session_missing_codex tests.test_replay_benchmarks -q`
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --only local_nocontrol`
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --only local_gdb_stale_nocontrol`
  - `python3 scripts/replay_benchmarks.py --allow-codex-missing --gate`
- Result:
  - `demo_local_nocontrol` and `demo_local_gdb_stale_nocontrol` are green again
  - replay gate now only reports one delta: `demo_local_file_nonpie_cwd_dotfile` is improved relative to the checked-in baseline (`run_rc/final_exit_code` old `1` -> current `0`), which looks like stale baseline data rather than a fresh regression
- Important failure visibility / deferred follow-up:
  - attempted `python3 -m unittest discover -s tests -q` to validate whether baseline refresh would be responsible, but the full suite is currently red for broader pre-existing drift unrelated to this seam. The failing concentration is in `tests.test_codex_with_mcp`, `tests.test_health_check_mcp`, `tests.test_codex_cli_adapter`, and `tests.test_start_session`, with representative failures showing checked-in config/path expectations and wrapper auth/launcher behavior drifting from current code. Because of that broader red baseline, I did **not** treat a full-suite-green claim as part of this cycle and did **not** rely on it to justify a baseline rewrite.
- Why this matters: this is a portability/stability fix with direct benchmark value. Fresh no-control evidence now actually downgrades exploitability conclusions instead of leaving stale RIP-control state behind, which improves routing/recovery decisions for both OpenClaw runs and future host-side Codex CLI sessions.

## 2026-03-12 23:09 CST — Replay baseline refreshed after confirming the last gate delta was stale data, not a fresh regression

- Re-ran the full replay gate with `python3 scripts/replay_benchmarks.py --allow-codex-missing --gate` and confirmed the only remaining delta was `demo_local_file_nonpie_cwd_dotfile` versus stale checked-in baseline values (`run_rc/final_exit_code` old `1` -> current `0`).
- Verified this was a benchmark-maintenance issue rather than a new runtime failure: the case now completes with the expected portable local path (`recon` + `gdb_evidence`, acceptance passed, local fallback notes intact), so leaving the old baseline in place would only keep the gate artificially red.
- Refreshed the checked-in replay baseline with `python3 scripts/replay_benchmarks.py --allow-codex-missing --write-baseline benchmarks/baseline/latest.json`.
- Verification after refresh: the write-baseline run completed successfully and produced a new baseline from the current 24-case suite (`23` executed / `1` skipped) with gate enforcement back to green on the same portable no-Codex replay surface.
- Important failure visibility / deferred follow-up:
  - I did **not** treat the broader unit-test situation as fixed; `python3 -m unittest discover -s tests -q` is still known-red from older wrapper/health/start-session drift plus the `tests.test_gdb_direct_probe` import mismatch, and this baseline refresh should not be read as a substitute for repairing those suites.
  - I did **not** make a local commit this cycle because the repository worktree still contains a large amount of pre-existing unrelated churn/untracked files; a clean commit should be split once the intended tracked subset is isolated.
- Why this matters: it restores an honest green replay gate for the current portable benchmark contract instead of leaving the project stuck behind stale expectations, while still keeping real unresolved test/runtime drift visible for the next cycles.

## 2026-03-12 23:31 CST — Direct gdb probe adapter re-aligned with shared helpers; unit slice green again, replay seam still visible

- Chased a concrete portability/test drift that was still explicitly called out in working state: `tests.test_gdb_direct_probe` could not even import because `scripts/gdb_direct_probe.py` had fallen far behind the shared ABI/stack/stdin helper layer and modern `gdb-mcp` surface.
- Reworked `scripts/gdb_direct_probe.py` to stop acting like an old machine-private one-off and instead align with the current portable contract:
  - re-used shared ELF ABI / stack parsing / PC-offset helpers from `core.gdb_evidence_utils`
  - re-used shared stdin seed selection / cyclic-window behavior from `core.stdin_seed_utils`
  - repo-anchored relative `--state` paths again
  - accepted PATH-discovered `gdb-mcp` without forcing a fake cwd
  - restored modern/legacy MCP tool-surface compatibility (`gdb_start` / `gdb_terminate` and `start_binary` / `stop_session`)
  - normalized JSON-wrapped live-style `gdb_command` output before parsing
  - cleared stale offset/control hints when fresh direct-gdb evidence no longer proves control
  - updated state/report emission so direct-probe outputs again carry the expected `gdb.mode/source/stdin_*` fields used by replay assertions
- Verification:
  - `python3 -m unittest tests.test_gdb_direct_probe -q` → `36 tests`, passing
  - `python3 -m unittest tests.test_run_session_missing_codex tests.test_replay_benchmarks -q` → passing (`21 tests`)
- Important failure visibility / deferred follow-up:
  - Fresh benchmark run `python3 scripts/replay_benchmarks.py --allow-codex-missing --only demo_direct_gdb_nonpie` is still red.
  - Current failure is no longer adapter import drift; it is benchmark-facing orchestration drift: `run_session.py --allow-codex-missing --no-fast` only executes `recon` and never reaches `gdb_evidence`, so replay expectations for direct-gdb evidence/state stay unmet.
  - I am intentionally logging that failure instead of masking it with a baseline tweak, because the next useful cycle should decide whether the direct no-fast/missing-Codex stage planner regressed or whether replay case/runtime selection is still bypassing the intended direct-probe path.
- Why this matters: it restores a transferable direct-gdb runtime adapter for both OpenClaw and host-style Codex environments, and it narrows the remaining problem from “adapter/test drift” to a more valuable benchmark-visible orchestration seam.
