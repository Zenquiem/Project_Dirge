# bench_local_gdb

Tiny local benchmark fixture for the no-Codex portable path.

Behavior:
- reads one line into a stack buffer
- if the line starts with `CRASH`, it dereferences NULL and crashes
- otherwise exits normally

Purpose:
- exercise `recon + gdb_evidence` under `--allow-codex-missing`
- keep the benchmark reproducible on a plain host with only gcc + gdb
