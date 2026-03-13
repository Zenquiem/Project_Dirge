# bench_local_nonpie

Tiny local benchmark fixture for portable no-Codex `gdb_evidence` on a non-PIE binary.

- Built with `-no-pie`
- Reads up to 400 bytes into a 64-byte stack buffer
- Intended to crash on a cyclic pattern so the local gdb fallback can recover `pc_offset`/`offset_to_rip` even when `info proc mappings` does not yield a PIE mapping
