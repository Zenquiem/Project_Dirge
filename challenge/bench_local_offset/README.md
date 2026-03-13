# bench_local_offset

Tiny local benchmark fixture for portable no-Codex `gdb_evidence` offset recovery.

- Reads up to 400 bytes into a 64-byte stack buffer
- Intended to crash on a cyclic pattern so `run_session.py` can recover `offset_to_rip`
- Built for local host-side smoke/regression coverage, not as a real challenge
