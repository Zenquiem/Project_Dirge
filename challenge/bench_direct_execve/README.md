# bench_direct_execve

Tiny local benchmark fixture for a non-ret2win shared exploit path.

- Built with `-no-pie`
- Contains a real `get_shell()` / `execve("/bin/sh", ...)` target plus `/bin/sh` string
- Main reads 400 bytes into a 64-byte stack buffer
- Intended to drive `recon -> gdb_evidence -> exploit_l3` into the shared `direct_execve_shell` strategy
- Gives Project_Dirge a real replayable non-ret2win exploit slice, instead of proving verify-learned fact retention only with focused unit tests
