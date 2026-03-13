# bench_local_nocontrol

Small local crash fixture for the no-Codex portable gdb path.

Behavior:
- reads stdin
- intentionally crashes via NULL dereference
- does **not** provide RIP control

Purpose:
- prove Dirge can distinguish "has crash / has pc_offset" from actual `control_rip`
- guard against false-positive exploit routing in the host-portable local gdb fallback
