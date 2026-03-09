from __future__ import annotations

from typing import Callable, List, Tuple


def detect_bundle_plan(
    stages: List[str],
    *,
    enabled: bool,
    include_exploit_stages: bool,
    exploit_stage_level_fn: Callable[[str], int],
    require_consecutive: bool = True,
) -> Tuple[bool, str, List[str]]:
    if not enabled:
        return False, "", []

    core = ["recon", "ida_slice", "gdb_evidence"]
    present = [stage for stage in core if stage in stages]
    if len(present) < 3:
        return False, "", []

    ordered = [stage for stage in stages if stage in core]
    if include_exploit_stages:
        ordered.extend([stage for stage in stages if exploit_stage_level_fn(stage) >= 0])
    ordered = list(dict.fromkeys(ordered))

    if require_consecutive:
        indices = [stages.index(stage) for stage in core]
        if not (indices[0] < indices[1] < indices[2]):
            return False, "", []

    trigger = ordered[0] if ordered else ""
    return bool(trigger), trigger, ordered
