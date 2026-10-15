"""Processing time versus a manual baseline.

The automated side is measured. The manual side is an ASSUMPTION: how long an
analyst takes to look one indicator up in one feed and write the result down.
The default is a placeholder, not a measurement; replace it with timed analyst
runs before quoting any speed-up.
"""

from __future__ import annotations

import statistics
import time
from pathlib import Path
from typing import Any

from .pipeline import run_scenario

DEFAULT_MANUAL_SECONDS_PER_LOOKUP = 30.0


def benchmark(
    scenario_dir: str | Path,
    manual_seconds_per_lookup: float = DEFAULT_MANUAL_SECONDS_PER_LOOKUP,
    feeds_checked_manually: int = 2,
    repeat: int = 5,
) -> dict[str, Any]:
    totals: list[float] = []
    indicators = 0
    stages: dict[str, list[float]] = {}
    for _ in range(max(1, repeat)):
        start = time.perf_counter()
        run = run_scenario(scenario_dir)
        totals.append(time.perf_counter() - start)
        indicators = len(run.verdicts)
        for name, secs in run.seconds.items():
            stages.setdefault(name, []).append(secs)
    automated = statistics.median(totals)
    manual = indicators * feeds_checked_manually * manual_seconds_per_lookup
    return {
        "indicators": indicators,
        "runs": len(totals),
        "automated_seconds_median": automated,
        "stage_seconds_median": {k: statistics.median(v) for k, v in stages.items()},
        "manual_seconds_assumed": manual,
        "manual_assumption": (
            f"{manual_seconds_per_lookup:g} s per indicator per feed x {feeds_checked_manually} feeds; "
            "a placeholder, not a measurement"
        ),
        "speedup_vs_assumed_manual": manual / automated if automated else float("inf"),
    }


def _speedup(x: float) -> str:
    return "over 1000x" if x > 1000 else f"~{x:.0f}x"


def format_benchmark(b: dict[str, Any]) -> str:
    stages = ", ".join(f"{k} {v * 1000:.1f} ms" for k, v in b["stage_seconds_median"].items())
    return "\n".join([
        f"{b['indicators']} indicators, median of {b['runs']} runs",
        f"automated:  {b['automated_seconds_median'] * 1000:.1f} ms ({stages})",
        f"manual:     {b['manual_seconds_assumed']:.0f} s  [ASSUMED: {b['manual_assumption']}]",
        f"speed-up:   {_speedup(b['speedup_vs_assumed_manual'])} against that assumption (not a measured baseline; tiny synthetic dataset)",
        "Automation does not replace analyst review of the results; it removes the lookup and bookkeeping time.",
    ])
