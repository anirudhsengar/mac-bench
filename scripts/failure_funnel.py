#!/usr/bin/env python3
"""Trace every missed benchmark case to the pipeline stage where it was lost.

For each run and each benchmark case that the run did NOT get credit for, the final
AssessmentState is inspected to decide where the case fell out:

  not_mapped          no endpoint for the case's route was ever recorded
  not_assigned        the route was recorded but never handed to verification
                      (multi-agent: the Coordinator never assigned it; single agent: never tested)
  not_attempted       the route was verified, but no claim was ever submitted for this case
                      (for DVWA graded cases: this security level was never exploited)
  agent_rejected      the agent submitted the case as rejected or inconclusive
  oracle_rejected     the agent claimed it confirmed, but the evidence failed the oracle

Usage: failure_funnel.py <results_subdir> [<results_subdir> ...]
Writes <results_subdir>/summary/failure_funnel.json and prints a per-architecture table.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from mac_bench.config import repo_root
from mac_bench.evaluation.metrics import BENCHMARK_CASE_IDS
from mac_bench.oracles.verify_oracles import CASE_ROUTE, adjudicate_finding_against_oracle, match_benchmark_case
from mac_bench.schemas import FindingRecord

STAGES = ["not_mapped", "not_assigned", "not_attempted", "agent_rejected", "oracle_rejected"]


def _route_eps(state: dict, case: str) -> list[dict]:
    target, frag = CASE_ROUTE[case]
    return [
        ep for ep in state.get("endpoints", [])
        if ep.get("target") == target and frag in urlsplit(ep.get("url", "")).path.lower()
    ]


def classify_miss(state: dict, case: str) -> str:
    claims = []
    for raw in state.get("findings", []):
        f = FindingRecord.model_validate(raw)
        if match_benchmark_case(f) == case:
            claims.append((f.verdict, adjudicate_finding_against_oracle(f)["oracle_label"]))
    if any(v == "confirmed" for v, _ in claims):
        return "oracle_rejected"
    if claims:
        return "agent_rejected"
    eps = _route_eps(state, case)
    route_tested = any(
        ep.get("verification_attempts", 0) > 0 or ep.get("task_status") in ("verified", "rejected") for ep in eps
    )
    # A claim for a sibling level on the same route also proves the route reached verification.
    target, frag = CASE_ROUTE[case]
    sibling_claim = any(
        r.get("target") == target and frag in urlsplit(r.get("endpoint_url", "")).path.lower()
        for r in state.get("findings", [])
    )
    if route_tested or sibling_claim:
        return "not_attempted"
    if eps:
        return "not_assigned"
    return "not_mapped"


def analyse(subdir: str) -> dict:
    res = repo_root() / "results" / subdir
    by_arch: dict[str, Counter] = defaultdict(Counter)
    by_case: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    misses = 0
    for trial in sorted((res / "trials").glob("trial_*.json")):
        run = json.loads(trial.read_text(encoding="utf-8"))
        arch = run["architecture"]
        state = run.get("state", {})
        credited = set()
        for raw in state.get("findings", []):
            f = FindingRecord.model_validate(raw)
            o = adjudicate_finding_against_oracle(f)
            if o["benchmark_aligned"] and o["oracle_label"] == "confirmed":
                credited.add(o["case_id"])
        for case in BENCHMARK_CASE_IDS:
            if case in credited:
                continue
            stage = classify_miss(state, case)
            by_arch[arch][stage] += 1
            by_case[arch][case][stage] += 1
            misses += 1
    out = {
        "results_subdir": subdir,
        "total_misses": misses,
        "by_architecture": {a: {s: c[s] for s in STAGES} for a, c in by_arch.items()},
        "by_case": {a: {k: dict(v) for k, v in cases.items()} for a, cases in by_case.items()},
    }
    (res / "summary").mkdir(parents=True, exist_ok=True)
    (res / "summary" / "failure_funnel.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    for subdir in sys.argv[1:]:
        out = analyse(subdir)
        print(f"== {subdir} (misses: {out['total_misses']})")
        for arch, stages in out["by_architecture"].items():
            print(f"  {arch:15s} " + "  ".join(f"{s}={n}" for s, n in stages.items()))
        for arch, cases in out["by_case"].items():
            for case, stages in sorted(cases.items()):
                print(f"    {arch[:2]} {case:24s} {stages}")


if __name__ == "__main__":
    main()
