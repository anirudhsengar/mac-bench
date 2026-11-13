#!/usr/bin/env python3
"""Discard trial pairs in which any upstream LLM call failed (e.g. a provider outage).

A run whose model calls returned a non-200 status measured the provider, not the agent, so its
whole pair (both architectures) is deleted and must be rerun with run_trials.py --resume.
Usage: invalidate_failed_pairs.py <results_subdir>   Prints the invalidated trial indices.
"""
from __future__ import annotations

import json
import shutil
import sys

from mac_bench.config import repo_root


def main() -> None:
    res = repo_root() / "results" / sys.argv[1]
    bad_trials: set[int] = set()
    for audit in (res / "llm_logs").glob("trial_*_*/llm_audit.jsonl"):
        statuses = [json.loads(line)["status"] for line in audit.read_text(encoding="utf-8").splitlines() if line]
        if any(s != 200 for s in statuses):
            bad_trials.add(int(audit.parent.name.split("_")[1]))
    log = res / "summary" / "invalidated_pairs.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    for t in sorted(bad_trials):
        for arch in ("ma", "sa"):
            run_id = f"trial_{t}_{arch}"
            (res / "trials" / f"{run_id}.json").unlink(missing_ok=True)
            shutil.rmtree(res / "llm_logs" / run_id, ignore_errors=True)
            shutil.rmtree(res / "proxy_logs" / run_id, ignore_errors=True)
        with log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"trial_index": t, "reason": "non-200 upstream LLM status"}) + "\n")
    print(" ".join(str(t) for t in sorted(bad_trials)))


if __name__ == "__main__":
    main()
