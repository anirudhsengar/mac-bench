#!/usr/bin/env python3
"""Blinded finding evaluation, statistical aggregation, CSV/JSON export, and secret-hygiene audit."""

from __future__ import annotations

import csv
import datetime as dt
import json
import re
import sys
from pathlib import Path

from mac_bench.config import repo_root, results_root
from mac_bench.evaluation.blind_review import run_blind_review_pipeline
from mac_bench.evaluation import stats
from mac_bench.evaluation.metrics import (
    BENCHMARK_CASE_IDS,
    TIER_CASE_IDS,
    TIERS,
    aggregate_architecture_metrics,
    compute_single_run_metrics,
)

LEAK_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}"),
    re.compile(r"BenchAcct[12]_2026!"),
    re.compile(r"dvwa_root_local"),
]


def audit_results_for_leaks(results_dir: Path) -> dict[str, object]:
    scanned_files = 0
    violations: list[str] = []
    for p in results_dir.rglob("*"):
        if p.is_file() and p.suffix in (".json", ".jsonl", ".csv", ".md"):
            scanned_files += 1
            text = p.read_text(encoding="utf-8", errors="ignore")
            for pat in LEAK_PATTERNS:
                if pat.search(text):
                    violations.append(f"{p.relative_to(results_dir)}: matched {pat.pattern}")
    return {"scanned_files": scanned_files, "leak_violations": violations, "clean": len(violations) == 0}


def main() -> None:
    root = repo_root()
    res_root = results_root()
    trials_dir = res_root / "trials"
    trial_files = sorted(trials_dir.glob("trial_*.json"))
    if not trial_files:
        raise SystemExit("No trial artifacts found in results/trials/.")

    trial_runs = [json.loads(p.read_text(encoding="utf-8")) for p in trial_files]

    blind_dir = res_root / "blind_review"
    review_summary = run_blind_review_pipeline(trial_runs, blind_dir)

    per_run_metrics = []
    for run in trial_runs:
        adj = review_summary["adjudicated_by_run"].get(run["run_id"], [])
        per_run_metrics.append(compute_single_run_metrics(run, adj))

    aggregated = aggregate_architecture_metrics(per_run_metrics)

    # Paired MA-vs-SA significance (exact Wilcoxon signed-rank) across trials.
    per_run = aggregated["per_run"]
    ma_by_t = {r["trial_index"]: r for r in per_run if r["architecture"] == "multi_agent"}
    sa_by_t = {r["trial_index"]: r for r in per_run if r["architecture"] == "react_baseline"}
    common = sorted(set(ma_by_t) & set(sa_by_t))
    paired_significance: dict[str, object] = {"paired_trials": len(common)}
    if common:
        paired_significance["overall_recall"] = stats.paired_summary(
            [ma_by_t[t]["discovery"]["recall"] for t in common],
            [sa_by_t[t]["discovery"]["recall"] for t in common],
        )
        for tier in TIER_CASE_IDS:
            paired_significance[f"tier{tier}_recall"] = stats.paired_summary(
                [ma_by_t[t]["discovery"]["per_tier_recall"][tier]["recall"] for t in common],
                [sa_by_t[t]["discovery"]["per_tier_recall"][tier]["recall"] for t in common],
            )
        paired_significance["total_tokens"] = stats.paired_summary(
            [ma_by_t[t]["efficiency"]["total_tokens"] for t in common],
            [sa_by_t[t]["efficiency"]["total_tokens"] for t in common],
        )
        paired_significance["runtime_seconds"] = stats.paired_summary(
            [ma_by_t[t]["efficiency"]["runtime_seconds"] for t in common],
            [sa_by_t[t]["efficiency"]["runtime_seconds"] for t in common],
        )

    summary_dir = res_root / "summary"
    summary_dir.mkdir(parents=True, exist_ok=True)

    csv_path = summary_dir / "per_run_metrics.csv"
    fieldnames = [
        "run_id",
        "trial_index",
        "pair_execution_order",
        "architecture",
        "recall",
        "dvwa_recall",
        "juiceshop_recall",
        *[f"tier{t}_recall" for t in TIERS],
        "tp_count",
        "fp_count",
        "fdp",
        "inconclusive_count",
        "unsubstantiated_count",
        "duplicate_count",
        "out_of_benchmark_count",
        *BENCHMARK_CASE_IDS,
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cost_tokens_per_verified_instance",
        "llm_calls",
        "http_transactions",
        "tool_invocations",
        "handoffs",
        "runtime_seconds",
        "recoverable_failures",
        "recovered_failures",
        "recovery_rate",
        "in_scope_allowed_requests",
        "proxy_blocked_requests",
        "firewall_dropped_packets",
        "out_of_scope_escapes",
        "halt_reason",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in aggregated["per_run"]:
            d = r["discovery"]
            e = r["efficiency"]
            c = r["containment"]
            row = {
                "run_id": r["run_id"],
                "trial_index": r["trial_index"],
                "pair_execution_order": r["pair_execution_order"],
                "architecture": r["architecture"],
                "recall": d["recall"],
                "dvwa_recall": d["dvwa_recall"],
                "juiceshop_recall": d["juiceshop_recall"],
                **{f"tier{t}_recall": d["per_tier_recall"][t]["recall"] for t in TIERS},
                "tp_count": d["tp_count"],
                "fp_count": d["fp_count"],
                "fdp": "undefined" if d["fdp"] is None else d["fdp"],
                "inconclusive_count": d["inconclusive_count"],
                "unsubstantiated_count": d["unsubstantiated_count"],
                "duplicate_count": d["duplicate_count"],
                "out_of_benchmark_count": d["out_of_benchmark_count"],
                **{cid: int(d["per_case_verified"][cid]) for cid in BENCHMARK_CASE_IDS},
                "input_tokens": e["input_tokens"],
                "output_tokens": e["output_tokens"],
                "total_tokens": e["total_tokens"],
                "cost_tokens_per_verified_instance": "undefined"
                if e["cost_tokens_per_verified_instance"] is None
                else e["cost_tokens_per_verified_instance"],
                "llm_calls": e["llm_calls"],
                "http_transactions": e["http_transactions"],
                "tool_invocations": e["tool_invocations"],
                "handoffs": e["handoffs"],
                "runtime_seconds": e["runtime_seconds"],
                "recoverable_failures": e["recoverable_failures"],
                "recovered_failures": e["recovered_failures"],
                "recovery_rate": "undefined" if e["recovery_rate"] is None else e["recovery_rate"],
                "in_scope_allowed_requests": c["in_scope_allowed_requests"],
                "proxy_blocked_requests": c["proxy_blocked_requests"],
                "firewall_dropped_packets": c["firewall_dropped_packets"],
                "out_of_scope_escapes": c["out_of_scope_escapes"],
                "halt_reason": e["halt_reason"],
            }
            writer.writerow(row)

    leak_audit = audit_results_for_leaks(res_root)

    full_summary = {
        "evaluated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "total_runs_evaluated": len(trial_runs),
        "blind_review_summary": {
            "total_submitted_findings": review_summary["total_submitted_findings"],
            "reviewer_disagreements": review_summary["reviewer_disagreements"],
            "inter_reviewer_agreement_rate": review_summary["inter_reviewer_agreement_rate"],
        },
        "metrics": aggregated,
        "paired_significance": paired_significance,
        "redaction_hygiene_audit": leak_audit,
    }
    summary_json = summary_dir / "benchmark_summary.json"
    summary_json.write_text(json.dumps(full_summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Summary JSON saved to {summary_json}")
    print(f"Per-run CSV saved to  {csv_path}")
    print(f"Redaction audit:      {leak_audit}")

    for arch, s in aggregated["by_architecture"].items():
        tiers_str = " ".join(
            f"T{t}={s['per_tier_recall'][f'tier_{t}']['mean']}" for t in TIERS
        )
        print(
            f"\n[{arch}] Mean Recall={s['recall']['mean']} (SD={s['recall']['sample_sd']}) | "
            f"{tiers_str} | Mean FDP={s['fdp']['mean']} | "
            f"Mean Tokens={s['efficiency']['total_tokens']['mean']} | "
            f"Mean Runtime={s['efficiency']['runtime_seconds']['mean']}s"
        )

    if common:
        print("\n=== Paired MA-vs-SA (exact Wilcoxon signed-rank) ===")
        for key in ["overall_recall", *[f"tier{t}_recall" for t in TIER_CASE_IDS], "total_tokens", "runtime_seconds"]:
            ps = paired_significance[key]
            w = ps["wilcoxon"]
            print(
                f"  {key:16} MA={ps['ma_mean']} SA={ps['sa_mean']} "
                f"diff={ps['mean_diff_ma_minus_sa']} (MA>SA:{ps['pairs_ma_gt_sa']}/SA>MA:{ps['pairs_ma_lt_sa']}/tie:{ps['pairs_tied']}) "
                f"W={w['W']} p={w['p_two_sided']}"
            )

    if not leak_audit["clean"]:
        print("ERROR: Credential/token leak detected in results!", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
