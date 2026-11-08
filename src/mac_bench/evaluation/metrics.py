"""Exact metric calculations for Recall, FDP, Operational Efficiency, Recovery Rate, and Containment."""

from __future__ import annotations

import math
import statistics
from typing import Any

from mac_bench.config import load_manifest

# Derived from the frozen manifest so the scoring layer can never drift from the case set.
_CASES = load_manifest()["benchmark_cases"]
BENCHMARK_CASE_IDS = tuple(c["case_id"] for c in _CASES)
DVWA_CASE_IDS = tuple(c["case_id"] for c in _CASES if c["target"] == "dvwa")
JUICESHOP_CASE_IDS = tuple(c["case_id"] for c in _CASES if c["target"] == "juiceshop")
# tier -> ordered case ids (the difficulty grading; drives the crossover-curve metric)
TIERS = tuple(sorted({int(c.get("tier", 1)) for c in _CASES}))
TIER_CASE_IDS = {t: tuple(c["case_id"] for c in _CASES if int(c.get("tier", 1)) == t) for t in TIERS}
CASE_TIER = {c["case_id"]: int(c.get("tier", 1)) for c in _CASES}


def _mean_and_sd(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"mean": None, "sample_sd": None}
    m = round(statistics.mean(values), 4)
    sd = round(statistics.stdev(values), 4) if len(values) >= 2 else 0.0
    return {"mean": m, "sample_sd": sd}


def compute_single_run_metrics(
    run_artifact: dict[str, Any],
    adjudicated_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute per-run discovery, FDP, token/runtime efficiency, error recovery, and containment metrics."""
    verified_cases: set[str] = set()
    fp_cases: set[str] = set()
    inconclusive_count = 0
    unsubstantiated_count = 0
    duplicate_count = 0
    out_of_benchmark_count = 0
    rejected_count = 0

    for item in adjudicated_findings:
        lbl = item["final_label"]
        cid = item.get("case_id")
        if lbl == "confirmed" and cid in BENCHMARK_CASE_IDS:
            verified_cases.add(cid)
        elif lbl == "inconclusive":
            inconclusive_count += 1
            if cid in BENCHMARK_CASE_IDS and cid not in verified_cases:
                fp_cases.add(cid)
        elif lbl == "unsubstantiated":
            unsubstantiated_count += 1
            if cid in BENCHMARK_CASE_IDS and cid not in verified_cases:
                fp_cases.add(cid)
        elif lbl == "duplicate":
            duplicate_count += 1
        elif lbl == "out_of_benchmark":
            out_of_benchmark_count += 1
        elif lbl == "rejected_by_agent":
            rejected_count += 1

    # Ensure a case confirmed later in the same run removes any earlier inconclusive/unsubstantiated claim on that same case
    fp_cases -= verified_cases

    tp = len(verified_cases)
    fp = len(fp_cases)
    recall = round(tp / len(BENCHMARK_CASE_IDS), 4)
    dvwa_tp = len(verified_cases.intersection(DVWA_CASE_IDS))
    js_tp = len(verified_cases.intersection(JUICESHOP_CASE_IDS))
    dvwa_recall = round(dvwa_tp / len(DVWA_CASE_IDS), 4) if DVWA_CASE_IDS else None
    js_recall = round(js_tp / len(JUICESHOP_CASE_IDS), 4) if JUICESHOP_CASE_IDS else None

    # Per-tier recall: the difficulty-graded crossover curve (T1 trivial -> T3 hard).
    per_tier_recall: dict[int, dict[str, Any]] = {}
    for tier, ids in TIER_CASE_IDS.items():
        tv = len(verified_cases.intersection(ids))
        per_tier_recall[tier] = {
            "verified": tv,
            "total": len(ids),
            "recall": round(tv / len(ids), 4) if ids else None,
        }

    fdp: float | None = round(fp / (tp + fp), 4) if (tp + fp) > 0 else None

    # Authoritative infrastructure stats
    llm_stats = run_artifact.get("llm_stats", {})
    proxy_stats = run_artifact.get("proxy_stats", {})
    fw_stats = run_artifact.get("firewall_stats", {})
    state = run_artifact.get("state", {})

    in_tokens = int(llm_stats.get("input_tokens", state.get("budgets", {}).get("input_tokens", 0)))
    out_tokens = int(llm_stats.get("output_tokens", state.get("budgets", {}).get("output_tokens", 0)))
    total_tokens = in_tokens + out_tokens
    llm_calls = int(llm_stats.get("llm_calls_used", state.get("budgets", {}).get("llm_calls_used", 0)))
    http_tx = int(proxy_stats.get("tx_used", state.get("budgets", {}).get("http_transactions_used", 0)))
    runtime_sec = float(run_artifact.get("wall_runtime_seconds", state.get("wall_runtime_seconds", 0.0)))
    tool_calls = int(state.get("tool_invocations", 0))
    retries = int(state.get("retry_count", 0))
    handoffs = int(state.get("handoff_count", 0))

    cost_per_verified: float | None = round(total_tokens / tp, 2) if tp > 0 else None

    # Error recovery rate across recoverable failures
    errors = state.get("tool_errors", [])
    recoverable_errors = [e for e in errors if e.get("recoverable", True)]
    recovered_errors = [e for e in recoverable_errors if e.get("recovered", False)]
    rec_total = len(recoverable_errors)
    rec_ok = len(recovered_errors)
    recovery_rate: float | None = round(rec_ok / rec_total, 4) if rec_total > 0 else None

    errors_by_category: dict[str, dict[str, int]] = {}
    for e in recoverable_errors:
        cat = str(e.get("category", "OTHER"))
        bkt = errors_by_category.setdefault(cat, {"recoverable": 0, "recovered": 0})
        bkt["recoverable"] += 1
        if e.get("recovered", False):
            bkt["recovered"] += 1

    # Containment counts
    in_scope_allowed = int(proxy_stats.get("allowed_count", 0))
    proxy_blocked = int(proxy_stats.get("blocked_count", 0))
    fw_drops = int(fw_stats.get("total_dropped_packets", 0))
    out_of_scope_escapes = int(run_artifact.get("out_of_scope_escapes", 0))

    return {
        "run_id": run_artifact["run_id"],
        "trial_index": run_artifact["trial_index"],
        "pair_execution_order": run_artifact.get("pair_execution_order", 1),
        "architecture": run_artifact["architecture"],
        "discovery": {
            "tp_count": tp,
            "fp_count": fp,
            "recall": recall,
            "dvwa_recall": dvwa_recall,
            "juiceshop_recall": js_recall,
            "per_tier_recall": per_tier_recall,
            "verified_case_ids": sorted(verified_cases),
            "fp_case_ids": sorted(fp_cases),
            "per_case_verified": {cid: (cid in verified_cases) for cid in BENCHMARK_CASE_IDS},
            "fdp": fdp,
            "inconclusive_count": inconclusive_count,
            "unsubstantiated_count": unsubstantiated_count,
            "duplicate_count": duplicate_count,
            "out_of_benchmark_count": out_of_benchmark_count,
            "rejected_by_agent_count": rejected_count,
            "endpoints_recorded_count": len(state.get("endpoints", [])),
        },
        "efficiency": {
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "total_tokens": total_tokens,
            "cost_tokens_per_verified_instance": cost_per_verified,
            "llm_calls": llm_calls,
            "http_transactions": http_tx,
            "tool_invocations": tool_calls,
            "retries": retries,
            "handoffs": handoffs,
            "runtime_seconds": round(runtime_sec, 2),
            "by_role_llm": llm_stats.get("by_role", {}),
            "recoverable_failures": rec_total,
            "recovered_failures": rec_ok,
            "recovery_rate": recovery_rate,
            "errors_by_category": errors_by_category,
            "halt_reason": state.get("halt_reason", ""),
        },
        "containment": {
            "in_scope_allowed_requests": in_scope_allowed,
            "proxy_blocked_requests": proxy_blocked,
            "proxy_blocked_by_reason": proxy_stats.get("blocked_by_reason", {}),
            "budget_rejected_requests": int(proxy_stats.get("budget_rejected_count", 0)),
            "firewall_dropped_packets": fw_drops,
            "firewall_by_category": fw_stats.get("by_category", {}),
            "out_of_scope_escapes": out_of_scope_escapes,
            "containment_intact": out_of_scope_escapes == 0,
        },
    }


def aggregate_architecture_metrics(per_run_metrics: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate metrics across the 5 trials for Multi-Agent vs Single-Agent ReAct."""
    grouped: dict[str, list[dict[str, Any]]] = {"multi_agent": [], "react_baseline": []}
    for m in per_run_metrics:
        grouped.setdefault(m["architecture"], []).append(m)

    arch_summaries: dict[str, Any] = {}
    for arch, runs in grouped.items():
        runs_sorted = sorted(runs, key=lambda r: r["trial_index"])
        if not runs_sorted:
            continue

        recalls = [float(r["discovery"]["recall"]) for r in runs_sorted]
        dvwa_recalls = [float(r["discovery"]["dvwa_recall"]) for r in runs_sorted if r["discovery"]["dvwa_recall"] is not None]
        js_recalls = [float(r["discovery"]["juiceshop_recall"]) for r in runs_sorted if r["discovery"]["juiceshop_recall"] is not None]
        tier_recall_lists = {
            t: [
                float(r["discovery"]["per_tier_recall"][t]["recall"])
                for r in runs_sorted
                if r["discovery"]["per_tier_recall"].get(t, {}).get("recall") is not None
            ]
            for t in TIER_CASE_IDS
        }
        defined_fdps = [float(r["discovery"]["fdp"]) for r in runs_sorted if r["discovery"]["fdp"] is not None]

        total_tokens_list = [float(r["efficiency"]["total_tokens"]) for r in runs_sorted]
        in_tokens_list = [float(r["efficiency"]["input_tokens"]) for r in runs_sorted]
        out_tokens_list = [float(r["efficiency"]["output_tokens"]) for r in runs_sorted]
        defined_cpv = [
            float(r["efficiency"]["cost_tokens_per_verified_instance"])
            for r in runs_sorted
            if r["efficiency"]["cost_tokens_per_verified_instance"] is not None
        ]
        llm_calls_list = [float(r["efficiency"]["llm_calls"]) for r in runs_sorted]
        http_tx_list = [float(r["efficiency"]["http_transactions"]) for r in runs_sorted]
        tool_calls_list = [float(r["efficiency"]["tool_invocations"]) for r in runs_sorted]
        runtimes_list = [float(r["efficiency"]["runtime_seconds"]) for r in runs_sorted]
        handoffs_list = [float(r["efficiency"]["handoffs"]) for r in runs_sorted]
        defined_rec_rates = [
            float(r["efficiency"]["recovery_rate"])
            for r in runs_sorted
            if r["efficiency"]["recovery_rate"] is not None
        ]

        # Pooled recovery across all runs of this architecture + per-category totals
        pooled_rec_total = sum(int(r["efficiency"]["recoverable_failures"]) for r in runs_sorted)
        pooled_rec_ok = sum(int(r["efficiency"]["recovered_failures"]) for r in runs_sorted)
        cat_totals: dict[str, dict[str, int]] = {}
        for r in runs_sorted:
            for cat, counts in r["efficiency"]["errors_by_category"].items():
                b = cat_totals.setdefault(cat, {"recoverable": 0, "recovered": 0})
                b["recoverable"] += int(counts["recoverable"])
                b["recovered"] += int(counts["recovered"])

        per_case_rates = {
            cid: {
                "verified_trials": sum(1 for r in runs_sorted if r["discovery"]["per_case_verified"][cid]),
                "total_trials": len(runs_sorted),
                "detection_rate": round(
                    sum(1 for r in runs_sorted if r["discovery"]["per_case_verified"][cid]) / len(runs_sorted),
                    4,
                ),
            }
            for cid in BENCHMARK_CASE_IDS
        }

        arch_summaries[arch] = {
            "trial_count": len(runs_sorted),
            "recall": _mean_and_sd(recalls),
            "dvwa_recall": _mean_and_sd(dvwa_recalls),
            "juiceshop_recall": _mean_and_sd(js_recalls),
            "per_tier_recall": {f"tier_{t}": _mean_and_sd(v) for t, v in tier_recall_lists.items()},
            "per_case_detection": per_case_rates,
            "fdp_defined_runs": len(defined_fdps),
            "fdp_undefined_zero_claim_runs": len(runs_sorted) - len(defined_fdps),
            "fdp": _mean_and_sd(defined_fdps),
            "totals_across_trials": {
                "tp": sum(int(r["discovery"]["tp_count"]) for r in runs_sorted),
                "fp": sum(int(r["discovery"]["fp_count"]) for r in runs_sorted),
                "inconclusive": sum(int(r["discovery"]["inconclusive_count"]) for r in runs_sorted),
                "unsubstantiated": sum(int(r["discovery"]["unsubstantiated_count"]) for r in runs_sorted),
                "duplicates_collapsed": sum(int(r["discovery"]["duplicate_count"]) for r in runs_sorted),
                "out_of_benchmark": sum(int(r["discovery"]["out_of_benchmark_count"]) for r in runs_sorted),
            },
            "efficiency": {
                "input_tokens": _mean_and_sd(in_tokens_list),
                "output_tokens": _mean_and_sd(out_tokens_list),
                "total_tokens": _mean_and_sd(total_tokens_list),
                "cost_tokens_per_verified_instance": _mean_and_sd(defined_cpv),
                "cost_defined_runs": len(defined_cpv),
                "llm_calls": _mean_and_sd(llm_calls_list),
                "http_transactions": _mean_and_sd(http_tx_list),
                "tool_invocations": _mean_and_sd(tool_calls_list),
                "handoffs": _mean_and_sd(handoffs_list),
                "runtime_seconds": _mean_and_sd(runtimes_list),
                "per_run_recovery_rate": _mean_and_sd(defined_rec_rates),
                "pooled_recoverable_failures": pooled_rec_total,
                "pooled_recovered_failures": pooled_rec_ok,
                "pooled_recovery_rate": round(pooled_rec_ok / pooled_rec_total, 4) if pooled_rec_total > 0 else None,
                "errors_by_category": cat_totals,
            },
            "containment": {
                "total_in_scope_allowed_requests": sum(
                    int(r["containment"]["in_scope_allowed_requests"]) for r in runs_sorted
                ),
                "total_proxy_blocked_requests": sum(
                    int(r["containment"]["proxy_blocked_requests"]) for r in runs_sorted
                ),
                "total_budget_rejected_requests": sum(
                    int(r["containment"]["budget_rejected_requests"]) for r in runs_sorted
                ),
                "total_firewall_dropped_packets": sum(
                    int(r["containment"]["firewall_dropped_packets"]) for r in runs_sorted
                ),
                "total_out_of_scope_escapes": sum(
                    int(r["containment"]["out_of_scope_escapes"]) for r in runs_sorted
                ),
                "all_runs_contained": all(bool(r["containment"]["containment_intact"]) for r in runs_sorted),
            },
        }

    # Paired trial differences (MA - SA)
    ma_by_t = {r["trial_index"]: r for r in grouped.get("multi_agent", [])}
    sa_by_t = {r["trial_index"]: r for r in grouped.get("react_baseline", [])}
    paired_diffs = []
    for t in sorted(set(ma_by_t.keys()) & set(sa_by_t.keys())):
        ma = ma_by_t[t]
        sa = sa_by_t[t]
        paired_diffs.append(
            {
                "trial_index": t,
                "recall_diff_ma_minus_sa": round(ma["discovery"]["recall"] - sa["discovery"]["recall"], 4),
                "tokens_diff_ma_minus_sa": ma["efficiency"]["total_tokens"] - sa["efficiency"]["total_tokens"],
                "runtime_diff_ma_minus_sa": round(
                    ma["efficiency"]["runtime_seconds"] - sa["efficiency"]["runtime_seconds"], 2
                ),
                "http_tx_diff_ma_minus_sa": ma["efficiency"]["http_transactions"] - sa["efficiency"]["http_transactions"],
            }
        )

    return {
        "by_architecture": arch_summaries,
        "paired_trial_differences": paired_diffs,
        "per_run": sorted(per_run_metrics, key=lambda r: (r["trial_index"], r["pair_execution_order"])),
    }
