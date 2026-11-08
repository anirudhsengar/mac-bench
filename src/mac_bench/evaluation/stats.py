"""Self-contained exact paired statistics (no numpy/scipy dependency).

For the paired MA-vs-SA design at n=10 the exact Wilcoxon signed-rank null distribution is
cheap to enumerate (2^n sign assignments via DP over ranks), which is more appropriate than
a normal approximation at this sample size.
"""

from __future__ import annotations

import statistics
from typing import Any


def _avg_ranks(absvals: list[float]) -> list[float]:
    order = sorted(range(len(absvals)), key=lambda i: absvals[i])
    ranks = [0.0] * len(absvals)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and absvals[order[j + 1]] == absvals[order[i]]:
            j += 1
        avg = (i + 1 + j + 1) / 2.0  # average rank for the tie block (1-indexed)
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def wilcoxon_signed_rank(diffs: list[float]) -> dict[str, Any]:
    """Exact two-sided Wilcoxon signed-rank test on paired differences (zeros dropped)."""
    nz = [float(d) for d in diffs if d != 0]
    n = len(nz)
    if n == 0:
        return {"n_nonzero": 0, "W": None, "p_two_sided": None, "method": "degenerate_all_zero"}
    ranks = _avg_ranks([abs(d) for d in nz])
    w_plus = sum(ranks[i] for i in range(n) if nz[i] > 0)
    w_minus = sum(ranks[i] for i in range(n) if nz[i] < 0)
    w = min(w_plus, w_minus)

    # Exact null distribution of W+ : each rank is independently added (+) or not (-).
    dp: dict[float, int] = {0.0: 1}
    for r in ranks:
        ndp: dict[float, int] = {}
        for s, c in dp.items():
            ndp[s] = ndp.get(s, 0) + c
            ndp[s + r] = ndp.get(s + r, 0) + c
        dp = ndp
    total = 1 << n
    mean = sum(ranks) / 2.0
    lo, hi = min(w_plus, 2 * mean - w_plus), max(w_plus, 2 * mean - w_plus)
    tail = sum(c for s, c in dp.items() if s <= lo or s >= hi)
    p = min(1.0, tail / total)
    return {
        "n_nonzero": n,
        "W": round(w, 2),
        "W_plus": round(w_plus, 2),
        "W_minus": round(w_minus, 2),
        "p_two_sided": round(p, 5),
        "method": "exact",
    }


def paired_summary(ma_values: list[float], sa_values: list[float]) -> dict[str, Any]:
    """Paired MA-vs-SA summary: per-pair diffs, central tendency, range, and exact Wilcoxon."""
    diffs = [round(float(m) - float(s), 6) for m, s in zip(ma_values, sa_values)]
    pos = sum(1 for d in diffs if d > 0)
    neg = sum(1 for d in diffs if d < 0)
    zero = sum(1 for d in diffs if d == 0)
    return {
        "n_pairs": len(diffs),
        "ma_mean": round(statistics.mean(ma_values), 4) if ma_values else None,
        "sa_mean": round(statistics.mean(sa_values), 4) if sa_values else None,
        "mean_diff_ma_minus_sa": round(statistics.mean(diffs), 4) if diffs else None,
        "median_diff_ma_minus_sa": round(statistics.median(diffs), 4) if diffs else None,
        "diff_range": [min(diffs), max(diffs)] if diffs else None,
        "pairs_ma_gt_sa": pos,
        "pairs_ma_lt_sa": neg,
        "pairs_tied": zero,
        "wilcoxon": wilcoxon_signed_rank(diffs),
    }
