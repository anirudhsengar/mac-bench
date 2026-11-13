#!/usr/bin/env python3
"""Generate the paper's LaTeX tables and figure directly from the benchmark summaries.

Numbers are never hand-transcribed. Reads results/<set>/<slug>/summary/benchmark_summary.json
(set = PAPER_RESULTS_SET, default "models_v3") plus the per-run CSVs, and writes
paper_springer/tables/*.tex for \\input, and digest.json for the prose.

Optional inputs, used when present:
  results/models/<slug>/summary/...              original (pre-fix) run, original grader
  results/models_v2_rescored/<slug>/summary/...  original run, corrected grader
  results/<set>/<slug>_static/summary/...        ablation: multi-agent without the LLM Coordinator
  results/<set>/<slug>/summary/failure_funnel.json  (scripts/failure_funnel.py)
"""

from __future__ import annotations

import csv
import json
import os
import random
import statistics
from pathlib import Path

from mac_bench.config import repo_root
from mac_bench.evaluation.metrics import BENCHMARK_CASE_IDS, CASE_TIER
from mac_bench.evaluation.stats import wilcoxon_signed_rank

LADDER = [
    ("haiku", "Haiku 5.5", "claude-haiku-5-5"),
    ("sonnet", "Sonnet 5", "claude-sonnet-5"),
    ("opus", "Opus 4.8", "claude-opus-4-8"),
]
CASE_LABEL = {
    "DVWA-SQLI-001": "SQLi, low", "DVWA-CMDI-002": "Cmd inj., low", "DVWA-XSS-003": "Stored XSS",
    "JUICE-BOLA-004": "Basket BOLA", "JUICE-EXPOSURE-005": "FTP document",
    "DVWA-SQLI-MED-006": "SQLi, medium", "DVWA-CMDI-MED-007": "Cmd inj., medium",
    "JUICE-LOGINSQLI-008": "Login SQLi", "JUICE-SEARCHSQLI-009": "Search SQLi",
    "JUICE-FEEDBACKPII-010": "Feedback PII",
    "DVWA-SQLI-HIGH-011": "SQLi, high", "DVWA-CMDI-HIGH-012": "Cmd inj., high",
    "JUICE-NULLBYTE-013": "Null-byte read", "JUICE-ENCKEYS-014": "Key directory",
}
MA, SA = "multi_agent", "react_baseline"
STAGE_LABEL = [
    ("not_mapped", "Route never mapped"),
    ("not_assigned", "Mapped, never assigned"),
    ("not_attempted", "Route verified, this instance never claimed"),
    ("agent_rejected", "Claimed as rejected or inconclusive by agent"),
    ("oracle_rejected", "Claimed, evidence failed oracle"),
]


def _summary(root: Path, rel: str) -> dict | None:
    p = root / "results" / rel / "summary" / "benchmark_summary.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _runs(root: Path, rel: str) -> dict[str, dict[int, dict]]:
    """Per-run metrics keyed by architecture then trial index."""
    p = root / "results" / rel / "summary" / "per_run_metrics.csv"
    out: dict[str, dict[int, dict]] = {}
    if not p.exists():
        return out
    with p.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out.setdefault(row["architecture"], {})[int(row["trial_index"])] = row
    return out


def _col(runs: dict, arch: str, key: str) -> list[float]:
    return [float(runs[arch][t][key]) for t in sorted(runs.get(arch, {}))]


def _paired(runs: dict, key: str) -> tuple[list[float], list[float]]:
    common = sorted(set(runs.get(MA, {})) & set(runs.get(SA, {})))
    return [float(runs[MA][t][key]) for t in common], [float(runs[SA][t][key]) for t in common]


def _boot_ci(diffs: list[float], reps: int = 10000, seed: int = 20261113) -> tuple[float, float]:
    """Percentile bootstrap 95% CI of the mean paired difference (deterministic seed)."""
    rng = random.Random(seed)
    n = len(diffs)
    means = sorted(statistics.mean(rng.choices(diffs, k=n)) for _ in range(reps))
    return means[int(0.025 * reps)], means[int(0.975 * reps) - 1]


def _rank_biserial(w: dict) -> float | None:
    wp, wm = w.get("W_plus"), w.get("W_minus")
    if wp is None or (wp + wm) == 0:
        return None
    return (wp - wm) / (wp + wm)


def _pfmt(p: float | None) -> str:
    if p is None:
        return "--"
    star = "\\textsuperscript{*}" if p < 0.05 else ""
    return (f"{p:.3f}" if p >= 0.001 else "<0.001") + star


def _ms(vals: list[float], fmt: str = "{:.2f}", scale: float = 1.0) -> str:
    if not vals:
        return "--"
    m = statistics.mean(vals) / scale
    sd = statistics.stdev(vals) / scale if len(vals) > 1 else 0.0
    return f"{fmt.format(m)} $\\pm$ {fmt.format(sd)}"


def _tab(colspec: str, header: str, body: str, small: bool = True) -> str:
    pre = "\\footnotesize\n" if small else ""
    return (
        pre + "\\renewcommand{\\arraystretch}{1.12}\n"
        f"\\begin{{tabular}}{{{colspec}}}\n\\hline\\noalign{{\\smallskip}}\n{header} \\\\\n"
        "\\noalign{\\smallskip}\\hline\\noalign{\\smallskip}\n" + body
        + "\\noalign{\\smallskip}\\hline\n\\end{tabular}\n"
    )


def _test(runs: dict, key: str) -> dict:
    ma, sa = _paired(runs, key)
    diffs = [m - s for m, s in zip(ma, sa)]
    w = wilcoxon_signed_rank(diffs)
    lo, hi = _boot_ci(diffs) if diffs else (None, None)
    return {
        "ma_mean": statistics.mean(ma) if ma else None, "sa_mean": statistics.mean(sa) if sa else None,
        "ma_sd": statistics.stdev(ma) if len(ma) > 1 else None, "sa_sd": statistics.stdev(sa) if len(sa) > 1 else None,
        "mean_diff": statistics.mean(diffs) if diffs else None, "ci95": [lo, hi],
        "p": w.get("p_two_sided"), "r_rb": _rank_biserial(w), "n": len(diffs),
        "pairs_sa_better": sum(1 for d in diffs if d < 0), "pairs_tied": sum(1 for d in diffs if d == 0),
    }


def main() -> None:
    root = repo_root()
    rset = os.environ.get("PAPER_RESULTS_SET", "models_v3")
    out_dir = root / "paper_springer" / "tables"
    out_dir.mkdir(parents=True, exist_ok=True)
    present = [(s, lab, mid, d, _runs(root, f"{rset}/{s}")) for s, lab, mid in LADDER if (d := _summary(root, f"{rset}/{s}"))]
    if not present:
        raise SystemExit(f"No summaries under results/{rset}/*/summary/.")
    digest: dict = {"results_set": rset, "models": {}}

    # ---- Headline: recall, FDP, runtime (mean +- SD) with paired tests ----
    rows = []
    for slug, label, mid, d, runs in present:
        rec, rt, tok = _test(runs, "recall"), _test(runs, "runtime_seconds"), _test(runs, "total_tokens")
        fdp_ma = d["metrics"]["by_architecture"][MA]["fdp"]["mean"]
        fdp_sa = d["metrics"]["by_architecture"][SA]["fdp"]["mean"]
        ma_r, sa_r = _paired(runs, "recall")
        ma_t, sa_t = _paired(runs, "runtime_seconds")
        ci = rec["ci95"]
        p_cell = (f"{_pfmt(rec['p'])} ({rec['r_rb']:+.2f})" if rec["r_rb"] is not None
                  else "-- (all pairs tied)")
        rows.append(
            f"{label} & MA & {_ms(ma_r)} & {fdp_ma:.3f} & {_ms(ma_t, '{:.0f}')} \\\\\n"
            f" & SA & {_ms(sa_r)} & {fdp_sa:.3f} & {_ms(sa_t, '{:.0f}')} \\\\\n"
            f" & $\\Delta$ [95\\% CI] & {rec['mean_diff']:+.2f} [{ci[0]:+.2f}, {ci[1]:+.2f}] & & "
            f"{rt['mean_diff']:+.0f} \\\\\n"
            f" & $p$ ($r$) & {p_cell} & & {_pfmt(rt['p'])} \\\\\n"
        )
        digest["models"][slug] = {"label": label, "model_id": mid, "recall": rec, "runtime": rt, "tokens": tok,
                                  "fdp_ma": fdp_ma, "fdp_sa": fdp_sa}
    (out_dir / "headline.tex").write_text(_tab(
        "@{}l l c c c@{}",
        "Model & & Recall (mean $\\pm$ SD) & FDP & Runtime (s)",
        "\\noalign{\\smallskip}\\hline\\noalign{\\smallskip}\n".join(rows)), encoding="utf-8")

    # ---- Efficiency: LLM calls, tool calls, HTTP, handoffs, tokens, recovery ----
    erows = []
    for slug, label, mid, d, runs in present:
        for arch, tag in ((MA, "MA"), (SA, "SA")):
            e = d["metrics"]["by_architecture"][arch]["efficiency"]
            erows.append(
                f"{label if arch == MA else ''} & {tag} & {_ms(_col(runs, arch, 'llm_calls'), '{:.0f}')} & "
                f"{_ms(_col(runs, arch, 'tool_invocations'), '{:.0f}')} & "
                f"{_ms(_col(runs, arch, 'http_transactions'), '{:.0f}')} & "
                f"{statistics.mean(_col(runs, arch, 'handoffs')):.1f} & "
                f"{_ms(_col(runs, arch, 'total_tokens'), '{:.0f}', 1000)} & "
                f"{e['pooled_recovered_failures']}/{e['pooled_recoverable_failures']} \\\\\n"
            )
        for key in ("llm_calls", "tool_invocations", "http_transactions", "total_tokens"):
            digest["models"][slug][key] = _test(runs, key)
    (out_dir / "efficiency.tex").write_text(_tab(
        "@{}l l c c c c c c@{}",
        "Model & & LLM calls & Tool calls & HTTP req. & Handoffs & Tokens (k) & Recovered",
        "".join(erows)), encoding="utf-8")

    # ---- Per-case detection: MA rates in two side-by-side halves; SA exceptions listed for the caption ----
    def _rate(d, arch, cid):
        return d["metrics"]["by_architecture"][arch]["per_case_detection"][cid]["detection_rate"]
    cells_by_case = []
    for cid in BENCHMARK_CASE_IDS:
        cells_by_case.append(f"{CASE_LABEL[cid]} & {CASE_TIER[cid]} & "
                             + " & ".join(f"{_rate(d, MA, cid):.1f}" for _, _, _, d, _ in present))
    half = (len(cells_by_case) + 1) // 2
    left, right = cells_by_case[:half], cells_by_case[half:]
    crows = "".join(f"{l} & {r if r else ' & & ' + ' & '.join([''] * len(present))} \\\\\n"
                    for l, r in zip(left, right + [""] * (len(left) - len(right))))
    models_hdr = " & ".join(lab.split()[0] for _, lab, *_ in present)
    (out_dir / "percase.tex").write_text(_tab(
        "@{}l c" + " c" * len(present) + " @{\\hspace{1.2em}} l c" + " c" * len(present) + "@{}",
        f"Case & T & {models_hdr} & Case & T & {models_hdr}", crows), encoding="utf-8")
    sa_exceptions = [
        f"{CASE_LABEL[cid]} on {lab.split()[0]} ({_rate(d, SA, cid):.1f})"
        for cid in BENCHMARK_CASE_IDS for _, lab, _, d, _ in present if _rate(d, SA, cid) < 1.0
    ]
    digest["sa_percase_exceptions"] = sa_exceptions

    # ---- Per-tier figure (pgfplots) ----
    panels = []
    for i, (slug, label, mid, d, runs) in enumerate(present):
        tiers = d["metrics"]["by_architecture"]
        ma = [tiers[MA]["per_tier_recall"][f"tier_{t}"]["mean"] for t in (1, 2, 3)]
        sa = [tiers[SA]["per_tier_recall"][f"tier_{t}"]["mean"] for t in (1, 2, 3)]
        opts = f"title={{{label}}}" + (",ylabel={Recall}" if i == 0 else ",yticklabels={}")
        panels.append(
            f"\\nextgroupplot[{opts}]\n"
            "\\addplot[fill=black!72,draw=black!72] coordinates {" + "".join(f"({t},{ma[t-1]:.2f})" for t in (1, 2, 3)) + "};\n"
            "\\addplot[fill=black!18,draw=black!55] coordinates {" + "".join(f"({t},{sa[t-1]:.2f})" for t in (1, 2, 3)) + "};\n"
            + ("\\legend{Multi-agent, Single-agent}\n" if i == 0 else "")
        )
        digest["models"][slug]["tiers"] = {"ma": ma, "sa": sa}
    (out_dir / "fig_pertier.tex").write_text(
        "\\begin{tikzpicture}\n\\begin{groupplot}[\n"
        f"  group style={{group size={len(present)} by 1, horizontal sep=0.35cm}},\n"
        "  width=0.37\\textwidth, height=4.0cm, ybar, /pgf/bar width=5pt,\n"
        "  ymin=0, ymax=1.09, ytick={0,0.25,0.5,0.75,1.0},\n"
        "  xtick={1,2,3}, xticklabels={Tier 1,Tier 2,Tier 3}, enlarge x limits=0.28,\n"
        "  tick label style={font=\\scriptsize}, label style={font=\\scriptsize}, title style={font=\\footnotesize},\n"
        "  legend style={font=\\scriptsize, draw=none, at={(1.6,-0.28)}, anchor=north, legend columns=-1},\n]\n"
        + "".join(panels) + "\\end{groupplot}\n\\end{tikzpicture}\n", encoding="utf-8")

    # ---- Containment ----
    krows = []
    for slug, label, mid, d, runs in present:
        for arch, tag in ((MA, "MA"), (SA, "SA")):
            c = d["metrics"]["by_architecture"][arch]["containment"]
            krows.append(f"{label if arch == MA else ''} & {tag} & {c['total_in_scope_allowed_requests']} & "
                         f"{c['total_proxy_blocked_requests']} & {c['total_firewall_dropped_packets']} & "
                         f"{c['total_out_of_scope_escapes']} \\\\\n")
            digest["models"][slug][f"containment_{tag}"] = c
    (out_dir / "containment.tex").write_text(_tab(
        "@{}l l c c c c@{}", "Model & & In-scope allowed & Proxy blocked & Firewall drops & Escapes",
        "".join(krows)), encoding="utf-8")

    # ---- Original vs. corrected multi-agent recall (bug-fix history) ----
    hrows = []
    for slug, label, mid, d, runs in present:
        orig, resc = _summary(root, f"models/{slug}"), _summary(root, f"models_v2_rescored/{slug}")
        cells = [label]
        for s in (orig, resc, d):
            if s is None:
                cells.append("--")
                continue
            ba = s["metrics"]["by_architecture"]
            cells.append(f"{ba[MA]['recall']['mean']:.2f} / {ba[SA]['recall']['mean']:.2f}")
        hrows.append(" & ".join(cells) + " \\\\\n")
        digest["models"][slug]["history"] = cells[1:]
    (out_dir / "history.tex").write_text(_tab(
        "@{}l c c c@{}",
        "Model & Original run, & Original run, & Corrected rerun \\\\\n & original grader & corrected grader & (this paper)",
        "".join(hrows)), encoding="utf-8")

    # ---- Failure funnel (multi-agent misses by stage, summed over models) ----
    funnel = {MA: {k: 0 for k, _ in STAGE_LABEL}, SA: {k: 0 for k, _ in STAGE_LABEL}}
    have_funnel = False
    for slug, *_ in present:
        p = root / "results" / rset / slug / "summary" / "failure_funnel.json"
        if p.exists():
            have_funnel = True
            f = json.loads(p.read_text(encoding="utf-8"))
            for arch in (MA, SA):
                for k, _ in STAGE_LABEL:
                    funnel[arch][k] += f["by_architecture"].get(arch, {}).get(k, 0)
            digest["models"][slug]["funnel"] = f
    if have_funnel:
        frows = "".join(f"{lab} & {funnel[MA][k]} & {funnel[SA][k]} \\\\\n" for k, lab in STAGE_LABEL)
        frows += ("\\noalign{\\smallskip}\\hline\\noalign{\\smallskip}\n"
                  f"Total missed case-runs & {sum(funnel[MA].values())} & {sum(funnel[SA].values())} \\\\\n")
        (out_dir / "funnel.tex").write_text(_tab("@{}l c c@{}", "Stage where the case was lost & MA & SA", frows),
                                            encoding="utf-8")
        digest["funnel_total"] = funnel

    # ---- Ablation: multi-agent without the LLM Coordinator ----
    arows = []
    for slug, label, mid, d, runs in present:
        st = _runs(root, f"{rset}/{slug}_static")
        if not st.get(MA):
            continue
        s_rec, s_rt = _col(st, MA, "recall"), _col(st, MA, "runtime_seconds")
        s_llm = _col(st, MA, "llm_calls")
        arows.append(
            f"{label} & {_ms(_col(runs, MA, 'recall'))} & {_ms(s_rec)} & {_ms(_col(runs, SA, 'recall'))} \\\\\n"
            f" & {_ms(_col(runs, MA, 'runtime_seconds'), '{:.0f}')} & {_ms(s_rt, '{:.0f}')} & "
            f"{_ms(_col(runs, SA, 'runtime_seconds'), '{:.0f}')} \\\\\n"
        )
        digest["models"][slug]["ablation_static"] = {
            "recall_mean": statistics.mean(s_rec), "recall_sd": statistics.stdev(s_rec) if len(s_rec) > 1 else 0,
            "runtime_mean": statistics.mean(s_rt), "llm_calls_mean": statistics.mean(s_llm), "n": len(s_rec),
            "per_case": _summary(root, f"{rset}/{slug}_static")["metrics"]["by_architecture"][MA]["per_case_detection"]
            if _summary(root, f"{rset}/{slug}_static") else None,
        }
    if arows:
        (out_dir / "ablation.tex").write_text(_tab(
            "@{}l c c c@{}", "Model & MA (LLM Coordinator) & MA (fixed routing) & SA", "".join(arows)), encoding="utf-8")

    for slug, label, mid, d, runs in present:
        ba = d["metrics"]["by_architecture"]
        digest["models"][slug]["oob"] = {a: ba[a]["totals_across_trials"]["out_of_benchmark"] for a in (MA, SA)}
        digest["models"][slug]["totals"] = {a: ba[a]["totals_across_trials"] for a in (MA, SA)}
        digest["models"][slug]["review"] = d.get("blind_review_summary")
    (out_dir / "digest.json").write_text(json.dumps(digest, indent=2), encoding="utf-8")
    print(f"Wrote tables for {', '.join(s for s, *_ in present)} from results/{rset} -> {out_dir}")


if __name__ == "__main__":
    main()
