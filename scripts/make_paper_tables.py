#!/usr/bin/env python3
"""Generate the paper's LaTeX result tables directly from each model's benchmark_summary.json.

Numbers are never hand-transcribed: this reads results/models/<slug>/summary/benchmark_summary.json
for each model in the ladder and writes paper/tables/*.tex for \\input. Tolerates missing models
(e.g. a run still in progress) by skipping them and noting which were included.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from mac_bench.config import repo_root
from mac_bench.evaluation.metrics import BENCHMARK_CASE_IDS, CASE_TIER

# Display order / labels for the capability ladder.
LADDER = [
    ("haiku", "Haiku 5.5", "claude-haiku-5-5"),
    ("sonnet", "Sonnet 5", "claude-sonnet-5"),
    ("opus", "Opus 4.8", "claude-opus-4-8"),
]
CASE_LABEL = {
    "DVWA-SQLI-001": "SQLi (low)", "DVWA-CMDI-002": "Cmd-inj (low)", "DVWA-XSS-003": "Stored XSS (low)",
    "JUICE-BOLA-004": "Basket BOLA", "JUICE-EXPOSURE-005": "FTP doc exposure",
    "DVWA-SQLI-MED-006": "SQLi (med)", "DVWA-CMDI-MED-007": "Cmd-inj (med)",
    "JUICE-LOGINSQLI-008": "Login SQLi", "JUICE-SEARCHSQLI-009": "Search SQLi",
    "JUICE-FEEDBACKPII-010": "Feedback PII",
    "DVWA-SQLI-HIGH-011": "SQLi (high)", "DVWA-CMDI-HIGH-012": "Cmd-inj (high)",
    "JUICE-NULLBYTE-013": "Null-byte read", "JUICE-ENCKEYS-014": "Enc-keys dir",
}


def _load(root: Path, slug: str) -> dict | None:
    p = root / "results" / "models" / slug / "summary" / "benchmark_summary.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def _p(sig: dict, key: str) -> str:
    """Format a Wilcoxon p-value with significance star."""
    w = sig.get(key, {}).get("wilcoxon", {})
    pv = w.get("p_two_sided")
    if pv is None:
        return "--"
    star = "\\textsuperscript{*}" if pv < 0.05 else ""
    return f"{pv:.3f}{star}"


def _m(summary: dict, arch: str, *path):
    node = summary["metrics"]["by_architecture"][arch]
    for k in path:
        node = node[k]
    return node


def _wrap(colspec: str, header: str, body: str, arraystretch: str = "1.15", small: bool = False) -> str:
    """Emit a complete tabular so it can be \\input at table-body level (avoids \\noalign-in-\\input)."""
    pre = ("\\footnotesize\n" if small else "") + f"\\renewcommand{{\\arraystretch}}{{{arraystretch}}}\n"
    return (
        pre
        + f"\\begin{{tabular}}{{{colspec}}}\n\\toprule\n{header} \\\\\n\\midrule\n"
        + body
        + "\\bottomrule\n\\end{tabular}\n"
    )


def main() -> None:
    root = repo_root()
    out_dir = root / "paper" / "tables"
    out_dir.mkdir(parents=True, exist_ok=True)
    present = [(slug, label, mid, d) for slug, label, mid in LADDER if (d := _load(root, slug))]
    if not present:
        raise SystemExit("No model summaries found under results/models/*/summary/.")

    # ---- Table 1: cross-model headline (recall, per-tier, FDP, tokens, runtime, Wilcoxon p) ----
    lines = []
    for slug, label, mid, d in present:
        ma_r = _m(d, "multi_agent", "recall")
        sa_r = _m(d, "react_baseline", "recall")
        ma_fdp = _m(d, "multi_agent", "fdp")["mean"]
        sa_fdp = _m(d, "react_baseline", "fdp")["mean"]
        ma_tok = _m(d, "multi_agent", "efficiency", "total_tokens")["mean"]
        sa_tok = _m(d, "react_baseline", "efficiency", "total_tokens")["mean"]
        ma_rt = _m(d, "multi_agent", "efficiency", "runtime_seconds")["mean"]
        sa_rt = _m(d, "react_baseline", "efficiency", "runtime_seconds")["mean"]
        sig = d.get("paired_significance", {})
        lines.append(
            f"{label} & MA & {ma_r['mean']:.2f} & {ma_fdp:.3f} & {ma_tok/1000:.0f}k & {ma_rt:.0f} \\\\\n"
            f" & SA & \\textbf{{{sa_r['mean']:.2f}}} & {sa_fdp:.3f} & {sa_tok/1000:.0f}k & {sa_rt:.0f} \\\\\n"
            f" & $p$ & {_p(sig,'overall_recall')} & & {_p(sig,'total_tokens')} & {_p(sig,'runtime_seconds')} \\\\\n"
        )
    (out_dir / "headline.tex").write_text(
        _wrap("@{}l l c c r r@{}",
              "\\textbf{Model} & & \\textbf{Recall} & \\textbf{FDP} & \\textbf{Tokens} & \\textbf{Runtime}",
              "\\midrule\n".join(lines)),
        encoding="utf-8")

    # ---- Table 2: per-tier recall MA vs SA per model ----
    tlines = []
    for slug, label, mid, d in present:
        sig = d.get("paired_significance", {})
        row = [label]
        for t in (1, 2, 3):
            ma = _m(d, "multi_agent", "per_tier_recall", f"tier_{t}")["mean"]
            sa = _m(d, "react_baseline", "per_tier_recall", f"tier_{t}")["mean"]
            row.append(f"{ma:.2f}/{sa:.2f}")
        tlines.append(" & ".join(row) + f" & {_p(sig,'overall_recall')} \\\\\n")
    (out_dir / "pertier.tex").write_text(
        _wrap("@{}l c c c c@{}",
              "\\textbf{Model} & \\textbf{Tier 1} & \\textbf{Tier 2} & \\textbf{Tier 3} & \\textbf{$p$}",
              "".join(tlines)),
        encoding="utf-8")

    # ---- Figure (pgfplots): per-tier recall MA vs SA, one panel per model ----
    # Emitted from the same summaries so figure values never diverge from the tables.
    panels = []
    for i, (slug, label, mid, d) in enumerate(present):
        ma = [_m(d, "multi_agent", "per_tier_recall", f"tier_{t}")["mean"] for t in (1, 2, 3)]
        sa = [_m(d, "react_baseline", "per_tier_recall", f"tier_{t}")["mean"] for t in (1, 2, 3)]
        ma_c = "".join(f"({t},{ma[t-1]:.2f})" for t in (1, 2, 3))
        sa_c = "".join(f"({t},{sa[t-1]:.2f})" for t in (1, 2, 3))
        opts = f"title={{{label}}}"
        if i == 0:
            opts += ",ylabel={Recall}"
        legend = "\\legend{Multi-agent, Single-agent}\n" if i == 0 else ""
        panels.append(
            f"\\nextgroupplot[{opts}]\n"
            f"\\addplot[fill=black!72,draw=black!72] coordinates {{{ma_c}}};\n"
            f"\\addplot[fill=black!20,draw=black!45] coordinates {{{sa_c}}};\n"
            f"{legend}"
        )
    fig = (
        "\\begin{tikzpicture}\n"
        "\\begin{groupplot}[\n"
        f"  group style={{group size={len(present)} by 1, horizontal sep=1.0cm}},\n"
        "  width=0.33\\textwidth, height=4.1cm, ybar, /pgf/bar width=5pt,\n"
        "  ymin=0, ymax=1.09, ytick={0,0.25,0.5,0.75,1.0},\n"
        "  xtick={1,2,3}, xticklabels={T1,T2,T3}, enlarge x limits=0.3,\n"
        "  tick label style={font=\\footnotesize}, label style={font=\\footnotesize},\n"
        "  title style={font=\\small},\n"
        "  legend style={font=\\footnotesize, draw=none, at={(0.5,-0.30)}, anchor=north, legend columns=-1},\n"
        "]\n"
        + "".join(panels)
        + "\\end{groupplot}\n\\end{tikzpicture}\n"
    )
    (out_dir / "fig_pertier.tex").write_text(fig, encoding="utf-8")

    # ---- Table 3: per-case detection rate (MA/SA) per model ----
    clines = []
    for cid in BENCHMARK_CASE_IDS:
        cells = [f"{CASE_LABEL.get(cid, cid)} (T{CASE_TIER[cid]})"]
        for slug, label, mid, d in present:
            ma = _m(d, "multi_agent", "per_case_detection")[cid]["detection_rate"]
            sa = _m(d, "react_baseline", "per_case_detection")[cid]["detection_rate"]
            cells.append(f"{ma:.1f}/{sa:.1f}")
        clines.append(" & ".join(cells) + " \\\\\n")
    pc_header = "\\textbf{Case (tier)} & " + " & ".join(f"\\textbf{{{label}}}" for _, label, _, _ in present)
    (out_dir / "percase.tex").write_text(
        _wrap("@{}l" + " c" * len(present) + "@{}", pc_header, "".join(clines), arraystretch="1.1", small=True),
        encoding="utf-8")

    # ---- Table 4: containment (summed) per model ----
    konts = []
    for slug, label, mid, d in present:
        for arch, a in (("MA", "multi_agent"), ("SA", "react_baseline")):
            c = _m(d, a, "containment")
            konts.append(
                f"{label} & {arch} & {c['total_in_scope_allowed_requests']} & "
                f"{c['total_proxy_blocked_requests']} & {c['total_firewall_dropped_packets']} & "
                f"\\textbf{{{c['total_out_of_scope_escapes']}}} \\\\\n"
            )
    (out_dir / "containment.tex").write_text(
        _wrap("@{}l l c c c c@{}",
              "\\textbf{Model} & & \\textbf{In-scope} & \\textbf{Proxy blk} & \\textbf{FW drop} & \\textbf{Escapes}",
              "".join(konts)),
        encoding="utf-8")

    # ---- machine-readable digest for prose/abstract ----
    digest = {}
    for slug, label, mid, d in present:
        digest[slug] = {
            "label": label, "model_id": mid,
            "ma_recall": _m(d, "multi_agent", "recall")["mean"],
            "sa_recall": _m(d, "react_baseline", "recall")["mean"],
            "ma_runtime": _m(d, "multi_agent", "efficiency", "runtime_seconds")["mean"],
            "sa_runtime": _m(d, "react_baseline", "efficiency", "runtime_seconds")["mean"],
            "ma_tokens": _m(d, "multi_agent", "efficiency", "total_tokens")["mean"],
            "sa_tokens": _m(d, "react_baseline", "efficiency", "total_tokens")["mean"],
            "overall_p": d.get("paired_significance", {}).get("overall_recall", {}).get("wilcoxon", {}).get("p_two_sided"),
            "oob_ma": _m(d, "multi_agent", "totals_across_trials")["out_of_benchmark"],
            "escapes_ma": _m(d, "multi_agent", "containment")["total_out_of_scope_escapes"],
            "escapes_sa": _m(d, "react_baseline", "containment")["total_out_of_scope_escapes"],
        }
    (out_dir / "digest.json").write_text(json.dumps(digest, indent=2), encoding="utf-8")

    print(f"Wrote tables for: {', '.join(s for s, _, _, _ in present)}")
    print(f"  -> {out_dir}/*.tex + digest.json")
    for slug, label, mid, d in present:
        ma = _m(d, "multi_agent", "recall")["mean"]
        sa = _m(d, "react_baseline", "recall")["mean"]
        print(f"  {label}: MA recall {ma:.3f} vs SA {sa:.3f}")


if __name__ == "__main__":
    main()
