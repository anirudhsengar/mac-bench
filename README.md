# Evaluative Benchmarking of a Specialized Multi-Agent LLM Architecture for Web Vulnerability Identification in Isolated Environments

Benchmarking framework and empirical evaluation comparing a 3-role LangGraph Multi-Agent architecture (Coordinator, Surface Mapper, Verification Agent) against a Single-Agent ReAct baseline on DVWA 2.3 and OWASP Juice Shop v16.0.0 under strict Docker network isolation and `mitmproxy` request mediation.

## Results (v3: corrected agents and scorer)

The benchmark is a **14-case, 3-tier** difficulty-graded suite on DVWA 2.3 and OWASP Juice Shop
v16.0.0; budgets are 600 HTTP / 120 LLM / 3600 s, which no run exhausts. Both architectures receive
the same scope prompt (`src/mac_bench/prompts/shared_scope.py`), which names the vulnerability
classes and example payloads, so the task is guided verification rather than open discovery.

```bash
uv run python scripts/run_preflight.py                         # containment + 14 oracles (must pass)
uv run python scripts/freeze_experiment.py                     # pin model, budgets, source hashes
MAC_BENCH_MODEL=claude-haiku-5-5 MAC_BENCH_RESULTS_SUBDIR=models_v3/haiku \
  uv run python scripts/run_trials.py --resume                 # 10 paired trials (20 runs)
uv run python scripts/invalidate_failed_pairs.py models_v3/haiku  # drop pairs with failed LLM calls, then rerun
MAC_BENCH_RESULTS_SUBDIR=models_v3/haiku uv run python scripts/evaluate_results.py
uv run python scripts/failure_funnel.py models_v3/haiku        # where each missed case was lost
# repeat with claude-sonnet-5 / claude-opus-4-8; ablation: MAC_BENCH_MA_COORDINATOR=static ... --arch ma
uv run python scripts/make_paper_tables.py                     # regenerate paper_springer/tables/*.tex
```

Headline (10 paired trials per model; exact Wilcoxon signed-rank, MA vs SA):

| Model | MA recall | SA recall | p (recall) | MA:SA runtime | p (runtime) |
|---|---|---|---|---|---|
| Haiku 5.5 | 0.86 | 0.94 | 0.031 | 2.7x | 0.002 |
| Sonnet 5  | 0.89 | 1.00 | 0.50 | 2.8x | 0.002 |
| Opus 4.8  | 0.96 | 0.99 | 0.50 | 3.3x | 0.002 |

Role specialization never improved recall (SA equal or higher in 29/30 pairs; pooled p = 0.002) and
always cost ~2.7-3.3x the runtime. Multi-agent misses trace to coordination: DVWA security levels left
untested once a route was marked verified, and (Sonnet, 2/10 runs) Coordinator halts that contradicted
its own stated reasoning, leaving Juice Shop unmapped. Replacing the LLM Coordinator with fixed routing
(Haiku) lowered recall further (0.79), while giving it per-instance coverage tracking with a halt check
restored recall to the single agent's level (0.93 in all 10 runs vs 0.94) without reducing the time cost (278 s vs 102 s). Containment held in all runs (0 escapes).

**Corrections.** An earlier run (archived numbers in `results/models/`) contained three defects, fixed
with regression tests: (i) the multi-agent state reducer keyed findings by route+CWE, so DVWA
command-injection levels overwrote each other; (ii) the scorer routed `/ftp/` listing findings to the
null-byte case; (iii) the scorer assigned DVWA SQLi levels by keyword before payload. Together they more
than doubled the apparent multi-agent recall deficit (0.21-0.26 -> 0.04-0.11). `results/models_v2_rescored/`
holds the original runs rescored with the corrected scorer. The v1 (saturated 5-case) result is in `archive/v1/`.

**Model selection.** Opus 5 and Opus 5.5 decline both architectures' opening prompts, and Sonnet 5.5
declines the single agent's, with a `cyber` refusal; the raw responses (and the accepting controls) are in
`results/model_refusals/`, produced by `scripts/probe_model_refusals.py`.

## Paper

The paper (Springer format) is maintained separately and is not included in this repository. Its
tables are generated directly from the benchmark summaries by `scripts/make_paper_tables.py`, so every
number traces back to `results/models_v3/<slug>/summary/`.
