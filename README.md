# Evaluative Benchmarking of a Specialized Multi-Agent LLM Architecture for Web Vulnerability Identification in Isolated Environments

Benchmarking framework and empirical evaluation comparing a 3-role LangGraph Multi-Agent architecture (Coordinator, Surface Mapper, Verification Agent) against a Single-Agent ReAct baseline on DVWA 2.3 and OWASP Juice Shop v16.0.0 under strict Docker network isolation and `mitmproxy` request mediation.

## Results (v2: difficulty-graded, multi-model)

The benchmark is a **14-case, 3-tier** difficulty-graded suite (trivial / moderate / hard);
budgets are 600 HTTP / 120 LLM / 3600 s so neither architecture is budget-capped. Run the
pipeline (requires Docker + `ANTHROPIC_API_KEY` in `.env`):

```bash
uv run python scripts/run_preflight.py                         # containment + 14 oracles (must pass)
uv run python scripts/freeze_experiment.py                     # pin model, budgets, source hashes
MAC_BENCH_MODEL=claude-haiku-5-5  MAC_BENCH_RESULTS_SUBDIR=models/haiku  \
  uv run python scripts/run_trials.py                          # 10 paired trials (20 runs)
MAC_BENCH_RESULTS_SUBDIR=models/haiku uv run python scripts/evaluate_results.py
# repeat with MAC_BENCH_MODEL=claude-sonnet-5 / claude-opus-4-8 and matching subdir
uv run python scripts/make_paper_tables.py                     # regenerate paper/tables/*.tex
```

Per-model artifacts land in `results/models/<slug>/summary/`. Headline across **10 paired
trials per model** (exact Wilcoxon signed-rank, MA vs SA):

| Model | MA recall | SA recall | p | MA:SA runtime |
|---|---|---|---|---|
| Haiku 5.5 | 0.71 | 0.93 | 0.002 | 2.45× |
| Sonnet 5  | 0.74 | 1.00 | 0.002 | 2.65× |
| Opus 4.8  | 0.79 | 1.00 | 0.002 | 2.81× |

**The single-agent ReAct baseline significantly out-recalls the 3-role multi-agent system on
every model**, while running ~2.5–2.8× faster at comparable-or-lower token cost. The MA deficit
concentrates in specific vulnerability classes — command injection (missed even as a single-shot
Low case, 0.3/0.1/0.1 MA vs 1.0 SA) and, on the larger models, FTP/PII exposure — not in the
hardest cases (MA matches SA on the DVWA SQLi Medium/High variants on Sonnet/Opus). Containment
held in all 60 runs (0 out-of-scope escapes). The newest Claude models (Sonnet 5.5, Opus 5/5.5) decline the assessment-agent role
under cyber safeguards, so the ladder uses the most capable non-refusing model per tier.
The v1 (saturated 5-case) result is archived in `archive/v1/`.

## Paper

The IEEE-format write-up is maintained separately and is not included in this repository.
Its result tables and the per-tier figure are generated directly from the benchmark summaries by
`scripts/make_paper_tables.py` (into a local `paper/tables/` directory), so every number in the
paper traces back to the artifacts under `results/models/<slug>/summary/`.
