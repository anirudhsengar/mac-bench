# Reproducibility & Demonstration Guide

This document records the exact container digests, network containment configuration, target seeding procedures, frozen experimental controls, and step-by-step commands required to reproduce the benchmark from scratch.

---

## 1. Pinned Artifacts & Container Digests

All container images and source archives are pinned to immutable SHA-256 digests in [`docker-compose.yml`](docker-compose.yml), [`docker/`](docker/), and [`configs/frozen_experiment.json`](configs/frozen_experiment.json):

| Component | Version / Tag | Pinned SHA-256 Digest |
|---|---|---|
| **DVWA Source Archive** | Release `2.3` (`digininja/DVWA`) | `f19bed738dd2d3867b5a7d50ffafe6fe07b30278824467e0ff24a1737e009f22` |
| **DVWA Runtime Base** | `php:8.2-apache-bookworm` | `sha256:46804ea2b61eaf25ca47fa8aafc917015b8dad6b7a64c4364bb051a9dff275d5` |
| **DVWA Database** | `mariadb:10.11` | `sha256:d769e37960821dfdcf096954f6e7ac89f747e116c1bba98e48edd265dfc7deae` |
| **OWASP Juice Shop** | `bkimminich/juice-shop:v16.0.0` | `sha256:5aef8464395d101d984d255166b079a52a573fba900450612f8cf3da2ad3a2dd` |
| **Mediator Proxy Base** | `python:3.12-slim-bookworm` + `mitmproxy` | `sha256:da54eb86849fe19be7584d8b3f291fcf0c53c196760ab3d70dc6382f681ef9c0` |
| **Agent Sandbox Base** | `mcr.microsoft.com/playwright:v1.62.0-noble` | `sha256:baed2032d533817f3dbe6425de795788430ba345e819a1201337009ba17c9d07` |
| **Netns Firewall Sidecar** | `alpine:3.22` + `iptables` | `sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce` |
| **LLM Models** | `claude-haiku-5-5`, `claude-sonnet-5`, `claude-opus-4-8` (Anthropic Messages API) | `max_tokens=4096`, `stream=false`, one model frozen per run set |

---

## 2. Network Isolation & Containment Architecture

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ HOST MACHINE                                                               │
│  • .env (ANTHROPIC_API_KEY stays strictly in host memory; never mounted)   │
│  • HostLLMRelay  ──► Unix Socket (/run/llm-relay/anthropic.sock)           │
│      - Permits ONLY POST /v1/messages for the frozen model        │
│      - Enforces the per-run LLM-call cap & logs exact token counts         │
│  • Proxy Control ──► Unix Socket (/run/proxy-ctl/control.sock)             │
│      - Mounted ONLY into proxy (inaccessible to agent container)           │
└───────────────▲───────────────────────────────────────▲────────────────────┘
                │ UDS                                   │ UDS + ./results/proxy_logs
┌───────────────┴───────────────────────┐   ┌───────────┴────────────────────┐
│ agent_net (internal: true, no ports)  │   │ proxy (mitmproxy 11.x)         │
│  ┌─────────────────────────────────┐  │   │  • Joins agent_net & target_net│
│  │ agent-firewall (NET_ADMIN)      │  │   │  • Deny-by-default policy      │
│  │  • OUTPUT policy DROP           │  │   │    (http://dvwa:80,            │
│  │  • Allows ONLY lo, 127.0.0.11:53│  │   │     http://juiceshop:3000)     │
│  │    and proxy:8080               │  │   │  • Validates 3xx Redirect URLs │
│  │  • Counts & rejects all direct  │  │   │  • Blocks CONNECT & WebSockets │
│  │    socket / bridge attempts     │  │   │  • Enforces per-run HTTP cap   │
│  ├─────────────────────────────────┤  │   └───────────────┬────────────────┘
│  │ agent (network_mode: firewall)  │──┼──► TCP :8080 ─────┤
│  │  • user=pwuser, cap_drop=[ALL]  │  │                   ▼
│  │  • no-new-privileges:true       │  │   ┌────────────────────────────────┐
│  └─────────────────────────────────┘  │   │ target_net (internal: true)    │
└───────────────────────────────────────┘   │  • dvwa:80 + dvwa-db:3306      │
                                            │  • juiceshop:3000              │
                                            │  • redirect-trap:8090 (preflt) │
                                            └────────────────────────────────┘
```

### Why This Boundary Satisfies RQ3 Without Host-Root Risk
1. **Dual `internal: true` Docker Networks**: Neither `agent_net` nor `target_net` has an external default route, and zero `ports:` are published to the host.
2. **Defense-in-Depth Netns Firewall**: Because Linux Docker bridge networks can otherwise permit packets addressed to the host's `.1` bridge interface IP, `agent` shares the network namespace of `agent-firewall` (`cap_add: [NET_ADMIN]`) while running as unprivileged `pwuser` with `cap_drop: [ALL]`. `iptables` rules in `AGENT_FW_BLOCK` reject and count any direct socket attempt to the host bridge IP, unauthorized proxy ports, or non-proxied destinations.
3. **Host-Only Secret & Budget Control**: `ANTHROPIC_API_KEY` never enters any container; `agent` communicates with the frozen model exclusively via a mounted Unix socket handled by [`HostLLMRelay`](src/mac_bench/llm_relay.py), and proxy budget resets occur over a separate host-to-proxy Unix socket inaccessible to `agent`.

---

## 3. Step-by-Step Reproduction Instructions

### Prerequisites
- Linux host with Docker Engine 24+ and Docker Compose v2+
- [`uv`](https://docs.astral.sh/uv/) (Python 3.12 toolchain)
- `.env` file in the repository root containing `ANTHROPIC_API_KEY=sk-ant-...`

### Step 1: Install Host Python Environment & Run Unit Tests
```bash
uv sync --python 3.12
.venv/bin/pytest -v
```

### Step 2: Fetch DVWA 2.3 Source Tarball (if not cached locally) & Build Containers
```bash
mkdir -p docker/dvwa results/proxy_logs run_state/proxy_ctl run_state/llm_relay run_state/agent_out
chmod 777 run_state/agent_out
if [ ! -f docker/dvwa/dvwa-src.tar.gz ]; then
  curl -fsSL https://github.com/digininja/DVWA/archive/refs/tags/2.3.tar.gz -o docker/dvwa/dvwa-src.tar.gz
fi
echo "f19bed738dd2d3867b5a7d50ffafe6fe07b30278824467e0ff24a1737e009f22  docker/dvwa/dvwa-src.tar.gz" | sha256sum -c -
docker compose build
```

### Step 3: Run Preflight Containment & Ground-Truth Oracle Suite
Benchmark runs are gated on 100% pass of [`scripts/run_preflight.py`](scripts/run_preflight.py), which tests network topology, direct socket egress/target/host-bridge/wrong-port blocking, proxy destination/CONNECT/WebSocket/prohibited-redirect blocking, hard HTTP budget enforcement, exploitation of all 14 ground-truth instances on the live targets, and clean database state reset:
```bash
.venv/bin/python scripts/run_preflight.py
```
Inspect output at `results/preflight/preflight_report.json`.

### Step 4: Freeze and Execute 10 Paired Trials per Model (20 Runs Each)
[`scripts/freeze_experiment.py`](scripts/freeze_experiment.py) writes [`configs/frozen_experiment.json`](configs/frozen_experiment.json), which locks the SHA-256 hashes of all prompts, tool and agent code, the mediator, the LLM relay, the manifest, budgets (`600` HTTP transactions, `120` LLM calls, `3600 s` wall-clock), and the counterbalanced pair schedule; `run_trials.py` refuses to run if any hash differs. The freeze records used for the paper's run sets are kept as `configs/frozen_experiment_main_v3.json` (main runs), `configs/frozen_experiment_ablation_static.json` (fixed-routing ablation), `configs/frozen_experiment_ablation_tracked.json` (coverage-tracking ablation), and `configs/frozen_experiment_sa_budgetmsg.json` (single-agent budget-message check).
```bash
.venv/bin/python scripts/freeze_experiment.py
for pair in "haiku claude-haiku-5-5" "sonnet claude-sonnet-5" "opus claude-opus-4-8"; do
  set -- $pair
  export MAC_BENCH_MODEL=$2 MAC_BENCH_RESULTS_SUBDIR=models_v3/$1
  .venv/bin/python scripts/run_trials.py --resume
  .venv/bin/python scripts/invalidate_failed_pairs.py models_v3/$1   # drop pairs with any failed LLM call ...
  .venv/bin/python scripts/run_trials.py --resume                    # ... and rerun them in full
done
# Ablations (Haiku only): fixed routing instead of the LLM Coordinator, and the LLM Coordinator
# with per-instance coverage tracking and a halt check
for v in static tracked; do
  MAC_BENCH_MA_COORDINATOR=$v MAC_BENCH_MODEL=claude-haiku-5-5 MAC_BENCH_RESULTS_SUBDIR=models_v3/haiku_$v \
    .venv/bin/python scripts/run_trials.py --resume --arch ma
done
```
Each run recreates Juice Shop v16.0.0, resets DVWA 2.3 via `setup.php`, seeds the two Juice Shop accounts, zeroes firewall and proxy counters, verifies `0` out-of-scope escapes afterward, and writes redacted artifacts to `results/<subdir>/trials/`. Prompt caching is applied at the host relay; it changes billing and latency, not the model input.

### Step 5: Score, Analyse, and Regenerate the Paper Tables
```bash
for m in haiku sonnet opus haiku_static haiku_tracked; do
  MAC_BENCH_RESULTS_SUBDIR=models_v3/$m .venv/bin/python scripts/evaluate_results.py
  .venv/bin/python scripts/failure_funnel.py models_v3/$m
done
.venv/bin/python scripts/make_paper_tables.py      # writes paper_springer/tables/*.tex and digest.json
.venv/bin/python scripts/probe_model_refusals.py   # optional: re-record model refusals (results/model_refusals/)
```
Outputs per run set (`results/models_v3/<slug>/`):
- `blind_review/` — architecture-anonymized finding packets and dual-rubric labels with oracle resolution
- `summary/per_run_metrics.csv` — per-run recall, FDP, tokens, LLM/tool/HTTP counts, handoffs, runtime, error recovery, containment
- `summary/benchmark_summary.json` — aggregated statistics, exact paired Wilcoxon tests, secret-leak scan
- `summary/failure_funnel.json` — the pipeline stage at which every missed instance was lost
- `summary/invalidated_pairs.jsonl` — pairs discarded because of provider errors (rerun in full)

Earlier result sets are kept for transparency: `results/models/` (original runs, original scorer) and `results/models_v2_rescored/` (original runs, corrected scorer). See the README for the three defects corrected between them.

---

## 4. Live Demonstration Script (Presentation Walkthrough)

For a concise 3-minute live demonstration:
1. **Show network & container isolation**:
   ```bash
   docker network inspect mac-bench_agent_net --format 'Internal={{.Internal}}'
   docker network inspect mac-bench_target_net --format 'Internal={{.Internal}}'
   docker compose ps
   ```
2. **Run preflight containment & ground-truth verification**:
   ```bash
   .venv/bin/python scripts/run_preflight.py
   ```
3. **Inspect redacted proxy audit logs and final summary metrics**:
   ```bash
   head -n 5 results/models_v3/haiku/proxy_logs/trial_1_ma/proxy_audit.jsonl
   cat results/models_v3/haiku/summary/per_run_metrics.csv
   ```
