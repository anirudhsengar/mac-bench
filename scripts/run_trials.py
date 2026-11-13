#!/usr/bin/env python3
"""Execute the 5 paired benchmark trials (10 isolated runs) under frozen budgets and containment."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from mac_bench.config import load_dotenv_key, load_frozen_config, repo_root, results_root
from mac_bench.crypto_redact import redact_obj
from mac_bench.llm_relay import HostLLMRelay
from mac_bench.targets.reset_and_seed import (
    prepare_clean_run,
    send_proxy_control,
    snapshot_firewall_counters,
)

ALLOWED_DESTINATIONS = {"dvwa:80", "juiceshop:3000"}


def verify_frozen_hashes(root: Path, frozen: dict[str, Any]) -> None:
    expected = frozen.get("code_and_prompt_sha256", {})
    mapping = {
        "benchmark_manifest_yaml": root / "configs" / "benchmark_manifest.yaml",
        "shared_scope_py": root / "src" / "mac_bench" / "prompts" / "shared_scope.py",
        "multi_agent_prompts_py": root / "src" / "mac_bench" / "prompts" / "multi_agent_prompts.py",
        "react_prompts_py": root / "src" / "mac_bench" / "prompts" / "react_prompts.py",
        "web_tools_py": root / "src" / "mac_bench" / "tools" / "web_tools.py",
        "multi_agent_py": root / "src" / "mac_bench" / "agents" / "multi_agent.py",
        "react_baseline_py": root / "src" / "mac_bench" / "agents" / "react_baseline.py",
        "mediator_addon_py": root / "docker" / "proxy" / "mediator_addon.py",
        "llm_relay_py": root / "src" / "mac_bench" / "llm_relay.py",
    }
    for key, path in mapping.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected.get(key) != actual:
            raise RuntimeError(f"Frozen hash mismatch on {key}: expected {expected.get(key)}, got {actual}")


def count_out_of_scope_escapes(proxy_log_file: Path) -> int:
    if not proxy_log_file.exists():
        return 0
    escapes = 0
    with open(proxy_log_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("decision") == "allow" and rec.get("destination") not in ALLOWED_DESTINATIONS:
                escapes += 1
    return escapes


def main() -> None:
    parser = argparse.ArgumentParser(description="Run 5 paired trials (Multi-Agent vs Single-Agent ReAct).")
    parser.add_argument("--resume", action="store_true", help="Skip individual runs whose output artifact already exists.")
    parser.add_argument("--trials", type=int, nargs="*", help="Optional subset of trial indices (default: all).")
    parser.add_argument("--arch", choices=["ma", "sa"], help="Run only this architecture's run(s) (for short foreground calls).")
    args = parser.parse_args()

    root = repo_root()
    preflight_file = root / "results" / "preflight" / "preflight_report.json"
    if not preflight_file.exists() or not json.loads(preflight_file.read_text(encoding="utf-8")).get("overall_passed"):
        raise SystemExit("Preflight check has not passed; run scripts/run_preflight.py first.")

    frozen = load_frozen_config()
    if not frozen:
        raise SystemExit("configs/frozen_experiment.json missing; run scripts/freeze_experiment.py first.")
    verify_frozen_hashes(root, frozen)

    budgets = frozen["shared_budgets"]
    max_http = int(budgets["max_http_transactions"])
    max_llm = int(budgets["max_llm_calls"])
    max_dur = int(budgets["max_duration_seconds"])
    # Model is env-overridable for the multi-model capability ladder; default is the frozen model.
    model_id = os.environ.get("MAC_BENCH_MODEL") or frozen["model"]["model_id"]

    res_root = results_root()
    trials_dir = res_root / "trials"
    trials_dir.mkdir(parents=True, exist_ok=True)
    llm_log_dir = res_root / "llm_logs"
    llm_log_dir.mkdir(parents=True, exist_ok=True)
    print(f"[run_trials] model={model_id} results_root={res_root}", flush=True)

    relay = HostLLMRelay(
        api_key=load_dotenv_key("ANTHROPIC_API_KEY"),
        relay_sock_path=root / "run_state" / "llm_relay" / "anthropic.sock",
        log_root=llm_log_dir,
        allowed_model=model_id,
    )
    relay.start_background()

    try:
        schedule = frozen["paired_trial_schedule"]
        for pair in schedule:
            t_idx = int(pair["trial_index"])
            if args.trials and t_idx not in args.trials:
                continue

            for pos_idx, arch in enumerate(pair["order"], start=1):
                short = "ma" if arch == "multi_agent" else "sa"
                if args.arch and short != args.arch:
                    continue
                run_id = f"trial_{t_idx}_{short}"
                artifact_path = trials_dir / f"{run_id}.json"

                if args.resume and artifact_path.exists():
                    print(f"[SKIP] {run_id} already exists (--resume).")
                    continue

                print(
                    f"\n=== Starting {run_id} (Trial {t_idx}/{len(schedule)}, Pair Order #{pos_idx}: {arch}) ===",
                    flush=True,
                )
                prep = prepare_clean_run(run_id, mode="benchmark", tx_limit=max_http)
                relay.start_run(run_id, llm_limit=max_llm)

                container_out = f"/app/work/{run_id}_state.json"
                host_agent_out = root / "run_state" / "agent_out" / f"{run_id}_state.json"
                if host_agent_out.exists():
                    host_agent_out.unlink()

                t0 = time.monotonic()
                timed_out = False
                try:
                    proc = subprocess.run(
                        [
                            "docker",
                            "compose",
                            "exec",
                            "-T",
                            "-e",
                            f"MAC_BENCH_MODEL={model_id}",
                            "-e",
                            f"MAC_BENCH_MA_COORDINATOR={os.environ.get('MAC_BENCH_MA_COORDINATOR', 'llm')}",
                            "agent",
                            "python3",
                            "-m",
                            "mac_bench.agents.runner_entry",
                            "--run-id",
                            run_id,
                            "--architecture",
                            arch,
                            "--output",
                            container_out,
                        ],
                        cwd=str(root),
                        text=True,
                        capture_output=True,
                        timeout=max_dur + 30,
                        check=True,
                    )
                    if proc.stdout.strip():
                        print(f"    Runner summary: {proc.stdout.strip().splitlines()[-1]}", flush=True)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    print(f"    [TIMEOUT] {run_id} reached 30-minute wall-clock cap.", flush=True)
                except subprocess.CalledProcessError as exc:
                    print(f"    [WARN] Runner exited non-zero: {exc.stderr[-400:]}", file=sys.stderr, flush=True)
                    raise

                wall_sec = round(time.monotonic() - t0, 2)
                llm_stats = relay.get_stats()
                proxy_stats = send_proxy_control({"action": "get_stats"})["stats"]
                fw_stats = snapshot_firewall_counters()

                proxy_audit_path = root / "results" / "proxy_logs" / run_id / "proxy_audit.jsonl"
                escapes = count_out_of_scope_escapes(proxy_audit_path)
                if escapes > 0:
                    raise RuntimeError(
                        f"CONTAINMENT BREACH: {escapes} out-of-scope allowed request(s) in {run_id}! Halting immediately."
                    )

                state_data: dict[str, Any] = {}
                if host_agent_out.exists():
                    state_data = json.loads(host_agent_out.read_text(encoding="utf-8"))

                run_artifact = redact_obj(
                    {
                        "run_id": run_id,
                        "trial_index": t_idx,
                        "pair_execution_order": pos_idx,
                        "architecture": arch,
                        "model_id": model_id,
                        "started_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "wall_runtime_seconds": wall_sec,
                        "timed_out": timed_out,
                        "starting_seed_state": prep["seed"],
                        "llm_stats": llm_stats,
                        "proxy_stats": proxy_stats,
                        "firewall_stats": fw_stats,
                        "out_of_scope_escapes": escapes,
                        "state": state_data,
                    }
                )
                artifact_path.write_text(json.dumps(run_artifact, indent=2, ensure_ascii=False), encoding="utf-8")
                print(
                    f"    Completed {run_id} in {wall_sec:.1f}s | "
                    f"LLM={llm_stats['llm_calls_used']}/{max_llm} "
                    f"({llm_stats['total_tokens']} tok) | "
                    f"HTTP={proxy_stats['tx_used']}/{max_http} | "
                    f"Endpoints={len(state_data.get('endpoints', []))} | "
                    f"Findings={len(state_data.get('findings', []))}",
                    flush=True,
                )
    finally:
        relay.stop()


if __name__ == "__main__":
    main()
