"""Container CLI entrypoint executing a single Multi-Agent or ReAct run inside the isolated sandbox."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from mac_bench.agents.multi_agent import run_multi_agent_assessment
from mac_bench.agents.react_baseline import run_react_baseline_assessment
from mac_bench.crypto_redact import redact_obj


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute a benchmark run inside the isolated agent container.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--architecture", choices=["multi_agent", "react_baseline"], required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    t0 = time.monotonic()
    session_mgr = None
    try:
        if args.architecture == "multi_agent":
            final_state, session_mgr = run_multi_agent_assessment(args.run_id)
        else:
            final_state, session_mgr = run_react_baseline_assessment(args.run_id)
    finally:
        if session_mgr is not None:
            session_mgr.close()

    wall_seconds = round(time.monotonic() - t0, 2)
    state_dict = redact_obj(final_state.model_dump())
    state_dict["wall_runtime_seconds"] = wall_seconds

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(state_dict, f, indent=2, ensure_ascii=False)

    print(
        json.dumps(
            {
                "run_id": args.run_id,
                "architecture": args.architecture,
                "wall_runtime_seconds": wall_seconds,
                "endpoints_count": len(final_state.endpoints),
                "findings_count": len(final_state.findings),
                "http_used": final_state.budgets.http_transactions_used,
                "llm_used": final_state.budgets.llm_calls_used,
                "halt_reason": final_state.halt_reason,
            }
        )
    )


if __name__ == "__main__":
    main()
