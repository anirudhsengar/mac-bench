"""Container-side LLM client factory and live infrastructure budget synchronizer."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx
from langchain_anthropic import ChatAnthropic

from mac_bench.schemas import BudgetState

# Model is frozen per run; the relay independently enforces the allowed model, and the host
# run driver passes MAC_BENCH_MODEL into the container so client and relay always agree.
FROZEN_MODEL_ID = os.environ.get("MAC_BENCH_MODEL", "claude-haiku-5-5")
FROZEN_MAX_TOKENS = 4096


def build_role_llm(role: str) -> ChatAnthropic:
    """Create a frozen ChatAnthropic instance routed through the loopback->Unix-socket host relay."""
    relay_url = os.environ.get("MAC_LLM_BASE_URL", "http://127.0.0.1:18080")
    return ChatAnthropic(
        model=FROZEN_MODEL_ID,
        anthropic_api_url=relay_url,
        anthropic_api_key="relay-managed-key",
        max_tokens=FROZEN_MAX_TOKENS,
        max_retries=1,
        default_headers={"x-agent-role": role},
    )


def fetch_mediator_budget() -> dict[str, Any]:
    proxy_url = os.environ.get("HTTP_PROXY", "http://proxy:8080")
    with httpx.Client(proxy=proxy_url, timeout=5.0) as client:
        resp = client.get("http://mediator.status/budget")
        resp.raise_for_status()
        return resp.json()


def fetch_llm_budget() -> dict[str, Any]:
    relay_url = os.environ.get("MAC_LLM_BASE_URL", "http://127.0.0.1:18080")
    with httpx.Client(trust_env=False, timeout=5.0) as client:
        resp = client.get(f"{relay_url}/budget")
        resp.raise_for_status()
        return resp.json()


def sync_live_budgets(prev: BudgetState, started_at_epoch: float) -> BudgetState:
    """Pull authoritative HTTP and LLM counters from mediator proxy and host LLM relay."""
    http_used = prev.http_transactions_used
    llm_used = prev.llm_calls_used
    in_tok = prev.input_tokens
    out_tok = prev.output_tokens

    try:
        m = fetch_mediator_budget()
        http_used = max(http_used, int(m.get("tx_used", 0)))
    except Exception:
        pass

    try:
        l_stats = fetch_llm_budget()
        llm_used = max(llm_used, int(l_stats.get("llm_calls_used", 0)))
        in_tok = max(in_tok, int(l_stats.get("input_tokens", 0)))
        out_tok = max(out_tok, int(l_stats.get("output_tokens", 0)))
    except Exception:
        pass

    elapsed = round(max(prev.elapsed_seconds, time.time() - started_at_epoch), 2)
    return BudgetState(
        max_http_transactions=prev.max_http_transactions,
        http_transactions_used=http_used,
        max_llm_calls=prev.max_llm_calls,
        llm_calls_used=llm_used,
        max_duration_seconds=prev.max_duration_seconds,
        elapsed_seconds=elapsed,
        input_tokens=in_tok,
        output_tokens=out_tok,
    )
