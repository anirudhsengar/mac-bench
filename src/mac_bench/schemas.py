"""Pydantic v2 state and artifact schemas for Multi-Agent and ReAct vulnerability assessment."""

from __future__ import annotations

import operator
import time
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from mac_bench.config import load_manifest

# Default budget ceilings are sourced from the frozen manifest so that the LangGraph state
# channel's default equals the run budget. (merge_budgets takes the MIN of ceilings as a
# safety invariant; if the default were smaller than the configured budget, LangGraph's
# seed-then-reduce would silently clamp the run to the default. Keeping them equal preserves
# both the invariant and the configured budget.)
try:
    _BUDGETS = load_manifest().get("budgets", {})
except Exception:  # pragma: no cover - fallback if manifest unreadable at import
    _BUDGETS = {}
_DEFAULT_MAX_HTTP = int(_BUDGETS.get("max_http_transactions", 200))
_DEFAULT_MAX_LLM = int(_BUDGETS.get("max_llm_calls", 50))
_DEFAULT_MAX_DURATION = int(_BUDGETS.get("max_duration_seconds", 1800))


def normalize_endpoint_key(target: str, method: str, url_or_path: str) -> str:
    parsed = urlsplit(url_or_path)
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        # Keep trailing slash distinction consistent only by normalizing duplicate slashes
        while "//" in path:
            path = path.replace("//", "/")
    return f"{target.lower()}:{method.upper()}:{path}"


class TargetEndpoint(BaseModel):
    """Observed or candidate endpoint record produced by Surface Mapper."""

    endpoint_id: str
    target: Literal["dvwa", "juiceshop"]
    url: str
    path: str
    method: str = "GET"
    parameter_names: list[str] = Field(default_factory=list)
    auth_context: str = "unauth"
    discovery_status: Literal["observed", "candidate"] = "observed"
    suspected_cwes: list[str] = Field(default_factory=list)
    observation_evidence: str = ""
    task_status: Literal[
        "pending_verification",
        "in_verification",
        "verified",
        "rejected",
        "needs_more_mapping",
        "archived",
    ] = "pending_verification"
    mapping_attempts: int = 1
    verification_attempts: int = 0


class FindingRecord(BaseModel):
    """Structured vulnerability assessment record with behavioral verification evidence."""

    finding_id: str
    target: Literal["dvwa", "juiceshop"]
    endpoint_url: str
    method: str
    parameter: str = ""
    cwe: str
    title: str
    verdict: Literal["confirmed", "rejected", "inconclusive"]
    request_sequence: list[str] = Field(default_factory=list)
    response_evidence: str = ""
    browser_js_evidence: str | None = None
    reported_by_role: str = "verifier"


class BudgetState(BaseModel):
    """Immutable-ceiling shared run budget tracked across all agents."""

    max_http_transactions: int = _DEFAULT_MAX_HTTP
    http_transactions_used: int = 0
    max_llm_calls: int = _DEFAULT_MAX_LLM
    llm_calls_used: int = 0
    max_duration_seconds: int = _DEFAULT_MAX_DURATION
    elapsed_seconds: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def http_remaining(self) -> int:
        return max(0, self.max_http_transactions - self.http_transactions_used)

    @property
    def llm_remaining(self) -> int:
        return max(0, self.max_llm_calls - self.llm_calls_used)

    @property
    def duration_remaining(self) -> float:
        return max(0.0, float(self.max_duration_seconds) - self.elapsed_seconds)

    def is_depleted(self) -> tuple[bool, str]:
        if self.http_transactions_used >= self.max_http_transactions:
            return True, "http_budget_depleted"
        if self.llm_calls_used >= self.max_llm_calls:
            return True, "llm_budget_depleted"
        if self.elapsed_seconds >= self.max_duration_seconds:
            return True, "duration_budget_depleted"
        return False, ""


class ToolErrorRecord(BaseModel):
    """Tracks tool failures and whether subsequent agent actions recovered."""

    error_id: str
    step_index: int
    agent_role: str
    tool_name: str
    target_hint: str = ""
    category: str
    recoverable: bool = True
    error_message: str
    recovered: bool = False
    recovery_detail: str | None = None


def merge_budgets(prev: BudgetState, new: BudgetState) -> BudgetState:
    """Monotonic reducer: prevents any node from resetting usage or enlarging ceilings."""
    return BudgetState(
        max_http_transactions=min(prev.max_http_transactions, new.max_http_transactions),
        http_transactions_used=max(prev.http_transactions_used, new.http_transactions_used),
        max_llm_calls=min(prev.max_llm_calls, new.max_llm_calls),
        llm_calls_used=max(prev.llm_calls_used, new.llm_calls_used),
        max_duration_seconds=min(prev.max_duration_seconds, new.max_duration_seconds),
        elapsed_seconds=max(prev.elapsed_seconds, new.elapsed_seconds),
        input_tokens=max(prev.input_tokens, new.input_tokens),
        output_tokens=max(prev.output_tokens, new.output_tokens),
    )


def merge_endpoints(prev: list[TargetEndpoint], new: list[TargetEndpoint]) -> list[TargetEndpoint]:
    """Upsert endpoints by endpoint_id while preserving parameter unions and observed upgrades."""
    by_id: dict[str, TargetEndpoint] = {ep.endpoint_id: ep.model_copy(deep=True) for ep in prev}
    for inc in new:
        if inc.endpoint_id in by_id:
            cur = by_id[inc.endpoint_id]
            merged_params = list(dict.fromkeys([*cur.parameter_names, *inc.parameter_names]))
            merged_cwes = list(dict.fromkeys([*cur.suspected_cwes, *inc.suspected_cwes]))
            # Upgrade candidate -> observed when actually observed
            disc = (
                "observed"
                if (cur.discovery_status == "observed" or inc.discovery_status == "observed")
                else "candidate"
            )
            by_id[inc.endpoint_id] = cur.model_copy(
                update={
                    "url": inc.url or cur.url,
                    "parameter_names": merged_params,
                    "auth_context": inc.auth_context if inc.auth_context != "unauth" else cur.auth_context,
                    "discovery_status": disc,
                    "suspected_cwes": merged_cwes,
                    "observation_evidence": inc.observation_evidence or cur.observation_evidence,
                    "task_status": inc.task_status,
                    "mapping_attempts": max(cur.mapping_attempts, inc.mapping_attempts),
                    "verification_attempts": max(cur.verification_attempts, inc.verification_attempts),
                }
            )
        else:
            by_id[inc.endpoint_id] = inc.model_copy(deep=True)
    return list(by_id.values())


def merge_findings(prev: list[FindingRecord], new: list[FindingRecord]) -> list[FindingRecord]:
    by_id: dict[str, FindingRecord] = {f.finding_id: f.model_copy(deep=True) for f in prev}
    for inc in new:
        by_id[inc.finding_id] = inc.model_copy(deep=True)
    return list(by_id.values())


def merge_errors(prev: list[ToolErrorRecord], new: list[ToolErrorRecord]) -> list[ToolErrorRecord]:
    by_id: dict[str, ToolErrorRecord] = {e.error_id: e.model_copy(deep=True) for e in prev}
    for inc in new:
        if inc.error_id in by_id:
            cur = by_id[inc.error_id]
            by_id[inc.error_id] = cur.model_copy(
                update={
                    "recovered": cur.recovered or inc.recovered,
                    "recovery_detail": inc.recovery_detail or cur.recovery_detail,
                }
            )
        else:
            by_id[inc.error_id] = inc.model_copy(deep=True)
    return list(by_id.values())


def merge_unique_strings(prev: list[str], new: list[str]) -> list[str]:
    return list(dict.fromkeys([*prev, *new]))


class AssessmentState(BaseModel):
    """Explicit LangGraph state schema shared across Coordinator, Surface Mapper, and Verifier."""

    run_id: str
    architecture: Literal["multi_agent", "react_baseline"]
    objective: str = (
        "Discover and behaviorally verify security vulnerabilities across permitted targets "
        "(http://dvwa and http://juiceshop:3000) within strict HTTP, LLM, and duration budgets."
    )
    started_at_epoch: float = Field(default_factory=time.time)
    budgets: Annotated[BudgetState, merge_budgets] = Field(default_factory=BudgetState)
    endpoints: Annotated[list[TargetEndpoint], merge_endpoints] = Field(default_factory=list)
    findings: Annotated[list[FindingRecord], merge_findings] = Field(default_factory=list)
    tool_errors: Annotated[list[ToolErrorRecord], merge_errors] = Field(default_factory=list)
    completed_tasks: Annotated[list[str], merge_unique_strings] = Field(default_factory=list)
    handoff_count: int = 0
    tool_invocations: int = 0
    retry_count: int = 0
    next_action: Literal["surface_mapper", "verifier", "halt"] = "surface_mapper"
    active_assignment: str = ""
    assigned_endpoint_ids: list[str] = Field(default_factory=list)
    halt_reason: str = ""
    notes: Annotated[list[str], operator.add] = Field(default_factory=list)
