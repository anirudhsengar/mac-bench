"""Specialized 3-role LangGraph Multi-Agent architecture (Coordinator, Surface Mapper, Verification Agent)."""

from __future__ import annotations

import json
import os
from typing import Any, Literal

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

from mac_bench.crypto_redact import RunRedactor
from mac_bench.llm_client import build_role_llm, sync_live_budgets
from mac_bench.prompts.multi_agent_prompts import (
    COORDINATOR_SYSTEM_PROMPT,
    SURFACE_MAPPER_SYSTEM_PROMPT,
    VERIFIER_SYSTEM_PROMPT,
)
from mac_bench.config import load_manifest
from mac_bench.oracles.verify_oracles import CASE_ROUTE, SCOPE_ITEM_LABEL, scope_coverage
from mac_bench.schemas import AssessmentState, BudgetState, TargetEndpoint, normalize_endpoint_key
from mac_bench.tools.session_store import SessionManager
from mac_bench.tools.web_tools import ToolRuntimeContext, build_shared_tools

MAX_WORKER_TURNS_PER_HANDOFF = 7

# Ablation: fixed routing instead of the LLM Coordinator (MAC_BENCH_MA_COORDINATOR=static).
STATIC_MAPPING_ASSIGNMENTS = [
    "Map the in-scope attack surface of the DVWA target (http://dvwa): every vulnerability-class route named "
    "in the scope, with its exact form fields, parameters, and submit-button names.",
    "Map the in-scope attack surface of the OWASP Juice Shop target (http://juiceshop:3000): every "
    "vulnerability-class route named in the scope, including REST API endpoints and exposed directories.",
]
STATIC_VERIFY_INSTRUCTION = (
    "Behaviorally verify the assigned endpoint(s) for every in-scope vulnerability class that applies to them. "
    "For DVWA routes, test every security level named in the scope and submit one finding per level."
)
STATIC_VERIFY_BATCH = 2
# Ablation: LLM Coordinator plus per-instance coverage tracking (MAC_BENCH_MA_COORDINATOR=tracked).
MAX_COVERAGE_OVERRIDES = 4
COVERAGE_NOTE_PREFIX = "[CoverageCheck"
STATIC_MAX_VERIFY_ATTEMPTS = 2


class CoordinatorDecision(BaseModel):
    """Structured work assignment or halt decision produced by Coordinator."""

    route_to: Literal["surface_mapper", "verifier", "halt"] = Field(
        description="Next worker role to invoke, or 'halt' when assessment is complete or budgets are nearly exhausted."
    )
    assignment_instructions: str = Field(
        description="Focused, concrete task instructions for the chosen worker role."
    )
    target_endpoint_ids: list[str] = Field(
        default_factory=list,
        description="Specific endpoint_id values from AssessmentState assigned to the worker (especially for 'verifier').",
    )
    reopen_for_mapping_ids: list[str] = Field(
        default_factory=list,
        description="Optional endpoint_id values whose status should be set to 'needs_more_mapping' for deeper inspection.",
    )
    completed_task_summary: str = Field(
        default="",
        description="Concise label for any milestone completed since the previous turn.",
    )
    halt_reason: str = Field(
        default="",
        description="Reason for halting when route_to == 'halt'.",
    )


def _format_state_brief_for_coordinator(state: AssessmentState, with_coverage: bool = False) -> str:
    b = state.budgets
    ep_rows = [
        {
            "endpoint_id": ep.endpoint_id,
            "target": ep.target,
            "method": ep.method,
            "url": ep.url,
            "params": ep.parameter_names,
            "auth": ep.auth_context,
            "discovery": ep.discovery_status,
            "suspected_cwes": ep.suspected_cwes,
            "status": ep.task_status,
            "verify_attempts": ep.verification_attempts,
        }
        for ep in state.endpoints
    ]
    finding_rows = [
        {
            "finding_id": f.finding_id,
            "target": f.target,
            "cwe": f.cwe,
            "url": f.endpoint_url,
            "verdict": f.verdict,
            "title": f.title,
        }
        for f in state.findings
    ]
    summary = {
        "budgets": {
            "http_used": b.http_transactions_used,
            "http_remaining": b.http_remaining,
            "llm_used": b.llm_calls_used,
            "llm_remaining": b.llm_remaining,
            "elapsed_seconds": round(b.elapsed_seconds, 1),
            "duration_remaining_seconds": round(b.duration_remaining, 1),
        },
        "handoff_count": state.handoff_count,
        "completed_tasks": state.completed_tasks[-15:],
        "recent_worker_notes": state.notes[-6:],
        "endpoints_inventory": ep_rows,
        "findings_inventory": finding_rows,
    }
    if with_coverage:
        cov = scope_coverage(state.findings)
        summary["scope_coverage_checklist"] = {SCOPE_ITEM_LABEL[c]: st for c, st in cov.items()}
    return json.dumps(summary, indent=2, ensure_ascii=False)


def _execute_tool_loop(
    *,
    role: str,
    system_prompt: str,
    task_prompt: str,
    tools: list[Any],
    ctx: ToolRuntimeContext,
    state: AssessmentState,
    max_turns: int = MAX_WORKER_TURNS_PER_HANDOFF,
) -> tuple[str, str]:
    """Run a bounded tool-calling loop for a worker agent while strictly respecting shared budgets."""
    ctx.active_role = role
    llm = build_role_llm(role).bind_tools(tools)
    tool_map = {t.name: t for t in tools}

    messages: list[BaseMessage] = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=task_prompt),
    ]
    final_summary = ""
    depleted_reason = ""

    for _ in range(max_turns):
        live_b = sync_live_budgets(state.budgets, state.started_at_epoch)
        depleted, reason = live_b.is_depleted()
        if depleted:
            depleted_reason = reason
            break

        try:
            ai_msg: AIMessage = llm.invoke(messages)
        except Exception as exc:
            err_txt = str(exc)
            if "depleted" in err_txt.lower() or "budget" in err_txt.lower():
                depleted_reason = "llm_budget_depleted"
                break
            final_summary = f"{role} LLM error: {err_txt[:180]}"
            break

        messages.append(ai_msg)
        if isinstance(ai_msg.content, str) and ai_msg.content.strip():
            final_summary = ai_msg.content.strip()[:500]
        elif isinstance(ai_msg.content, list):
            text_parts = [
                blk.get("text", "")
                for blk in ai_msg.content
                if isinstance(blk, dict) and blk.get("type") == "text"
            ]
            if any(text_parts):
                final_summary = " ".join(text_parts).strip()[:500]

        tool_calls = getattr(ai_msg, "tool_calls", None) or []
        if not tool_calls:
            break

        for tc in tool_calls:
            t_name = tc["name"]
            t_args = tc.get("args") or {}
            t_id = tc["id"]
            # Check HTTP budget before running network-consuming tools
            live_b = sync_live_budgets(state.budgets, state.started_at_epoch)
            if t_name in ("http_request", "browser_navigate") and live_b.http_remaining <= 0:
                depleted_reason = "http_budget_depleted"
                messages.append(
                    ToolMessage(
                        content=json.dumps({"error": "HTTP budget depleted; cannot execute network tool."}),
                        tool_call_id=t_id,
                    )
                )
                continue

            tool_fn = tool_map.get(t_name)
            if tool_fn is None:
                obs = json.dumps({"error": f"Unknown tool: {t_name}"})
            else:
                try:
                    obs = str(tool_fn.invoke(t_args))
                except Exception as exc:
                    obs = json.dumps({"error": f"Tool execution error: {str(exc)[:240]}"})
            messages.append(ToolMessage(content=obs, tool_call_id=t_id))

        if depleted_reason:
            break

    return final_summary or f"{role} finished assigned step.", depleted_reason


def run_multi_agent_assessment(run_id: str, coordinator: str | None = None) -> tuple[AssessmentState, SessionManager]:
    """Build and execute the 3-role LangGraph workflow (Coordinator, Surface Mapper, Verification Agent).

    coordinator: "llm" (default), "static" (ablation: deterministic routing, no Coordinator LLM calls), or
    "tracked" (ablation: LLM Coordinator that sees a per-instance coverage checklist and cannot halt while
    items remain open, up to MAX_COVERAGE_OVERRIDES times).
    """
    coordinator = coordinator or os.environ.get("MAC_BENCH_MA_COORDINATOR", "llm")
    if coordinator not in ("llm", "static", "tracked"):
        raise ValueError(f"Unknown coordinator mode: {coordinator}")
    redactor = RunRedactor()
    session_mgr = SessionManager()
    ctx = ToolRuntimeContext(session_mgr=session_mgr, redactor=redactor)

    mapper_tools = build_shared_tools(ctx, allow_record_endpoint=True, allow_submit_finding=False)
    verifier_tools = build_shared_tools(ctx, allow_record_endpoint=False, allow_submit_finding=True)

    def _coverage_override(state: AssessmentState, budgets: BudgetState) -> dict[str, Any] | None:
        """Refuse a halt while scope items are open: send them to the Verifier (or the Mapper)."""
        used = sum(1 for n in state.notes if n.startswith(COVERAGE_NOTE_PREFIX))
        depleted, _ = budgets.is_depleted()
        if used >= MAX_COVERAGE_OVERRIDES or depleted or budgets.llm_remaining < 10:
            return None
        open_items = [c for c, st in scope_coverage(state.findings).items() if st in ("open", "inconclusive")]
        if not open_items:
            return None
        labels = "; ".join(SCOPE_ITEM_LABEL[c] for c in open_items)
        ep_ids: list[str] = []
        for c in open_items:
            target, frag = CASE_ROUTE[c]
            for ep in state.endpoints:
                if ep.target == target and frag in ep.path.lower() and ep.endpoint_id not in ep_ids:
                    ep_ids.append(ep.endpoint_id)
        if ep_ids:
            route, assignment = "verifier", (
                f"Coverage check: these scope items have no confirmed or rejected finding yet: {labels}. "
                "Verify them on the assigned endpoints, setting the DVWA security level as each item requires, "
                "and submit one finding per item."
            )
            ep_ids = ep_ids[:3]
        else:
            route, assignment = "surface_mapper", (
                f"Coverage check: these scope items have no mapped route yet: {labels}. Map their routes."
            )
        return {
            "budgets": budgets,
            "handoff_count": state.handoff_count + 1,
            "next_action": route,
            "active_assignment": assignment,
            "assigned_endpoint_ids": ep_ids,
            "notes": [f"{COVERAGE_NOTE_PREFIX} {used + 1}/{MAX_COVERAGE_OVERRIDES} -> {route}] halt refused; open: {labels}"[:400]],
        }

    def coordinator_node(state: AssessmentState) -> dict[str, Any]:
        live_b = sync_live_budgets(state.budgets, state.started_at_epoch)
        depleted, reason = live_b.is_depleted()
        if depleted or live_b.llm_remaining <= 0:
            return {
                "budgets": live_b,
                "next_action": "halt",
                "halt_reason": reason or "llm_budget_depleted",
            }
        # Reserve stopping cleanly if only 1 LLM call left and nothing trivial left, or let last worker act if >1
        if live_b.llm_remaining == 1:
            return {
                "budgets": live_b,
                "next_action": "halt",
                "halt_reason": "final_llm_call_reserve_halt",
            }

        ctx.active_role = "coordinator"
        coord_llm = build_role_llm("coordinator").with_structured_output(CoordinatorDecision)
        state_json = _format_state_brief_for_coordinator(
            state.model_copy(update={"budgets": live_b}), with_coverage=(coordinator == "tracked")
        )

        try:
            decision: CoordinatorDecision = coord_llm.invoke(
                [
                    SystemMessage(content=COORDINATOR_SYSTEM_PROMPT),
                    HumanMessage(
                        content=(
                            "Review the current AssessmentState JSON below and emit the next CoordinatorDecision:\n\n"
                            f"{state_json}"
                        )
                    ),
                ]
            )
        except Exception as exc:
            updated_b = sync_live_budgets(live_b, state.started_at_epoch)
            return {
                "budgets": updated_b,
                "next_action": "halt",
                "halt_reason": f"coordinator_stop:{str(exc)[:120]}",
            }

        updated_b = sync_live_budgets(live_b, state.started_at_epoch)

        if coordinator == "tracked" and decision.route_to == "halt":
            override = _coverage_override(state, updated_b)
            if override is not None:
                return override

        # Apply optional reopen_for_mapping transitions on candidate endpoints
        reopened_eps: list[TargetEndpoint] = []
        if decision.reopen_for_mapping_ids:
            reopen_set = set(decision.reopen_for_mapping_ids)
            for ep in state.endpoints:
                if ep.endpoint_id in reopen_set:
                    reopened_eps.append(
                        ep.model_copy(
                            update={
                                "task_status": "needs_more_mapping",
                                "mapping_attempts": ep.mapping_attempts + 1,
                            }
                        )
                    )

        completed_add = [decision.completed_task_summary] if decision.completed_task_summary.strip() else []
        handoff_inc = 0 if decision.route_to == "halt" else 1

        return {
            "budgets": updated_b,
            "endpoints": reopened_eps,
            "completed_tasks": completed_add,
            "handoff_count": state.handoff_count + handoff_inc,
            "next_action": decision.route_to,
            "active_assignment": decision.assignment_instructions,
            "assigned_endpoint_ids": decision.target_endpoint_ids,
            "halt_reason": decision.halt_reason if decision.route_to == "halt" else state.halt_reason,
            "notes": [
                f"[Coordinator -> {decision.route_to}] {redactor.sanitize_text(decision.assignment_instructions)[:280]}"
            ],
        }

    def static_coordinator_node(state: AssessmentState) -> dict[str, Any]:
        live_b = sync_live_budgets(state.budgets, state.started_at_epoch)
        depleted, reason = live_b.is_depleted()
        if depleted or live_b.llm_remaining <= 0:
            return {"budgets": live_b, "next_action": "halt", "halt_reason": reason or "llm_budget_depleted"}
        if state.handoff_count < len(STATIC_MAPPING_ASSIGNMENTS):
            assignment = STATIC_MAPPING_ASSIGNMENTS[state.handoff_count]
            return {
                "budgets": live_b,
                "handoff_count": state.handoff_count + 1,
                "next_action": "surface_mapper",
                "active_assignment": assignment,
                "assigned_endpoint_ids": [],
                "notes": [f"[StaticRouter -> surface_mapper] {assignment[:200]}"],
            }
        pending = [
            ep.endpoint_id
            for ep in state.endpoints
            if ep.task_status in ("pending_verification", "needs_more_mapping")
            and ep.verification_attempts < STATIC_MAX_VERIFY_ATTEMPTS
        ]
        if not pending:
            return {"budgets": live_b, "next_action": "halt", "halt_reason": "static_schedule_complete"}
        batch = pending[:STATIC_VERIFY_BATCH]
        return {
            "budgets": live_b,
            "handoff_count": state.handoff_count + 1,
            "next_action": "verifier",
            "active_assignment": STATIC_VERIFY_INSTRUCTION,
            "assigned_endpoint_ids": batch,
            "notes": [f"[StaticRouter -> verifier] {batch}"],
        }

    def surface_mapper_node(state: AssessmentState) -> dict[str, Any]:
        ctx.recorded_endpoints.clear()
        existing_brief = [
            f"{ep.endpoint_id} ({ep.discovery_status}, params={ep.parameter_names}, status={ep.task_status})"
            for ep in state.endpoints
        ]
        prompt = (
            f"## Coordinator Assignment\n{state.active_assignment}\n\n"
            f"## Already Recorded Endpoints (avoid duplicate crawling unless re-mapping parameters)\n"
            + ("\n".join(existing_brief) if existing_brief else "(None yet)")
            + f"\n\n## Current Remaining Budgets\nHTTP remaining: {state.budgets.http_remaining}/{state.budgets.max_http_transactions}, "
            f"LLM remaining: {state.budgets.llm_remaining}/{state.budgets.max_llm_calls}.\n"
            "Map the assigned target surface and call `record_endpoint` for each observed or candidate endpoint."
        )
        summary, dep_reason = _execute_tool_loop(
            role="surface_mapper",
            system_prompt=SURFACE_MAPPER_SYSTEM_PROMPT,
            task_prompt=prompt,
            tools=mapper_tools,
            ctx=ctx,
            state=state,
        )
        new_eps = list(ctx.recorded_endpoints)
        ctx.recorded_endpoints.clear()
        updated_b = sync_live_budgets(state.budgets, state.started_at_epoch)
        return {
            "budgets": updated_b,
            "endpoints": new_eps,
            "tool_errors": list(ctx.tool_errors),
            "tool_invocations": ctx.tool_invocations,
            "retry_count": ctx.retry_count,
            "halt_reason": dep_reason or state.halt_reason,
            "notes": [
                f"[SurfaceMapper] Recorded {len(new_eps)} endpoint(s). {redactor.sanitize_text(summary)[:260]}"
            ],
        }

    def verifier_node(state: AssessmentState) -> dict[str, Any]:
        ctx.recorded_findings.clear()
        assigned_set = set(state.assigned_endpoint_ids)
        target_eps = [ep for ep in state.endpoints if ep.endpoint_id in assigned_set]
        if not target_eps:
            target_eps = [ep for ep in state.endpoints if ep.task_status == "pending_verification"][:2]

        ep_details = json.dumps([ep.model_dump() for ep in target_eps], indent=2, ensure_ascii=False)
        prompt = (
            f"## Coordinator Verification Assignment\n{state.active_assignment}\n\n"
            f"## Assigned Candidate Endpoint Records\n{ep_details}\n\n"
            f"## Current Remaining Budgets\nHTTP remaining: {state.budgets.http_remaining}/{state.budgets.max_http_transactions}, "
            f"LLM remaining: {state.budgets.llm_remaining}/{state.budgets.max_llm_calls}.\n"
            "Execute behavioral verification for the assigned endpoint(s) and call `submit_finding` with "
            "complete request_sequence and behavioral response_evidence (plus browser_js_evidence where applicable)."
        )
        summary, dep_reason = _execute_tool_loop(
            role="verifier",
            system_prompt=VERIFIER_SYSTEM_PROMPT,
            task_prompt=prompt,
            tools=verifier_tools,
            ctx=ctx,
            state=state,
        )

        new_findings = list(ctx.recorded_findings)
        ctx.recorded_findings.clear()

        # Update status of tested TargetEndpoints based on submitted verdicts
        findings_by_ep: dict[str, list[str]] = {}
        for f in new_findings:
            ek = normalize_endpoint_key(f.target, f.method, f.endpoint_url)
            findings_by_ep.setdefault(ek, []).append(f.verdict)

        updated_eps: list[TargetEndpoint] = []
        for ep in target_eps:
            verdicts = findings_by_ep.get(ep.endpoint_id, [])
            if "confirmed" in verdicts:
                new_status: Literal[
                    "pending_verification",
                    "in_verification",
                    "verified",
                    "rejected",
                    "needs_more_mapping",
                    "archived",
                ] = "verified"
            elif "rejected" in verdicts:
                new_status = "rejected"
            elif "inconclusive" in verdicts:
                new_status = "needs_more_mapping"
            else:
                new_status = ep.task_status
            updated_eps.append(
                ep.model_copy(
                    update={
                        "task_status": new_status,
                        "verification_attempts": ep.verification_attempts + 1,
                    }
                )
            )

        updated_b = sync_live_budgets(state.budgets, state.started_at_epoch)
        return {
            "budgets": updated_b,
            "endpoints": updated_eps,
            "findings": new_findings,
            "tool_errors": list(ctx.tool_errors),
            "tool_invocations": ctx.tool_invocations,
            "retry_count": ctx.retry_count,
            "halt_reason": dep_reason or state.halt_reason,
            "notes": [
                f"[Verifier] Submitted {len(new_findings)} finding(s). {redactor.sanitize_text(summary)[:260]}"
            ],
        }

    def route_from_coordinator(
        state: AssessmentState,
    ) -> Literal["surface_mapper", "verifier", "__end__"]:
        if state.next_action == "surface_mapper":
            return "surface_mapper"
        if state.next_action == "verifier":
            return "verifier"
        return "__end__"

    graph = StateGraph(state_schema=AssessmentState)
    graph.add_node("coordinator", static_coordinator_node if coordinator == "static" else coordinator_node)
    graph.add_node("surface_mapper", surface_mapper_node)
    graph.add_node("verifier", verifier_node)

    graph.add_edge(START, "coordinator")
    graph.add_conditional_edges(
        "coordinator",
        route_from_coordinator,
        {
            "surface_mapper": "surface_mapper",
            "verifier": "verifier",
            "__end__": END,
        },
    )
    graph.add_edge("surface_mapper", "coordinator")
    graph.add_edge("verifier", "coordinator")

    compiled = graph.compile()
    _bud = load_manifest()["budgets"]
    init_state = AssessmentState(
        run_id=run_id,
        architecture="multi_agent",
        budgets=BudgetState(
            max_http_transactions=int(_bud["max_http_transactions"]),
            max_llm_calls=int(_bud["max_llm_calls"]),
            max_duration_seconds=int(_bud["max_duration_seconds"]),
        ),
    )
    raw_final = compiled.invoke(init_state, config={"recursion_limit": 600})
    final_state = AssessmentState.model_validate(raw_final)
    final_b = sync_live_budgets(final_state.budgets, final_state.started_at_epoch)
    final_state = final_state.model_copy(update={"budgets": final_b})
    return final_state, session_mgr
