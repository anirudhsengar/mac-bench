"""Single-Agent ReAct Baseline using identical model, scope, sessions, tools, and shared budgets."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal
import operator

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

from mac_bench.crypto_redact import RunRedactor
from mac_bench.llm_client import build_role_llm, sync_live_budgets
from mac_bench.prompts.react_prompts import REACT_BASELINE_SYSTEM_PROMPT
from mac_bench.config import load_manifest
from mac_bench.schemas import AssessmentState, BudgetState, merge_budgets
from mac_bench.tools.session_store import SessionManager
from mac_bench.tools.web_tools import ToolRuntimeContext, build_shared_tools


class ReActGraphState(BaseModel):
    """LangGraph state for the single-agent ReAct loop (carries full cumulative message history)."""

    run_id: str
    started_at_epoch: float
    budgets: Annotated[BudgetState, merge_budgets] = Field(default_factory=BudgetState)
    messages: Annotated[list[BaseMessage], operator.add] = Field(default_factory=list)
    should_continue: Literal["tools", "halt"] = "tools"
    halt_reason: str = ""


def run_react_baseline_assessment(run_id: str) -> tuple[AssessmentState, SessionManager]:
    """Build and execute the Single-Agent ReAct baseline in LangGraph."""
    redactor = RunRedactor()
    session_mgr = SessionManager()
    ctx = ToolRuntimeContext(session_mgr=session_mgr, redactor=redactor)
    ctx.active_role = "react_single"

    tools = build_shared_tools(ctx, allow_record_endpoint=True, allow_submit_finding=True)
    tool_map = {t.name: t for t in tools}
    llm = build_role_llm("react_single").bind_tools(tools)

    _bud = load_manifest()["budgets"]
    _init_budgets = BudgetState(
        max_http_transactions=int(_bud["max_http_transactions"]),
        max_llm_calls=int(_bud["max_llm_calls"]),
        max_duration_seconds=int(_bud["max_duration_seconds"]),
    )
    init_assessment = AssessmentState(run_id=run_id, architecture="react_baseline", budgets=_init_budgets)

    def reason_node(state: ReActGraphState) -> dict[str, Any]:
        live_b = sync_live_budgets(state.budgets, state.started_at_epoch)
        depleted, reason = live_b.is_depleted()
        if depleted or live_b.llm_remaining <= 0:
            return {
                "budgets": live_b,
                "should_continue": "halt",
                "halt_reason": reason or "llm_budget_depleted",
            }

        try:
            ai_msg: AIMessage = llm.invoke(state.messages)
        except Exception as exc:
            updated_b = sync_live_budgets(live_b, state.started_at_epoch)
            err_txt = str(exc)
            h_reason = "llm_budget_depleted" if "budget" in err_txt.lower() or "depleted" in err_txt.lower() else f"llm_error:{err_txt[:120]}"
            return {
                "budgets": updated_b,
                "should_continue": "halt",
                "halt_reason": h_reason,
            }

        updated_b = sync_live_budgets(live_b, state.started_at_epoch)
        tool_calls = getattr(ai_msg, "tool_calls", None) or []
        if not tool_calls:
            return {
                "budgets": updated_b,
                "messages": [ai_msg],
                "should_continue": "halt",
                "halt_reason": "agent_completed",
            }
        return {
            "budgets": updated_b,
            "messages": [ai_msg],
            "should_continue": "tools",
        }

    def act_node(state: ReActGraphState) -> dict[str, Any]:
        last_msg = state.messages[-1]
        tool_calls = getattr(last_msg, "tool_calls", None) or []
        tool_msgs: list[BaseMessage] = []
        halt_reason = state.halt_reason

        for tc in tool_calls:
            t_name = tc["name"]
            t_args = tc.get("args") or {}
            t_id = tc["id"]

            live_b = sync_live_budgets(state.budgets, state.started_at_epoch)
            if t_name in ("http_request", "browser_navigate") and live_b.http_remaining <= 0:
                halt_reason = "http_budget_depleted"
                tool_msgs.append(
                    ToolMessage(
                        content=json.dumps({"error": "HTTP budget depleted; halting network requests."}),
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
            tool_msgs.append(ToolMessage(content=obs, tool_call_id=t_id))

        updated_b = sync_live_budgets(state.budgets, state.started_at_epoch)
        depleted, reason = updated_b.is_depleted()
        next_step: Literal["tools", "halt"] = "halt" if depleted else "tools"
        return {
            "budgets": updated_b,
            "messages": tool_msgs,
            "should_continue": next_step,
            "halt_reason": reason or halt_reason,
        }

    def route_after_reason(state: ReActGraphState) -> Literal["act", "__end__"]:
        return "act" if state.should_continue == "tools" else "__end__"

    def route_after_act(state: ReActGraphState) -> Literal["reason", "__end__"]:
        return "reason" if state.should_continue == "tools" else "__end__"

    graph = StateGraph(state_schema=ReActGraphState)
    graph.add_node("reason", reason_node)
    graph.add_node("act", act_node)
    graph.add_edge(START, "reason")
    graph.add_conditional_edges("reason", route_after_reason, {"act": "act", "__end__": END})
    graph.add_conditional_edges("act", route_after_act, {"reason": "reason", "__end__": END})

    compiled = graph.compile()
    initial_messages: list[BaseMessage] = [
        SystemMessage(content=REACT_BASELINE_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"Begin security assessment run '{run_id}'. Map and behaviorally verify vulnerabilities across "
                "both http://dvwa and http://juiceshop:3000 within the "
                f"{_init_budgets.max_http_transactions} HTTP transaction and {_init_budgets.max_llm_calls} LLM call limits. "
                "Record endpoints via `record_endpoint` and verified findings via `submit_finding`."
            )
        ),
    ]
    raw_out = compiled.invoke(
        ReActGraphState(
            run_id=run_id,
            started_at_epoch=init_assessment.started_at_epoch,
            budgets=_init_budgets.model_copy(deep=True),
            messages=initial_messages,
        ),
        config={"recursion_limit": 600},
    )
    out_state = ReActGraphState.model_validate(raw_out)
    final_b = sync_live_budgets(out_state.budgets, init_assessment.started_at_epoch)

    final_assessment = AssessmentState(
        run_id=run_id,
        architecture="react_baseline",
        started_at_epoch=init_assessment.started_at_epoch,
        budgets=final_b,
        endpoints=list(ctx.recorded_endpoints),
        findings=list(ctx.recorded_findings),
        tool_errors=list(ctx.tool_errors),
        handoff_count=0,
        tool_invocations=ctx.tool_invocations,
        retry_count=ctx.retry_count,
        next_action="halt",
        halt_reason=out_state.halt_reason or "completed",
        notes=[f"[ReActBaseline] Total messages in single context: {len(out_state.messages)}"],
    )
    return final_assessment, session_mgr
