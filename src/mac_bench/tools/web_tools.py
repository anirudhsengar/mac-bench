"""Shared LangChain tool definitions and error-recovery instrumentation."""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup
from langchain_core.tools import BaseTool, tool

from mac_bench.crypto_redact import RunRedactor
from mac_bench.llm_client import fetch_llm_budget, fetch_mediator_budget
from mac_bench.schemas import (
    FindingRecord,
    TargetEndpoint,
    ToolErrorRecord,
    normalize_endpoint_key,
)
from mac_bench.tools.session_store import SessionManager


def _extract_html_structure(html_text: str, base_url: str) -> dict[str, Any]:
    soup = BeautifulSoup(html_text, "html.parser")
    links: list[str] = []
    for a in soup.find_all("a", href=True):
        href = str(a["href"]).strip()
        if href and not href.startswith(("javascript:", "mailto:", "#")):
            full = urljoin(base_url, href)
            if full.startswith(("http://dvwa", "http://juiceshop:3000")) and full not in links:
                links.append(full)
        elif href.startswith("#/"):
            frag_url = f"{base_url.rstrip('/')}/{href}"
            if frag_url not in links:
                links.append(frag_url)

    forms: list[dict[str, Any]] = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, str(form.get("action") or base_url))
        method = str(form.get("method") or "GET").upper()
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                fields.append(
                    {
                        "name": str(name),
                        "type": str(inp.get("type") or inp.name),
                        "maxlength": inp.get("maxlength"),
                        "value": str(inp.get("value") or "")[:40],
                    }
                )
        forms.append({"action": action, "method": method, "fields": fields})

    # Strip script/style boilerplate for clean readable excerpt
    text_excerpt = " ".join(soup.get_text(" ", strip=True).split())[:1800]
    return {"links": links[:35], "forms": forms[:10], "visible_text": text_excerpt}


class ToolRuntimeContext:
    """Per-run shared runtime state for tools, budget readbacks, and error recovery tracking."""

    def __init__(self, session_mgr: SessionManager, redactor: RunRedactor) -> None:
        self.session_mgr = session_mgr
        self.redactor = redactor
        self.active_role: str = "agent"
        self.tool_invocations: int = 0
        self.retry_count: int = 0
        self.recorded_endpoints: list[TargetEndpoint] = []
        self.recorded_findings: list[FindingRecord] = []
        self.tool_errors: list[ToolErrorRecord] = []
        self._last_target_key: str | None = None

    def budget_footer(self) -> dict[str, Any]:
        http_used, http_limit = 0, 200
        llm_used, llm_limit = 0, 50
        try:
            m = fetch_mediator_budget()
            http_used = int(m.get("tx_used", 0))
            http_limit = int(m.get("tx_limit", 200))
        except Exception:
            pass
        try:
            l_st = fetch_llm_budget()
            llm_used = int(l_st.get("llm_calls_used", 0))
            llm_limit = int(l_st.get("llm_limit", 50))
        except Exception:
            pass
        return {
            "http_used": http_used,
            "http_remaining": max(0, http_limit - http_used),
            "llm_used": llm_used,
            "llm_remaining": max(0, llm_limit - llm_used),
        }

    def note_call(self, tool_name: str, target_hint: str) -> int:
        self.tool_invocations += 1
        key = f"{tool_name}:{target_hint}"
        if self._last_target_key == key and any(not e.recovered for e in self.tool_errors if e.target_hint == target_hint):
            self.retry_count += 1
        self._last_target_key = key
        return self.tool_invocations

    def record_error(
        self,
        *,
        step_index: int,
        tool_name: str,
        target_hint: str,
        category: str,
        message: str,
        recoverable: bool = True,
    ) -> None:
        self.tool_errors.append(
            ToolErrorRecord(
                error_id=f"err_{uuid.uuid4().hex[:10]}",
                step_index=step_index,
                agent_role=self.active_role,
                tool_name=tool_name,
                target_hint=target_hint,
                category=category,
                recoverable=recoverable,
                error_message=self.redactor.sanitize_text(message)[:240],
                recovered=False,
            )
        )

    def mark_recovered_for_target(self, step_index: int, target_hint: str, detail: str) -> None:
        host = urlsplit(target_hint).hostname or target_hint
        for err in self.tool_errors:
            if err.recoverable and not err.recovered:
                err_host = urlsplit(err.target_hint).hostname or err.target_hint
                if err_host == host or err.category == "PROXY_POLICY_BLOCK":
                    err.recovered = True
                    err.recovery_detail = f"Recovered at tool step {step_index}: {detail[:120]}"


def build_shared_tools(
    ctx: ToolRuntimeContext,
    *,
    allow_record_endpoint: bool = True,
    allow_submit_finding: bool = True,
) -> list[BaseTool]:
    """Build shared LangChain tools with identical schemas across Multi-Agent and ReAct systems."""

    @tool
    def http_request(
        method: Literal["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
        url: str,
        session: Literal["unauth", "dvwa_admin", "juiceshop_acct1", "juiceshop_acct2"] = "unauth",
        params: dict[str, str] | None = None,
        form_data: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> str:
        """Send an HTTP request through the isolated mediator proxy to an in-scope target.

        Args:
            method: HTTP verb (GET, POST, PUT, DELETE, OPTIONS, HEAD).
            url: Full target URL (must be http://dvwa/... or http://juiceshop:3000/...).
            session: Named session context ('unauth', 'dvwa_admin', 'juiceshop_acct1', 'juiceshop_acct2').
            params: Optional query-string parameters dict.
            form_data: Optional application/x-www-form-urlencoded dict (e.g. DVWA form submissions).
            json_body: Optional JSON body dict (e.g. Juice Shop REST API requests).
            headers: Optional extra request headers.
            follow_redirects: Whether to follow HTTP 3xx redirects automatically (each hop counts against HTTP budget).
        """
        step_idx = ctx.note_call("http_request", url)
        try:
            client, sess_meta = ctx.session_mgr.get_http_client(session, ctx.active_role)
            req_headers = {"x-agent-role": ctx.active_role}
            if headers:
                for k, v in headers.items():
                    req_headers[str(k)] = str(v)

            resp = client.request(
                method=method.upper(),
                url=url,
                params=params,
                data=form_data,
                json=json_body,
                headers=req_headers,
                follow_redirects=follow_redirects,
            )

            status = resp.status_code
            loc = resp.headers.get("location", "")
            ctype = resp.headers.get("content-type", "")

            # Classify recoverable tool/protocol errors
            if status == 429 and "http_budget_depleted" in resp.text:
                ctx.record_error(
                    step_index=step_idx,
                    tool_name="http_request",
                    target_hint=url,
                    category="BUDGET_DEPLETED",
                    message="HTTP transaction budget (200) depleted.",
                    recoverable=False,
                )
            elif status == 403 and (
                "blocked_by_destination_policy" in resp.text
                or "blocked_prohibited_redirect" in resp.text
                or "websocket_upgrade_disabled" in resp.text
            ):
                ctx.record_error(
                    step_index=step_idx,
                    tool_name="http_request",
                    target_hint=url,
                    category="PROXY_POLICY_BLOCK",
                    message=resp.text[:200],
                    recoverable=True,
                )
            elif status in (401, 403) or (status in (301, 302) and "login.php" in loc):
                ctx.record_error(
                    step_index=step_idx,
                    tool_name="http_request",
                    target_hint=url,
                    category="AUTH_OR_CSRF_MISSING",
                    message=f"HTTP {status} (Location={loc})",
                    recoverable=True,
                )
            elif status in (400, 405, 422):
                ctx.record_error(
                    step_index=step_idx,
                    tool_name="http_request",
                    target_hint=url,
                    category="MALFORMED_REQUEST_OR_PARAM",
                    message=f"HTTP {status}: {resp.text[:160]}",
                    recoverable=True,
                )
            elif status in (502, 503, 504):
                ctx.record_error(
                    step_index=step_idx,
                    tool_name="http_request",
                    target_hint=url,
                    category="HTTP_TIMEOUT_OR_TRANSIENT",
                    message=f"HTTP {status}",
                    recoverable=True,
                )
            elif 200 <= status < 400:
                ctx.mark_recovered_for_target(step_idx, url, f"{method} {url} -> {status} ({session})")

            payload: dict[str, Any] = {
                "status_code": status,
                "final_url": str(resp.url),
                "session_info": sess_meta,
                "content_type": ctype,
            }
            if loc:
                payload["redirect_location"] = loc

            raw_text = ctx.redactor.sanitize_text(resp.text)
            if "html" in ctype.lower() or "<html" in raw_text[:300].lower():
                parsed_html = _extract_html_structure(raw_text, str(resp.url))
                payload["html_summary"] = parsed_html
                # Also preserve <pre> blocks verbatim for SQLi / Command Injection evidence!
                soup = BeautifulSoup(raw_text, "html.parser")
                pre_blocks = [p.get_text("\n", strip=True) for p in soup.find_all("pre")]
                if pre_blocks:
                    payload["pre_blocks"] = pre_blocks[:10]
            else:
                payload["body_excerpt"] = raw_text[:3000]

            payload["budgets"] = ctx.budget_footer()
            return json.dumps(payload, ensure_ascii=False)

        except httpx.HTTPError as exc:
            ctx.record_error(
                step_index=step_idx,
                tool_name="http_request",
                target_hint=url,
                category="HTTP_TIMEOUT_OR_TRANSIENT",
                message=str(exc),
                recoverable=True,
            )
            return json.dumps({"error": ctx.redactor.sanitize_text(str(exc)), "budgets": ctx.budget_footer()})
        except Exception as exc:
            ctx.record_error(
                step_index=step_idx,
                tool_name="http_request",
                target_hint=url,
                category="MALFORMED_REQUEST_OR_PARAM",
                message=str(exc),
                recoverable=True,
            )
            return json.dumps({"error": ctx.redactor.sanitize_text(str(exc)), "budgets": ctx.budget_footer()})

    @tool
    def browser_navigate(
        url: str,
        session: Literal["unauth", "dvwa_admin", "juiceshop_acct1", "juiceshop_acct2"] = "unauth",
        wait_ms: int = 800,
    ) -> str:
        """Open a URL in headless Playwright Chromium routed through the mediator proxy.

        IMPORTANT BUDGET NOTE: Every subresource request (scripts, stylesheets, XHRs, images)
        made by Chromium counts toward the shared 200 HTTP transaction budget. Reserve
        browser_navigate for JavaScript-rendered SPA views or verifying client-side Stored XSS execution,
        and use browser_read_dom / browser_eval_js afterward at 0 network cost.
        """
        step_idx = ctx.note_call("browser_navigate", url)
        try:
            before_b = ctx.budget_footer()["http_used"]
            page, sess_meta = ctx.session_mgr.get_browser_page(session, ctx.active_role)
            resp = page.goto(url, wait_until="domcontentloaded", timeout=20000)
            if wait_ms > 0:
                page.wait_for_timeout(min(wait_ms, 3000))
            html = ctx.redactor.sanitize_text(page.content())
            summary = _extract_html_structure(html, page.url)
            after_b = ctx.budget_footer()
            status = resp.status if resp else 0
            if 200 <= status < 400:
                ctx.mark_recovered_for_target(step_idx, url, f"browser_navigate {url} -> {status}")
            return json.dumps(
                {
                    "status_code": status,
                    "current_url": page.url,
                    "title": page.title(),
                    "session_info": sess_meta,
                    "http_transactions_consumed_by_navigation": max(0, after_b["http_used"] - before_b),
                    "dom_summary": summary,
                    "budgets": after_b,
                },
                ensure_ascii=False,
            )
        except Exception as exc:
            ctx.record_error(
                step_index=step_idx,
                tool_name="browser_navigate",
                target_hint=url,
                category="PLAYWRIGHT_NAVIGATION_OR_SELECTOR_ERROR",
                message=str(exc),
                recoverable=True,
            )
            return json.dumps({"error": ctx.redactor.sanitize_text(str(exc)), "budgets": ctx.budget_footer()})

    @tool
    def browser_read_dom(selector: str = "body") -> str:
        """Read text and HTML snippet of a CSS selector on the active Playwright page (0 HTTP network cost)."""
        step_idx = ctx.note_call("browser_read_dom", selector)
        page = ctx.session_mgr.get_current_page()
        if page is None:
            ctx.record_error(
                step_index=step_idx,
                tool_name="browser_read_dom",
                target_hint=selector,
                category="PLAYWRIGHT_NAVIGATION_OR_SELECTOR_ERROR",
                message="No active browser page; call browser_navigate first.",
                recoverable=True,
            )
            return json.dumps({"error": "No active browser page; call browser_navigate first."})
        try:
            loc = page.locator(selector).first
            inner_html = ctx.redactor.sanitize_text(loc.inner_html(timeout=5000))[:2500]
            inner_text = ctx.redactor.sanitize_text(loc.inner_text(timeout=5000))[:2000]
            ctx.mark_recovered_for_target(step_idx, page.url, f"browser_read_dom({selector})")
            return json.dumps(
                {
                    "current_url": page.url,
                    "selector": selector,
                    "inner_text": inner_text,
                    "inner_html_excerpt": inner_html,
                    "budgets": ctx.budget_footer(),
                },
                ensure_ascii=False,
            )
        except Exception as exc:
            ctx.record_error(
                step_index=step_idx,
                tool_name="browser_read_dom",
                target_hint=selector,
                category="PLAYWRIGHT_NAVIGATION_OR_SELECTOR_ERROR",
                message=str(exc),
                recoverable=True,
            )
            return json.dumps({"error": ctx.redactor.sanitize_text(str(exc)), "budgets": ctx.budget_footer()})

    @tool
    def browser_eval_js(expression: str) -> str:
        """Evaluate a JavaScript expression in the active Playwright page context (e.g. 'window.xss_flag')."""
        step_idx = ctx.note_call("browser_eval_js", expression[:60])
        page = ctx.session_mgr.get_current_page()
        if page is None:
            ctx.record_error(
                step_index=step_idx,
                tool_name="browser_eval_js",
                target_hint=expression[:60],
                category="PLAYWRIGHT_NAVIGATION_OR_SELECTOR_ERROR",
                message="No active browser page; call browser_navigate first.",
                recoverable=True,
            )
            return json.dumps({"error": "No active browser page; call browser_navigate first."})
        try:
            val = page.evaluate(f"() => ({expression})")
            ctx.mark_recovered_for_target(step_idx, page.url, f"browser_eval_js({expression[:40]})")
            return json.dumps(
                {
                    "current_url": page.url,
                    "expression": expression,
                    "result": val,
                    "budgets": ctx.budget_footer(),
                },
                ensure_ascii=False,
            )
        except Exception as exc:
            ctx.record_error(
                step_index=step_idx,
                tool_name="browser_eval_js",
                target_hint=expression[:60],
                category="PLAYWRIGHT_NAVIGATION_OR_SELECTOR_ERROR",
                message=str(exc),
                recoverable=True,
            )
            return json.dumps({"error": ctx.redactor.sanitize_text(str(exc)), "budgets": ctx.budget_footer()})

    @tool
    def record_endpoint(
        target: Literal["dvwa", "juiceshop"],
        url: str,
        method: str = "GET",
        parameter_names: list[str] | None = None,
        auth_context: str = "unauth",
        discovery_status: Literal["observed", "candidate"] = "observed",
        suspected_cwes: list[str] | None = None,
        observation_evidence: str = "",
    ) -> str:
        """Record an observed route or inferred candidate route into the shared TargetEndpoint inventory."""
        ctx.note_call("record_endpoint", url)
        parsed = urlsplit(url)
        ep_id = normalize_endpoint_key(target, method, url)
        ep = TargetEndpoint(
            endpoint_id=ep_id,
            target=target,
            url=url,
            path=parsed.path or "/",
            method=method.upper(),
            parameter_names=parameter_names or [],
            auth_context=auth_context,
            discovery_status=discovery_status,
            suspected_cwes=suspected_cwes or [],
            observation_evidence=ctx.redactor.sanitize_text(observation_evidence)[:600],
            task_status="pending_verification",
        )
        ctx.recorded_endpoints.append(ep)
        return json.dumps({"recorded": True, "endpoint_id": ep_id, "discovery_status": discovery_status})

    @tool
    def submit_finding(
        target: Literal["dvwa", "juiceshop"],
        endpoint_url: str,
        method: str,
        cwe: str,
        title: str,
        verdict: Literal["confirmed", "rejected", "inconclusive"],
        request_sequence: list[str],
        response_evidence: str,
        parameter: str = "",
        browser_js_evidence: str | None = None,
    ) -> str:
        """Record a structured vulnerability verification result into the assessment findings store.

        IMPORTANT: Status code HTTP 200 alone is NEVER proof. Only mark verdict='confirmed' when
        behavioral verification criteria are proven in response_evidence / browser_js_evidence.
        """
        ctx.note_call("submit_finding", endpoint_url)
        ep_key = normalize_endpoint_key(target, method, endpoint_url)
        fid = f"{ep_key}:{cwe.upper().strip()}"
        rec = FindingRecord(
            finding_id=fid,
            target=target,
            endpoint_url=endpoint_url,
            method=method.upper(),
            parameter=parameter,
            cwe=cwe.upper().strip(),
            title=title[:160],
            verdict=verdict,
            request_sequence=[ctx.redactor.sanitize_text(s)[:300] for s in request_sequence[:12]],
            response_evidence=ctx.redactor.sanitize_text(response_evidence)[:2000],
            browser_js_evidence=ctx.redactor.sanitize_text(browser_js_evidence)[:400]
            if browser_js_evidence
            else None,
            reported_by_role=ctx.active_role,
        )
        ctx.recorded_findings.append(rec)
        return json.dumps({"submitted": True, "finding_id": fid, "verdict": verdict})

    tools: list[BaseTool] = [http_request, browser_navigate, browser_read_dom, browser_eval_js]
    if allow_record_endpoint:
        tools.append(record_endpoint)
    if allow_submit_finding:
        tools.append(submit_finding)
    return tools
