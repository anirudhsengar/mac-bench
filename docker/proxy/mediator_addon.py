"""Deterministic mitmproxy request mediator, destination policy enforcer, and budget accountant."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from mitmproxy import http

SENSITIVE_PARAM_RE = re.compile(
    r"(pass|pwd|token|jwt|secret|key|auth|cookie|sess)",
    re.IGNORECASE,
)


def redact_url(raw_url: str) -> str:
    try:
        parts = urlsplit(raw_url)
        if not parts.query:
            return raw_url
        redacted_pairs = []
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            if SENSITIVE_PARAM_RE.search(k):
                redacted_pairs.append((k, "[REDACTED]"))
            else:
                redacted_pairs.append((k, v[:120]))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(redacted_pairs), ""))
    except Exception:
        return "[UNPARSEABLE_URL]"


class DeterministicMediator:
    """Enforces deny-by-default target policy, redirect validation, WS/CONNECT block, and HTTP budget."""

    BASE_TARGETS: dict[tuple[str, int], str] = {
        ("dvwa", 80): "http",
        ("juiceshop", 3000): "http",
    }
    PREFLIGHT_EXTRA_TARGETS: dict[tuple[str, int], str] = {
        ("redirect-trap", 8090): "http",
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.log_root = Path(os.environ.get("MEDIATOR_LOG_DIR", "/logs"))
        self.control_sock_path = Path(os.environ.get("MEDIATOR_CONTROL_SOCK", "/run/proxy-ctl/control.sock"))
        self.log_root.mkdir(parents=True, exist_ok=True)

        self.run_id: str = "init"
        self.mode: str = "benchmark"
        self.tx_limit: int = 200
        self.tx_used: int = 0
        self.budget_rejected_count: int = 0
        self.allowed_count: int = 0
        self.blocked_count: int = 0
        self.blocked_by_reason: dict[str, int] = {}
        self.upstream_error_count: int = 0
        self._corr_salt: bytes = secrets.token_bytes(32)

        self._start_control_server()

    def _start_control_server(self) -> None:
        self.control_sock_path.parent.mkdir(parents=True, exist_ok=True)
        if self.control_sock_path.exists():
            self.control_sock_path.unlink()

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(self.control_sock_path))
        os.chmod(self.control_sock_path, 0o666)
        srv.listen(8)

        def _serve() -> None:
            while True:
                conn, _ = srv.accept()
                try:
                    raw = conn.recv(16384).decode("utf-8")
                    payload = json.loads(raw) if raw else {}
                    resp = self._handle_control(payload)
                    conn.sendall(json.dumps(resp).encode("utf-8"))
                except Exception as exc:
                    conn.sendall(json.dumps({"ok": False, "error": str(exc)}).encode("utf-8"))
                finally:
                    conn.close()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()

    def _handle_control(self, payload: dict[str, object]) -> dict[str, object]:
        action = payload.get("action")
        with self._lock:
            if action == "start_run":
                self.run_id = str(payload.get("run_id", "unnamed_run"))
                self.mode = str(payload.get("mode", "benchmark"))
                self.tx_limit = int(payload.get("tx_limit", 200))
                self.tx_used = 0
                self.budget_rejected_count = 0
                self.allowed_count = 0
                self.blocked_count = 0
                self.blocked_by_reason = {}
                self.upstream_error_count = 0
                self._corr_salt = secrets.token_bytes(32)
                run_dir = self.log_root / self.run_id
                run_dir.mkdir(parents=True, exist_ok=True)
                return {"ok": True, "stats": self._stats_unlocked()}
            if action == "get_stats":
                return {"ok": True, "stats": self._stats_unlocked()}
            return {"ok": False, "error": f"Unknown control action: {action}"}

    def _stats_unlocked(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "mode": self.mode,
            "tx_used": self.tx_used,
            "tx_limit": self.tx_limit,
            "tx_remaining": max(0, self.tx_limit - self.tx_used),
            "budget_rejected_count": self.budget_rejected_count,
            "allowed_count": self.allowed_count,
            "blocked_count": self.blocked_count,
            "blocked_by_reason": dict(self.blocked_by_reason),
            "upstream_error_count": self.upstream_error_count,
        }

    def _correlation_id(self, headers: http.Headers) -> str | None:
        parts = []
        cookie = headers.get("cookie", "")
        auth = headers.get("authorization", "")
        if cookie:
            parts.append(f"c:{cookie}")
        if auth:
            parts.append(f"a:{auth}")
        if not parts:
            return None
        digest = hmac.new(self._corr_salt, "|".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()
        return f"sid_{digest[:12]}"

    def _validate_destination(
        self,
        scheme: str,
        host: str,
        port: int,
        *,
        allow_preflight_trap: bool,
    ) -> tuple[bool, str, str | None]:
        scheme_l = (scheme or "").lower()
        host_l = (host or "").lower().strip(".")

        if scheme_l != "http":
            return False, f"prohibited_scheme:{scheme_l}", None

        allowed_map = dict(self.BASE_TARGETS)
        if allow_preflight_trap and self.mode == "preflight":
            allowed_map.update(self.PREFLIGHT_EXTRA_TARGETS)

        if (host_l, port) not in allowed_map:
            return False, f"unpermitted_destination:{host_l}:{port}", None

        try:
            resolved_ip = socket.gethostbyname(host_l)
            ip_obj = ipaddress.ip_address(resolved_ip)
        except Exception:
            return False, f"dns_resolution_failed:{host_l}", None

        if (
            ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
            or not ip_obj.is_private
        ):
            return False, f"prohibited_resolved_ip:{resolved_ip}", resolved_ip

        # Never permit bridge .1 gateway IP even if DNS were spoofed
        if resolved_ip.endswith(".1"):
            return False, f"prohibited_gateway_ip:{resolved_ip}", resolved_ip

        return True, "in_scope_target", resolved_ip

    def _write_audit(
        self,
        *,
        tx_index: int,
        agent_role: str,
        method: str,
        url: str,
        host: str,
        port: int,
        resolved_ip: str | None,
        status_code: int,
        decision: str,
        reason: str,
        session_corr_id: str | None,
        budget_used: int,
        budget_limit: int,
    ) -> None:
        run_dir = self.log_root / self.run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "run_id": self.run_id,
            "tx_index": tx_index,
            "agent": agent_role,
            "method": method,
            "destination": f"{host}:{port}",
            "resolved_ip": resolved_ip,
            "url_redacted": redact_url(url),
            "status": status_code,
            "decision": decision,
            "reason": reason,
            "session_corr_id": session_corr_id,
            "budget_used": budget_used,
            "budget_limit": budget_limit,
        }
        log_file = run_dir / "proxy_audit.jsonl"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _record_block_unlocked(self, reason_key: str) -> None:
        self.blocked_count += 1
        self.blocked_by_reason[reason_key] = self.blocked_by_reason.get(reason_key, 0) + 1

    def _budget_headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Mediator-Tx-Used": str(self.tx_used),
            "X-Mediator-Tx-Limit": str(self.tx_limit),
            "X-Mediator-Tx-Remaining": str(max(0, self.tx_limit - self.tx_used)),
        }

    def http_connect(self, flow: http.HTTPFlow) -> None:
        agent_role = flow.request.headers.get("x-agent-role", "unknown")[:40]
        corr_id = self._correlation_id(flow.request.headers)
        with self._lock:
            if self.tx_used >= self.tx_limit:
                self.budget_rejected_count += 1
                tx_idx = self.tx_used
                decision = "block_budget"
                reason = "http_budget_depleted"
                status = 429
            else:
                self.tx_used += 1
                tx_idx = self.tx_used
                self._record_block_unlocked("connect_tunnel_disabled")
                decision = "block"
                reason = "connect_tunnel_disabled"
                status = 403
            hdrs = self._budget_headers()
            used, limit = self.tx_used, self.tx_limit

        flow.metadata["handled_block"] = True
        flow.response = http.Response.make(
            status,
            json.dumps({"error": reason, "budget_used": used, "budget_limit": limit}).encode("utf-8"),
            hdrs,
        )
        self._write_audit(
            tx_index=tx_idx,
            agent_role=agent_role,
            method="CONNECT",
            url=f"https://{flow.request.host}:{flow.request.port}",
            host=flow.request.host,
            port=flow.request.port,
            resolved_ip=None,
            status_code=status,
            decision=decision,
            reason=reason,
            session_corr_id=corr_id,
            budget_used=used,
            budget_limit=limit,
        )

    def request(self, flow: http.HTTPFlow) -> None:
        # Read-only zero-budget status check for internal state sync
        if flow.request.pretty_host == "mediator.status" and flow.request.path == "/budget":
            flow.metadata["virtual_status"] = True
            with self._lock:
                stats = self._stats_unlocked()
            flow.response = http.Response.make(
                200,
                json.dumps(stats).encode("utf-8"),
                {"Content-Type": "application/json"},
            )
            return

        agent_role = flow.request.headers.get("x-agent-role", "browser_or_tool")[:40]
        corr_id = self._correlation_id(flow.request.headers)
        # Strip internal role header before forwarding to target application
        if "x-agent-role" in flow.request.headers:
            del flow.request.headers["x-agent-role"]

        with self._lock:
            if self.tx_used >= self.tx_limit:
                self.budget_rejected_count += 1
                tx_idx = self.tx_used
                hdrs = self._budget_headers()
                used, limit = self.tx_used, self.tx_limit
                flow.metadata["handled_block"] = True
                flow.response = http.Response.make(
                    429,
                    json.dumps(
                        {
                            "error": "http_budget_depleted",
                            "message": f"HTTP transaction budget ({limit}) is depleted.",
                            "budget_used": used,
                            "budget_limit": limit,
                        }
                    ).encode("utf-8"),
                    hdrs,
                )
                self._write_audit(
                    tx_index=tx_idx,
                    agent_role=agent_role,
                    method=flow.request.method,
                    url=flow.request.pretty_url,
                    host=flow.request.pretty_host,
                    port=flow.request.port,
                    resolved_ip=None,
                    status_code=429,
                    decision="block_budget",
                    reason="http_budget_depleted",
                    session_corr_id=corr_id,
                    budget_used=used,
                    budget_limit=limit,
                )
                return

            # Count this attempted HTTP transaction centrally
            self.tx_used += 1
            tx_idx = self.tx_used
            used, limit = self.tx_used, self.tx_limit

            # Block WebSocket upgrades unless mediated & countable (disabled by policy)
            upgrade_hdr = flow.request.headers.get("upgrade", "").lower()
            if upgrade_hdr == "websocket" or "websocket" in flow.request.headers.get("sec-websocket-key", "").lower():
                self._record_block_unlocked("websocket_upgrade_disabled")
                hdrs = self._budget_headers()
                flow.metadata["handled_block"] = True
                flow.response = http.Response.make(
                    403,
                    json.dumps({"error": "websocket_upgrade_disabled"}).encode("utf-8"),
                    hdrs,
                )
                self._write_audit(
                    tx_index=tx_idx,
                    agent_role=agent_role,
                    method=flow.request.method,
                    url=flow.request.pretty_url,
                    host=flow.request.pretty_host,
                    port=flow.request.port,
                    resolved_ip=None,
                    status_code=403,
                    decision="block",
                    reason="websocket_upgrade_disabled",
                    session_corr_id=corr_id,
                    budget_used=used,
                    budget_limit=limit,
                )
                return

            ok, reason, resolved_ip = self._validate_destination(
                flow.request.scheme,
                flow.request.pretty_host,
                flow.request.port,
                allow_preflight_trap=True,
            )
            if not ok:
                reason_cat = reason.split(":", 1)[0]
                self._record_block_unlocked(reason_cat)
                hdrs = self._budget_headers()
                flow.metadata["handled_block"] = True
                flow.response = http.Response.make(
                    403,
                    json.dumps({"error": "blocked_by_destination_policy", "reason": reason}).encode("utf-8"),
                    hdrs,
                )
                self._write_audit(
                    tx_index=tx_idx,
                    agent_role=agent_role,
                    method=flow.request.method,
                    url=flow.request.pretty_url,
                    host=flow.request.pretty_host,
                    port=flow.request.port,
                    resolved_ip=resolved_ip,
                    status_code=403,
                    decision="block",
                    reason=reason,
                    session_corr_id=corr_id,
                    budget_used=used,
                    budget_limit=limit,
                )
                return

            flow.metadata["tx_index"] = tx_idx
            flow.metadata["agent_role"] = agent_role
            flow.metadata["session_corr_id"] = corr_id
            flow.metadata["resolved_ip"] = resolved_ip
            flow.metadata["budget_used_snapshot"] = used

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("virtual_status") or flow.metadata.get("handled_block"):
            return

        tx_idx = int(flow.metadata.get("tx_index", 0))
        agent_role = str(flow.metadata.get("agent_role", "browser_or_tool"))
        corr_id = flow.metadata.get("session_corr_id")
        resolved_ip = flow.metadata.get("resolved_ip")

        assert flow.response is not None

        # Inspect every HTTP redirect destination before returning to client
        if flow.response.status_code in (301, 302, 303, 307, 308):
            loc = flow.response.headers.get("location")
            if loc:
                resolved_target = urljoin(flow.request.pretty_url, loc)
                parsed = urlsplit(resolved_target)
                r_scheme = parsed.scheme or "http"
                r_host = parsed.hostname or ""
                r_port = parsed.port or (443 if r_scheme == "https" else 80)
                ok, reason, _ = self._validate_destination(
                    r_scheme,
                    r_host,
                    r_port,
                    allow_preflight_trap=False,
                )
                if not ok:
                    with self._lock:
                        self._record_block_unlocked("prohibited_redirect")
                        hdrs = self._budget_headers()
                        used, limit = self.tx_used, self.tx_limit
                    flow.response = http.Response.make(
                        403,
                        json.dumps(
                            {
                                "error": "blocked_prohibited_redirect",
                                "reason": reason,
                                "redirect_target_redacted": redact_url(resolved_target),
                            }
                        ).encode("utf-8"),
                        hdrs,
                    )
                    self._write_audit(
                        tx_index=tx_idx,
                        agent_role=agent_role,
                        method=flow.request.method,
                        url=flow.request.pretty_url,
                        host=flow.request.pretty_host,
                        port=flow.request.port,
                        resolved_ip=resolved_ip,
                        status_code=403,
                        decision="block",
                        reason=f"prohibited_redirect->{reason}",
                        session_corr_id=corr_id,
                        budget_used=used,
                        budget_limit=limit,
                    )
                    return

        with self._lock:
            self.allowed_count += 1
            used, limit = self.tx_used, self.tx_limit
            flow.response.headers["X-Mediator-Tx-Used"] = str(used)
            flow.response.headers["X-Mediator-Tx-Limit"] = str(limit)
            flow.response.headers["X-Mediator-Tx-Remaining"] = str(max(0, limit - used))

        self._write_audit(
            tx_index=tx_idx,
            agent_role=agent_role,
            method=flow.request.method,
            url=flow.request.pretty_url,
            host=flow.request.pretty_host,
            port=flow.request.port,
            resolved_ip=resolved_ip,
            status_code=flow.response.status_code,
            decision="allow",
            reason="in_scope_target",
            session_corr_id=corr_id,
            budget_used=used,
            budget_limit=limit,
        )

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("virtual_status") or flow.metadata.get("handled_block"):
            return
        tx_idx = int(flow.metadata.get("tx_index", 0))
        agent_role = str(flow.metadata.get("agent_role", "browser_or_tool"))
        corr_id = flow.metadata.get("session_corr_id")
        resolved_ip = flow.metadata.get("resolved_ip")
        with self._lock:
            self.upstream_error_count += 1
            used, limit = self.tx_used, self.tx_limit
        err_msg = str(flow.error) if flow.error else "upstream_error"
        self._write_audit(
            tx_index=tx_idx,
            agent_role=agent_role,
            method=flow.request.method,
            url=flow.request.pretty_url,
            host=flow.request.pretty_host,
            port=flow.request.port,
            resolved_ip=resolved_ip,
            status_code=502,
            decision="allow_upstream_error",
            reason=err_msg[:120],
            session_corr_id=corr_id,
            budget_used=used,
            budget_limit=limit,
        )


addons = [DeterministicMediator()]
