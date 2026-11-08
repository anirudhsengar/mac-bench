"""Host-side Unix domain socket relay for Claude Haiku 5.5 with hard 50-call budget accounting."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import httpx


class HostLLMRelay:
    """Mediates container LLM calls over a Unix socket so agent_net stays internal and API keys stay on host."""

    def __init__(
        self,
        *,
        api_key: str,
        relay_sock_path: Path,
        log_root: Path,
        allowed_model: str = "claude-haiku-5-5",
    ) -> None:
        self._api_key = api_key
        self.relay_sock_path = relay_sock_path
        self.log_root = log_root
        self.allowed_model = allowed_model

        self._lock = threading.Lock()
        self.run_id: str = "init"
        self.llm_limit: int = 50
        self.llm_calls_used: int = 0
        self.budget_rejected_calls: int = 0
        self.input_tokens: int = 0
        self.output_tokens: int = 0
        self.by_role: dict[str, dict[str, Any]] = {}

        self._server_thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None

    def start_run(self, run_id: str, llm_limit: int = 50) -> dict[str, Any]:
        with self._lock:
            self.run_id = run_id
            self.llm_limit = llm_limit
            self.llm_calls_used = 0
            self.budget_rejected_calls = 0
            self.input_tokens = 0
            self.output_tokens = 0
            self.by_role = {}
            (self.log_root / run_id).mkdir(parents=True, exist_ok=True)
            return self._stats_unlocked()

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return self._stats_unlocked()

    def _stats_unlocked(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "model": self.allowed_model,
            "llm_calls_used": self.llm_calls_used,
            "llm_limit": self.llm_limit,
            "llm_remaining": max(0, self.llm_limit - self.llm_calls_used),
            "budget_rejected_calls": self.budget_rejected_calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.input_tokens + self.output_tokens,
            "by_role": {k: dict(v) for k, v in self.by_role.items()},
        }

    def start_background(self) -> None:
        ready = threading.Event()

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            loop.run_until_complete(self._serve_async(ready))

        self._server_thread = threading.Thread(target=_runner, daemon=True)
        self._server_thread.start()
        if not ready.wait(timeout=10.0):
            raise RuntimeError("HostLLMRelay failed to bind Unix socket within 10s")

    def stop(self) -> None:
        if self._loop and self._stop_event:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._server_thread:
            self._server_thread.join(timeout=5.0)

    async def _serve_async(self, ready: threading.Event) -> None:
        self.relay_sock_path.parent.mkdir(parents=True, exist_ok=True)
        if self.relay_sock_path.exists():
            self.relay_sock_path.unlink()

        self._stop_event = asyncio.Event()
        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=15.0)) as client:
            server = await asyncio.start_unix_server(
                lambda r, w: self._handle_http(r, w, client),
                path=str(self.relay_sock_path),
            )
            os.chmod(self.relay_sock_path, 0o666)
            ready.set()
            await self._stop_event.wait()
            server.close()
            await server.wait_closed()

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client: httpx.AsyncClient,
    ) -> None:
        try:
            header_bytes = await reader.readuntil(b"\r\n\r\n")
        except Exception:
            writer.close()
            return

        try:
            header_text = header_bytes.decode("iso-8859-1")
            lines = header_text.split("\r\n")
            req_line = lines[0].split(" ")
            method = req_line[0].upper()
            path = req_line[1] if len(req_line) > 1 else "/"
            headers: dict[str, str] = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            content_len = int(headers.get("content-length", "0"))
            body = b""
            if content_len > 0:
                body = await reader.readexactly(content_len)

            if method == "GET" and path == "/budget":
                payload = json.dumps(self.get_stats()).encode("utf-8")
                await self._send_response(writer, 200, payload)
                return

            clean_path = path.split("?", 1)[0]
            if method != "POST" or clean_path != "/v1/messages":
                err = json.dumps({"error": "Only POST /v1/messages is permitted by HostLLMRelay"}).encode("utf-8")
                await self._send_response(writer, 403, err)
                return

            req_json = json.loads(body.decode("utf-8"))
            req_model = req_json.get("model", "")
            if req_model != self.allowed_model:
                err = json.dumps(
                    {"error": f"Model '{req_model}' is prohibited; frozen model is '{self.allowed_model}'"}
                ).encode("utf-8")
                await self._send_response(writer, 403, err)
                return

            # Enforce non-streaming JSON response for exact token accounting
            req_json["stream"] = False
            role = headers.get("x-agent-role", "unspecified")[:40]

            with self._lock:
                if self.llm_calls_used >= self.llm_limit:
                    self.budget_rejected_calls += 1
                    err = json.dumps(
                        {
                            "type": "error",
                            "error": {
                                "type": "invalid_request_error",
                                "message": f"Shared LLM budget ({self.llm_limit} calls) is depleted.",
                            },
                        }
                    ).encode("utf-8")
                    await self._send_response(writer, 400, err)
                    return
                self.llm_calls_used += 1
                call_index = self.llm_calls_used
                current_run_id = self.run_id

            upstream_headers = {
                "x-api-key": self._api_key,
                "anthropic-version": headers.get("anthropic-version", "2023-06-01"),
                "content-type": "application/json",
            }
            if "anthropic-beta" in headers:
                upstream_headers["anthropic-beta"] = headers["anthropic-beta"]

            t0 = time.monotonic()
            resp_bytes = b""
            resp_status = 500
            for attempt in range(3):
                try:
                    up_resp = await client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers=upstream_headers,
                        content=json.dumps(req_json).encode("utf-8"),
                    )
                    resp_status = up_resp.status_code
                    resp_bytes = up_resp.content
                    if resp_status not in (500, 502, 503, 504, 529):
                        break
                except httpx.HTTPError as exc:
                    resp_status = 502
                    resp_bytes = json.dumps({"error": str(exc)}).encode("utf-8")
                await asyncio.sleep(1.5 * (attempt + 1))

            latency_ms = round((time.monotonic() - t0) * 1000.0, 1)

            in_tok = 0
            out_tok = 0
            try:
                parsed_resp = json.loads(resp_bytes.decode("utf-8"))
                usage = parsed_resp.get("usage") or {}
                in_tok = int(usage.get("input_tokens", 0)) + int(usage.get("cache_creation_input_tokens", 0)) + int(
                    usage.get("cache_read_input_tokens", 0)
                )
                out_tok = int(usage.get("output_tokens", 0))
            except Exception:
                pass

            with self._lock:
                self.input_tokens += in_tok
                self.output_tokens += out_tok
                role_bucket = self.by_role.setdefault(
                    role,
                    {"calls": 0, "input_tokens": 0, "output_tokens": 0, "latency_ms_total": 0.0},
                )
                role_bucket["calls"] += 1
                role_bucket["input_tokens"] += in_tok
                role_bucket["output_tokens"] += out_tok
                role_bucket["latency_ms_total"] = round(role_bucket["latency_ms_total"] + latency_ms, 1)
                used_snapshot = self.llm_calls_used
                limit_snapshot = self.llm_limit

            self._write_log(
                run_id=current_run_id,
                call_index=call_index,
                role=role,
                status=resp_status,
                in_tok=in_tok,
                out_tok=out_tok,
                latency_ms=latency_ms,
                used=used_snapshot,
                limit=limit_snapshot,
            )

            await self._send_response(writer, resp_status, resp_bytes)
        except Exception as exc:
            err = json.dumps({"error": f"Relay internal error: {exc}"}).encode("utf-8")
            await self._send_response(writer, 500, err)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _write_log(
        self,
        *,
        run_id: str,
        call_index: int,
        role: str,
        status: int,
        in_tok: int,
        out_tok: int,
        latency_ms: float,
        used: int,
        limit: int,
    ) -> None:
        run_dir = self.log_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "run_id": run_id,
            "call_index": call_index,
            "agent_role": role,
            "model": self.allowed_model,
            "status": status,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "latency_ms": latency_ms,
            "llm_calls_used": used,
            "llm_limit": limit,
        }
        with open(run_dir / "llm_audit.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    async def _send_response(self, writer: asyncio.StreamWriter, status: int, body: bytes) -> None:
        reason = "OK" if status == 200 else "Error"
        hdr = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("iso-8859-1")
        writer.write(hdr + body)
        await writer.drain()
