"""Named proxy-mediated HTTP and Playwright session manager shared across both agent architectures."""

from __future__ import annotations

import os
import re
from typing import Any

import httpx
from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright

from mac_bench.config import load_manifest


class SessionManager:
    """Maintains named cookie/JWT sessions and an optional reusable Playwright browser routed via proxy:8080."""

    VALID_SESSIONS = ("unauth", "dvwa_admin", "juiceshop_acct1", "juiceshop_acct2")

    def __init__(self, proxy_url: str | None = None) -> None:
        self.proxy_url = proxy_url or os.environ.get("HTTP_PROXY", "http://proxy:8080")
        self.manifest = load_manifest()
        self._http_clients: dict[str, httpx.Client] = {}
        self._session_meta: dict[str, dict[str, Any]] = {}
        self._authenticated: set[str] = {"unauth"}

        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self._pw_contexts: dict[str, BrowserContext] = {}
        self._pw_pages: dict[str, Page] = {}
        self._active_page_session: str | None = None

    def get_http_client(self, session_name: str, role: str) -> tuple[httpx.Client, dict[str, Any]]:
        if session_name not in self.VALID_SESSIONS:
            raise ValueError(f"Unknown session '{session_name}'. Valid: {self.VALID_SESSIONS}")

        if session_name not in self._http_clients:
            self._http_clients[session_name] = httpx.Client(
                proxy=self.proxy_url,
                follow_redirects=False,
                timeout=httpx.Timeout(20.0, connect=10.0),
            )
            self._session_meta[session_name] = {"session": session_name}

        client = self._http_clients[session_name]
        if session_name not in self._authenticated:
            self._authenticate_client(session_name, client, role)
            self._authenticated.add(session_name)

        return client, dict(self._session_meta[session_name])

    def _authenticate_client(self, session_name: str, client: httpx.Client, role: str) -> None:
        hdrs = {"x-agent-role": role}
        if session_name == "dvwa_admin":
            cfg = self.manifest["targets"]["dvwa"]
            creds = cfg["credentials"]["admin"]
            base = cfg["base_url"]
            r_login = client.get(f"{base}/login.php", headers=hdrs)
            m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", r_login.text)
            form = {"username": creds["username"], "password": creds["password"], "Login": "Login"}
            if m:
                form["user_token"] = m.group(1)
            client.post(f"{base}/login.php", data=form, headers=hdrs, follow_redirects=True)
            if not any(c.name == "security" for c in client.cookies.jar):
                client.cookies.set("security", "low", domain="dvwa", path="/")
            self._session_meta[session_name] = {
                "session": session_name,
                "target": "dvwa",
                "username": creds["username"],
                "security_level": "low",
            }
            return

        if session_name in ("juiceshop_acct1", "juiceshop_acct2"):
            cfg = self.manifest["targets"]["juiceshop"]
            key = "account_1" if session_name == "juiceshop_acct1" else "account_2"
            creds = cfg["credentials"][key]
            base = cfg["base_url"]
            resp = client.post(
                f"{base}/rest/user/login",
                json={"email": creds["email"], "password": creds["password"]},
                headers=hdrs,
            )
            resp.raise_for_status()
            auth = resp.json().get("authentication", {})
            token = auth.get("token", "")
            bid = auth.get("bid")
            client.headers["Authorization"] = f"Bearer {token}"
            client.cookies.set("token", token, domain="juiceshop", path="/")
            self._session_meta[session_name] = {
                "session": session_name,
                "target": "juiceshop",
                "email": creds["email"],
                "own_basket_id": bid,
            }

    def get_browser_page(self, session_name: str, role: str) -> tuple[Page, dict[str, Any]]:
        client, meta = self.get_http_client(session_name, role)
        if self._pw is None:
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(
                headless=True,
                proxy={"server": self.proxy_url},
            )
        assert self._browser is not None

        if session_name not in self._pw_contexts:
            extra_headers = {"x-agent-role": role}
            if "Authorization" in client.headers:
                extra_headers["Authorization"] = client.headers["Authorization"]
            ctx = self._browser.new_context(extra_http_headers=extra_headers)
            cookie_url = "http://dvwa" if session_name == "dvwa_admin" else "http://juiceshop:3000"
            cookies_to_add = []
            for cookie in client.cookies.jar:
                cookies_to_add.append(
                    {
                        "name": cookie.name,
                        "value": cookie.value,
                        "url": cookie_url,
                    }
                )
            if cookies_to_add:
                ctx.add_cookies(cookies_to_add)
            page = ctx.new_page()
            self._pw_contexts[session_name] = ctx
            self._pw_pages[session_name] = page

        self._pw_contexts[session_name].set_extra_http_headers(
            {
                **({"Authorization": client.headers["Authorization"]} if "Authorization" in client.headers else {}),
                "x-agent-role": role,
            }
        )
        self._active_page_session = session_name
        return self._pw_pages[session_name], meta

    def get_current_page(self) -> Page | None:
        if self._active_page_session and self._active_page_session in self._pw_pages:
            return self._pw_pages[self._active_page_session]
        return None

    def close(self) -> None:
        for client in self._http_clients.values():
            try:
                client.close()
            except Exception:
                pass
        self._http_clients.clear()
        for ctx in self._pw_contexts.values():
            try:
                ctx.close()
            except Exception:
                pass
        self._pw_contexts.clear()
        self._pw_pages.clear()
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._pw is not None:
            try:
                self._pw.stop()
            except Exception:
                pass
            self._pw = None
