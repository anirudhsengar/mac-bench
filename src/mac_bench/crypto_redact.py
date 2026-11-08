"""Redaction and non-reversible salted correlation helpers for audit-safe logging."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import Any

# Secrets & session tokens that must never appear in persisted logs or artifacts
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]+"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9\-._~+/]+=*"), r"\1[REDACTED_JWT]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)(PHPSESSID\s*=\s*)[A-Za-z0-9]{8,}"), r"\1[REDACTED_SESSID]"),
    (re.compile(r"(?i)(BenchAcct[12]_2026!|p@ssw0rd|dvwa_root_local)"), "[REDACTED_CREDENTIAL]"),
    (re.compile(r"(?i)((?:password|passwd|pwd|token|secret)\s*[=:]\s*['\"]?)([^'\"&\s,}]+)"), r"\1[REDACTED]"),
]


class RunRedactor:
    """Per-run redactor maintaining an ephemeral random HMAC key for non-reversible correlation IDs."""

    def __init__(self, salt: bytes | None = None) -> None:
        self._salt = salt or secrets.token_bytes(32)

    def correlation_id(self, raw_secret_value: str) -> str:
        digest = hmac.new(self._salt, raw_secret_value.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"corr_{digest[:12]}"

    def sanitize_text(self, text: str) -> str:
        if not text:
            return text
        out = text
        for pattern, repl in SECRET_PATTERNS:
            out = pattern.sub(repl, out)
        return out

    def sanitize_obj(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.sanitize_text(obj)
        if isinstance(obj, dict):
            cleaned: dict[str, Any] = {}
            for k, v in obj.items():
                key_l = str(k).lower()
                if any(s in key_l for s in ("api_key", "authorization", "cookie", "set-cookie", "password")):
                    if isinstance(v, str) and v:
                        cleaned[k] = f"[REDACTED:{self.correlation_id(v)}]"
                    else:
                        cleaned[k] = "[REDACTED]"
                else:
                    cleaned[k] = self.sanitize_obj(v)
            return cleaned
        if isinstance(obj, list):
            return [self.sanitize_obj(item) for item in obj]
        return obj


DEFAULT_REDACTOR = RunRedactor()


def redact_text(text: str) -> str:
    return DEFAULT_REDACTOR.sanitize_text(text)


def redact_obj(obj: Any) -> Any:
    return DEFAULT_REDACTOR.sanitize_obj(obj)
