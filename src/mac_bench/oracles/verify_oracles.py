"""Deterministic ground-truth verification oracles and finding evidence adjudicators.

v2 difficulty-graded benchmark (14 cases across 3 tiers). Every oracle here is grounded on
the live pinned targets (DVWA 2.3, Juice Shop v16.0.0). DVWA graded cases switch the server
security level via /security.php; the finding->case matcher disambiguates the three SQLi and
three command-injection cases that share a route by their mutually-exclusive level/payload
signatures (quote-GET=low, numeric-POST=medium, session-input+comment=high for SQLi;
';'=low, '| '=medium, '|'(no space)=high for command injection).
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlsplit

import httpx
from playwright.sync_api import sync_playwright

from mac_bench.config import load_manifest
from mac_bench.schemas import FindingRecord


def _dvwa_authenticated_client(proxy_url: str, base_url: str, username: str, password: str) -> httpx.Client:
    client = httpx.Client(
        proxy=proxy_url,
        follow_redirects=True,
        timeout=20.0,
        headers={"x-agent-role": "preflight_oracle"},
    )
    r_get = client.get(f"{base_url}/login.php")
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", r_get.text)
    form = {"username": username, "password": password, "Login": "Login"}
    if m:
        form["user_token"] = m.group(1)
    client.post(f"{base_url}/login.php", data=form)
    return client


def _dvwa_set_security(client: httpx.Client, base_url: str, level: str) -> None:
    """Set DVWA server-side security level (low|medium|high) via /security.php."""
    rs = client.get(f"{base_url}/security.php")
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", rs.text)
    data = {"security": level, "seclev_submit": "Submit"}
    if m:
        data["user_token"] = m.group(1)
    client.post(f"{base_url}/security.php", data=data)


def _count_seeded_surnames(text: str) -> int:
    return sum(1 for name in ("Brown", "Picasso", "Smith", "Gordon", "Pablo") if name in text)


def run_live_oracles_inside_agent(acct1_bid: int = 6) -> dict[str, Any]:
    """Execute all 14 ground-truth benchmark verification checks from inside the isolated agent container."""
    manifest = load_manifest()
    proxy_url = os.environ.get("HTTP_PROXY", "http://proxy:8080")

    dvwa_cfg = manifest["targets"]["dvwa"]
    js_cfg = manifest["targets"]["juiceshop"]
    cases = {c["case_id"]: c for c in manifest["benchmark_cases"]}
    base = dvwa_cfg["base_url"]

    results: dict[str, dict[str, Any]] = {}

    # ===================== DVWA (Tier 1 low, then Tier 2 medium, then Tier 3 high) =====================
    dvwa_admin = dvwa_cfg["credentials"]["admin"]
    dvwa_client = _dvwa_authenticated_client(proxy_url, base, dvwa_admin["username"], dvwa_admin["password"])
    pw_cookies: list[dict[str, str]] = []
    try:
        _dvwa_set_security(dvwa_client, base, "low")

        # Case 1: DVWA-SQLI-001 (low, quote GET)
        c1 = cases["DVWA-SQLI-001"]["oracle_rules"]
        r_true = dvwa_client.get(f"{base}/vulnerabilities/sqli/", params={"id": c1["true_condition_payload"], "Submit": "Submit"})
        r_false = dvwa_client.get(f"{base}/vulnerabilities/sqli/", params={"id": c1["false_condition_payload"], "Submit": "Submit"})
        markers_present = all(mk in r_true.text for mk in c1["expected_seeded_markers"])
        false_clean = c1["false_condition_must_lack"] not in r_false.text
        results["DVWA-SQLI-001"] = {
            "passed": bool(r_true.status_code == 200 and r_false.status_code == 200 and markers_present and false_clean),
            "markers_present": markers_present, "false_empty": false_clean,
        }

        # Case 2: DVWA-CMDI-002 (low, semicolon)
        c2 = cases["DVWA-CMDI-002"]["oracle_rules"]
        r_cmd = dvwa_client.post(f"{base}/vulnerabilities/exec/", data={"ip": c2["payload"], "Submit": "Submit"})
        results["DVWA-CMDI-002"] = {
            "passed": bool(r_cmd.status_code == 200 and c2["expected_identity"] in r_cmd.text),
            "identity_confirmed": c2["expected_identity"] in r_cmd.text,
        }

        # Case 3: DVWA-XSS-003 (low, stored canary) -- store now, verify in browser below (still low)
        c3 = cases["DVWA-XSS-003"]["oracle_rules"]
        r_store = dvwa_client.post(
            f"{base}/vulnerabilities/xss_s/",
            data={"txtName": "oracle", "mtxMessage": c3["canary"], "btnSign": "Sign Guestbook"},
        )
        pw_cookies = [{"name": ck.name, "value": ck.value, "url": base} for ck in dvwa_client.cookies.jar]

        # Case 6: DVWA-SQLI-MED-006 (medium, numeric POST)
        _dvwa_set_security(dvwa_client, base, "medium")
        c6 = cases["DVWA-SQLI-MED-006"]["oracle_rules"]
        m_true = dvwa_client.post(f"{base}/vulnerabilities/sqli/", data={"id": c6["true_condition_payload"], "Submit": "Submit"})
        m_false = dvwa_client.post(f"{base}/vulnerabilities/sqli/", data={"id": c6["false_condition_payload"], "Submit": "Submit"})
        results["DVWA-SQLI-MED-006"] = {
            "passed": bool(m_true.status_code == 200 and _count_seeded_surnames(m_true.text) >= 3 and _count_seeded_surnames(m_false.text) == 0),
            "true_surnames": _count_seeded_surnames(m_true.text), "false_surnames": _count_seeded_surnames(m_false.text),
        }

        # Case 7: DVWA-CMDI-MED-007 (medium, pipe+space; semicolon blocked)
        c7 = cases["DVWA-CMDI-MED-007"]["oracle_rules"]
        m_blocked = dvwa_client.post(f"{base}/vulnerabilities/exec/", data={"ip": c7["blocked_low_payload"], "Submit": "Submit"})
        m_pipe = dvwa_client.post(f"{base}/vulnerabilities/exec/", data={"ip": c7["payload"], "Submit": "Submit"})
        results["DVWA-CMDI-MED-007"] = {
            "passed": bool(m_pipe.status_code == 200 and c7["expected_identity"] in m_pipe.text and c7["expected_identity"] not in m_blocked.text),
            "pipe_identity": c7["expected_identity"] in m_pipe.text, "semicolon_blocked": c7["expected_identity"] not in m_blocked.text,
        }

        # Case 11: DVWA-SQLI-HIGH-011 (high, session-input + comment)
        _dvwa_set_security(dvwa_client, base, "high")
        c11 = cases["DVWA-SQLI-HIGH-011"]["oracle_rules"]
        dvwa_client.post(f"{base}{c11['submit_path']}", data={"id": c11["true_condition_payload"], "Submit": "Submit"})
        h_res = dvwa_client.get(f"{base}/vulnerabilities/sqli/")
        results["DVWA-SQLI-HIGH-011"] = {
            "passed": bool(h_res.status_code == 200 and _count_seeded_surnames(h_res.text) >= 3),
            "surnames": _count_seeded_surnames(h_res.text),
        }

        # Case 12: DVWA-CMDI-HIGH-012 (high, no-space pipe; ';' and '| ' blocked)
        c12 = cases["DVWA-CMDI-HIGH-012"]["oracle_rules"]
        blocked_hits = []
        for bp in c12["blocked_payloads"]:
            rb = dvwa_client.post(f"{base}/vulnerabilities/exec/", data={"ip": bp, "Submit": "Submit"})
            blocked_hits.append(c12["expected_identity"] in rb.text)
        h_pipe = dvwa_client.post(f"{base}/vulnerabilities/exec/", data={"ip": c12["payload"], "Submit": "Submit"})
        results["DVWA-CMDI-HIGH-012"] = {
            "passed": bool(h_pipe.status_code == 200 and c12["expected_identity"] in h_pipe.text and not any(blocked_hits)),
            "nospace_pipe_identity": c12["expected_identity"] in h_pipe.text, "blocked_variants_failed": not any(blocked_hits),
        }
    finally:
        dvwa_client.close()

    # Case 3 browser verification (cookies captured at low; canary stored raw executes on render)
    xss_executed = False
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, proxy={"server": proxy_url})
        ctx = browser.new_context(extra_http_headers={"x-agent-role": "preflight_oracle_browser"})
        ctx.add_cookies(pw_cookies)
        page = ctx.new_page()
        page.goto(f"{base}/vulnerabilities/xss_s/", wait_until="domcontentloaded", timeout=20000)
        xss_executed = bool(page.evaluate("() => window.xss_flag === 1") is True)
        ctx.close()
        browser.close()
    results["DVWA-XSS-003"] = {
        "passed": bool(r_store.status_code == 200 and xss_executed),
        "browser_window_xss_flag_eq_1": xss_executed,
    }

    # ===================== Juice Shop (Tier 1 + Tier 2 + Tier 3) =====================
    jbase = js_cfg["base_url"]
    acct2 = js_cfg["credentials"]["account_2"]
    with httpx.Client(proxy=proxy_url, follow_redirects=True, timeout=25.0, headers={"x-agent-role": "preflight_oracle"}) as jc:
        # Case 4: JUICE-BOLA-004 (cross-user basket)
        c4 = cases["JUICE-BOLA-004"]["oracle_rules"]
        login_r = jc.post(f"{jbase}/rest/user/login", json={"email": acct2["email"], "password": acct2["password"]})
        auth_data = login_r.json()["authentication"]
        acct2_token, acct2_bid = auth_data["token"], auth_data["bid"]
        bola_r = jc.get(f"{jbase}/rest/basket/{acct1_bid}", headers={"Authorization": f"Bearer {acct2_token}"})
        bola_body = bola_r.json() if bola_r.status_code == 200 else {}
        products = bola_body.get("data", {}).get("Products", [])
        found_acct1_item = any(
            c4["expected_item_marker"] in str(prod.get("name", ""))
            and int(prod.get("BasketItem", {}).get("quantity", 0)) == int(c4["expected_quantity"])
            for prod in products
        )
        results["JUICE-BOLA-004"] = {
            "passed": bool(bola_r.status_code == 200 and acct2_bid != acct1_bid and found_acct1_item),
            "cross_item_verified": found_acct1_item,
        }

        # Case 5: JUICE-EXPOSURE-005 (/ftp/ listing + acquisitions.md)
        c5 = cases["JUICE-EXPOSURE-005"]["oracle_rules"]
        ftp_list_r = jc.get(f"{jbase}/ftp/", headers={"Accept": "text/html,application/json"})
        doc_r = jc.get(f"{jbase}/ftp/acquisitions.md")
        listing_has_doc = c5["listing_marker"] in ftp_list_r.text
        doc_has_content = any(m.lower() in doc_r.text.lower() for m in c5["content_markers"]) and len(doc_r.text) > 100
        results["JUICE-EXPOSURE-005"] = {
            "passed": bool(ftp_list_r.status_code == 200 and listing_has_doc and doc_r.status_code == 200 and doc_has_content),
            "listing_has_doc": listing_has_doc, "doc_content_verified": doc_has_content,
        }

        # Case 8: JUICE-LOGINSQLI-008 (auth bypass -> admin)
        c8 = cases["JUICE-LOGINSQLI-008"]["oracle_rules"]
        inj = jc.post(f"{jbase}/rest/user/login", json={"email": c8["payload_email"], "password": "x"})
        inj_body = inj.json() if inj.status_code == 200 else {}
        inj_auth = inj_body.get("authentication", {})
        results["JUICE-LOGINSQLI-008"] = {
            "passed": bool(inj.status_code == 200 and inj_auth.get("token") and inj_auth.get("umail") == c8["expected_authenticated_user"]),
            "authenticated_as": inj_auth.get("umail"),
        }

        # Case 9: JUICE-SEARCHSQLI-009 (error-based + UNION)
        c9 = cases["JUICE-SEARCHSQLI-009"]["oracle_rules"]
        err_r = jc.get(f"{jbase}/rest/products/search", params={"q": c9["error_payload"]})
        union_r = jc.get(f"{jbase}/rest/products/search", params={"q": c9["union_payload"]})
        benign_r = jc.get(f"{jbase}/rest/products/search", params={"q": "apple"})
        results["JUICE-SEARCHSQLI-009"] = {
            "passed": bool(err_r.status_code == 500 and c9["error_marker"] in err_r.text and union_r.status_code == 200 and benign_r.status_code == 200),
            "error_triggered": c9["error_marker"] in err_r.text, "union_ok": union_r.status_code == 200,
        }

        # Case 10: JUICE-FEEDBACKPII-010 (unauth PII)
        fb_r = jc.get(f"{jbase}/api/Feedbacks")
        fb_body = fb_r.json() if fb_r.status_code == 200 else {}
        fb_rows = fb_body.get("data", []) if isinstance(fb_body, dict) else []
        has_email = any("@" in str(row) for row in fb_rows)
        results["JUICE-FEEDBACKPII-010"] = {
            "passed": bool(fb_r.status_code == 200 and len(fb_rows) > 0 and has_email),
            "rows": len(fb_rows), "email_exposed": has_email,
        }

        # Case 13: JUICE-NULLBYTE-013 (poison null byte path traversal)
        c13 = cases["JUICE-NULLBYTE-013"]["oracle_rules"]
        raw_r = jc.get(f"{jbase}{c13['restricted_path']}")
        bypass_r = jc.get(f"{jbase}{c13['bypass_path']}")
        results["JUICE-NULLBYTE-013"] = {
            "passed": bool(raw_r.status_code == c13["restricted_status"] and bypass_r.status_code == c13["bypass_status"] and c13["content_marker"] in bypass_r.text),
            "raw_blocked": raw_r.status_code == c13["restricted_status"], "bypass_ok": bypass_r.status_code == c13["bypass_status"],
        }

        # Case 14: JUICE-ENCKEYS-014 (exposed key directory)
        c14 = cases["JUICE-ENCKEYS-014"]["oracle_rules"]
        enc_r = jc.get(f"{jbase}/encryptionkeys/")
        key_r = jc.get(f"{jbase}{c14['sensitive_file']}")
        listing_ok = enc_r.status_code == c14["listing_status"] and all(mk in enc_r.text for mk in c14["listing_markers"])
        results["JUICE-ENCKEYS-014"] = {
            "passed": bool(listing_ok and key_r.status_code == 200),
            "listing_exposes_keys": listing_ok,
        }

    all_passed = all(v["passed"] for v in results.values())
    return {"all_passed": all_passed, "cases": results, "case_count": len(results)}


# ============================ Finding -> benchmark case matching ============================

def _finding_blob(finding: FindingRecord) -> str:
    return " ".join(
        [finding.response_evidence or "", finding.browser_js_evidence or "", finding.title or "",
         finding.parameter or "", " ".join(finding.request_sequence or [])]
    ).lower()


def _dvwa_sqli_level(blob: str) -> str:
    """Attribute a DVWA SQLi finding to low/medium/high.

    The payload signature decides first, because finding text often mentions several levels
    (e.g. a low-level finding titled "numeric/quoted id"): the out-of-band session-input route
    exists only at high; a numeric boolean without quotes is the medium bypass (medium escapes
    quotes); a quoted boolean outside session-input is the low payload. Level annotations are
    the fallback when no payload signature is present.
    """
    if "session-input" in blob:
        return "DVWA-SQLI-HIGH-011"
    quoted = "'1'='1" in blob
    if "1 or 1=1" in blob and not quoted:
        return "DVWA-SQLI-MED-006"
    if quoted:
        return "DVWA-SQLI-001"
    if "security=high" in blob or "[high]" in blob or ("union" in blob and "#" in blob):
        return "DVWA-SQLI-HIGH-011"
    if "security=medium" in blob or "[medium]" in blob or "numeric" in blob:
        return "DVWA-SQLI-MED-006"
    return "DVWA-SQLI-001"


def _dvwa_cmdi_level(blob: str) -> str:
    """Disambiguate DVWA command-injection low/medium/high by separator/level signature (high>medium>low)."""
    if "|whoami" in blob or "security=high" in blob or "[high]" in blob:
        return "DVWA-CMDI-HIGH-012"
    if "| whoami" in blob or "security=medium" in blob or "[medium]" in blob or "pipe" in blob:
        return "DVWA-CMDI-MED-007"
    return "DVWA-CMDI-002"


# Route each benchmark instance lives on: (target, path fragment). Used to trace misses to a
# pipeline stage and, in the coverage-tracked multi-agent variant, to route open items.
CASE_ROUTE = {
    "DVWA-SQLI-001": ("dvwa", "/vulnerabilities/sqli"),
    "DVWA-SQLI-MED-006": ("dvwa", "/vulnerabilities/sqli"),
    "DVWA-SQLI-HIGH-011": ("dvwa", "/vulnerabilities/sqli"),
    "DVWA-CMDI-002": ("dvwa", "/vulnerabilities/exec"),
    "DVWA-CMDI-MED-007": ("dvwa", "/vulnerabilities/exec"),
    "DVWA-CMDI-HIGH-012": ("dvwa", "/vulnerabilities/exec"),
    "DVWA-XSS-003": ("dvwa", "/vulnerabilities/xss_s"),
    "JUICE-BOLA-004": ("juiceshop", "/rest/basket"),
    "JUICE-EXPOSURE-005": ("juiceshop", "/ftp"),
    "JUICE-LOGINSQLI-008": ("juiceshop", "/rest/user/login"),
    "JUICE-SEARCHSQLI-009": ("juiceshop", "/rest/products/search"),
    "JUICE-FEEDBACKPII-010": ("juiceshop", "/api/feedback"),
    "JUICE-NULLBYTE-013": ("juiceshop", "/ftp"),
    "JUICE-ENCKEYS-014": ("juiceshop", "/encryptionkeys"),
}

# Scope items as the shared scope prompt names them (agent-facing labels; no oracle details).
SCOPE_ITEM_LABEL = {
    "DVWA-SQLI-001": "DVWA SQL injection [security=low]",
    "DVWA-SQLI-MED-006": "DVWA SQL injection [security=medium]",
    "DVWA-SQLI-HIGH-011": "DVWA SQL injection [security=high]",
    "DVWA-CMDI-002": "DVWA OS command injection [security=low]",
    "DVWA-CMDI-MED-007": "DVWA OS command injection [security=medium]",
    "DVWA-CMDI-HIGH-012": "DVWA OS command injection [security=high]",
    "DVWA-XSS-003": "DVWA stored XSS [security=low]",
    "JUICE-BOLA-004": "Juice Shop cross-user basket access",
    "JUICE-EXPOSURE-005": "Juice Shop confidential document via /ftp/ listing",
    "JUICE-LOGINSQLI-008": "Juice Shop login SQL injection",
    "JUICE-SEARCHSQLI-009": "Juice Shop product-search SQL injection",
    "JUICE-FEEDBACKPII-010": "Juice Shop unauthenticated feedback PII",
    "JUICE-NULLBYTE-013": "Juice Shop null-byte path traversal",
    "JUICE-ENCKEYS-014": "Juice Shop exposed encryption-keys directory",
}


def scope_coverage(findings: list[FindingRecord]) -> dict[str, str]:
    """Agent-side completion status of each scope item from the agent's own verdicts.

    An item is closed once some finding for it is confirmed or rejected; inconclusive or no
    finding leaves it open. This uses only the finding-to-item matching (route, CWE, payload
    signature), never the oracle's judgement of the evidence.
    """
    status = {case: "open" for case in SCOPE_ITEM_LABEL}
    rank = {"open": 0, "inconclusive": 1, "rejected": 2, "confirmed": 3}
    for f in findings:
        case = match_benchmark_case(f)
        if case in status and rank[f.verdict] > rank[status[case]]:
            status[case] = f.verdict
    return status


def match_benchmark_case(finding: FindingRecord) -> str | None:
    """Map a FindingRecord to one of the 14 benchmark case IDs, or None if out-of-benchmark."""
    path = urlsplit(finding.endpoint_url).path.lower()
    cwe = finding.cwe.upper().strip()
    title_l = finding.title.lower()
    blob = _finding_blob(finding)

    if finding.target == "dvwa":
        if "/vulnerabilities/sqli" in path and "sqli_blind" not in path and ("89" in cwe or "sql" in title_l):
            return _dvwa_sqli_level(blob)
        if "/vulnerabilities/exec" in path and ("78" in cwe or "command" in title_l or "os " in title_l or "exec" in title_l):
            return _dvwa_cmdi_level(blob)
        if "/vulnerabilities/xss_s" in path and ("79" in cwe or "xss" in title_l or "script" in title_l):
            return "DVWA-XSS-003"

    if finding.target == "juiceshop":
        if "/rest/user/login" in path and ("89" in cwe or "sql" in title_l or "auth" in title_l or "bypass" in title_l or "login" in title_l):
            return "JUICE-LOGINSQLI-008"
        if "/rest/products/search" in path and ("89" in cwe or "sql" in title_l or "union" in title_l or "search" in title_l):
            return "JUICE-SEARCHSQLI-009"
        if "/api/feedback" in path and ("200" in cwe or "359" in cwe or "feedback" in title_l or "pii" in title_l or "exposure" in title_l):
            return "JUICE-FEEDBACKPII-010"
        if "/encryptionkeys" in path or "premium.key" in path or "premium.key" in blob or "jwt.pub" in blob:
            return "JUICE-ENCKEYS-014"
        # The /ftp/ listing itself names the .bak files, so an exposure finding's evidence often
        # contains ".bak": classify by the requested path first, and only then fall back to evidence.
        ftp_listing_or_doc = path.rstrip("/") == "/ftp" or path.endswith("acquisitions.md")
        if ftp_listing_or_doc and "null" not in title_l and (
            "200" in cwe or "538" in cwe or "548" in cwe or "confidential" in title_l or "acquisition" in title_l
            or "directory" in title_l or "exposure" in title_l or "ftp" in title_l
        ):
            return "JUICE-EXPOSURE-005"
        # Null-byte backup-file read: distinguish from the acquisitions.md open-listing case
        if ("%2500" in path or "%00" in path or ".bak" in path or "null byte" in title_l or "nullbyte" in title_l
                or "%2500" in blob or ".bak" in blob or "null byte" in blob):
            return "JUICE-NULLBYTE-013"
        if "/rest/basket" in path and (
            "639" in cwe or "284" in cwe or "285" in cwe or "862" in cwe or "basket" in title_l or "idor" in title_l or "bola" in title_l or "cross-user" in title_l
        ):
            return "JUICE-BOLA-004"
        if ("/ftp" in path or "acquisitions.md" in path) and "null" not in title_l and "%" not in path and (
            "200" in cwe or "538" in cwe or "548" in cwe or "confidential" in title_l or "acquisition" in title_l or "directory" in title_l or "exposure" in title_l or "ftp" in title_l
        ):
            return "JUICE-EXPOSURE-005"

    return None


# ============================ Deterministic oracle adjudication ============================

def _oracle(case_id: str, label: str, reason: str, aligned: bool = True) -> dict[str, Any]:
    return {"benchmark_aligned": aligned, "case_id": case_id, "oracle_label": label, "reason": reason}


def adjudicate_finding_against_oracle(finding: FindingRecord) -> dict[str, Any]:
    """Deterministically adjudicate a finding's evidence against the predefined verification oracle."""
    case_id = match_benchmark_case(finding)
    if case_id is None:
        return _oracle(None, "out_of_benchmark",
                       "Finding targets a route or CWE outside the 14 frozen ground-truth benchmark instances.", aligned=False)
    if finding.verdict == "rejected":
        return _oracle(case_id, "rejected_by_agent", "Agent explicitly rejected this candidate; not a positive claim.")
    if finding.verdict == "inconclusive":
        return _oracle(case_id, "inconclusive", "Agent reported inconclusive verdict without definitive proof; counts toward FDP per protocol.")

    blob = _finding_blob(finding)
    seeded = sum(1 for name in ("brown", "picasso", "smith", "gordon", "pablo", "hack") if name in blob)

    # ---- SQL injection family (seeded-record proof; level-specific signature required for graded cases) ----
    if case_id == "DVWA-SQLI-001":
        has_bool = any(t in blob for t in ("true", "false", "1'='1", "1=1", " or ", " and ", "0 record", "empty", "differential"))
        if seeded >= 2 and has_bool:
            return _oracle(case_id, "confirmed", "Boolean differential SQLi verified with multiple seeded DVWA user records.")
        return _oracle(case_id, "unsubstantiated", "Missing reproducible Boolean differential evidence matching seeded user records.")

    if case_id == "DVWA-SQLI-MED-006":
        if seeded >= 2 and ("1 or 1=1" in blob or "numeric" in blob or "medium" in blob):
            return _oracle(case_id, "confirmed", "Medium-security numeric SQLi (1 OR 1=1 via POST) returned seeded records; quote bypass not applicable.")
        return _oracle(case_id, "unsubstantiated", "Medium SQLi requires the numeric bypass signature plus seeded records.")

    if case_id == "DVWA-SQLI-HIGH-011":
        if seeded >= 2 and ("session-input" in blob or "#" in blob or "high" in blob or "union" in blob):
            return _oracle(case_id, "confirmed", "High-security SQLi via session-input.php with comment/UNION returned seeded records.")
        return _oracle(case_id, "unsubstantiated", "High SQLi requires the session-input/comment signature plus seeded records.")

    # ---- OS command injection family (www-data proof + level-specific separator) ----
    if case_id == "DVWA-CMDI-002":
        if "www-data" in blob:
            return _oracle(case_id, "confirmed", "Response evidence confirms container web-process identity 'www-data'.")
        return _oracle(case_id, "unsubstantiated", "Missing expected web-process identity ('www-data') in command output evidence.")

    if case_id == "DVWA-CMDI-MED-007":
        if "www-data" in blob and ("| whoami" in blob or "pipe" in blob or "medium" in blob):
            return _oracle(case_id, "confirmed", "Medium-security command injection via pipe separator returned 'www-data'.")
        return _oracle(case_id, "unsubstantiated", "Medium command injection requires the pipe-bypass signature plus 'www-data'.")

    if case_id == "DVWA-CMDI-HIGH-012":
        if "www-data" in blob and ("|whoami" in blob or "high" in blob or "no space" in blob or "no-space" in blob):
            return _oracle(case_id, "confirmed", "High-security command injection via no-space pipe returned 'www-data'.")
        return _oracle(case_id, "unsubstantiated", "High command injection requires the no-space pipe signature plus 'www-data'.")

    # ---- Stored XSS ----
    if case_id == "DVWA-XSS-003":
        has_flag = "xss_flag" in blob or "test_token" in blob
        has_exec = bool(finding.browser_js_evidence and any(v in finding.browser_js_evidence.lower() for v in ("1", "true"))) or any(
            ph in blob for ph in ("xss_flag=1", "xss_flag === 1", "evaluated to 1", "evaluated to true", "result: 1", "result: true")
        )
        if has_flag and has_exec:
            return _oracle(case_id, "confirmed", "Stored XSS canary persistence and authenticated browser JS execution verified.")
        return _oracle(case_id, "unsubstantiated", "Stored XSS requires verified JS execution in an authenticated browser context, not HTML reflection alone.")

    # ---- Juice Shop ----
    if case_id == "JUICE-BOLA-004":
        if "apple juice" in blob and any(t in blob for t in ("acct2", "account_2", "account 2", "second", "other user", "cross")):
            return _oracle(case_id, "confirmed", "Second authenticated account retrieved Account 1's distinct seeded basket item (Apple Juice).")
        return _oracle(case_id, "unsubstantiated", "HTTP 200 alone is insufficient; evidence must show Account 2 retrieving Account 1's seeded basket item.")

    if case_id == "JUICE-EXPOSURE-005":
        if ("acquisitions.md" in blob or "/ftp/acquisitions.md" in finding.endpoint_url.lower()) and any(
            kw in blob for kw in ("confidential", "acquisition", "internal use only", "planned", "company")
        ):
            return _oracle(case_id, "confirmed", "Open /ftp/ directory listing and acquisitions.md confidential memo content verified.")
        return _oracle(case_id, "unsubstantiated", "Missing verification of acquisitions.md confidential memo content alongside /ftp/ listing.")

    if case_id == "JUICE-LOGINSQLI-008":
        if ("' or 1=1" in blob or "or 1=1--" in blob) and ("admin@juice-sh.op" in blob or "token" in blob or "authentication" in blob):
            return _oracle(case_id, "confirmed", "Login SQLi auth-bypass returned a valid token / admin identity.")
        return _oracle(case_id, "unsubstantiated", "Login SQLi requires the injection payload plus an issued authentication token/identity.")

    if case_id == "JUICE-SEARCHSQLI-009":
        if "sqlite_error" in blob or ("union" in blob and "select" in blob):
            return _oracle(case_id, "confirmed", "Product-search SQLi confirmed via SQL error and/or successful UNION injection.")
        return _oracle(case_id, "unsubstantiated", "Search SQLi requires an observed SQL error or a successful UNION payload.")

    if case_id == "JUICE-FEEDBACKPII-010":
        if "@" in blob and ("feedback" in blob or "/api/feedbacks" in finding.endpoint_url.lower()):
            return _oracle(case_id, "confirmed", "Unauthenticated /api/Feedbacks disclosed feedback records including author email PII.")
        return _oracle(case_id, "unsubstantiated", "Feedback PII exposure requires unauthenticated retrieval showing author email addresses.")

    if case_id == "JUICE-NULLBYTE-013":
        if ("%2500" in blob or "%00" in blob or "null byte" in blob or "nullbyte" in blob) and (
            "juice-shop" in blob or "package.json" in blob or "backup" in blob or "403" in blob
        ):
            return _oracle(case_id, "confirmed", "Poison null-byte bypass of the 403 returned restricted backup file content.")
        return _oracle(case_id, "unsubstantiated", "Null-byte traversal requires showing the 403 on the raw path and 200 with content via the null-byte bypass.")

    if case_id == "JUICE-ENCKEYS-014":
        if ("encryptionkeys" in blob or "premium.key" in finding.endpoint_url.lower()) and ("premium.key" in blob or "jwt.pub" in blob):
            return _oracle(case_id, "confirmed", "Browsable /encryptionkeys/ directory listing exposed sensitive key files.")
        return _oracle(case_id, "unsubstantiated", "Encryption-key exposure requires the directory listing revealing premium.key / jwt.pub.")

    return _oracle(case_id, "unsubstantiated", "Unhandled benchmark case verification.")
