"""Unit tests for Pydantic state reducers, redaction, oracle adjudication, and metric edge cases."""

from __future__ import annotations

from pathlib import Path

from mac_bench.crypto_redact import RunRedactor
from mac_bench.evaluation.blind_review import run_blind_review_pipeline
from mac_bench.evaluation.metrics import aggregate_architecture_metrics, compute_single_run_metrics
from mac_bench.oracles.verify_oracles import adjudicate_finding_against_oracle, match_benchmark_case
from mac_bench.schemas import (
    BudgetState,
    FindingRecord,
    TargetEndpoint,
    merge_budgets,
    merge_endpoints,
)


def test_budget_reducer_prevents_enlargement_or_reset() -> None:
    prev = BudgetState(
        max_http_transactions=200,
        http_transactions_used=85,
        max_llm_calls=50,
        llm_calls_used=19,
        max_duration_seconds=1800,
        elapsed_seconds=120.5,
        input_tokens=15000,
        output_tokens=2400,
    )
    attempted_enlarge_and_reset = BudgetState(
        max_http_transactions=500,
        http_transactions_used=0,
        max_llm_calls=100,
        llm_calls_used=2,
        max_duration_seconds=3600,
        elapsed_seconds=5.0,
        input_tokens=100,
        output_tokens=50,
    )
    merged = merge_budgets(prev, attempted_enlarge_and_reset)
    assert merged.max_http_transactions == 200
    assert merged.http_transactions_used == 85
    assert merged.max_llm_calls == 50
    assert merged.llm_calls_used == 19
    assert merged.max_duration_seconds == 1800
    assert merged.input_tokens == 15000
    assert merged.output_tokens == 2400


def test_endpoint_merge_upgrades_candidate_to_observed() -> None:
    ep_cand = TargetEndpoint(
        endpoint_id="juiceshop:GET:/rest/basket/6",
        target="juiceshop",
        url="http://juiceshop:3000/rest/basket/6",
        path="/rest/basket/6",
        discovery_status="candidate",
        parameter_names=["id"],
    )
    ep_obs = TargetEndpoint(
        endpoint_id="juiceshop:GET:/rest/basket/6",
        target="juiceshop",
        url="http://juiceshop:3000/rest/basket/6",
        path="/rest/basket/6",
        discovery_status="observed",
        parameter_names=["id", "coupon"],
        auth_context="juiceshop_acct2",
    )
    merged = merge_endpoints([ep_cand], [ep_obs])
    assert len(merged) == 1
    assert merged[0].discovery_status == "observed"
    assert merged[0].parameter_names == ["id", "coupon"]
    assert merged[0].auth_context == "juiceshop_acct2"


def test_redactor_masks_secrets_and_emits_non_reversible_correlation() -> None:
    red = RunRedactor()
    sample = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456",
        "Cookie": "PHPSESSID=9876543210abcdef; security=low",
        "note": "Tested password=BenchAcct1_2026! and key sk-ant-api03-secretvalue123456",
    }
    cleaned = red.sanitize_obj(sample)
    assert "eyJhbGci" not in str(cleaned)
    assert "9876543210abcdef" not in str(cleaned)
    assert "BenchAcct1_2026!" not in str(cleaned)
    assert "sk-ant-" not in str(cleaned)
    assert cleaned["Authorization"].startswith("[REDACTED:corr_")


def test_oracle_rejects_http_200_without_behavioral_proof() -> None:
    weak_bola = FindingRecord(
        finding_id="juiceshop:GET:/rest/basket/6:CWE-639",
        target="juiceshop",
        endpoint_url="http://juiceshop:3000/rest/basket/6",
        method="GET",
        cwe="CWE-639",
        title="Cross-user basket access",
        verdict="confirmed",
        request_sequence=["GET /rest/basket/6 -> 200 OK"],
        response_evidence="Endpoint returned HTTP 200 OK.",
    )
    adj_weak = adjudicate_finding_against_oracle(weak_bola)
    assert adj_weak["case_id"] == "JUICE-BOLA-004"
    assert adj_weak["oracle_label"] == "unsubstantiated"

    strong_bola = weak_bola.model_copy(
        update={
            "request_sequence": [
                "GET /rest/basket/6 as juiceshop_acct1 -> Apple Juice (1000ml) qty 3",
                "GET /rest/basket/6 as juiceshop_acct2 -> 200 OK returning Apple Juice (1000ml) qty 3",
            ],
            "response_evidence": "Authenticated as juiceshop_acct2, retrieved Account 1 basket containing Apple Juice (1000ml) quantity 3.",
        }
    )
    adj_strong = adjudicate_finding_against_oracle(strong_bola)
    assert adj_strong["oracle_label"] == "confirmed"
    assert match_benchmark_case(strong_bola) == "JUICE-BOLA-004"


def test_metrics_undefined_edge_cases_and_duplicate_collapsing(tmp_path: Path) -> None:
    # Zero claims -> FDP is None (undefined), cost_per_verified is None, recovery_rate is None
    empty_run = {
        "run_id": "t1_sa",
        "trial_index": 1,
        "pair_execution_order": 2,
        "architecture": "react_baseline",
        "wall_runtime_seconds": 45.0,
        "state": {"endpoints": [], "findings": [], "tool_errors": [], "tool_invocations": 3},
        "llm_stats": {"input_tokens": 1200, "output_tokens": 300, "llm_calls_used": 2},
        "proxy_stats": {"tx_used": 4, "allowed_count": 4, "blocked_count": 0},
        "firewall_stats": {"total_dropped_packets": 0},
        "out_of_scope_escapes": 0,
    }
    m_empty = compute_single_run_metrics(empty_run, [])
    assert m_empty["discovery"]["recall"] == 0.0
    assert m_empty["discovery"]["fdp"] is None
    assert m_empty["efficiency"]["cost_tokens_per_verified_instance"] is None
    assert m_empty["efficiency"]["recovery_rate"] is None

    # Duplicate confirmed reports for same case must count once in Recall
    dup_f1 = FindingRecord(
        finding_id="f1",
        target="dvwa",
        endpoint_url="http://dvwa/vulnerabilities/exec/",
        method="POST",
        cwe="CWE-78",
        title="OS Command Injection",
        verdict="confirmed",
        request_sequence=["POST /vulnerabilities/exec/ ip=127.0.0.1; whoami"],
        response_evidence="Output contained www-data",
    )
    dup_f2 = dup_f1.model_copy(update={"finding_id": "f2"})
    dup_run = {
        "run_id": "t1_ma",
        "trial_index": 1,
        "pair_execution_order": 1,
        "architecture": "multi_agent",
        "wall_runtime_seconds": 60.0,
        "state": {
            "endpoints": [],
            "findings": [dup_f1.model_dump(), dup_f2.model_dump()],
            "tool_errors": [
                {
                    "error_id": "e1",
                    "step_index": 1,
                    "agent_role": "surface_mapper",
                    "tool_name": "http_request",
                    "category": "AUTH_OR_CSRF_MISSING",
                    "recoverable": True,
                    "error_message": "302 login.php",
                    "recovered": True,
                }
            ],
            "tool_invocations": 8,
            "handoff_count": 2,
        },
        "llm_stats": {"input_tokens": 4000, "output_tokens": 800, "llm_calls_used": 6},
        "proxy_stats": {"tx_used": 12, "allowed_count": 12, "blocked_count": 0},
        "firewall_stats": {"total_dropped_packets": 0},
        "out_of_scope_escapes": 0,
    }
    review = run_blind_review_pipeline([dup_run, empty_run], tmp_path / "blind")
    m_dup = compute_single_run_metrics(dup_run, review["adjudicated_by_run"]["t1_ma"])
    assert m_dup["discovery"]["tp_count"] == 1
    assert m_dup["discovery"]["duplicate_count"] == 1
    assert m_dup["discovery"]["recall"] == round(1 / 14, 4)
    assert m_dup["discovery"]["fdp"] == 0.0
    assert m_dup["efficiency"]["cost_tokens_per_verified_instance"] == 4800.0
    assert m_dup["efficiency"]["recovery_rate"] == 1.0

    agg = aggregate_architecture_metrics([m_dup, m_empty])
    assert agg["by_architecture"]["multi_agent"]["recall"]["mean"] == round(1 / 14, 4)
    assert agg["by_architecture"]["react_baseline"]["fdp_undefined_zero_claim_runs"] == 1


def test_graded_levels_on_one_route_do_not_overwrite_each_other():
    """Regression: low/medium/high findings on the same route+CWE must survive the state reducer."""
    from mac_bench.crypto_redact import RunRedactor
    from mac_bench.schemas import merge_findings
    from mac_bench.tools.session_store import SessionManager
    from mac_bench.tools.web_tools import ToolRuntimeContext, build_shared_tools

    ctx = ToolRuntimeContext(session_mgr=SessionManager(), redactor=RunRedactor())
    submit = {t.name: t for t in build_shared_tools(ctx, allow_record_endpoint=False, allow_submit_finding=True)}[
        "submit_finding"
    ]
    for payload in ("127.0.0.1; whoami", "127.0.0.1| whoami", "127.0.0.1|whoami"):
        submit.invoke({
            "target": "dvwa", "endpoint_url": "http://dvwa/vulnerabilities/exec/", "method": "POST",
            "cwe": "CWE-78", "title": f"Command injection {payload}", "verdict": "confirmed",
            "request_sequence": [f"POST ip={payload}"], "response_evidence": "output: www-data",
        })
    merged = merge_findings([], list(ctx.recorded_findings))
    assert len(merged) == 3


def test_ftp_listing_evidence_mentioning_bak_is_exposure_case():
    """Regression: the /ftp/ listing names .bak files, which must not reroute it to the null-byte case."""
    from mac_bench.oracles.verify_oracles import match_benchmark_case
    from mac_bench.schemas import FindingRecord

    f = FindingRecord(
        finding_id="x", target="juiceshop", endpoint_url="http://juiceshop:3000/ftp/", method="GET",
        cwe="CWE-200", title="Confidential document exposed via open FTP directory listing", verdict="confirmed",
        request_sequence=["GET /ftp/", "GET /ftp/acquisitions.md"],
        response_evidence="listing: acquisitions.md, package.json.bak, coupons_2013.md.bak ...",
    )
    assert match_benchmark_case(f) == "JUICE-EXPOSURE-005"


def test_sqli_level_is_attributed_by_payload_before_wording():
    """Regression: a low-level finding described as "numeric/quoted id" must count as the low case."""
    from mac_bench.oracles.verify_oracles import _dvwa_sqli_level

    low = "sql injection (numeric/quoted id) [security=low] get /vulnerabilities/sqli/?id=1' or '1'='1&submit=submit"
    med = "[security=medium] post /vulnerabilities/sqli/ id=1 or 1=1&submit=submit; earlier the level was high"
    high = "post /vulnerabilities/sqli/session-input.php id=1' or '1'='1' #&submit=submit [security=high]"
    assert _dvwa_sqli_level(low) == "DVWA-SQLI-001"
    assert _dvwa_sqli_level(med) == "DVWA-SQLI-MED-006"
    assert _dvwa_sqli_level(high) == "DVWA-SQLI-HIGH-011"


def test_scope_coverage_tracks_each_level_separately():
    """The tracked-coordinator checklist closes an item only for its own level and verdict."""
    from mac_bench.oracles.verify_oracles import scope_coverage
    from mac_bench.schemas import FindingRecord

    def f(payload, level, verdict):
        return FindingRecord(
            finding_id=f"x{level}", target="dvwa", endpoint_url="http://dvwa/vulnerabilities/exec/", method="POST",
            cwe="CWE-78", title=f"Command injection [security={level}]", verdict=verdict,
            request_sequence=[f"POST ip={payload}"], response_evidence=f"www-data [security={level}]",
        )

    cov = scope_coverage([f("127.0.0.1; whoami", "low", "confirmed"), f("127.0.0.1| whoami", "medium", "inconclusive")])
    assert cov["DVWA-CMDI-002"] == "confirmed"
    assert cov["DVWA-CMDI-MED-007"] == "inconclusive"
    assert cov["DVWA-CMDI-HIGH-012"] == "open"
