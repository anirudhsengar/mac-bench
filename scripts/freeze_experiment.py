#!/usr/bin/env python3
"""Freeze model settings, prompt/tool SHA-256 digests, container image digests, and paired trial schedule."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from mac_bench.config import load_manifest, repo_root
from mac_bench.llm_client import FROZEN_MAX_TOKENS, FROZEN_MODEL_ID


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    root = repo_root()
    preflight_path = root / "results" / "preflight" / "preflight_report.json"
    if not preflight_path.exists():
        raise SystemExit("Preflight report missing; run scripts/run_preflight.py before freezing.")
    preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
    if not preflight.get("overall_passed"):
        raise SystemExit("Preflight did not pass; cannot freeze experiment.")

    manifest = load_manifest()

    # v2: 10 paired trials (20 isolated runs), order counterbalanced across trials to
    # cancel ordering effects (5 runs start with each architecture).
    paired_schedule = [
        {
            "trial_index": i,
            "order": (["multi_agent", "react_baseline"] if i % 2 == 1 else ["react_baseline", "multi_agent"]),
        }
        for i in range(1, 11)
    ]

    frozen = {
        "frozen_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "preflight_verified": True,
        "model": {
            "provider": "anthropic",
            "model_id": FROZEN_MODEL_ID,
            "model_created_at": "2026-10-07T18:00:00Z",
            "max_tokens": FROZEN_MAX_TOKENS,
            "temperature": None,
            "sdk_max_retries": 1,
            "relay_transient_5xx_retries": 3,
        },
        "shared_budgets": manifest["budgets"],
        "pinned_artifacts_and_digests": {
            "dvwa_2_3_release_tarball_sha256": "f19bed738dd2d3867b5a7d50ffafe6fe07b30278824467e0ff24a1737e009f22",
            "php_8_2_apache_bookworm": "php@sha256:46804ea2b61eaf25ca47fa8aafc917015b8dad6b7a64c4364bb051a9dff275d5",
            "mariadb_10_11": "mariadb@sha256:d769e37960821dfdcf096954f6e7ac89f747e116c1bba98e48edd265dfc7deae",
            "juiceshop_v16_0_0": "bkimminich/juice-shop@sha256:5aef8464395d101d984d255166b079a52a573fba900450612f8cf3da2ad3a2dd",
            "python_3_12_slim_bookworm": "python@sha256:da54eb86849fe19be7584d8b3f291fcf0c53c196760ab3d70dc6382f681ef9c0",
            "playwright_v1_62_0_noble": "mcr.microsoft.com/playwright@sha256:baed2032d533817f3dbe6425de795788430ba345e819a1201337009ba17c9d07",
            "alpine_3_22": "alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce",
        },
        "code_and_prompt_sha256": {
            "benchmark_manifest_yaml": sha256_file(root / "configs" / "benchmark_manifest.yaml"),
            "shared_scope_py": sha256_file(root / "src" / "mac_bench" / "prompts" / "shared_scope.py"),
            "multi_agent_prompts_py": sha256_file(root / "src" / "mac_bench" / "prompts" / "multi_agent_prompts.py"),
            "react_prompts_py": sha256_file(root / "src" / "mac_bench" / "prompts" / "react_prompts.py"),
            "web_tools_py": sha256_file(root / "src" / "mac_bench" / "tools" / "web_tools.py"),
            "multi_agent_py": sha256_file(root / "src" / "mac_bench" / "agents" / "multi_agent.py"),
            "react_baseline_py": sha256_file(root / "src" / "mac_bench" / "agents" / "react_baseline.py"),
            "mediator_addon_py": sha256_file(root / "docker" / "proxy" / "mediator_addon.py"),
        },
        "paired_trial_schedule": paired_schedule,
    }

    out_path = root / "configs" / "frozen_experiment.json"
    out_path.write_text(json.dumps(frozen, indent=2) + "\n", encoding="utf-8")
    print(f"Frozen experiment configuration written to {out_path}")


if __name__ == "__main__":
    main()
