"""Configuration loader for benchmark manifest and frozen experiment settings."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml


def repo_root() -> Path:
    # Inside agent container: /app; on host: repository root
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "configs" / "benchmark_manifest.yaml").exists():
            return parent
    return Path.cwd()


def results_root() -> Path:
    """Results base dir, optionally nested per-model via MAC_BENCH_RESULTS_SUBDIR (e.g. 'models/sonnet')."""
    sub = os.environ.get("MAC_BENCH_RESULTS_SUBDIR", "").strip("/")
    base = repo_root() / "results"
    return (base / sub) if sub else base


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    target = path or (repo_root() / "configs" / "benchmark_manifest.yaml")
    with open(target, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_frozen_config(path: Path | None = None) -> dict[str, Any]:
    target = path or (repo_root() / "configs" / "frozen_experiment.json")
    if not target.exists():
        return {}
    with open(target, encoding="utf-8") as f:
        return json.load(f)


def load_dotenv_key(key: str, env_path: Path | None = None) -> str:
    target = env_path or (repo_root() / ".env")
    if target.exists():
        with open(target, encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() == key:
                        return v.strip().strip('"').strip("'")
    raise RuntimeError(f"Required key {key} not found in {target}")
