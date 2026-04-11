#!/usr/bin/env python3
"""Run multiple ocw batch pools in parallel with retries and file-save repair.

This runner is designed for large CVE prompt batches where:
- multiple provider/model/key pools should run simultaneously
- output is file-first (canonical JSON written to /home/user1/dataset_pipeline/cves/<CVE>__<COMMIT>.json)
- transient failures (429/5xx/timeouts) should be retried
- quota-exhausted pools should be disabled and work requeued to sibling pools
- missing canonical files should trigger an in-session repair prompt

Pool API keys are read from environment variables referenced in the pool config.
Keys are never persisted by this script.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shlex
import subprocess
import sys
import time
import traceback
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from export_trajectories_per_cve import export_records_to_flat_cve_files


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
COMMIT_HASH_RE = re.compile(r"\b[0-9a-f]{7,64}\b", re.IGNORECASE)
COMMIT_HASH_FIELD_RE = re.compile(r"(?im)^\s*-\s*commit_hash\s*:\s*([0-9a-f]{7,64})\s*$")
COMMIT_URL_RE = re.compile(r"/commit/([0-9a-f]{7,64})", re.IGNORECASE)
ENV_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SESSION_ID_RELEVANT_KEYS = ("sessionID", "sessionId", "session_id")
FILENAME_CVE_COMMIT_RE = re.compile(r"(?i)^(CVE-\d{4}-\d{4,})__([0-9a-f]{7,64})\.json$")

TRANSIENT_TOKENS = (
    "429",
    "500",
    "502",
    "503",
    "504",
    "rate limit",
    "too many requests",
    "timeout",
    "timed out",
    "temporarily unavailable",
    "temporarily overloaded",
    "connection reset",
    "econnreset",
    "upstream",
)

QUOTA_TOKENS = (
    "quota",
    "insufficient_quota",
    "exhausted",
    "credit",
    "billing",
    "out of credits",
)

PROVIDER_ENV_ALIASES: dict[str, tuple[str, ...]] = {
    "minimax": ("MINIMAX_API_KEY", "MINIMAX_CODING_PLAN_API_KEY"),
    "glm": ("GLM_API_KEY", "ZAI_API_KEY", "ZAI_CODING_PLAN_API_KEY"),
}

PROVIDER_AUTH_IDS: dict[str, tuple[str, ...]] = {
    "minimax": ("minimax-coding-plan",),
    "glm": ("zai-coding-plan",),
}

DEFAULT_EXTRA_SKIP_DIRS: tuple[Path, ...] = (
    Path("/home/user1/dataset_pipeline/filtered_results").resolve(),
)
DEFAULT_TOOL_TRAJECTORY_DIR = Path("/home/user1/dataset_pipeline/tool_trajectory").resolve()
DEFAULT_TRAJECTORY_EXPORTER = (Path(__file__).resolve().parent / "export_trajectories_per_cve.py").resolve()


@dataclass
class PoolConfig:
    name: str
    provider: str  # normalized provider bucket used for routing: "glm" / "minimax" / fallback raw
    provider_raw: str  # original provider id from config (e.g. "zai-coding-plan")
    model: str
    workers: int
    api_key_env: str
    extra_run_flags: list[str] = field(default_factory=list)


@dataclass
class PromptTask:
    prompt: str
    cve: str | None
    commit_hash: str | None
    attempts: int = 0
    last_error: str = ""


@dataclass
class PoolRunResult:
    pool_name: str
    succeeded: list[PromptTask] = field(default_factory=list)
    retry_same_pool: list[PromptTask] = field(default_factory=list)
    requeue_same_provider: list[PromptTask] = field(default_factory=list)
    failed: list[PromptTask] = field(default_factory=list)
    disabled_for_quota: bool = False
    stats: dict[str, int] = field(default_factory=dict)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Parallel multi-provider ocw batch runner with retries and repair.")
    p.add_argument("--ocw", default="opencode-cli-wrapper/ocw", help="Path to ocw executable")
    p.add_argument("--prompts-jsonl", required=True, help="Input prompts JSONL (each line: {\"prompt\": ...})")
    p.add_argument("--pool-config", required=True, help="Pool config JSON file")
    p.add_argument("--run-root", required=True, help="Run directory root")
    p.add_argument(
        "--canonical-dir",
        default="/home/user1/dataset_pipeline/cves",
        help="Canonical JSON output directory used by prompts",
    )
    p.add_argument(
        "--prompt-timeout-seconds",
        type=float,
        default=2400.0,
        help="Passed to ocw batch/run",
    )
    p.add_argument("--max-attempts", type=int, default=3, help="Max attempts per prompt task")
    p.add_argument("--base-backoff-seconds", type=float, default=8.0, help="Retry backoff base")
    p.add_argument("--jitter-seconds", type=float, default=4.0, help="Retry backoff jitter")
    p.add_argument(
        "--quota-cooldown-seconds",
        type=float,
        default=5 * 60 * 60,
        help="Expected quota reset window used for reporting; runner still probes disabled pools every idle-wait interval.",
    )
    p.add_argument(
        "--idle-wait-seconds",
        type=float,
        default=30 * 60,
        help="Sleep interval while waiting for quota cooldown reactivation (default 30 minutes).",
    )
    p.add_argument(
        "--disabled-pools",
        default="",
        help="Comma-separated pool names to disable permanently at startup (no cooldown probing).",
    )
    p.add_argument(
        "--manual-kill-file",
        default="",
        help="Optional file with pool names to disable permanently at runtime; supports JSON array or text names.",
    )
    p.add_argument(
        "--repair-missing-file",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Attempt in-session repair run if canonical file is missing",
    )
    p.add_argument(
        "--set-method",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Normalize context_quality.method to provider label (glm/minimax)",
    )
    p.add_argument(
        "--share-across-providers",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Allow rerouting/requeue across all active pools (glm/minimax sharing).",
    )
    p.add_argument(
        "--respect-opencode-permissions",
        action="store_true",
        help="Pass through to ocw; default keeps full allow",
    )
    p.add_argument(
        "--export-trajectories",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Export per-(CVE, commit) tool trajectories after multi-pool run completes",
    )
    p.add_argument(
        "--trajectory-exporter",
        default=str(DEFAULT_TRAJECTORY_EXPORTER),
        help="Path to export_trajectories_per_cve.py",
    )
    p.add_argument(
        "--tool-trajectory-dir",
        default=str(DEFAULT_TOOL_TRAJECTORY_DIR),
        help="Root directory for trajectory outputs",
    )
    p.add_argument(
        "--trajectory-keep-merged",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Keep merged trajectory JSONL intermediates",
    )
    p.add_argument("--dry-run", action="store_true", help="Plan only; do not execute ocw commands")
    return p.parse_args()


def load_result_records(paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    records.append(payload)
    return records


def load_pool_config(path: Path) -> list[PoolConfig]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit("error: pool config must be a JSON object with key 'pools'")
    pools = payload.get("pools")
    if not isinstance(pools, list) or not pools:
        raise SystemExit("error: pool config must include a non-empty 'pools' array")

    parsed: list[PoolConfig] = []
    for idx, item in enumerate(pools):
        if not isinstance(item, dict):
            raise SystemExit(f"error: pool[{idx}] must be an object")
        try:
            model_text = str(item["model"]).strip()
            provider_text = str(item.get("provider", "")).strip()
            if not provider_text and "/" in model_text:
                provider_text = model_text.split("/", 1)[0].strip()
            provider_text = provider_text or "unknown"
            pool = PoolConfig(
                name=str(item["name"]).strip(),
                provider=normalize_provider_label(provider_text),
                provider_raw=provider_text,
                model=model_text,
                workers=int(item["workers"]),
                api_key_env=str(item["api_key_env"]).strip(),
                extra_run_flags=[str(v) for v in item.get("extra_run_flags", [])],
            )
        except KeyError as exc:
            raise SystemExit(f"error: pool[{idx}] missing required field: {exc}") from exc
        if not pool.name:
            raise SystemExit(f"error: pool[{idx}] name is empty")
        if pool.workers < 1:
            raise SystemExit(f"error: pool[{idx}] workers must be >= 1")
        if not pool.api_key_env:
            raise SystemExit(f"error: pool[{idx}] api_key_env is empty")
        if not ENV_VAR_RE.fullmatch(pool.api_key_env):
            raise SystemExit(
                f"error: pool[{idx}] api_key_env must be an environment variable name, got: {pool.api_key_env!r}"
            )
        parsed.append(pool)
    return parsed


def normalize_provider_label(value: str) -> str:
    v = (value or "").strip().lower()
    if v in {"zai", "zai-coding-plan", "glm", "glm-5.1"}:
        return "glm"
    if v in {"minimax", "minimax.io", "minimax-coding-plan"}:
        return "minimax"
    return v or "unknown"


def parse_name_list(raw: str) -> set[str]:
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def read_disabled_pools_file(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return set()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, list):
        return {str(v).strip() for v in payload if str(v).strip()}
    names: set[str] = set()
    for line in text.splitlines():
        for piece in line.replace(",", " ").split():
            item = piece.strip()
            if item:
                names.add(item)
    return names


def load_tasks(prompts_jsonl: Path) -> list[PromptTask]:
    tasks: list[PromptTask] = []
    with prompts_jsonl.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"error: invalid JSON at {prompts_jsonl}:{line_no}: {exc}") from exc
            if not isinstance(item, dict):
                raise SystemExit(f"error: expected object at {prompts_jsonl}:{line_no}")
            prompt = item.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                raise SystemExit(f"error: missing/non-string prompt at {prompts_jsonl}:{line_no}")
            cve = extract_cve(prompt)
            commit_hash = extract_commit_hash(prompt)
            tasks.append(PromptTask(prompt=prompt.strip(), cve=cve, commit_hash=commit_hash))
    if not tasks:
        raise SystemExit("error: no prompt tasks loaded")
    return tasks


def extract_cve(text: str) -> str | None:
    match = CVE_RE.search(text or "")
    return match.group(0).upper() if match else None


def extract_commit_hash(text: str) -> str | None:
    if not text:
        return None
    match = COMMIT_HASH_FIELD_RE.search(text)
    if match:
        return match.group(1).lower()
    match = COMMIT_URL_RE.search(text)
    if match:
        return match.group(1).lower()
    if "commit_hash" in text.lower() or "/commit/" in text.lower():
        match = COMMIT_HASH_RE.search(text)
        if match:
            return match.group(0).lower()
    return None


def normalize_commit_hash(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    if COMMIT_HASH_RE.fullmatch(text):
        return text
    match = COMMIT_URL_RE.search(text)
    if match:
        return match.group(1).lower()
    return ""


def cve_commit_key(cve_value: str, commit_value: str) -> tuple[str, str] | None:
    cve = extract_cve(cve_value or "")
    commit = normalize_commit_hash(commit_value or "")
    if not cve or not commit:
        return None
    return (cve, commit)


def task_cve_commit_key(task: PromptTask) -> tuple[str, str] | None:
    if not task.cve or not task.commit_hash:
        return None
    return cve_commit_key(task.cve, task.commit_hash)


def collect_cve_commit_keys_from_directory(path: Path) -> set[tuple[str, str]]:
    if not path.exists() or not path.is_dir():
        return set()
    keys: set[tuple[str, str]] = set()
    for file_path in path.rglob("*.json"):
        if not file_path.is_file():
            continue
        # Fast-path from canonical filename format.
        match = FILENAME_CVE_COMMIT_RE.match(file_path.name)
        if match:
            keys.add((match.group(1).upper(), match.group(2).lower()))
            continue

        try:
            payload = json.loads(file_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        records: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            records = [payload]
        elif isinstance(payload, list):
            records = [item for item in payload if isinstance(item, dict)]

        for record in records:
            key = cve_commit_key(
                str(record.get("cve_id", "")) or file_path.name,
                str(record.get("commit_hash") or record.get("commit") or ""),
            )
            if key is not None:
                keys.add(key)
    return keys


def collect_existing_keys(paths: list[Path]) -> tuple[set[tuple[str, str]], dict[str, int]]:
    merged: set[tuple[str, str]] = set()
    per_dir_counts: dict[str, int] = {}
    for path in paths:
        keys = collect_cve_commit_keys_from_directory(path)
        per_dir_counts[str(path)] = len(keys)
        merged.update(keys)
    return merged, per_dir_counts


def weighted_pool_order(pools: list[PoolConfig]) -> list[str]:
    order: list[str] = []
    for pool in pools:
        order.extend([pool.name] * pool.workers)
    if not order:
        raise SystemExit("error: empty pool order")
    return order


def shard_tasks(tasks: list[PromptTask], pools: list[PoolConfig]) -> dict[str, list[PromptTask]]:
    order = weighted_pool_order(pools)
    bucket: dict[str, list[PromptTask]] = {p.name: [] for p in pools}
    idx = 0
    for task in tasks:
        pool_name = order[idx % len(order)]
        bucket[pool_name].append(task)
        idx += 1
    return bucket


def write_prompts_jsonl(path: Path, tasks: list[PromptTask]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for task in tasks:
            handle.write(json.dumps({"prompt": task.prompt}, ensure_ascii=True) + "\n")


def classify_error(exit_code: int, stderr: str) -> str:
    text = (stderr or "").lower()
    if any(tok in text for tok in QUOTA_TOKENS):
        return "quota"
    if exit_code == 124:
        return "transient"
    if any(tok in text for tok in TRANSIENT_TOKENS):
        return "transient"
    return "fatal"


def extract_last_session_id(stdout: str) -> str | None:
    last: str | None = None
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        for key in SESSION_ID_RELEVANT_KEYS:
            value = event.get(key)
            if isinstance(value, str) and value:
                last = value
        part = event.get("part")
        if isinstance(part, dict):
            for key in SESSION_ID_RELEVANT_KEYS:
                value = part.get(key)
                if isinstance(value, str) and value:
                    last = value
    return last


def canonical_path(canonical_dir: Path, cve: str | None, commit_hash: str | None) -> Path | None:
    if not cve:
        return None
    if commit_hash:
        return canonical_dir / f"{cve}__{commit_hash}.json"
    return canonical_dir / f"{cve}.json"


def is_valid_json_file(path: Path | None) -> bool:
    if path is None or not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict)


def partition_existing_tasks(
    tasks: list[PromptTask],
    *,
    canonical_dir: Path,
    existing_keys: set[tuple[str, str]],
) -> tuple[list[PromptTask], list[PromptTask]]:
    pending: list[PromptTask] = []
    skipped_existing: list[PromptTask] = []
    for task in tasks:
        key = task_cve_commit_key(task)
        if key is not None and key in existing_keys:
            task.last_error = "already has canonical json (existing key)"
            skipped_existing.append(task)
            continue
        path = canonical_path(canonical_dir, task.cve, task.commit_hash)
        if is_valid_json_file(path):
            task.last_error = "already has canonical json"
            if key is not None:
                existing_keys.add(key)
            skipped_existing.append(task)
        else:
            pending.append(task)
    return pending, skipped_existing


def normalize_method(path: Path, provider: str) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return
    cq = payload.get("context_quality")
    if not isinstance(cq, dict):
        cq = {}
        payload["context_quality"] = cq
    provider_key = normalize_provider_label(provider)
    if provider_key in {"glm", "minimax"}:
        cq["method"] = provider_key
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def run_command(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
) -> int:
    completed = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_path.write_text(completed.stdout or "", encoding="utf-8")
    stderr_path.write_text(completed.stderr or "", encoding="utf-8")
    return completed.returncode


def read_incremental_jsonl_records(
    path: Path,
    *,
    offset: int,
    partial: bytes,
) -> tuple[list[dict[str, Any]], int, bytes]:
    if not path.exists():
        return [], offset, partial
    with path.open("rb") as handle:
        handle.seek(offset)
        chunk = handle.read()
        new_offset = handle.tell()
    if not chunk:
        return [], new_offset, partial

    data = partial + chunk
    lines = data.split(b"\n")
    new_partial = lines.pop() if lines else b""
    records: list[dict[str, Any]] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            item = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(item, dict):
            records.append(item)
    return records, new_offset, new_partial


def flush_incremental_jsonl_partial(partial: bytes) -> list[dict[str, Any]]:
    line = partial.strip()
    if not line:
        return []
    try:
        item = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    return [item] if isinstance(item, dict) else []


def build_pool_env(pool: PoolConfig, api_key: str) -> dict[str, str]:
    """Build a deterministic env for one pool so sibling provider keys do not bleed in."""
    env = dict(os.environ)

    # Clear known provider-family key vars so only this pool key is visible.
    for aliases in PROVIDER_ENV_ALIASES.values():
        for alias in aliases:
            for key in list(env):
                if key == alias or key.startswith(alias + "_"):
                    env.pop(key, None)

    # Also clear this pool-specific key var in case it's inherited with stale value.
    env.pop(pool.api_key_env, None)

    # Keep the configured key name and also set canonical aliases used by provider integrations.
    env[pool.api_key_env] = api_key
    for alias in PROVIDER_ENV_ALIASES.get(pool.provider, ()):
        env[alias] = api_key
    return env


def seed_pool_auth(
    *,
    xdg_root: Path,
    pool: PoolConfig,
    api_key: str,
) -> None:
    """Write pool-isolated OpenCode auth state so each pool uses its assigned API key."""
    provider_ids = list(PROVIDER_AUTH_IDS.get(pool.provider, ()))
    raw_provider = (pool.provider_raw or "").strip()
    if raw_provider and raw_provider not in provider_ids:
        provider_ids.append(raw_provider)
    if not provider_ids:
        provider_ids = [pool.provider]

    auth_payload: dict[str, dict[str, str]] = {
        pid: {"type": "api", "key": api_key} for pid in provider_ids
    }

    # Root auth (used by controller-side operations).
    root_auth = xdg_root / "opencode" / "auth.json"
    root_auth.parent.mkdir(parents=True, exist_ok=True)
    root_auth.write_text(json.dumps(auth_payload, ensure_ascii=True, indent=2), encoding="utf-8")

    # Worker auth files (used by isolated workers with --isolation-root/worker-XXX).
    for idx in range(1, pool.workers + 1):
        worker_auth = xdg_root / f"worker-{idx:03d}" / "opencode" / "auth.json"
        worker_auth.parent.mkdir(parents=True, exist_ok=True)
        worker_auth.write_text(json.dumps(auth_payload, ensure_ascii=True, indent=2), encoding="utf-8")


def run_repair_prompt(
    *,
    ocw_path: Path,
    workspace_dir: Path,
    pool: PoolConfig,
    env: dict[str, str],
    xdg_data_home: str | None,
    session_id: str | None,
    cve: str | None,
    commit_hash: str | None,
    canonical_dir: Path,
    timeout_seconds: float,
    logs_dir: Path,
) -> bool:
    if not xdg_data_home or not session_id or not cve:
        return False
    target = canonical_path(canonical_dir, cve, commit_hash)
    if target is None:
        return False
    repair_prompt = (
        "Previous step did not persist the canonical file. "
        f"Write the final canonical JSON object to {target}. "
        f"After successful save, output exactly: SAVED {target}."
    )
    cmd = [
        str(ocw_path),
        "run",
        "--prompt",
        repair_prompt,
        "--cwd",
        str(workspace_dir),
        "--prompt-timeout-seconds",
        str(timeout_seconds),
        "--xdg-data-home",
        xdg_data_home,
        "--json-events",
        "--",
        "--session",
        session_id,
        "--continue",
        "--model",
        pool.model,
    ]
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    suffix = f"{cve}__{commit_hash}" if commit_hash else str(cve)
    out_file = logs_dir / f"repair_{pool.name}_{suffix}_{ts}.stdout.log"
    err_file = logs_dir / f"repair_{pool.name}_{suffix}_{ts}.stderr.log"
    _ = run_command(
        cmd,
        cwd=workspace_dir,
        env=env,
        stdout_path=out_file,
        stderr_path=err_file,
    )
    return is_valid_json_file(target)


def export_trajectory_for_record(
    *,
    record: dict[str, Any],
    ocw_path: Path,
    tool_trajectory_dir: Path,
    pool_name: str,
    result: PoolRunResult,
) -> None:
    try:
        trajectory_export = export_records_to_flat_cve_files(
            records=[record],
            ocw_path=ocw_path,
            out_dir=tool_trajectory_dir,
        )
        if trajectory_export.get("attempted"):
            result.stats["trajectory_files_written"] = result.stats.get("trajectory_files_written", 0) + int(
                trajectory_export.get("keys_written", 0)
            )
            result.stats["trajectory_records"] = result.stats.get("trajectory_records", 0) + int(
                trajectory_export.get("trajectory_records", 0)
            )
            result.stats["trajectory_unknown_records"] = result.stats.get(
                "trajectory_unknown_records", 0
            ) + int(trajectory_export.get("unknown_records", 0))
        else:
            result.stats["trajectory_skipped"] = result.stats.get("trajectory_skipped", 0) + 1
    except Exception as exc:
        result.stats["trajectory_export_errors"] = result.stats.get("trajectory_export_errors", 0) + 1
        print(
            f"[multi] warning: immediate trajectory export failed for pool={pool_name}: {exc}",
            file=sys.stderr,
        )


def handle_task_record(
    *,
    result: PoolRunResult,
    task: PromptTask,
    record: dict[str, Any],
    ocw_path: Path,
    workspace_dir: Path,
    pool: PoolConfig,
    env: dict[str, str],
    canonical_dir: Path,
    prompt_timeout_seconds: float,
    logs_dir: Path,
    tool_trajectory_dir: Path,
    max_attempts: int,
    repair_missing_file: bool,
    set_method_attr: bool,
) -> None:
    task.attempts += 1

    path = canonical_path(canonical_dir, task.cve, task.commit_hash)
    file_ok = is_valid_json_file(path)
    if int(record.get("exit_code", 1)) == 0 and file_ok:
        if set_method_attr and path is not None:
            normalize_method(path, pool.provider)
        result.succeeded.append(task)
        result.stats["success"] += 1
        export_trajectory_for_record(
            record=record,
            ocw_path=ocw_path,
            tool_trajectory_dir=tool_trajectory_dir,
            pool_name=pool.name,
            result=result,
        )
        return

    if int(record.get("exit_code", 1)) == 0 and not file_ok:
        result.stats["missing_file"] += 1
        repaired = False
        if repair_missing_file:
            repaired = run_repair_prompt(
                ocw_path=ocw_path,
                workspace_dir=workspace_dir,
                pool=pool,
                env=env,
                xdg_data_home=record.get("xdg_data_home") if isinstance(record.get("xdg_data_home"), str) else None,
                session_id=extract_last_session_id(record.get("stdout", "") if isinstance(record.get("stdout"), str) else ""),
                cve=task.cve,
                commit_hash=task.commit_hash,
                canonical_dir=canonical_dir,
                timeout_seconds=prompt_timeout_seconds,
                logs_dir=logs_dir,
            )
        if repaired and path is not None:
            if set_method_attr:
                normalize_method(path, pool.provider)
            result.succeeded.append(task)
            result.stats["success"] += 1
            result.stats["repaired"] += 1
            export_trajectory_for_record(
                record=record,
                ocw_path=ocw_path,
                tool_trajectory_dir=tool_trajectory_dir,
                pool_name=pool.name,
                result=result,
            )
            return
        task.last_error = "missing canonical file after repair attempt"
        if task.attempts < max_attempts:
            result.retry_same_pool.append(task)
            result.stats["retry_transient"] += 1
        else:
            result.failed.append(task)
            result.stats["failed"] += 1
        return

    stderr = record.get("stderr", "") if isinstance(record.get("stderr"), str) else ""
    kind = classify_error(int(record.get("exit_code", 1)), stderr)
    task.last_error = kind
    if kind == "quota":
        result.requeue_same_provider.append(task)
        result.stats["requeue_provider"] += 1
        result.stats["quota_errors"] += 1
        result.disabled_for_quota = True
    elif kind == "transient":
        result.retry_same_pool.append(task)
        result.stats["retry_transient"] += 1
        result.stats["transient_errors"] += 1
    else:
        result.failed.append(task)
        result.stats["failed"] += 1
        result.stats["fatal_errors"] += 1


def run_pool_round(
    *,
    pool: PoolConfig,
    tasks: list[PromptTask],
    ocw_path: Path,
    run_root: Path,
    canonical_dir: Path,
    prompt_timeout_seconds: float,
    tool_trajectory_dir: Path,
    max_attempts: int,
    respect_permissions: bool,
    repair_missing_file: bool,
    set_method_attr: bool,
    dry_run: bool,
) -> PoolRunResult:
    result = PoolRunResult(pool_name=pool.name)
    result.stats = {
        "input": len(tasks),
        "success": 0,
        "retry_transient": 0,
        "requeue_provider": 0,
        "failed": 0,
        "missing_file": 0,
        "repaired": 0,
        "quota_errors": 0,
        "transient_errors": 0,
        "fatal_errors": 0,
    }
    if not tasks:
        return result

    pool_root = run_root / "pools" / pool.name
    workspace_dir = pool_root / "workspace"
    logs_dir = pool_root / "logs"
    xdg_root = pool_root / ".xdg"
    pool_root.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    xdg_root.mkdir(parents=True, exist_ok=True)

    api_key = os.environ.get(pool.api_key_env)
    if not api_key:
        for task in tasks:
            task.last_error = f"missing api key env: {pool.api_key_env}"
            result.failed.append(task)
        result.stats["failed"] = len(tasks)
        return result

    env = build_pool_env(pool, api_key)
    seed_pool_auth(xdg_root=xdg_root, pool=pool, api_key=api_key)

    ts = int(time.time() * 1000)
    prompts_path = pool_root / f"attempt_{ts}.prompts.jsonl"
    output_path = pool_root / f"attempt_{ts}.results.jsonl"
    batch_stdout = logs_dir / f"attempt_{ts}.batch.stdout.log"
    batch_stderr = logs_dir / f"attempt_{ts}.batch.stderr.log"
    write_prompts_jsonl(prompts_path, tasks)

    cmd = [
        str(ocw_path),
        "batch",
        "-i",
        str(prompts_path),
        "-o",
        str(output_path),
        "--workers",
        str(pool.workers),
        "--cwd",
        str(workspace_dir),
        "--isolate-db",
        "--isolation-root",
        str(xdg_root),
        "--json-events",
        "--prompt-timeout-seconds",
        str(prompt_timeout_seconds),
    ]
    if respect_permissions:
        cmd.append("--respect-opencode-permissions")
    cmd.extend(["--", "--model", pool.model, *pool.extra_run_flags])

    if dry_run:
        batch_stdout.write_text(shlex.join(cmd) + "\n", encoding="utf-8")
        for task in tasks:
            task.last_error = "dry-run"
            result.retry_same_pool.append(task)
        result.stats["retry_transient"] = len(tasks)
        return result

    by_prompt: dict[str, deque[PromptTask]] = defaultdict(deque)
    for task in tasks:
        by_prompt[task.prompt].append(task)

    with batch_stdout.open("w", encoding="utf-8") as stdout_handle, batch_stderr.open(
        "w", encoding="utf-8"
    ) as stderr_handle:
        proc = subprocess.Popen(
            cmd,
            cwd=str(workspace_dir),
            env=env,
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
        )

        output_offset = 0
        output_partial = b""
        rc: int | None = None

        while True:
            records, output_offset, output_partial = read_incremental_jsonl_records(
                output_path,
                offset=output_offset,
                partial=output_partial,
            )
            for record in records:
                prompt = record.get("prompt")
                if not isinstance(prompt, str):
                    continue
                queue = by_prompt.get(prompt)
                if not queue:
                    continue
                task = queue.popleft()
                handle_task_record(
                    result=result,
                    task=task,
                    record=record,
                    ocw_path=ocw_path,
                    workspace_dir=workspace_dir,
                    pool=pool,
                    env=env,
                    canonical_dir=canonical_dir,
                    prompt_timeout_seconds=prompt_timeout_seconds,
                    logs_dir=logs_dir,
                    tool_trajectory_dir=tool_trajectory_dir,
                    max_attempts=max_attempts,
                    repair_missing_file=repair_missing_file,
                    set_method_attr=set_method_attr,
                )

            rc = proc.poll()
            if rc is not None:
                break
            time.sleep(1.0)

        trailing_records = flush_incremental_jsonl_partial(output_partial)
        for record in trailing_records:
            prompt = record.get("prompt")
            if not isinstance(prompt, str):
                continue
            queue = by_prompt.get(prompt)
            if not queue:
                continue
            task = queue.popleft()
            handle_task_record(
                result=result,
                task=task,
                record=record,
                ocw_path=ocw_path,
                workspace_dir=workspace_dir,
                pool=pool,
                env=env,
                canonical_dir=canonical_dir,
                prompt_timeout_seconds=prompt_timeout_seconds,
                logs_dir=logs_dir,
                tool_trajectory_dir=tool_trajectory_dir,
                max_attempts=max_attempts,
                repair_missing_file=repair_missing_file,
                set_method_attr=set_method_attr,
            )

    if rc != 0 and not output_path.exists():
        for task in tasks:
            task.last_error = f"pool batch failed before output parse (rc={rc})"
            result.retry_same_pool.append(task)
        result.stats["retry_transient"] = len(tasks)
        return result

    # Any unmatched tasks (missing output rows) are retried.
    for queue in by_prompt.values():
        while queue:
            task = queue.popleft()
            task.attempts += 1
            task.last_error = "missing output record"
            result.retry_same_pool.append(task)
            result.stats["retry_transient"] += 1

    return result


def choose_pool_for_provider(
    provider: str,
    pool_map: dict[str, PoolConfig],
    active_pools: set[str],
    provider_rr: dict[str, int],
    share_across_providers: bool,
) -> str | None:
    if share_across_providers:
        candidates = [p.name for p in pool_map.values() if p.name in active_pools]
        rr_key = "__all__"
    else:
        candidates = [p.name for p in pool_map.values() if p.provider == provider and p.name in active_pools]
        rr_key = provider
    if not candidates:
        return None
    candidates.sort()
    idx = provider_rr.get(rr_key, 0) % len(candidates)
    provider_rr[rr_key] = idx + 1
    return candidates[idx]


def reroute_or_fail_task(
    *,
    task: PromptTask,
    from_pool_name: str,
    pool_map: dict[str, PoolConfig],
    active_pools: set[str],
    provider_rr: dict[str, int],
    share_across_providers: bool,
    pending_by_pool: dict[str, list[PromptTask]],
    failed: list[PromptTask],
    reason: str,
) -> None:
    pool = pool_map[from_pool_name]
    target = choose_pool_for_provider(
        pool.provider,
        pool_map,
        active_pools,
        provider_rr,
        share_across_providers,
    )
    if target is None:
        task.last_error = reason
        failed.append(task)
        return
    pending_by_pool[target].append(task)


def collect_result_files(run_root: Path) -> list[Path]:
    files = [path for path in run_root.glob("pools/*/attempt_*.results.jsonl") if path.is_file()]
    return sorted(files, key=lambda p: str(p))


def main() -> int:
    args = parse_args()
    ocw_path = Path(args.ocw).expanduser().resolve()
    prompts_jsonl = Path(args.prompts_jsonl).expanduser().resolve()
    pool_config_path = Path(args.pool_config).expanduser().resolve()
    run_root = Path(args.run_root).expanduser().resolve()
    canonical_dir = Path(args.canonical_dir).expanduser().resolve()
    trajectory_exporter = Path(args.trajectory_exporter).expanduser().resolve()
    tool_trajectory_dir = Path(args.tool_trajectory_dir).expanduser().resolve()
    canonical_dir.mkdir(parents=True, exist_ok=True)
    run_root.mkdir(parents=True, exist_ok=True)
    skip_dirs: list[Path] = [canonical_dir]
    for path in DEFAULT_EXTRA_SKIP_DIRS:
        if path not in skip_dirs:
            skip_dirs.append(path)

    pools = load_pool_config(pool_config_path)
    tasks = load_tasks(prompts_jsonl)
    startup_trajectory_backfill: dict[str, Any] = {"attempted": False, "reason": "disabled"}
    if args.export_trajectories and not args.dry_run:
        historical_result_files = collect_result_files(run_root)
        if historical_result_files:
            historical_records = load_result_records(historical_result_files)
            startup_trajectory_backfill = export_records_to_flat_cve_files(
                records=historical_records,
                ocw_path=ocw_path,
                out_dir=tool_trajectory_dir,
            )
            print(
                "[multi] startup trajectory backfill="
                + json.dumps(startup_trajectory_backfill, ensure_ascii=True)
            )
    existing_keys, existing_key_counts_by_dir = collect_existing_keys(skip_dirs)
    print("[multi] existing output key scan:")
    for path in skip_dirs:
        print(f"[multi]   - {path}: keys={existing_key_counts_by_dir.get(str(path), 0)}")
    print(f"[multi]   merged existing keys={len(existing_keys)}")

    tasks, startup_skipped_existing = partition_existing_tasks(
        tasks,
        canonical_dir=canonical_dir,
        existing_keys=existing_keys,
    )
    if startup_skipped_existing:
        print(
            f"[multi] startup-skip existing canonical files: {len(startup_skipped_existing)}"
        )
    pool_map = {p.name: p for p in pools}
    active_pools = {p.name for p in pools}
    cooldown_until: dict[str, float] = {}
    quota_window_until: dict[str, float] = {}
    permanently_disabled: set[str] = set()

    initial_disabled = parse_name_list(args.disabled_pools)
    unknown_initial = sorted(name for name in initial_disabled if name not in pool_map)
    if unknown_initial:
        raise SystemExit(f"error: unknown pool(s) in --disabled-pools: {', '.join(unknown_initial)}")
    permanently_disabled.update(initial_disabled)
    for name in permanently_disabled:
        active_pools.discard(name)

    pending_by_pool = shard_tasks(tasks, pools)
    completed: list[PromptTask] = list(startup_skipped_existing)
    failed: list[PromptTask] = []
    provider_rr: dict[str, int] = {}
    round_index = 0
    kill_file_path = Path(args.manual_kill_file).expanduser().resolve() if args.manual_kill_file else None

    # Re-route startup-disabled pool tasks before processing begins.
    for pool_name in sorted(permanently_disabled):
        blocked = list(pending_by_pool.get(pool_name, []))
        pending_by_pool[pool_name] = []
        for task in blocked:
            reroute_or_fail_task(
                task=task,
                from_pool_name=pool_name,
                pool_map=pool_map,
                active_pools=active_pools,
                provider_rr=provider_rr,
                share_across_providers=args.share_across_providers,
                pending_by_pool=pending_by_pool,
                failed=failed,
                reason=f"pool permanently disabled: {pool_name}",
            )

    summary_path = run_root / "multi_provider_summary.json"
    while True:
        # Guard against reruns/restarts: if canonical file exists now, drop pending task before dispatch.
        skipped_existing_round = 0
        for pool_name, queue in list(pending_by_pool.items()):
            kept, skipped = partition_existing_tasks(
                queue,
                canonical_dir=canonical_dir,
                existing_keys=existing_keys,
            )
            if skipped:
                completed.extend(skipped)
                skipped_existing_round += len(skipped)
            pending_by_pool[pool_name] = kept
        if skipped_existing_round:
            print(f"[multi] round-skip existing canonical files: {skipped_existing_round}")

        if kill_file_path is not None:
            requested = read_disabled_pools_file(kill_file_path)
            unknown = sorted(name for name in requested if name not in pool_map)
            if unknown:
                print(f"[multi] warning: ignoring unknown pool(s) in manual kill file: {', '.join(unknown)}")
            for pool_name in sorted(requested):
                if pool_name not in pool_map or pool_name in permanently_disabled:
                    continue
                permanently_disabled.add(pool_name)
                active_pools.discard(pool_name)
                cooldown_until.pop(pool_name, None)
                quota_window_until.pop(pool_name, None)
                blocked = list(pending_by_pool.get(pool_name, []))
                pending_by_pool[pool_name] = []
                for task in blocked:
                    reroute_or_fail_task(
                        task=task,
                        from_pool_name=pool_name,
                        pool_map=pool_map,
                        active_pools=active_pools,
                        provider_rr=provider_rr,
                        share_across_providers=args.share_across_providers,
                        pending_by_pool=pending_by_pool,
                        failed=failed,
                        reason=f"pool manually disabled: {pool_name}",
                    )
                print(f"[multi] pool manually disabled (no probe): {pool_name}")

        now = time.time()
        for pool_name, ready_at in list(cooldown_until.items()):
            if pool_name in permanently_disabled:
                del cooldown_until[pool_name]
                continue
            if now >= ready_at:
                active_pools.add(pool_name)
                del cooldown_until[pool_name]
                print(f"[multi] reactivated pool after cooldown: {pool_name}")

        runnable = {
            pool_name: task_list
            for pool_name, task_list in pending_by_pool.items()
            if task_list and pool_name in active_pools
        }
        if not runnable:
            pending_total = sum(len(v) for v in pending_by_pool.values())
            if pending_total == 0:
                break

            cooling = [
                pool_name
                for pool_name, task_list in pending_by_pool.items()
                if task_list and pool_name in cooldown_until
            ]
            if cooling:
                next_ready = min(cooldown_until[name] for name in cooling)
                wait_for = max(0.0, next_ready - now)
                wait_for = min(wait_for if wait_for > 0 else args.idle_wait_seconds, max(args.idle_wait_seconds, 0.1))
                print(f"[multi] waiting {round(wait_for, 1)}s for quota cooldown reactivation")
                time.sleep(wait_for)
                continue

            # Pending tasks exist but no pool can execute them.
            for pool_name, task_list in pending_by_pool.items():
                if not task_list:
                    continue
                for task in task_list:
                    task.last_error = "no active pool available for pending task"
                    failed.append(task)
                pending_by_pool[pool_name] = []
            break
        round_index += 1
        print(f"[multi] round={round_index} runnable_pools={len(runnable)}")

        round_results: list[PoolRunResult] = []
        with ThreadPoolExecutor(max_workers=len(runnable)) as executor:
            future_map = {
                executor.submit(
                    run_pool_round,
                    pool=pool_map[pool_name],
                    tasks=task_list,
                    ocw_path=ocw_path,
                    run_root=run_root,
                    canonical_dir=canonical_dir,
                    prompt_timeout_seconds=args.prompt_timeout_seconds,
                    tool_trajectory_dir=tool_trajectory_dir,
                    max_attempts=args.max_attempts,
                    respect_permissions=args.respect_opencode_permissions,
                    repair_missing_file=args.repair_missing_file,
                    set_method_attr=args.set_method,
                    dry_run=args.dry_run,
                ): pool_name
                for pool_name, task_list in runnable.items()
            }
            for future in as_completed(future_map):
                pool_name = future_map[future]
                try:
                    res = future.result()
                except Exception as exc:
                    tb = traceback.format_exc()
                    print(
                        f"[multi] pool={pool_name} runner exception type={type(exc).__name__} "
                        f"message={exc!s}"
                    )
                    print(tb, end="" if tb.endswith("\n") else "\n")
                    # Return all tasks from this pool to retry queue on unexpected errors.
                    res = PoolRunResult(pool_name=pool_name)
                    for task in runnable[pool_name]:
                        task.attempts += 1
                        task.last_error = f"runner exception ({type(exc).__name__}): {exc}"
                        res.retry_same_pool.append(task)
                    res.stats = {"input": len(runnable[pool_name]), "runner_exceptions": len(runnable[pool_name])}
                round_results.append(res)

        # Clear current runnable queues; we'll refill from results.
        for pool_name in runnable:
            pending_by_pool[pool_name] = []

        for res in round_results:
            pool = pool_map[res.pool_name]
            if res.disabled_for_quota:
                active_pools.discard(res.pool_name)
                if res.pool_name in permanently_disabled:
                    print(f"[multi] pool quota-disabled permanently (manual kill): {res.pool_name}")
                else:
                    probe_after = max(args.idle_wait_seconds, 0.1)
                    ready_at = time.time() + probe_after
                    cooldown_until[res.pool_name] = ready_at
                    if args.quota_cooldown_seconds > 0:
                        quota_window_until[res.pool_name] = time.time() + args.quota_cooldown_seconds
                    print(
                        f"[multi] disabling pool due to quota: {res.pool_name} "
                        f"(next probe in {int(probe_after)}s)"
                    )
            completed.extend(res.succeeded)
            for task in res.succeeded:
                key = task_cve_commit_key(task)
                if key is not None:
                    existing_keys.add(key)

            for task in res.retry_same_pool:
                if task.attempts < args.max_attempts and res.pool_name in active_pools:
                    backoff = args.base_backoff_seconds * (2 ** max(task.attempts - 1, 0))
                    backoff += random.uniform(0.0, max(args.jitter_seconds, 0.0))
                    # Store delay hint in error field; queue immediately, scheduler round provides spacing.
                    task.last_error = f"{task.last_error} backoff={round(backoff, 2)}s"
                    pending_by_pool[res.pool_name].append(task)
                else:
                    failed.append(task)

            for task in res.requeue_same_provider:
                if task.attempts >= args.max_attempts:
                    failed.append(task)
                    continue
                next_pool = choose_pool_for_provider(
                    pool.provider,
                    pool_map,
                    active_pools,
                    provider_rr,
                    args.share_across_providers,
                )
                if next_pool is None:
                    if res.pool_name in cooldown_until and res.pool_name not in permanently_disabled:
                        pending_by_pool[res.pool_name].append(task)
                    else:
                        failed.append(task)
                    continue
                pending_by_pool[next_pool].append(task)

            failed.extend(res.failed)

            print(f"[multi] pool={res.pool_name} stats={json.dumps(res.stats, ensure_ascii=True)}")

    if not args.export_trajectories:
        trajectory_export: dict[str, Any] = {"attempted": False, "reason": "disabled"}
    elif args.dry_run:
        trajectory_export = {"attempted": False, "reason": "dry_run"}
    else:
        trajectory_export = {
            "attempted": False,
            "reason": "incremental_per_completion_only",
            "out_dir": str(tool_trajectory_dir),
        }

    summary = {
        "run_root": str(run_root),
        "canonical_dir": str(canonical_dir),
        "tool_trajectory_dir": str(tool_trajectory_dir),
        "skip_dirs": [str(path) for path in skip_dirs],
        "existing_keys_merged": len(existing_keys),
        "max_attempts": args.max_attempts,
        "prompt_timeout_seconds": args.prompt_timeout_seconds,
        "quota_cooldown_seconds": args.quota_cooldown_seconds,
        "startup_skipped_existing": len(startup_skipped_existing),
        "completed": len(completed),
        "failed": len(failed),
        "active_pools_remaining": sorted(active_pools),
        "permanently_disabled_pools": sorted(permanently_disabled),
        "cooldown_until": {k: v for k, v in cooldown_until.items()},
        "quota_window_until": {k: v for k, v in quota_window_until.items()},
        "trajectory_export": trajectory_export,
        "startup_trajectory_backfill": startup_trajectory_backfill,
        "failed_samples": [
            {
                "cve": task.cve,
                "attempts": task.attempts,
                "last_error": task.last_error,
            }
            for task in failed[:50]
        ],
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    trajectory_failed = False
    return 0 if (not failed and not trajectory_failed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
