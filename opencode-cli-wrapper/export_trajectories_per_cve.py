#!/usr/bin/env python3
"""Export tool trajectories as one JSONL file per (CVE, commit_hash)."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
COMMIT_HASH_RE = re.compile(r"\b[0-9a-f]{7,64}\b", re.IGNORECASE)
COMMIT_HASH_FIELD_RE = re.compile(r"(?im)^\s*-\s*commit_hash\s*:\s*([0-9a-f]{7,64})\s*$")
COMMIT_URL_RE = re.compile(r"/commit/([0-9a-f]{7,64})", re.IGNORECASE)
DEFAULT_CANONICAL_JSON_DIR = Path("/home/user1/dataset_pipeline/cves")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build per-(CVE, commit) trajectory JSONL files from ocw batch outputs.")
    p.add_argument(
        "--ocw",
        default="/Users/kushalkhemka/Desktop/untitled folder 3/opencode-cli-wrapper/ocw",
        help="Path to ocw executable",
    )
    p.add_argument(
        "--results",
        nargs="+",
        required=True,
        help="One or more ocw batch results JSONL files to combine",
    )
    p.add_argument(
        "--out-dir",
        required=True,
        help="Output directory for intermediates, manifests, and trajectory JSONL files",
    )
    p.add_argument(
        "--keep-merged",
        action="store_true",
        help="Keep merged trajectory JSONL in output directory",
    )
    p.add_argument(
        "--workspace-dir",
        help="Optional workspace directory containing per-prompt JSON outputs; defaults to <out-dir>/../workspace when present.",
    )
    p.add_argument(
        "--canonical-json-dir",
        default=str(DEFAULT_CANONICAL_JSON_DIR),
        help="Directory containing canonical JSON files (used as fallback when stdout lacks final JSON).",
    )
    return p.parse_args()


def load_result_records(paths: list[Path]) -> list[dict]:
    records: list[dict] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                records.append(json.loads(raw))
    return records


def write_combined_results(records: list[dict], out_path: Path) -> None:
    with out_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")


def write_raw_events_from_results(records: list[dict], out_path: Path) -> None:
    with out_path.open("w", encoding="utf-8") as handle:
        for record in records:
            stdout = record.get("stdout", "")
            if not isinstance(stdout, str) or not stdout:
                continue
            for line in stdout.splitlines():
                event = line.strip()
                if event.startswith("{") and event.endswith("}"):
                    handle.write(event + "\n")


def load_jsonl_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.is_file():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            payload = json.loads(raw)
            if isinstance(payload, dict):
                records.append(payload)
    return records


def run_ocw_trajectory(ocw_path: Path, raw_events: Path, output_path: Path) -> None:
    cmd = [
        str(ocw_path),
        "trajectory",
        "-i",
        str(raw_events),
        "-o",
        str(output_path),
        "--raw-ids",
    ]
    subprocess.run(cmd, check=True)


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


def record_key(cve: str, commit_hash: str | None) -> tuple[str, str]:
    commit = normalize_commit_hash(commit_hash or "") or "unknowncommit"
    return (cve.upper(), commit)


def trajectory_output_path(out_dir: Path, cve: str, commit_hash: str | None) -> Path:
    cve_text, commit_text = record_key(cve, commit_hash)
    return out_dir / f"{cve_text.lower()}_{commit_text}_trajectory.jsonl"


def cve_from_prompt(prompt: str) -> str | None:
    if not prompt:
        return None
    m = CVE_RE.search(prompt)
    if not m:
        return None
    return m.group(0).upper()


def cve_from_text(text: str) -> str | None:
    if not text:
        return None
    m = CVE_RE.search(text)
    if not m:
        return None
    return m.group(0).upper()


def final_text_event(stdout: str) -> str | None:
    result: str | None = None
    for line in stdout.splitlines():
        raw = line.strip()
        if not raw.startswith("{"):
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") != "text":
            continue
        part = event.get("part")
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if isinstance(text, str) and text.strip():
            result = text
    return result


def extract_session_ids_from_stdout(stdout: str) -> set[str]:
    session_ids: set[str] = set()
    for line in stdout.splitlines():
        raw = line.strip()
        if not raw or not raw.startswith("{"):
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        sid = event.get("sessionID")
        if isinstance(sid, str) and sid:
            session_ids.add(sid)
            continue
        part = event.get("part")
        if isinstance(part, dict):
            sid = part.get("sessionID")
            if isinstance(sid, str) and sid:
                session_ids.add(sid)
    return session_ids


def build_session_to_key(records: list[dict]) -> dict[str, tuple[str, str]]:
    session_to_key: dict[str, tuple[str, str]] = {}
    for record in records:
        prompt = record.get("prompt", "")
        cve = cve_from_prompt(prompt if isinstance(prompt, str) else "")
        if not cve:
            continue
        commit_hash = extract_commit_hash(prompt if isinstance(prompt, str) else "")
        stdout = record.get("stdout", "")
        if not isinstance(stdout, str) or not stdout:
            continue
        for session_id in extract_session_ids_from_stdout(stdout):
            session_to_key[session_id] = record_key(cve, commit_hash)
    return session_to_key


def merge_trajectory_records(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in [*existing, *incoming]:
        key = json.dumps(record, ensure_ascii=True, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        merged.append(record)
    return merged


def merge_trajectory_file(target_path: Path, incoming: list[dict[str, Any]]) -> int:
    existing: list[dict[str, Any]] = []
    if target_path.is_file():
        try:
            existing = load_jsonl_records(target_path)
        except json.JSONDecodeError:
            existing = []
    merged = merge_trajectory_records(existing, incoming)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8") as handle:
        for record in merged:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return len(merged)


def split_records_by_key(
    trajectory_records: list[dict[str, Any]],
    session_to_key: dict[str, tuple[str, str]],
) -> tuple[dict[tuple[str, str], list[dict[str, Any]]], list[dict[str, Any]]]:
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    unknown: list[dict[str, Any]] = []
    for record in trajectory_records:
        session_id = record.get("session_id", "")
        key = session_to_key.get(session_id) if isinstance(session_id, str) else None
        if key is None:
            unknown.append(record)
            continue
        buckets[key].append(record)
    return buckets, unknown


def export_records_to_flat_cve_files(
    *,
    records: list[dict[str, Any]],
    ocw_path: Path,
    out_dir: Path,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if not records:
        return {
            "attempted": False,
            "reason": "no_records",
            "keys_written": 0,
            "trajectory_records": 0,
        }

    with tempfile.TemporaryDirectory(prefix="traj_export_", dir=str(out_dir)) as tmp_dir:
        tmp_path = Path(tmp_dir)
        raw_events = tmp_path / "raw_events.jsonl"
        merged_trajectories = tmp_path / "tool_trajectories.jsonl"
        write_raw_events_from_results(records, raw_events)
        if raw_events.stat().st_size == 0:
            return {
                "attempted": False,
                "reason": "no_raw_events",
                "keys_written": 0,
                "trajectory_records": 0,
            }
        run_ocw_trajectory(ocw_path, raw_events, merged_trajectories)
        trajectory_records = load_jsonl_records(merged_trajectories)

    session_to_key = build_session_to_key(records)
    buckets, unknown = split_records_by_key(trajectory_records, session_to_key)
    counts: dict[str, int] = {}
    for (cve, commit_hash), key_records in sorted(buckets.items()):
        out_path = trajectory_output_path(out_dir, cve, commit_hash)
        counts[out_path.name] = merge_trajectory_file(out_path, key_records)

    return {
        "attempted": True,
        "reason": "ok",
        "keys_written": len(counts),
        "trajectory_records": len(trajectory_records),
        "unknown_records": len(unknown),
        "counts": counts,
    }


def recover_workspace_payloads(workspace_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, int], dict[str, str]]:
    stats = {
        "files_seen": 0,
        "parse_errors": 0,
        "non_object_payload": 0,
        "missing_cve": 0,
        "candidates": 0,
        "duplicate_candidates": 0,
        "selected": 0,
    }
    chosen: dict[str, tuple[int, str, dict[str, Any]]] = {}

    for path in sorted(workspace_dir.glob("*.json")):
        stats["files_seen"] += 1
        name = path.name
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            stats["parse_errors"] += 1
            continue
        if not isinstance(payload, dict):
            stats["non_object_payload"] += 1
            continue

        cve = None
        cve_id = payload.get("cve_id")
        if isinstance(cve_id, str):
            cve = cve_from_text(cve_id)
        if cve is None:
            cve = cve_from_text(name)
        if cve is None:
            cve = cve_from_text(json.dumps(payload, ensure_ascii=True))
        if cve is None:
            stats["missing_cve"] += 1
            continue

        stats["candidates"] += 1
        if name == f"{cve}.json":
            priority = 0
        elif name == f"{cve}_output.json":
            priority = 1
        elif name.startswith(f"{cve}__"):
            priority = 2
        elif name.startswith(cve):
            priority = 3
        else:
            priority = 4

        prev = chosen.get(cve)
        candidate = (priority, name, payload)
        if prev is None:
            chosen[cve] = candidate
            continue
        stats["duplicate_candidates"] += 1
        if candidate < prev:
            chosen[cve] = candidate

    payloads = {cve: payload for cve, (_, _, payload) in chosen.items()}
    source_files = {cve: name for cve, (_, name, _) in chosen.items()}
    stats["selected"] = len(payloads)
    return payloads, stats, source_files


def recover_canonical_dir_payloads(
    canonical_json_dir: Path,
    prompt_cves: set[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, int], dict[str, str]]:
    stats = {
        "files_expected": len(prompt_cves),
        "files_found": 0,
        "missing_files": 0,
        "parse_errors": 0,
        "non_object_payload": 0,
        "selected": 0,
    }
    payloads: dict[str, dict[str, Any]] = {}
    source_files: dict[str, str] = {}
    for cve in sorted(prompt_cves):
        candidates = [canonical_json_dir / f"{cve}.json", *sorted(canonical_json_dir.glob(f"{cve}__*.json"))]
        path = next((candidate for candidate in candidates if candidate.is_file()), None)
        if path is None:
            stats["missing_files"] += 1
            continue
        stats["files_found"] += 1
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            stats["parse_errors"] += 1
            continue
        if not isinstance(payload, dict):
            stats["non_object_payload"] += 1
            continue
        payloads[cve] = payload
        source_files[cve] = path.name
    stats["selected"] = len(payloads)
    return payloads, stats, source_files


def write_canonical_records(
    records: list[dict],
    out_dir: Path,
    workspace_dir: Path | None = None,
    canonical_json_dir: Path | None = None,
) -> dict[str, Any]:
    canonical_dir = out_dir / "canonical_records"
    canonical_dir.mkdir(parents=True, exist_ok=True)

    chosen: dict[str, dict[str, Any]] = {}
    chosen_source: dict[str, str] = {}
    prompt_cves: set[str] = set()
    duplicate_candidates_stdout = 0
    missing_cve_stdout = 0
    missing_text_stdout = 0
    invalid_json_stdout = 0

    for record in records:
        prompt = record.get("prompt", "")
        cve = cve_from_prompt(prompt if isinstance(prompt, str) else "")
        if not cve:
            missing_cve_stdout += 1
            continue
        prompt_cves.add(cve)

        stdout = record.get("stdout", "")
        if not isinstance(stdout, str) or not stdout:
            missing_text_stdout += 1
            continue

        text = final_text_event(stdout)
        if text is None:
            missing_text_stdout += 1
            continue

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            invalid_json_stdout += 1
            continue

        if cve in chosen:
            duplicate_candidates_stdout += 1
        chosen[cve] = payload
        chosen_source[cve] = "stdout"

    workspace_payloads: dict[str, dict[str, Any]] = {}
    workspace_source_files: dict[str, str] = {}
    workspace_stats: dict[str, int] = {
        "files_seen": 0,
        "parse_errors": 0,
        "non_object_payload": 0,
        "missing_cve": 0,
        "candidates": 0,
        "duplicate_candidates": 0,
        "selected": 0,
    }
    if workspace_dir is not None and workspace_dir.is_dir():
        workspace_payloads, workspace_stats, workspace_source_files = recover_workspace_payloads(workspace_dir)

    canonical_payloads: dict[str, dict[str, Any]] = {}
    canonical_source_files: dict[str, str] = {}
    canonical_stats: dict[str, int] = {
        "files_expected": 0,
        "files_found": 0,
        "missing_files": 0,
        "parse_errors": 0,
        "non_object_payload": 0,
        "selected": 0,
    }
    if canonical_json_dir is not None and canonical_json_dir.is_dir():
        canonical_payloads, canonical_stats, canonical_source_files = recover_canonical_dir_payloads(
            canonical_json_dir,
            prompt_cves,
        )

    canonical_recovered = 0
    canonical_missing_for_prompt_cves = 0
    for cve in sorted(prompt_cves):
        if cve in chosen:
            continue
        payload = canonical_payloads.get(cve)
        if payload is None:
            canonical_missing_for_prompt_cves += 1
            continue
        chosen[cve] = payload
        source_file = canonical_source_files.get(cve, "")
        chosen_source[cve] = f"canonical_json_dir:{source_file}" if source_file else "canonical_json_dir"
        canonical_recovered += 1

    workspace_recovered = 0
    workspace_missing_for_prompt_cves = 0
    for cve in sorted(prompt_cves):
        if cve in chosen:
            continue
        payload = workspace_payloads.get(cve)
        if payload is None:
            workspace_missing_for_prompt_cves += 1
            continue
        chosen[cve] = payload
        source_file = workspace_source_files.get(cve, "")
        chosen_source[cve] = f"workspace:{source_file}" if source_file else "workspace"
        workspace_recovered += 1

    for cve, payload in sorted(chosen.items()):
        out_file = canonical_dir / f"{cve}.json"
        out_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

    return {
        "written": len(chosen),
        "sources": {
            "stdout": len([cve for cve, source in chosen_source.items() if source == "stdout"]),
            "canonical_json_dir": len(
                [cve for cve, source in chosen_source.items() if source.startswith("canonical_json_dir")]
            ),
            "workspace": len([cve for cve, source in chosen_source.items() if source.startswith("workspace")]),
        },
        "stdout": {
            "duplicate_candidates": duplicate_candidates_stdout,
            "missing_cve": missing_cve_stdout,
            "missing_text": missing_text_stdout,
            "invalid_json": invalid_json_stdout,
            "prompt_cves_seen": len(prompt_cves),
        },
        "workspace": {
            "dir": str(workspace_dir) if workspace_dir is not None else None,
            "recovered_for_prompt_cves": workspace_recovered,
            "missing_for_prompt_cves": workspace_missing_for_prompt_cves,
            "scan": workspace_stats,
        },
        "canonical_json_dir": {
            "dir": str(canonical_json_dir) if canonical_json_dir is not None else None,
            "recovered_for_prompt_cves": canonical_recovered,
            "missing_for_prompt_cves": canonical_missing_for_prompt_cves,
            "scan": canonical_stats,
        },
    }


def split_by_key(trajectory_path: Path, out_dir: Path, session_to_key: dict[str, tuple[str, str]]) -> dict[str, int]:
    buckets, unknown = split_records_by_key(load_jsonl_records(trajectory_path), session_to_key)

    counts: dict[str, int] = {}
    for (cve, commit_hash), records in sorted(buckets.items()):
        out_file = trajectory_output_path(out_dir, cve, commit_hash)
        counts[out_file.name] = merge_trajectory_file(out_file, records)

    if unknown:
        unknown_file = out_dir / "unknown_trajectory.jsonl"
        merge_trajectory_file(unknown_file, unknown)
        counts[unknown_file.name] = len(unknown)

    return counts


def main() -> int:
    args = parse_args()
    ocw = Path(args.ocw).expanduser()
    results = [Path(p).expanduser() for p in args.results]
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir: Path | None = None
    if args.workspace_dir:
        workspace_dir = Path(args.workspace_dir).expanduser()
    else:
        inferred_workspace = out_dir.parent / "workspace"
        if inferred_workspace.is_dir():
            workspace_dir = inferred_workspace
    canonical_json_dir: Path | None = None
    if args.canonical_json_dir:
        canonical_json_dir = Path(args.canonical_json_dir).expanduser()

    records = load_result_records(results)

    combined_results = out_dir / "combined_batch_results.jsonl"
    raw_events = out_dir / "raw_events_merged.jsonl"
    merged_trajectories = out_dir / "tool_trajectories_merged.jsonl"
    manifest_path = out_dir / "trajectory_manifest.json"

    write_combined_results(records, combined_results)
    write_raw_events_from_results(records, raw_events)
    run_ocw_trajectory(ocw, raw_events, merged_trajectories)

    session_to_key = build_session_to_key(records)
    counts = split_by_key(merged_trajectories, out_dir, session_to_key)
    canonical_stats = write_canonical_records(
        records,
        out_dir,
        workspace_dir=workspace_dir,
        canonical_json_dir=canonical_json_dir,
    )

    manifest = {
        "input_results_files": [str(p) for p in results],
        "combined_records": len(records),
        "total_trajectory_files": len([k for k in counts if k != "unknown_trajectory.jsonl"]),
        "unknown_records": counts.get("unknown_trajectory.jsonl", 0),
        "trajectory_counts": counts,
        "trajectory_dir": str(out_dir),
        "intermediates": {
            "combined_batch_results": str(combined_results),
            "raw_events_merged": str(raw_events),
            "tool_trajectories_merged": str(merged_trajectories),
        },
        "canonical_records": {
            "dir": str(out_dir / "canonical_records"),
            "stats": canonical_stats,
        },
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, indent=2), encoding="utf-8")

    if not args.keep_merged:
        merged_trajectories.unlink(missing_ok=True)

    print(json.dumps(manifest, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
