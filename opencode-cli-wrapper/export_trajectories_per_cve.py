#!/usr/bin/env python3
"""Export tool trajectories as one JSONL file per CVE.

This utility uses ocw's deterministic trajectory extractor and then splits
records by CVE parsed from each trajectory record's prompt text.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build per-CVE trajectory JSONL files from ocw batch outputs.")
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
        help="Output directory for combined intermediates and by_cve files",
    )
    p.add_argument(
        "--keep-merged",
        action="store_true",
        help="Keep merged trajectory JSONL in output directory (default keeps only per-CVE + manifest + intermediates).",
    )
    p.add_argument(
        "--workspace-dir",
        help="Optional workspace directory containing per-prompt JSON outputs; defaults to <out-dir>/../workspace when present.",
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


def build_session_to_cve(records: list[dict]) -> dict[str, str]:
    session_to_cve: dict[str, str] = {}
    for record in records:
        prompt = record.get("prompt", "")
        cve = cve_from_prompt(prompt if isinstance(prompt, str) else "")
        if not cve:
            continue
        stdout = record.get("stdout", "")
        if not isinstance(stdout, str) or not stdout:
            continue
        for session_id in extract_session_ids_from_stdout(stdout):
            session_to_cve[session_id] = cve
    return session_to_cve


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


def write_canonical_records(records: list[dict], out_dir: Path, workspace_dir: Path | None = None) -> dict[str, Any]:
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
    }


def split_by_cve(trajectory_path: Path, out_dir: Path, session_to_cve: dict[str, str]) -> dict[str, int]:
    by_cve_dir = out_dir / "by_cve"
    by_cve_dir.mkdir(parents=True, exist_ok=True)

    buckets: dict[str, list[str]] = defaultdict(list)
    unknown: list[str] = []

    with trajectory_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            record = json.loads(raw)
            session_id = record.get("session_id", "")
            cve = session_to_cve.get(session_id) if isinstance(session_id, str) else None
            if cve is None:
                unknown.append(raw)
                continue
            buckets[cve].append(raw)

    counts: dict[str, int] = {}
    for cve, rows in sorted(buckets.items()):
        out_file = by_cve_dir / f"{cve}.jsonl"
        with out_file.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(row + "\n")
        counts[cve] = len(rows)

    if unknown:
        unknown_file = by_cve_dir / "UNKNOWN.jsonl"
        with unknown_file.open("w", encoding="utf-8") as handle:
            for row in unknown:
                handle.write(row + "\n")
        counts["UNKNOWN"] = len(unknown)

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

    records = load_result_records(results)

    combined_results = out_dir / "combined_batch_results.jsonl"
    raw_events = out_dir / "raw_events_merged.jsonl"
    merged_trajectories = out_dir / "tool_trajectories_merged.jsonl"
    manifest_path = out_dir / "by_cve_manifest.json"

    write_combined_results(records, combined_results)
    write_raw_events_from_results(records, raw_events)
    run_ocw_trajectory(ocw, raw_events, merged_trajectories)

    session_to_cve = build_session_to_cve(records)
    counts = split_by_cve(merged_trajectories, out_dir, session_to_cve)
    canonical_stats = write_canonical_records(records, out_dir, workspace_dir=workspace_dir)

    manifest = {
        "input_results_files": [str(p) for p in results],
        "combined_records": len(records),
        "total_cve_files": len([k for k in counts if k != "UNKNOWN"]),
        "unknown_records": counts.get("UNKNOWN", 0),
        "by_cve_counts": counts,
        "by_cve_dir": str(out_dir / "by_cve"),
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
