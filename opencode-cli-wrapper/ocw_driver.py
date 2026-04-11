#!/usr/bin/env python3
"""Interactive pipeline driver for CSV -> ocw batch -> per-(CVE, commit) trajectories."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CSV = (
    SCRIPT_DIR.parent / "csv" / "cvelistV5_exhaustive_commit_hashes_working_repos_only_deduped.csv"
).resolve()
DEFAULT_PROMPT_DIR = (SCRIPT_DIR.parent / "Prompts").resolve()
DEFAULT_OCW = (SCRIPT_DIR / "ocw").resolve()
DEFAULT_EXPORTER = (SCRIPT_DIR / "export_trajectories_per_cve.py").resolve()
DEFAULT_CANONICAL_JSON_DIR = (SCRIPT_DIR.parent / "cves").resolve()
DEFAULT_TOOL_TRAJECTORY_DIR = Path("/home/user1/dataset_pipeline/tool_trajectory").resolve()
DEFAULT_SKIP_CVES_DIRS = [
    Path("/home/user1/dataset_pipeline/filtered_results").resolve(),
    Path("/home/user1/dataset_pipeline/cves").resolve(),
]
DEFAULT_SKIP_CVES_DIRS_TEXT = ",".join(str(path) for path in DEFAULT_SKIP_CVES_DIRS)
DEFAULT_PROMPT_TIMEOUT_SECONDS = 2400.0
DEFAULT_FALLBACK_MODEL = ""

LANGUAGE_RULES: list[tuple[str, list[str]]] = [
    ("Python", [r"cpython", r"\bpython\b", r"django", r"flask", r"ansible", r"pypa", r"jupyter", r"saltstack"]),
    ("JavaScript", [r"node", r"javascript", r"\breact\b", r"vue", r"angular", r"next\.js", r"express", r"webpack", r"nuxt"]),
    ("TypeScript", [r"typescript", r"\bdeno\b"]),
    ("PHP", [r"wordpress", r"wp-", r"joomla", r"drupal", r"\bphp\b", r"laravel", r"symfony", r"magento"]),
    ("Go", [r"\bgolang\b", r"kubernetes", r"containerd", r"prometheus", r"helm", r"docker", r"moby", r"etcd", r"caddy", r"traefik"]),
    ("Rust", [r"\brust\b", r"cargo", r"tokio", r"serde", r"actix", r"rust-lang"]),
    ("Java", [r"\bjava\b", r"spring", r"hibernate", r"kafka", r"junit", r"openjdk", r"jenkins"]),
    ("Ruby", [r"\bruby\b", r"rails", r"rubygems", r"sidekiq", r"jekyll"]),
    ("C#", [r"csharp", r"\.net", r"dotnet", r"aspnet", r"nuget", r"roslyn", r"mono"]),
    ("Kotlin", [r"kotlin", r"ktor"]),
    ("Swift", [r"\bswift\b", r"swiftlang"]),
    ("C++", [r"\bc\+\+\b", r"\bqt\b", r"tensorflow"]),
    ("C", [r"openssl", r"ffmpeg", r"glibc", r"wireshark", r"imagemagick", r"mutt", r"krb5"]),
]
LANGUAGE_PATTERNS: list[tuple[str, list[re.Pattern[str]]]] = [
    (lang, [re.compile(pattern) for pattern in patterns]) for lang, patterns in LANGUAGE_RULES
]
CVES_IN_TEXT_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
COMMIT_HASH_RE = re.compile(r"^[0-9a-f]{7,64}$", re.IGNORECASE)

SOURCE_EXT_LANGUAGE: dict[str, str] = {
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".hh": "C++",
    ".hxx": "C++",
    ".cs": "C#",
    ".java": "Java",
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".php": "PHP",
    ".phtml": "PHP",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".swift": "Swift",
}

LANGUAGE_ALIASES: dict[str, str] = {
    "python": "Python",
    "py": "Python",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "typescript": "TypeScript",
    "ts": "TypeScript",
    "php": "PHP",
    "go": "Go",
    "golang": "Go",
    "rust": "Rust",
    "java": "Java",
    "ruby": "Ruby",
    "csharp": "C#",
    "kotlin": "Kotlin",
    "swift": "Swift",
    "cpp": "C++",
    "c": "C",
}

PROMPT_KEY_FALLBACKS: dict[str, list[str]] = {
    "javascript": ["javascript", "js"],
    "typescript": ["typescript", "ts", "javascript", "js"],
    "csharp": ["csharp", "csharpnet", "cs", "c#"],
    "cpp": ["cpp", "c++", "cplusplus"],
}


def normalize_language_name(value: str) -> str:
    normalized = (value or "").strip().lower()
    normalized = normalized.replace("c#", "csharp")
    normalized = normalized.replace("c++", "cpp")
    return re.sub(r"[^a-z0-9]+", "", normalized)


def canonical_language(value: str) -> str:
    key = normalize_language_name(value)
    if key in {"", "unknown", "na", "none", "null"}:
        return "Unknown"
    return LANGUAGE_ALIASES.get(key, value.strip() or "Unknown")


def is_linux_example(repo_name: str) -> bool:
    repo = (repo_name or "").lower()
    return "linux" in repo and ("kernel" in repo or "/linux" in repo or repo.startswith("linux/"))


def infer_language(repo_name: str) -> str:
    text = (repo_name or "").lower()
    for language, patterns in LANGUAGE_PATTERNS:
        for pattern in patterns:
            if pattern.search(text):
                return language
    return "Unknown"


def infer_language_from_source_file(source_file: str) -> str:
    text = (source_file or "").strip()
    if not text:
        return "Unknown"

    for raw_part in text.split(";"):
        part = raw_part.strip().lower()
        if not part:
            continue
        for ext, language in SOURCE_EXT_LANGUAGE.items():
            if part.endswith(ext):
                return language
    return "Unknown"


def discover_prompt_templates(prompt_dir: Path) -> dict[str, Path]:
    if not prompt_dir.exists() or not prompt_dir.is_dir():
        raise SystemExit(f"error: prompt directory not found: {prompt_dir}")

    mapping: dict[str, Path] = {}
    for entry in sorted(prompt_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in {".txt", ".md", ".prompt"}:
            continue
        key = normalize_language_name(entry.stem)
        if not key:
            continue
        if key in mapping:
            raise SystemExit(
                f"error: duplicate prompt template key '{key}' for {mapping[key]} and {entry}"
            )
        mapping[key] = entry

    if not mapping:
        raise SystemExit(f"error: no prompt templates found in {prompt_dir}")
    return mapping


def resolve_template_path(language: str, templates: dict[str, Path]) -> Path | None:
    key = normalize_language_name(language)
    candidates = [key, *PROMPT_KEY_FALLBACKS.get(key, [])]
    for candidate in candidates:
        resolved = templates.get(normalize_language_name(candidate))
        if resolved is not None:
            return resolved
    return None


def parse_csv_rows(csv_path: Path, exclude_linux: bool) -> list[dict[str, str]]:
    if not csv_path.exists():
        raise SystemExit(f"error: CSV file not found: {csv_path}")

    rows: list[dict[str, str]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise SystemExit("error: CSV file is missing a header row")

        for row_index, row in enumerate(reader, start=1):
            record = {k: (v or "").strip() for k, v in row.items()}
            repo_name = record.get("repo_name", "")
            if exclude_linux and is_linux_example(repo_name):
                continue

            csv_language = canonical_language(record.get("language", ""))
            source_language = infer_language_from_source_file(record.get("source_file", ""))
            inferred_language = infer_language(repo_name)
            if csv_language != "Unknown":
                resolved_language = csv_language
                language_source = "csv"
            elif source_language != "Unknown":
                resolved_language = source_language
                language_source = "source_file"
            elif inferred_language != "Unknown":
                resolved_language = inferred_language
                language_source = "repo_inferred"
            else:
                resolved_language = "Unknown"
                language_source = "unknown"

            record["_row_index"] = str(row_index)
            record["_language"] = resolved_language
            record["_language_source"] = language_source
            rows.append(record)
    return rows


def normalize_commit_hash(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    if COMMIT_HASH_RE.fullmatch(text):
        return text
    match = re.search(r"/commit/([0-9a-f]{7,64})", text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return ""


def cve_commit_key(cve_value: str, commit_value: str) -> tuple[str, str] | None:
    cve = cve_from_text(cve_value or "")
    commit = normalize_commit_hash(commit_value or "")
    if not cve or not commit:
        return None
    return (cve, commit)


def row_cve_commit_key(row: dict[str, str]) -> tuple[str, str] | None:
    return cve_commit_key(str(row.get("cve_id", "")), str(row.get("commit_hash", "")))


def entry_cve_commit_key(entry: dict[str, Any]) -> tuple[str, str] | None:
    return cve_commit_key(str(entry.get("cve_id", "")), str(entry.get("commit_hash", "")))


def collect_cve_commit_keys_from_directory(path: Path) -> set[tuple[str, str]]:
    if not path.exists() or not path.is_dir():
        return set()
    keys: set[tuple[str, str]] = set()
    for file_path in path.rglob("*.json"):
        if not file_path.is_file():
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


def filter_rows_by_cve_commit_keys(
    rows: list[dict[str, str]], excluded_keys: set[tuple[str, str]]
) -> tuple[list[dict[str, str]], int]:
    if not excluded_keys:
        return rows, 0
    kept: list[dict[str, str]] = []
    skipped = 0
    for row in rows:
        key = row_cve_commit_key(row)
        if key is not None and key in excluded_keys:
            skipped += 1
            continue
        kept.append(row)
    return kept, skipped


def parse_skip_directories(raw: str) -> list[Path]:
    values = [part.strip() for part in (raw or "").split(",") if part.strip()]
    seen: set[Path] = set()
    resolved: list[Path] = []
    for value in values:
        path = Path(value).expanduser().resolve()
        if path in seen:
            continue
        seen.add(path)
        resolved.append(path)
    return resolved


def count_cwes(rows: list[dict[str, str]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for row in rows:
        cwe_ids = (row.get("cwe_ids") or "").strip()
        if not cwe_ids:
            counter["UNKNOWN/EMPTY"] += 1
            continue
        for token in cwe_ids.split(";"):
            value = token.strip()
            if value:
                counter[value] += 1
    return counter


def read_template_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def render_prompt(template: str, row: dict[str, str]) -> str:
    render_data: dict[str, Any] = dict(row)
    render_data["language"] = row.get("_language", "")
    text = template

    replacements: dict[str, str] = {}
    for key, value in render_data.items():
        value_text = str(value)
        replacements[f"{{{key}}}"] = value_text
        replacements[f"{{{key.upper()}}}"] = value_text

    for token in sorted(replacements.keys(), key=len, reverse=True):
        text = text.replace(token, replacements[token])

    unresolved = re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", text)
    if unresolved:
        missing = unresolved[0]
        raise SystemExit(
            f"error: template references missing field '{missing}' for row {row.get('_row_index')}"
        )
    return text.strip()


def prompt_input(message: str, default: str | None = None) -> str:
    if default is None:
        value = input(message).strip()
    else:
        value = input(f"{message} [{default}]: ").strip()
    return value or (default or "")


def print_distribution(rows: list[dict[str, str]], title: str) -> None:
    language_counts = Counter(row["_language"] for row in rows)
    cwe_counts = count_cwes(rows)

    print(f"\n{title}")
    print(f"Rows: {len(rows)}")
    print("\nLanguage distribution:")
    for language, count in language_counts.most_common():
        print(f"  {language:12} {count:7}")
    print("\nTop CWE values:")
    for cwe, count in cwe_counts.most_common(20):
        print(f"  {cwe:16} {count:7}")


def parse_selected_languages(raw: str, available_languages: list[str]) -> list[str]:
    if raw.strip().lower() == "all":
        return available_languages
    chosen: list[str] = []
    normalized_available = {normalize_language_name(lang): lang for lang in available_languages}
    for token in raw.split(","):
        value = token.strip()
        if not value:
            continue
        key = normalize_language_name(value)
        if key not in normalized_available:
            raise SystemExit(f"error: unknown language selection '{value}'")
        language = normalized_available[key]
        if language not in chosen:
            chosen.append(language)
    if not chosen:
        raise SystemExit("error: at least one language must be selected")
    return chosen


def cve_from_text(text: str) -> str | None:
    if not text:
        return None
    match = CVES_IN_TEXT_RE.search(text)
    if not match:
        return None
    return match.group(0).upper()


def cve_sort_tuple(row: dict[str, Any]) -> tuple[int, int, int]:
    cve_id = str(row.get("cve_id", "")).strip().upper()
    match = CVE_ID_RE.match(cve_id)
    if not match:
        return (-1, -1, -1)
    year = int(match.group(1))
    number = int(match.group(2))
    row_index_raw = str(row.get("_row_index", "")).strip()
    row_index = int(row_index_raw) if row_index_raw.isdigit() else -1
    return (year, number, row_index)


def select_rows_per_language(
    rows: list[dict[str, str]],
    templates: dict[str, Path],
    selected_languages: list[str],
    per_language_limit: int,
) -> tuple[list[dict[str, str]], Counter[str]]:
    per_language_counts: Counter[str] = Counter()
    selected_rows: list[dict[str, str]] = []
    buckets: dict[str, list[dict[str, str]]] = {language: [] for language in selected_languages}

    for row in rows:
        language = row.get("_language", "Unknown")
        if language not in buckets:
            continue
        if resolve_template_path(language, templates) is None:
            continue
        buckets[language].append(row)

    for language in selected_languages:
        bucket = buckets.get(language, [])
        bucket.sort(key=cve_sort_tuple, reverse=True)
        if per_language_limit > 0:
            bucket = bucket[:per_language_limit]
        selected_rows.extend(bucket)
        per_language_counts[language] = len(bucket)

    return selected_rows, per_language_counts


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise SystemExit(f"error: expected JSON object lines in {path}")
            records.append(payload)
    return records


def append_jsonl(src_path: Path, dst_path: Path) -> int:
    if not src_path.exists():
        return 0
    appended = 0
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with src_path.open("r", encoding="utf-8") as src, dst_path.open("a", encoding="utf-8") as dst:
        for raw in src:
            line = raw.strip()
            if not line:
                continue
            dst.write(line + "\n")
            appended += 1
    return appended


def collect_completed_prompts(results_path: Path) -> set[str]:
    if not results_path.exists():
        return set()

    completed: set[str] = set()
    with results_path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            if int(record.get("exit_code", 1)) != 0:
                continue
            prompt = record.get("prompt", "")
            if not isinstance(prompt, str):
                continue
            normalized_prompt = prompt.strip()
            if normalized_prompt:
                completed.add(normalized_prompt)
    return completed


def load_existing_entries(manifest_jsonl: Path, prompts_jsonl: Path) -> list[dict[str, Any]]:
    manifest_rows = load_jsonl(manifest_jsonl)
    prompt_rows = load_jsonl(prompts_jsonl)
    if len(manifest_rows) != len(prompt_rows):
        raise SystemExit(
            "error: existing run has mismatched selected_manifest.jsonl and prompts.jsonl line counts"
        )

    entries: list[dict[str, Any]] = []
    for manifest, prompt_row in zip(manifest_rows, prompt_rows):
        prompt = prompt_row.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise SystemExit("error: prompts.jsonl contains empty/non-string prompt entries")
        entry = dict(manifest)
        entry["prompt"] = prompt
        entry["cve_id"] = str(entry.get("cve_id", "")).upper()
        entries.append(entry)
    return entries


def write_selected_entries(
    selected_rows: list[dict[str, str]],
    templates: dict[str, Path],
    prompts_jsonl: Path,
    manifest_jsonl: Path,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with prompts_jsonl.open("w", encoding="utf-8") as prompts_handle, manifest_jsonl.open(
        "w", encoding="utf-8"
    ) as manifest_handle:
        for sequence, row in enumerate(selected_rows):
            language = row.get("_language", "Unknown")
            template_path = resolve_template_path(language, templates)
            if template_path is None:
                continue

            template_text = read_template_text(template_path)
            prompt = render_prompt(template_text, row)
            if not prompt:
                continue

            manifest_row: dict[str, Any] = {
                "sequence": sequence,
                "row_index": row.get("_row_index", ""),
                "cve_id": (row.get("cve_id", "") or "").upper(),
                "language": language,
                "repo_name": row.get("repo_name", ""),
                "commit_hash": row.get("commit_hash", ""),
                "source_file": row.get("source_file", ""),
                "template_path": str(template_path),
            }
            prompts_handle.write(json.dumps({"prompt": prompt}, ensure_ascii=True) + "\n")
            manifest_handle.write(json.dumps(manifest_row, ensure_ascii=True) + "\n")

            manifest_row_with_prompt = dict(manifest_row)
            manifest_row_with_prompt["prompt"] = prompt
            entries.append(manifest_row_with_prompt)

    if not entries:
        raise SystemExit("error: no prompts generated after filters were applied")
    return entries


def write_pending_inputs(
    pending_entries: list[dict[str, Any]],
    pending_prompts_jsonl: Path,
    pending_manifest_jsonl: Path,
) -> None:
    with pending_prompts_jsonl.open("w", encoding="utf-8") as prompts_handle, pending_manifest_jsonl.open(
        "w", encoding="utf-8"
    ) as manifest_handle:
        for idx, entry in enumerate(pending_entries):
            prompt = entry.get("prompt", "")
            if not isinstance(prompt, str) or not prompt.strip():
                continue
            prompts_handle.write(json.dumps({"prompt": prompt}, ensure_ascii=True) + "\n")
            row = dict(entry)
            row["pending_index"] = idx
            manifest_handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def build_prompts_and_manifest(
    selected_rows: list[dict[str, str]],
    templates: dict[str, Path],
    prompts_jsonl: Path,
    manifest_jsonl: Path,
) -> list[dict[str, Any]]:
    return write_selected_entries(
        selected_rows=selected_rows,
        templates=templates,
        prompts_jsonl=prompts_jsonl,
        manifest_jsonl=manifest_jsonl,
    )


def run_batch(
    ocw_path: Path,
    prompts_jsonl: Path,
    output_path: Path,
    workers: int,
    model: str,
    extra_flags: str,
    run_cwd: Path,
    isolation_root: Path,
    prompt_timeout_seconds: float,
    fallback_model: str,
) -> int:
    command = [
        str(ocw_path),
        "batch",
        "-i",
        str(prompts_jsonl),
        "-o",
        str(output_path),
        "--workers",
        str(workers),
        "--cwd",
        str(run_cwd),
        "--isolate-db",
        "--isolation-root",
        str(isolation_root),
        "--json-events",
        "--prompt-timeout-seconds",
        str(prompt_timeout_seconds),
    ]
    if fallback_model.strip():
        command.extend(["--fallback-model", fallback_model.strip()])
    passthrough = ["--", "--model", model]
    if extra_flags.strip():
        passthrough.extend(shlex.split(extra_flags))
    command.extend(passthrough)

    print("\nRunning command:")
    print(" ", shlex.join(command))
    return subprocess.call(command)


def export_trajectories_per_cve(
    exporter_path: Path,
    ocw_path: Path,
    results_jsonl: Path,
    output_dir: Path,
    canonical_json_dir: Path | None = None,
) -> int:
    command = [
        sys.executable,
        str(exporter_path),
        "--ocw",
        str(ocw_path),
        "--results",
        str(results_jsonl),
        "--out-dir",
        str(output_dir),
    ]
    if canonical_json_dir is not None:
        command.extend(["--canonical-json-dir", str(canonical_json_dir)])
    print("\nExporting deterministic per-(CVE, commit) tool trajectories:")
    print(" ", shlex.join(command))
    return subprocess.call(command)


def copy_detected_canonical_records(
    workspace_dir: Path,
    cves: list[str],
    canonical_dir: Path,
    canonical_json_dir: Path | None = None,
) -> dict[str, Any]:
    canonical_dir.mkdir(parents=True, exist_ok=True)
    workspace_json_files = [path for path in workspace_dir.rglob("*.json") if path.is_file()]

    summary: dict[str, Any] = {"copied": {}, "missing": []}
    for cve in sorted(set(cves)):
        cve_upper = cve.upper()
        candidates = [path for path in workspace_json_files if cve_upper in path.name.upper()]
        if canonical_json_dir is not None:
            direct_candidate = canonical_json_dir / f"{cve_upper}.json"
            if direct_candidate.is_file():
                candidates.append(direct_candidate)
        if not candidates:
            summary["missing"].append(cve_upper)
            continue

        best = max(candidates, key=lambda path: path.stat().st_mtime)
        destination = canonical_dir / f"{cve_upper}.json"
        if best.resolve() != destination.resolve():
            shutil.copy2(best, destination)
        summary["copied"][cve_upper] = {
            "source": str(best),
            "destination": str(destination),
            "size_bytes": destination.stat().st_size if destination.exists() else 0,
        }

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Interactive menu pipeline: CSV -> ocw batch -> per-(CVE, commit) deterministic trajectories."
    )
    parser.add_argument("--csv", default=str(DEFAULT_CSV), help="Path to source CSV file")
    parser.add_argument(
        "--prompt-dir",
        default=str(DEFAULT_PROMPT_DIR),
        help="Directory containing language prompt templates (e.g., python.txt, go.txt, c#.txt)",
    )
    parser.add_argument("--ocw", default=str(DEFAULT_OCW), help="Path to ocw wrapper executable")
    parser.add_argument(
        "--exporter",
        default=str(DEFAULT_EXPORTER),
        help="Path to export_trajectories_per_cve.py",
    )
    parser.add_argument(
        "--canonical-json-dir",
        default=str(DEFAULT_CANONICAL_JSON_DIR),
        help="Directory where prompts save canonical JSON files as <CVE>.json",
    )
    parser.add_argument(
        "--tool-trajectory-dir",
        default=str(DEFAULT_TOOL_TRAJECTORY_DIR),
        help="Directory where trajectory artifacts are written",
    )
    parser.add_argument(
        "--skip-cves-dir",
        default=DEFAULT_SKIP_CVES_DIRS_TEXT,
        help=(
            "Comma-separated directories to scan for existing JSON outputs used for resume skipping. "
            "Rows are skipped only when both cve_id and commit_hash match an existing JSON record. "
            "Use empty string to disable."
        ),
    )
    parser.add_argument(
        "--include-linux",
        action="store_true",
        help="Include Linux examples (default excludes Linux-heavy rows)",
    )
    parser.add_argument(
        "--prompt-timeout-seconds",
        type=float,
        default=DEFAULT_PROMPT_TIMEOUT_SECONDS,
        help="Per-prompt timeout passed to ocw batch (0 disables timeout)",
    )
    parser.add_argument(
        "--fallback-model",
        default=DEFAULT_FALLBACK_MODEL,
        help="Fallback model used by ocw when a prompt times out",
    )
    parser.add_argument(
        "--per-language-limit",
        type=int,
        default=300,
        help="Max rows to sample per selected language (<=0 means no cap)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Default worker count shown in interactive prompt",
    )
    parser.add_argument(
        "--run-dir",
        help="Optional fixed run output directory (recommended for resumable runs)",
    )
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Resume mode: reuse existing manifest/prompts in run dir and skip already-successful CVEs",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv).expanduser().resolve()
    prompt_dir = Path(args.prompt_dir).expanduser().resolve()
    ocw_path = Path(args.ocw).expanduser().resolve()
    exporter_path = Path(args.exporter).expanduser().resolve()
    canonical_json_dir = Path(args.canonical_json_dir).expanduser().resolve()
    tool_trajectory_dir = Path(args.tool_trajectory_dir).expanduser().resolve()
    skip_cves_dirs = parse_skip_directories((args.skip_cves_dir or "").strip())

    templates = discover_prompt_templates(prompt_dir)
    rows = parse_csv_rows(csv_path=csv_path, exclude_linux=not args.include_linux)
    skipped_rows_by_existing = 0
    existing_keys: set[tuple[str, str]] = set()
    existing_key_counts_by_dir: dict[str, int] = {}
    for skip_dir in skip_cves_dirs:
        keys = collect_cve_commit_keys_from_directory(skip_dir)
        existing_key_counts_by_dir[str(skip_dir)] = len(keys)
        existing_keys.update(keys)
    rows, skipped_rows_by_existing = filter_rows_by_cve_commit_keys(rows, existing_keys)
    if skip_cves_dirs:
        print("\nExisting output skip directories:")
        for skip_dir in skip_cves_dirs:
            print(f"  - {skip_dir}: cve+commit keys={existing_key_counts_by_dir.get(str(skip_dir), 0)}")
        print(
            f"  merged keys={len(existing_keys)} rows_skipped={skipped_rows_by_existing}"
        )
    print_distribution(rows, title="Dataset summary (post-filter)")

    language_counts = Counter(row["_language"] for row in rows)
    template_languages = sorted(
        {
            language
            for language in language_counts
            if resolve_template_path(language, templates) is not None and language_counts[language] > 0
        },
        reverse=True,
    )
    if not template_languages:
        raise SystemExit(
            "error: no overlap between CSV languages and prompt templates in prompt directory"
        )

    print("\nLanguages with available templates:")
    for language in template_languages:
        template_path = resolve_template_path(language, templates)
        print(f"  - {language} ({language_counts[language]}) -> {template_path}")

    selected_raw = prompt_input("\nChoose languages (comma-separated or 'all')", "all")
    selected_languages = parse_selected_languages(selected_raw, template_languages)
    per_language_limit_raw = prompt_input(
        "How many samples per language (<=0 means no cap)",
        str(args.per_language_limit),
    )
    per_language_limit = int(per_language_limit_raw)
    selected_rows, selected_counts = select_rows_per_language(
        rows=rows,
        templates=templates,
        selected_languages=selected_languages,
        per_language_limit=per_language_limit,
    )
    selected_total = len(selected_rows)
    if selected_total < 1:
        raise SystemExit("error: no rows selected after applying language/template filters")

    workers_raw = prompt_input("How many parallel workers", str(args.workers))
    workers = int(workers_raw)
    if workers < 1:
        raise SystemExit("error: workers must be >= 1")

    model = prompt_input("Model", "zai-coding-plan/glm-5.1")
    extra_flags = prompt_input("Extra opencode flags after model (optional)", "")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.run_dir:
        default_run_dir = Path(args.run_dir).expanduser().resolve()
    else:
        default_run_dir = (Path.cwd() / f"ocw_run_{timestamp}").resolve()
    run_dir = Path(prompt_input("Run output directory", str(default_run_dir))).expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)

    input_dir = run_dir / "input"
    workspace_dir = run_dir / "workspace"
    canonical_records_dir = run_dir / "canonical_records"
    for directory in (input_dir, workspace_dir, tool_trajectory_dir, canonical_records_dir):
        directory.mkdir(parents=True, exist_ok=True)

    prompts_jsonl = input_dir / "prompts.jsonl"
    manifest_jsonl = input_dir / "selected_manifest.jsonl"
    batch_results_jsonl = tool_trajectory_dir / "batch_results.jsonl"
    isolation_root = run_dir / ".xdg_isolated"

    print("\nPlan:")
    print(f"  csv: {csv_path}")
    print(f"  prompt dir: {prompt_dir}")
    print(f"  selected languages: {', '.join(selected_languages)}")
    print(f"  per-language sample cap: {per_language_limit}")
    print(f"  rows selected: {selected_total}")
    print("  selected rows by language:")
    for language in selected_languages:
        print(f"    - {language}: {selected_counts.get(language, 0)}")
    print(f"  workers: {workers}")
    print(f"  model: {model}")
    print(f"  prompt timeout seconds: {args.prompt_timeout_seconds}")
    print(f"  fallback model for timed-out prompts: {args.fallback_model}")
    print(f"  resume mode: {args.resume}")
    print(f"  run dir: {run_dir}")
    print(f"  workspace (opencode cwd): {workspace_dir}")
    print(f"  batch results: {batch_results_jsonl}")
    print(f"  trajectories per cve+commit: {tool_trajectory_dir}")
    print(f"  canonical records target: {canonical_records_dir}")
    print(f"  canonical json source dir: {canonical_json_dir}")
    print("  trajectory generation is deterministic from raw events (not LLM-generated).")

    confirm = prompt_input("Start run? (yes/no)", "yes").strip().lower()
    if confirm not in {"y", "yes"}:
        print("Aborted.")
        return 0

    using_existing_inputs = args.resume and prompts_jsonl.exists() and manifest_jsonl.exists()
    if using_existing_inputs:
        print("\nResume mode: loading existing selected manifest/prompts from run directory.")
        selected_entries = load_existing_entries(manifest_jsonl=manifest_jsonl, prompts_jsonl=prompts_jsonl)
    else:
        selected_entries = build_prompts_and_manifest(
            selected_rows=selected_rows,
            templates=templates,
            prompts_jsonl=prompts_jsonl,
            manifest_jsonl=manifest_jsonl,
        )
        print(f"\nGenerated prompts: {prompts_jsonl} ({len(selected_entries)} rows)")

    selected_cves = [str(entry.get("cve_id", "")).upper() for entry in selected_entries if entry.get("cve_id")]
    completed_prompts = collect_completed_prompts(batch_results_jsonl) if args.resume else set()
    pending_entries = [
        entry for entry in selected_entries if str(entry.get("prompt", "")).strip() not in completed_prompts
    ]
    if existing_keys:
        before_pending = len(pending_entries)
        filtered_pending: list[dict[str, Any]] = []
        for entry in pending_entries:
            key = entry_cve_commit_key(entry)
            if key is not None and key in existing_keys:
                continue
            filtered_pending.append(entry)
        pending_entries = filtered_pending
        skipped_pending = before_pending - len(pending_entries)
        if skipped_pending > 0:
            print(
                f"Skipped pending entries due to existing cve+commit outputs in {len(skip_cves_dirs)} directories: {skipped_pending}"
            )
    selected_keys = {key for key in (entry_cve_commit_key(entry) for entry in selected_entries) if key is not None}
    completed_keys = {
        key
        for key in (entry_cve_commit_key(entry) for entry in selected_entries if str(entry.get("prompt", "")).strip() in completed_prompts)
        if key is not None
    }
    print(
        f"Resume status: total selected={len(selected_entries)}, completed={len(completed_prompts)}, pending={len(pending_entries)}"
    )

    appended_results = 0
    if pending_entries:
        pending_prompts_jsonl = input_dir / "pending_prompts.jsonl"
        pending_manifest_jsonl = input_dir / "pending_manifest.jsonl"
        write_pending_inputs(
            pending_entries=pending_entries,
            pending_prompts_jsonl=pending_prompts_jsonl,
            pending_manifest_jsonl=pending_manifest_jsonl,
        )
        pending_batch_results_jsonl = (
            tool_trajectory_dir / f"batch_results_pending_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        )
        batch_exit = run_batch(
            ocw_path=ocw_path,
            prompts_jsonl=pending_prompts_jsonl,
            output_path=pending_batch_results_jsonl,
            workers=workers,
            model=model,
            extra_flags=extra_flags,
            run_cwd=workspace_dir,
            isolation_root=isolation_root,
            prompt_timeout_seconds=args.prompt_timeout_seconds,
            fallback_model=args.fallback_model,
        )
        appended_results = append_jsonl(pending_batch_results_jsonl, batch_results_jsonl)
        print(f"Appended {appended_results} new batch result records into {batch_results_jsonl}")
    else:
        print("No pending prompts to run; skipping ocw batch.")
        batch_exit = 0

    if batch_results_jsonl.exists():
        trajectories_exit = export_trajectories_per_cve(
            exporter_path=exporter_path,
            ocw_path=ocw_path,
            results_jsonl=batch_results_jsonl,
            output_dir=tool_trajectory_dir,
            canonical_json_dir=canonical_json_dir,
        )
    else:
        print("No batch results file found; skipping trajectory export.")
        trajectories_exit = 0

    canonical_summary = copy_detected_canonical_records(
        workspace_dir=workspace_dir,
        cves=selected_cves,
        canonical_dir=canonical_records_dir,
        canonical_json_dir=canonical_json_dir,
    )
    canonical_manifest_path = run_dir / "canonical_records_manifest.json"
    canonical_manifest_path.write_text(
        json.dumps(canonical_summary, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )

    run_summary = {
        "batch_exit_code": batch_exit,
        "trajectory_export_exit_code": trajectories_exit,
        "run_dir": str(run_dir),
        "input": {
            "csv": str(csv_path),
            "prompts": str(prompts_jsonl),
            "manifest": str(manifest_jsonl),
        },
        "outputs": {
            "workspace": str(workspace_dir),
            "batch_results": str(batch_results_jsonl),
            "tool_trajectory_dir": str(tool_trajectory_dir),
            "canonical_records_dir": str(canonical_records_dir),
            "canonical_records_manifest": str(canonical_manifest_path),
        },
        "runtime_controls": {
            "workers": workers,
            "per_language_limit": per_language_limit,
            "prompt_timeout_seconds": args.prompt_timeout_seconds,
            "fallback_model": args.fallback_model,
            "resume": args.resume,
            "skip_cves_dir": ",".join(str(path) for path in skip_cves_dirs),
        },
        "resume": {
            "using_existing_inputs": using_existing_inputs,
            "selected_entries": len(selected_entries),
            "completed_entries": len(completed_prompts),
            "pending_entries": len(pending_entries),
            "new_results_appended": appended_results,
            "rows_skipped_by_existing_cves": skipped_rows_by_existing,
            "existing_cve_commit_keys_found": len(existing_keys),
            "selected_cve_commit_keys": len(selected_keys),
            "completed_cve_commit_keys": len(completed_keys),
            "existing_key_counts_by_dir": existing_key_counts_by_dir,
        },
        "deterministic_trajectory": True,
    }
    run_summary_path = run_dir / "run_summary.json"
    run_summary_path.write_text(json.dumps(run_summary, ensure_ascii=True, indent=2), encoding="utf-8")

    print("\nRun summary:")
    print(json.dumps(run_summary, ensure_ascii=True, indent=2))
    return 0 if batch_exit == 0 and trajectories_exit == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
