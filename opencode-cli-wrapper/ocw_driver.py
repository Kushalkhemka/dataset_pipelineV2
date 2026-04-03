#!/usr/bin/env python3
"""Interactive driver for language-filtered CSV -> ocw batch runs."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


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


def normalize_language_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


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
        mapping[key] = entry
    if not mapping:
        raise SystemExit(f"error: no prompt templates found in {prompt_dir}")
    return mapping


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
            if exclude_linux and is_linux_example(record.get("repo_name", "")):
                continue
            record["_row_index"] = str(row_index)
            record["_language"] = infer_language(record.get("repo_name", ""))
            rows.append(record)
    return rows


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
    try:
        text = template.format(**render_data)
    except KeyError as exc:
        missing = str(exc).strip("'")
        raise SystemExit(
            f"error: template references missing field '{missing}' for row {row.get('_row_index')}"
        ) from exc
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
        lang = normalized_available[key]
        if lang not in chosen:
            chosen.append(lang)
    if not chosen:
        raise SystemExit("error: at least one language must be selected")
    return chosen


def build_prompts_jsonl(
    rows: list[dict[str, str]],
    template_paths: dict[str, Path],
    selected_languages: list[str],
    limit: int,
) -> Path:
    selected_set = set(selected_languages)
    templates = {
        language: read_template_text(template_paths[normalize_language_name(language)])
        for language in selected_languages
    }

    generated = 0
    temp_file = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".jsonl")
    temp_path = Path(temp_file.name)
    with temp_file:
        for row in rows:
            language = row.get("_language", "Unknown")
            if language not in selected_set:
                continue
            prompt = render_prompt(templates[language], row)
            if not prompt:
                continue
            temp_file.write(json.dumps({"prompt": prompt}, ensure_ascii=True) + "\n")
            generated += 1
            if generated >= limit:
                break
    if generated == 0:
        temp_path.unlink(missing_ok=True)
        raise SystemExit("error: no prompts generated after filters were applied")
    return temp_path


def run_batch(
    ocw_path: Path,
    prompts_jsonl: Path,
    output_path: Path,
    workers: int,
    model: str,
    extra_flags: str,
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
        "--json-events",
    ]
    passthrough = ["--", "--model", model]
    if extra_flags.strip():
        passthrough.extend(shlex.split(extra_flags))
    command.extend(passthrough)

    print("\nRunning command:")
    print(" ", shlex.join(command))
    return subprocess.call(command)


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive driver for language-specific ocw batch runs.")
    parser.add_argument(
        "--csv",
        default="/Users/kushalkhemka/Desktop/untitled folder 3/check_exhaustive_out.csv",
        help="Path to source CSV file",
    )
    parser.add_argument(
        "--prompt-dir",
        default="/Users/kushalkhemka/Desktop/untitled folder 3/opencode-cli-wrapper/language-prompts",
        help="Directory containing language prompt templates named like python.txt, go.txt, etc.",
    )
    parser.add_argument(
        "--ocw",
        default="/Users/kushalkhemka/Desktop/untitled folder 3/opencode-cli-wrapper/ocw",
        help="Path to ocw wrapper executable",
    )
    parser.add_argument(
        "--include-linux",
        action="store_true",
        help="Include Linux examples (default excludes Linux-heavy rows)",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv).expanduser()
    prompt_dir = Path(args.prompt_dir).expanduser()
    ocw_path = Path(args.ocw).expanduser()

    templates = discover_prompt_templates(prompt_dir)
    rows = parse_csv_rows(csv_path=csv_path, exclude_linux=not args.include_linux)
    print_distribution(rows, title="Dataset summary (post-filter)")

    language_counts = Counter(row["_language"] for row in rows)
    template_languages = sorted(
        {
            language
            for language in language_counts
            if normalize_language_name(language) in templates and language_counts[language] > 0
        }
    )
    if not template_languages:
        raise SystemExit(
            "error: no overlap between inferred languages in CSV and template files in prompt directory"
        )

    print("\nLanguages with available templates:")
    for language in template_languages:
        print(f"  - {language} ({language_counts[language]})")

    default_langs = ",".join(template_languages)
    selected_raw = prompt_input("\nChoose languages (comma-separated or 'all')", "all")
    selected_languages = parse_selected_languages(selected_raw, template_languages)
    selected_total = sum(language_counts[lang] for lang in selected_languages)
    print(f"Selected languages: {', '.join(selected_languages)}")
    print(f"Matching rows: {selected_total}")

    default_limit = str(selected_total)
    limit_raw = prompt_input("How many rows to process", default_limit)
    limit = int(limit_raw)
    if limit < 1:
        raise SystemExit("error: row count must be >= 1")
    limit = min(limit, selected_total)

    cpu_count = os.cpu_count() or 8
    default_workers = str(min(max(cpu_count // 2, 1), 24))
    workers_raw = prompt_input("How many parallel workers", default_workers)
    workers = int(workers_raw)
    if workers < 1:
        raise SystemExit("error: workers must be >= 1")

    model = prompt_input("Model", "zai-coding-plan/glm-5.1")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_output = f"/Users/kushalkhemka/Desktop/untitled folder 3/opencode-cli-wrapper/output/run_{timestamp}.jsonl"
    output_path = Path(prompt_input("Output JSONL path", default_output)).expanduser()
    extra_flags = prompt_input(
        "Extra opencode flags after model (optional)",
        "",
    )

    print("\nPlan:")
    print(f"  rows: {limit}")
    print(f"  workers: {workers}")
    print(f"  model: {model}")
    print(f"  output: {output_path}")
    print(f"  linux examples included: {'yes' if args.include_linux else 'no'}")
    confirm = prompt_input("Start run? (yes/no)", "yes").strip().lower()
    if confirm not in {"y", "yes"}:
        print("Aborted.")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    prompts_jsonl = build_prompts_jsonl(
        rows=rows,
        template_paths=templates,
        selected_languages=selected_languages,
        limit=limit,
    )
    print(f"Generated prompt file: {prompts_jsonl}")

    try:
        return run_batch(
            ocw_path=ocw_path,
            prompts_jsonl=prompts_jsonl,
            output_path=output_path,
            workers=workers,
            model=model,
            extra_flags=extra_flags,
        )
    finally:
        prompts_jsonl.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
