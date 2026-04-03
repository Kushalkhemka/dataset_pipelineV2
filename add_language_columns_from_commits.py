#!/usr/bin/env python3
"""Add language and multiple_language columns to a CSV by inspecting commit diffs.

For GitHub repos, this script calls the GitHub commit API in parallel batches.
It deduplicates by (repo, commit), caches results, and is safe to resume.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests


EXT_LANGUAGE_MAP: Dict[str, str] = {
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".hh": "C++",
    ".cs": "C#",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".clj": "Clojure",
    ".go": "Go",
    ".rs": "Rust",
    ".py": "Python",
    ".rb": "Ruby",
    ".php": "PHP",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".lua": "Lua",
    ".pl": "Perl",
    ".pm": "Perl",
    ".r": "R",
    ".dart": "Dart",
    ".erl": "Erlang",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "Sass",
    ".less": "Less",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".xml": "XML",
    ".xsl": "XSLT",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
    ".toml": "TOML",
    ".ini": "INI",
    ".cfg": "Config",
    ".conf": "Config",
    ".md": "Markdown",
    ".rst": "reStructuredText",
    ".tex": "TeX",
    ".proto": "Protocol Buffers",
    ".asm": "Assembly",
    ".s": "Assembly",
}

SPECIAL_FILENAMES: Dict[str, str] = {
    "makefile": "Makefile",
    "cmakelists.txt": "CMake",
    "dockerfile": "Dockerfile",
    "jenkinsfile": "Groovy",
    "gemfile": "Ruby",
    "rakefile": "Ruby",
    "build.gradle": "Groovy",
    "build.gradle.kts": "Kotlin",
    "pom.xml": "Maven",
    "package.json": "JSON",
    "cargo.toml": "TOML",
    "go.mod": "Go",
    "go.sum": "Go",
}


@dataclass(frozen=True)
class CommitKey:
    owner: str
    repo: str
    sha: str

    @property
    def key(self) -> str:
        return f"{self.owner}/{self.repo}@{self.sha}"


def get_github_token() -> str:
    env_token = os.getenv("GITHUB_TOKEN", "").strip()
    if env_token and not env_token.startswith("PASTE_"):
        return env_token

    # Fallback to gh keyring token; unset invalid env to avoid gh selecting it.
    token = subprocess.check_output(
        ["env", "-u", "GITHUB_TOKEN", "gh", "auth", "token"],
        text=True,
    ).strip()
    if not token:
        raise RuntimeError("Unable to obtain GitHub token from env or gh auth.")
    return token


def parse_github_repo(repo_url: str) -> Optional[Tuple[str, str]]:
    if not isinstance(repo_url, str):
        return None
    parsed = urlparse(repo_url)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    owner = parts[0]
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def language_from_filename(path: str) -> str:
    p = Path(path)
    name = p.name.lower()
    if name in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[name]

    suffix = p.suffix.lower()
    if suffix in EXT_LANGUAGE_MAP:
        return EXT_LANGUAGE_MAP[suffix]

    return "Unknown"


def summarize_languages(file_paths: Iterable[str]) -> Tuple[str, bool, Dict[str, int]]:
    counts: Dict[str, int] = {}
    for fp in file_paths:
        lang = language_from_filename(fp)
        counts[lang] = counts.get(lang, 0) + 1

    # Prefer known languages over Unknown for majority decision.
    known_counts = {k: v for k, v in counts.items() if k != "Unknown"}
    target = known_counts if known_counts else counts

    if not target:
        return "Unknown", False, {}

    dominant = max(target.items(), key=lambda kv: (kv[1], kv[0]))[0]
    multi = len(target) > 1
    return dominant, multi, counts


def load_cache(path: Path) -> Dict[str, Dict[str, object]]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_cache(path: Path, cache: Dict[str, Dict[str, object]]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=True, sort_keys=True)
    tmp.replace(path)


def read_csv_rows(path: Path) -> Tuple[List[dict], List[str]]:
    with path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
        if reader.fieldnames is None:
            raise RuntimeError("CSV has no header")
        fieldnames = list(reader.fieldnames)
    return rows, fieldnames


def write_csv_rows(path: Path, rows: List[dict], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def fetch_commit_files(
    token: str,
    commit: CommitKey,
    timeout: int,
    max_attempts: int,
    secondary_limit_wait: int,
) -> List[str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "codex-language-column-updater",
    }

    files: List[str] = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{commit.owner}/{commit.repo}/commits/{commit.sha}"
        params = {"per_page": 100, "page": page}

        resp = None
        for attempt in range(max_attempts):
            try:
                resp = requests.get(url, headers=headers, params=params, timeout=timeout)
            except requests.RequestException:
                sleep_s = min(2 ** attempt, 20)
                time.sleep(sleep_s)
                continue

            if resp.status_code in (500, 502, 503, 504):
                sleep_s = min(2 ** attempt, 20)
                time.sleep(sleep_s)
                continue

            if resp.status_code in (403, 429):
                remaining = resp.headers.get("X-RateLimit-Remaining")
                reset = resp.headers.get("X-RateLimit-Reset")
                if remaining == "0" and reset:
                    fallback = fetch_commit_files_from_web_diff(token, commit, timeout)
                    return fallback if fallback is not None else []
                # Secondary abuse limits often return 403 with non-zero remaining.
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    sleep_s = max(int(retry_after), secondary_limit_wait)
                else:
                    sleep_s = secondary_limit_wait
                    try:
                        msg = (resp.json() or {}).get("message", "").lower()
                        if "secondary rate limit" in msg:
                            fallback = fetch_commit_files_from_web_diff(token, commit, timeout)
                            if fallback is not None:
                                return fallback
                            sleep_s = max(sleep_s, secondary_limit_wait)
                    except Exception:
                        pass
                time.sleep(sleep_s)
                continue

            if resp.status_code == 404:
                fallback = fetch_commit_files_from_web_diff(token, commit, timeout)
                if fallback is not None:
                    return fallback
                return []

            if resp.status_code == 401:
                raise RuntimeError("Unauthorized: token is invalid or expired.")

            if resp.status_code != 200:
                sleep_s = min(2 ** attempt, 20)
                time.sleep(sleep_s)
                continue

            break

        if resp is None or resp.status_code != 200:
            fallback = fetch_commit_files_from_web_diff(token, commit, timeout)
            if fallback is not None:
                return fallback
            return files

        payload = resp.json()
        page_files = payload.get("files", []) or []
        files.extend(f.get("filename", "") for f in page_files if f.get("filename"))

        link = resp.headers.get("Link", "")
        if 'rel="next"' in link:
            page += 1
            continue
        break

    return files


def fetch_commit_files_from_web_diff(
    token: str,
    commit: CommitKey,
    timeout: int,
) -> Optional[List[str]]:
    url = f"https://github.com/{commit.owner}/{commit.repo}/commit/{commit.sha}.diff"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/plain",
        "User-Agent": "codex-language-column-updater",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException:
        return None

    if resp.status_code == 404:
        return []
    if resp.status_code != 200:
        return None

    paths: List[str] = []
    pattern = re.compile(r"^diff --git a/(.+?) b/(.+)$")
    for line in resp.text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        path = match.group(2)
        if path and path != "/dev/null":
            paths.append(path)
    return paths


def batched(seq: List[CommitKey], size: int) -> Iterable[List[CommitKey]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input CSV path")
    parser.add_argument("--output", required=False, help="Output CSV path")
    parser.add_argument("--cache", default="commit_language_cache.json", help="Cache JSON file")
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--batch-size", type=int, default=300)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--secondary-limit-wait", type=int, default=15)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path
    cache_path = Path(args.cache)

    token = get_github_token()

    rows, fieldnames = read_csv_rows(input_path)

    commits: Dict[str, CommitKey] = {}
    row_key_by_index: List[Optional[str]] = [None] * len(rows)

    non_github_rows = 0
    for idx, row in enumerate(rows):
        repo_info = parse_github_repo(row.get("repo_url", ""))
        sha = (row.get("commit_hash") or "").strip()

        if not repo_info or not sha:
            non_github_rows += 1
            continue

        owner, repo = repo_info
        ck = CommitKey(owner=owner, repo=repo, sha=sha)
        key = ck.key
        commits[key] = ck
        row_key_by_index[idx] = key

    cache = load_cache(cache_path)

    all_commit_keys = list(commits.keys())
    pending_keys = [k for k in all_commit_keys if k not in cache]

    print(
        f"rows={len(rows)} github_rows={len(rows)-non_github_rows} non_github_rows={non_github_rows} unique_github_commits={len(all_commit_keys)} pending={len(pending_keys)}",
        flush=True,
    )

    if pending_keys:
        lock = threading.Lock()

        for batch_idx, batch_keys in enumerate(batched(pending_keys, args.batch_size), start=1):
            batch_commits = [commits[k] for k in batch_keys]
            started = time.time()
            done = 0

            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                future_map = {
                    pool.submit(
                        fetch_commit_files,
                        token,
                        ck,
                        args.timeout,
                        args.max_attempts,
                        args.secondary_limit_wait,
                    ): ck
                    for ck in batch_commits
                }

                for fut in as_completed(future_map):
                    ck = future_map[fut]
                    key = ck.key
                    try:
                        files = fut.result()
                        dominant, multi, counts = summarize_languages(files)
                        result = {
                            "language": dominant,
                            "multiple_language": multi,
                            "language_counts": counts,
                            "file_count": len(files),
                        }
                    except Exception as exc:  # noqa: BLE001
                        result = {
                            "language": "Unknown",
                            "multiple_language": False,
                            "language_counts": {},
                            "file_count": 0,
                            "error": str(exc),
                        }

                    with lock:
                        cache[key] = result
                        done += 1
                        if done % 50 == 0 or done == len(batch_commits):
                            print(
                                f"batch={batch_idx} progress={done}/{len(batch_commits)}",
                                flush=True,
                            )

            save_cache(cache_path, cache)
            elapsed = time.time() - started
            print(
                f"batch={batch_idx} complete commits={len(batch_commits)} elapsed_sec={elapsed:.1f} cache_saved={cache_path}",
                flush=True,
            )

    # Attach final columns.
    if "language" not in fieldnames:
        fieldnames.append("language")
    if "multiple_language" not in fieldnames:
        fieldnames.append("multiple_language")

    github_assigned = 0
    for idx, row in enumerate(rows):
        key = row_key_by_index[idx]
        if key and key in cache:
            row["language"] = cache[key].get("language", "Unknown")
            row["multiple_language"] = str(bool(cache[key].get("multiple_language", False))).lower()
            github_assigned += 1
        else:
            row["language"] = row.get("language") or "Unknown"
            row["multiple_language"] = row.get("multiple_language") or "false"

    write_csv_rows(output_path, rows, fieldnames)
    print(
        f"done output={output_path} github_assigned={github_assigned} total_rows={len(rows)}",
        flush=True,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
