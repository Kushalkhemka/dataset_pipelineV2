#!/usr/bin/env python3
"""Extract rows in full CSV that are missing from baseline CSV and fix unknown language.

Primary matching key: (cve_id, commit_hash)

Language resolution order for rows with unknown/empty language:
1. Majority known language for same repo_name in full CSV
2. GitHub GraphQL (commit metadata) + GitHub REST compare/commit files (diff file paths)
3. Commit diff fetch and file-extension inference
4. GitHub GraphQL repository primary language
5. Fallback language (default: Other)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests


UNKNOWN_VALUES = {"", "unknown", "unk", "na", "n/a", "none", "null"}

GITHUB_COMMIT_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-fA-F]{7,40})(?:$|[/?#])"
)
DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")


EXT_TO_LANGUAGE = {
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
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".scala": "Scala",
    ".lua": "Lua",
    ".pl": "Perl",
    ".pm": "Perl",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".json": "JSON",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".xml": "XML",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".vue": "Vue",
    ".dart": "Dart",
}

SUPPORTED_PROMPT_LANGUAGES = {
    "C",
    "C++",
    "C#",
    "Go",
    "Java",
    "JavaScript",
    "Kotlin",
    "PHP",
    "Python",
    "Ruby",
    "Rust",
    "Swift",
}

REPO_LANGUAGE_OVERRIDES: dict[str, str] = {
    "code.wireshark.org/wireshark": "C",
    "git.openssl.org/openssl": "C",
    "android.googlesource.com/platform/packages/modules/bluetooth": "C++",
    "git.moodle.org/moodle": "PHP",
    "libvirt.org/libvirt": "C",
    "phpmyadmin.git.sourceforge.net/phpmyadmin/phpmyadmin": "PHP",
    "android.googlesource.com/kernel/common": "C",
    "git.videolan.org/vlc": "C",
    "git.qemu-project.org/qemu": "C",
    "git.libav.org/libav": "C",
    "android.googlesource.com/platform/system/core": "C++",
    "git.exim.org/exim": "C",
    "libpng.git.sourceforge.net/libpng/libpng": "C",
    "bitbucket.org/ritt/elog": "C++",
    "gitlab.freedesktop.org/gstreamer/gstreamer/-": "C",
    "android.googlesource.com/platform/external/conscrypt": "Java",
    "chromium.googlesource.com/v8/v8": "C++",
    "android.googlesource.com/platform%2fframeworks%2fav": "C++",
    "bitbucket.org/tildeslash/monit": "C",
    "android.googlesource.com/platform/art": "C++",
    "android.googlesource.com/platform/libcore": "Java",
    "chromium.googlesource.com/infra/infra": "Python",
    "aomedia.googlesource.com/aom": "C",
    "gitlab.matrix.org/matrix-org/olm/-": "C++",
    "bitbucket.org/jeromerobert/k4dirstat": "C++",
    "bitbucket.org/csalgadow/demokratian_votaciones": "PHP",
    "git.busybox.net/busybox": "C",
    "bitbucket.org/libgd/gd-libgd": "C",
    "chromium.googlesource.com/angle/angle": "C++",
    "android.googlesource.com/platform%2fsystem%2fcore": "C++",
    "git.zx2c4.com/password-store": "Python",
    "bitbucket.org/butor-team/portal": "PHP",
    "gitlab.com/gnutls/gnutls/-": "C",
    "bitbucket.org/naviserver/naviserver": "C",
    "git.openldap.org/openldap/openldap/-": "C",
    "gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-": "PHP",
    "gitlab.gnome.org/gnome/gdk-pixbuf/-": "C",
    "gitlab.com/qemu-project/qemu/-": "C",
    "bitbucket.org/utmandrew/pcrs": "C",
    "android.googlesource.com/platform/packages/modules/connectivity": "Java",
    "gitlab.fusiondirectory.org/fusiondirectory/fd/-": "PHP",
    "bitbucket.org/nolife/coloradoftp": "C#",
    "gitlab.freedesktop.org/poppler/poppler/-": "C++",
    "gitlab.kitware.com/cmake/cmake/-": "C++",
    "gitlab.gnome.org/gnome/gimp/-": "C",
    "git.dpkg.org/cgit/dpkg/dpkg.git": "C",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract extra rows from full CSV and fix unknown language using diff/GitHub metadata."
    )
    p.add_argument("--full-csv", required=True, help="Source CSV (superset)")
    p.add_argument("--baseline-csv", required=True, help="Baseline CSV to exclude rows already present")
    p.add_argument("--out-csv", required=True, help="Output CSV for extra rows with language fixed")
    p.add_argument("--summary-json", required=True, help="Output summary JSON path")
    p.add_argument(
        "--cache-json",
        default="",
        help="Optional JSON cache path for commit-level language resolution",
    )
    p.add_argument(
        "--github-token-env",
        default="GITHUB_TOKEN",
        help="Environment variable name containing GitHub token",
    )
    p.add_argument("--workers", type=int, default=8, help="Parallel resolver workers")
    p.add_argument("--timeout-seconds", type=float, default=20.0, help="HTTP timeout")
    p.add_argument("--fallback-language", default="Other", help="Fallback when no language could be inferred")
    return p.parse_args()


def normalize_text(value: str) -> str:
    return (value or "").strip()


def is_unknown_language(value: str) -> bool:
    return normalize_text(value).lower() in UNKNOWN_VALUES


def row_key(row: dict[str, str]) -> tuple[str, str]:
    return (normalize_text(row.get("cve_id", "")).upper(), normalize_text(row.get("commit_hash", "")).lower())


def parse_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
        rows = [{k: normalize_text(v) for k, v in row.items()} for row in reader]
    return headers, rows


def write_csv(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            out = {h: row.get(h, "") for h in headers}
            writer.writerow(out)


def parse_commit_urls(raw: str) -> list[str]:
    text = normalize_text(raw)
    if not text:
        return []
    parts = re.split(r"[;\s,]+", text)
    return [p for p in parts if p.startswith("http://") or p.startswith("https://")]


def language_from_path(path: str) -> str | None:
    lowered = normalize_text(path).lower()
    if not lowered:
        return None
    base = lowered.rsplit("/", 1)[-1]
    if base in {"dockerfile"}:
        return "Dockerfile"
    if base.startswith("makefile"):
        return "Makefile"
    idx = base.rfind(".")
    if idx == -1:
        return None
    ext = base[idx:]
    return EXT_TO_LANGUAGE.get(ext)


def choose_primary_language(counter: Counter[str]) -> tuple[str | None, list[str]]:
    if not counter:
        return None, []
    ranked = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    languages = [name for name, _ in ranked]
    return languages[0], languages


def parse_diff_languages(diff_text: str) -> tuple[str | None, list[str]]:
    counter: Counter[str] = Counter()
    for line in diff_text.splitlines():
        m = DIFF_GIT_RE.match(line.strip())
        if not m:
            continue
        path_b = m.group(2)
        lang = language_from_path(path_b)
        if lang:
            counter[lang] += 1
    return choose_primary_language(counter)


def github_target_from_row(row: dict[str, str]) -> tuple[str, str, str] | None:
    for url in parse_commit_urls(row.get("commit_urls", "")):
        m = GITHUB_COMMIT_RE.match(url)
        if m:
            return (m.group("owner"), m.group("repo").removesuffix(".git"), m.group("sha"))

    repo_url = normalize_text(row.get("repo_url", ""))
    commit_hash = normalize_text(row.get("commit_hash", ""))
    if not repo_url or not commit_hash:
        return None
    parsed = urlparse(repo_url)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1].removesuffix(".git")
    return (owner, repo, commit_hash)


def heuristic_repo_language(row: dict[str, str]) -> str | None:
    repo_name = normalize_text(row.get("repo_name", "")).lower()
    repo_url = normalize_text(row.get("repo_url", "")).lower()
    commit_urls = normalize_text(row.get("commit_urls", "")).lower()

    if repo_name in REPO_LANGUAGE_OVERRIDES:
        return REPO_LANGUAGE_OVERRIDES[repo_name]

    text = " ".join([repo_name, repo_url, commit_urls])

    if "android.googlesource.com/kernel/common" in text:
        return "C"
    if "android.googlesource.com/platform/libcore" in text or "conscrypt" in text:
        return "Java"
    if "android.googlesource.com/platform/packages/modules/connectivity" in text:
        return "Java"
    if "android.googlesource.com" in text:
        return "C++"

    if "chromium.googlesource.com/infra" in text:
        return "Python"
    if "chromium.googlesource.com" in text:
        return "C++"

    c_keywords = [
        "openssl",
        "wireshark",
        "libvirt",
        "vlc",
        "qemu",
        "libav",
        "exim",
        "busybox",
        "openldap",
        "gimp",
        "dpkg",
        "gnutls",
        "libpng",
        "aom",
    ]
    if any(k in text for k in c_keywords):
        return "C"

    cpp_keywords = ["cmake", "poppler", "k4dirstat", "v8", "angle", "gstreamer", "olm"]
    if any(k in text for k in cpp_keywords):
        return "C++"

    php_keywords = ["moodle", "phpmyadmin", "fusiondirectory", "portal", "demokratian_votaciones", "lemonldap"]
    if any(k in text for k in php_keywords):
        return "PHP"

    if "coloradoftp" in text:
        return "C#"

    return None


class GitHubResolver:
    def __init__(self, token: str | None, timeout: float) -> None:
        self.token = token or ""
        self.timeout = timeout
        self.graphql_url = "https://api.github.com/graphql"
        self.rest_base = "https://api.github.com"
        self._lock = threading.Lock()
        self.request_failures = 0

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _request_json(self, method: str, url: str, **kwargs: Any) -> dict[str, Any] | None:
        tries = 4
        for attempt in range(tries):
            try:
                resp = requests.request(method, url, timeout=self.timeout, headers=self._headers(), **kwargs)
            except requests.RequestException:
                resp = None
            if resp is None:
                sleep_s = min(10.0, 1.5 * (2**attempt))
                time.sleep(sleep_s)
                continue
            if resp.status_code in {429, 500, 502, 503, 504}:
                sleep_s = min(20.0, 2.0 * (2**attempt))
                time.sleep(sleep_s)
                continue
            if resp.status_code >= 400:
                with self._lock:
                    self.request_failures += 1
                return None
            try:
                return resp.json()
            except ValueError:
                with self._lock:
                    self.request_failures += 1
                return None
        with self._lock:
            self.request_failures += 1
        return None

    def graphql_commit_parent_and_repo_language(
        self, owner: str, repo: str, sha: str
    ) -> tuple[str | None, str | None]:
        if not self.token:
            return None, None
        query = """
        query($owner: String!, $repo: String!, $oid: GitObjectID!) {
          repository(owner: $owner, name: $repo) {
            primaryLanguage { name }
            object(oid: $oid) {
              ... on Commit {
                oid
                parents(first: 1) { nodes { oid } }
              }
            }
          }
        }
        """
        payload = {"query": query, "variables": {"owner": owner, "repo": repo, "oid": sha}}
        data = self._request_json("POST", self.graphql_url, json=payload)
        if not isinstance(data, dict):
            return None, None
        repo_obj = ((data.get("data") or {}).get("repository") or {}) if isinstance(data.get("data"), dict) else {}
        if not isinstance(repo_obj, dict):
            return None, None
        primary = None
        primary_obj = repo_obj.get("primaryLanguage")
        if isinstance(primary_obj, dict):
            name = primary_obj.get("name")
            if isinstance(name, str) and name.strip():
                primary = name.strip()
        parent = None
        obj = repo_obj.get("object")
        if isinstance(obj, dict):
            parents = (((obj.get("parents") or {}).get("nodes")) or []) if isinstance(obj.get("parents"), dict) else []
            if parents and isinstance(parents[0], dict):
                poid = parents[0].get("oid")
                if isinstance(poid, str) and poid:
                    parent = poid
        return parent, primary

    def rest_commit_file_languages(self, owner: str, repo: str, sha: str, parent: str | None) -> tuple[str | None, list[str]]:
        file_counter: Counter[str] = Counter()

        # Prefer compare (parent...sha) for explicit diff scope when parent is known.
        if parent:
            cmp_url = f"{self.rest_base}/repos/{owner}/{repo}/compare/{parent}...{sha}"
            cmp_data = self._request_json("GET", cmp_url)
            files = cmp_data.get("files") if isinstance(cmp_data, dict) else None
            if isinstance(files, list):
                for item in files:
                    if not isinstance(item, dict):
                        continue
                    filename = item.get("filename")
                    if isinstance(filename, str):
                        lang = language_from_path(filename)
                        if lang:
                            file_counter[lang] += 1
                primary, all_langs = choose_primary_language(file_counter)
                if primary:
                    return primary, all_langs

        # Fallback: single commit files API
        commit_url = f"{self.rest_base}/repos/{owner}/{repo}/commits/{sha}"
        commit_data = self._request_json("GET", commit_url)
        files = commit_data.get("files") if isinstance(commit_data, dict) else None
        if isinstance(files, list):
            for item in files:
                if not isinstance(item, dict):
                    continue
                filename = item.get("filename")
                if isinstance(filename, str):
                    lang = language_from_path(filename)
                    if lang:
                        file_counter[lang] += 1

        return choose_primary_language(file_counter)


def build_repo_majority_map(rows: list[dict[str, str]]) -> dict[str, str]:
    buckets: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        lang = normalize_text(row.get("language", ""))
        if is_unknown_language(lang):
            continue
        repo_name = normalize_text(row.get("repo_name", "")).lower()
        if repo_name:
            buckets[repo_name][lang] += 1
    out: dict[str, str] = {}
    for repo_name, counter in buckets.items():
        lang, _ = choose_primary_language(counter)
        if lang:
            out[repo_name] = lang
    return out


def resolve_from_diff_urls(row: dict[str, str], timeout: float) -> tuple[str | None, list[str], str]:
    urls = parse_commit_urls(row.get("commit_urls", ""))
    candidates: list[str] = []
    for url in urls:
        if url.endswith(".diff"):
            candidates.append(url)
            continue
        m = GITHUB_COMMIT_RE.match(url)
        if m:
            candidates.append(url.rstrip("/") + ".diff")
            continue
    # Generic fallback from repo_url + commit_hash
    repo_url = normalize_text(row.get("repo_url", ""))
    commit_hash = normalize_text(row.get("commit_hash", ""))
    if repo_url and commit_hash:
        candidates.append(f"{repo_url.rstrip('/')}/commit/{commit_hash}.diff")

    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = requests.get(url, timeout=timeout)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        text = resp.text or ""
        if "diff --git " not in text:
            continue
        primary, languages = parse_diff_languages(text)
        if primary:
            return primary, languages, "diff_fetch"
    return None, [], "diff_fetch"


def main() -> int:
    args = parse_args()

    full_csv = Path(args.full_csv).expanduser().resolve()
    baseline_csv = Path(args.baseline_csv).expanduser().resolve()
    out_csv = Path(args.out_csv).expanduser().resolve()
    summary_json = Path(args.summary_json).expanduser().resolve()
    cache_json = Path(args.cache_json).expanduser().resolve() if args.cache_json else None

    full_headers, full_rows = parse_csv(full_csv)
    _, baseline_rows = parse_csv(baseline_csv)

    baseline_keys = {row_key(row) for row in baseline_rows}
    extra_rows = [row for row in full_rows if row_key(row) not in baseline_keys]

    unknown_indices = [i for i, row in enumerate(extra_rows) if is_unknown_language(row.get("language", ""))]
    unknown_before = len(unknown_indices)

    repo_majority = build_repo_majority_map(full_rows)
    token = os.environ.get(args.github_token_env, "").strip()
    gh = GitHubResolver(token=token, timeout=args.timeout_seconds)

    cache: dict[str, dict[str, Any]] = {}
    if cache_json and cache_json.is_file():
        try:
            payload = json.loads(cache_json.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                cache = {str(k): v for k, v in payload.items() if isinstance(v, dict)}
        except json.JSONDecodeError:
            cache = {}

    stats: Counter[str] = Counter()
    stats["extras_total"] = len(extra_rows)
    stats["unknown_before"] = unknown_before
    stats["token_present"] = 1 if token else 0

    def resolve_one(index: int) -> tuple[int, str, list[str], str]:
        row = extra_rows[index]
        repo_name = normalize_text(row.get("repo_name", "")).lower()
        cache_key = "||".join(
            [
                normalize_text(row.get("repo_url", "")).lower(),
                normalize_text(row.get("commit_hash", "")).lower(),
                normalize_text(row.get("commit_urls", "")),
            ]
        )
        cached = cache.get(cache_key)
        if cached:
            lang = normalize_text(str(cached.get("language", "")))
            if lang and not is_unknown_language(lang):
                langs = [str(x) for x in cached.get("languages", []) if str(x).strip()]
                return index, lang, langs, str(cached.get("method", "cache"))

        # 1) Repo majority
        if repo_name in repo_majority:
            lang = repo_majority[repo_name]
            langs = [lang]
            cache[cache_key] = {"language": lang, "languages": langs, "method": "repo_majority"}
            return index, lang, langs, "repo_majority"

        # 2) GitHub GraphQL + REST compare/commit files
        target = github_target_from_row(row)
        repo_primary = None
        if target:
            owner, repo, sha = target
            parent, repo_primary = gh.graphql_commit_parent_and_repo_language(owner, repo, sha)
            lang, langs = gh.rest_commit_file_languages(owner, repo, sha, parent)
            if lang and not is_unknown_language(lang):
                cache[cache_key] = {
                    "language": lang,
                    "languages": langs,
                    "method": "github_graphql_rest_diff",
                }
                return index, lang, langs, "github_graphql_rest_diff"

        # 3) Raw diff URL parsing
        lang, langs, method = resolve_from_diff_urls(row, timeout=args.timeout_seconds)
        if lang and not is_unknown_language(lang):
            cache[cache_key] = {"language": lang, "languages": langs, "method": method}
            return index, lang, langs, method

        # 4) GraphQL repo primary language fallback
        if repo_primary and not is_unknown_language(repo_primary):
            cache[cache_key] = {
                "language": repo_primary,
                "languages": [repo_primary],
                "method": "github_graphql_repo_primary",
            }
            return index, repo_primary, [repo_primary], "github_graphql_repo_primary"

        # 5) Hard fallback
        hlang = heuristic_repo_language(row)
        if hlang and hlang in SUPPORTED_PROMPT_LANGUAGES:
            cache[cache_key] = {
                "language": hlang,
                "languages": [hlang],
                "method": "heuristic_repo_map",
            }
            return index, hlang, [hlang], "heuristic_repo_map"

        # 6) Hard fallback
        cache[cache_key] = {
            "language": args.fallback_language,
            "languages": [args.fallback_language],
            "method": "fallback",
        }
        return index, args.fallback_language, [args.fallback_language], "fallback"

    if unknown_indices:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
            futures = [executor.submit(resolve_one, idx) for idx in unknown_indices]
            completed = 0
            for fut in as_completed(futures):
                idx, lang, langs, method = fut.result()
                row = extra_rows[idx]
                row["language"] = lang
                if "multiple_language" in row and row["multiple_language"] in {"", "false", "False", "0"}:
                    row["multiple_language"] = "true" if len(set(langs)) > 1 else "false"
                stats[f"resolved_{method}"] += 1
                completed += 1
                if completed % 200 == 0:
                    print(f"[progress] resolved_unknown={completed}/{len(unknown_indices)}")

    unknown_after = sum(1 for row in extra_rows if is_unknown_language(row.get("language", "")))
    stats["unknown_after"] = unknown_after
    stats["http_failures"] = gh.request_failures

    write_csv(out_csv, full_headers, extra_rows)

    summary = {
        "full_csv": str(full_csv),
        "baseline_csv": str(baseline_csv),
        "out_csv": str(out_csv),
        "summary_generated_at_unix": int(time.time()),
        "counts": dict(stats),
    }
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")

    if cache_json:
        cache_json.parent.mkdir(parents=True, exist_ok=True)
        cache_json.write_text(json.dumps(cache, ensure_ascii=True, indent=2), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
