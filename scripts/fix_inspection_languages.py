#!/usr/bin/env python3
"""Fix language labels for inspection CSV rows.

Resolution order per row:
1) Infer from changed files in commit URLs (diff/patch/html path extraction)
2) Repo-majority language from full dataset (restricted to Prompt languages)
3) Existing language if it maps to a Prompt language
4) Leave unchanged

This updates both `language` and `_language`.
"""

from __future__ import annotations

import argparse
import base64
import csv
import html
import json
import os
import re
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, unquote, urlparse

import requests


PROMPT_STEM_TO_LANGUAGE = {
    "c": "C",
    "cpp": "C++",
    "c#": "C#",
    "go": "Go",
    "java": "Java",
    "js": "JavaScript",
    "kotlin": "Kotlin",
    "php": "PHP",
    "python": "Python",
    "ruby": "Ruby",
    "rust": "Rust",
    "swift": "Swift",
}

# Broad detection map. Final output is constrained to Prompt languages.
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
    ".jsx": "JavaScript",
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
    ".pl": "Perl",
    ".pm": "Perl",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".lua": "Lua",
    ".scala": "Scala",
    ".xml": "XML",
    ".json": "JSON",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".vue": "Vue",
    ".dart": "Dart",
}

LANGUAGE_SYNONYMS = {
    "c": "C",
    "c++": "C++",
    "cpp": "C++",
    "c#": "C#",
    "go": "Go",
    "golang": "Go",
    "java": "Java",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "typescript": "JavaScript",
    "ts": "JavaScript",
    "kotlin": "Kotlin",
    "php": "PHP",
    "python": "Python",
    "py": "Python",
    "ruby": "Ruby",
    "rust": "Rust",
    "swift": "Swift",
    "objective-c": "C",
    "objective-c++": "C++",
}

UNKNOWN_VALUES = {"", "unknown", "unk", "na", "n/a", "none", "null"}

DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$", re.M)
PLUS_PLUS_RE = re.compile(r"^\+\+\+ b/(.+)$", re.M)
GOOGLESOURCE_PATH_RE = re.compile(r"/\+/[0-9a-f]{7,40}/([^\"'<>\s?#]+)", re.I)
F_PARAM_RE = re.compile(r"(?:[?&;]|%3B)f=([^&;\"'<>]+)", re.I)
TREE_PATH_RE = re.compile(r"/(?:tree|plain|blame|commit)/([^\"'?<> ]+)", re.I)
GITHUB_COMMIT_URL_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-f]{7,40})(?:$|[/?#])",
    re.I,
)
GITHUB_REPO_LANG_RE = re.compile(r'color-fg-default text-bold mr-1">([^<]+)</span>\s*<span>([0-9.]+)%</span>', re.I)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fix inspection CSV language labels using commit files + repo majority.")
    p.add_argument("--input-csv", required=True, help="Inspection CSV to fix")
    p.add_argument("--full-csv", required=True, help="Full dataset CSV for repo-majority fallback")
    p.add_argument("--prompts-dir", required=True, help="Directory containing Prompt templates (*.txt)")
    p.add_argument("--out-csv", default="", help="Output CSV path (default: overwrite input)")
    p.add_argument("--cache-json", default="", help="Optional cache json path")
    p.add_argument("--summary-json", default="", help="Optional summary json path")
    p.add_argument("--workers", type=int, default=12, help="Parallel workers")
    p.add_argument("--timeout-seconds", type=float, default=12.0, help="HTTP timeout")
    p.add_argument("--max-commit-urls", type=int, default=3, help="Max commit urls to inspect per row")
    p.add_argument("--max-candidates-per-url", type=int, default=6, help="Max transformed URLs per commit url")
    p.add_argument(
        "--github-token-env",
        default="GITHUB_TOKEN",
        help="Optional GitHub token env var for API-backed repo language fallback",
    )
    return p.parse_args()


def normalize_text(value: str) -> str:
    return (value or "").strip()


def is_unknown(value: str) -> bool:
    return normalize_text(value).lower() in UNKNOWN_VALUES


def parse_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        headers = list(r.fieldnames or [])
        rows = [{k: normalize_text(v) for k, v in row.items()} for row in r]
    return headers, rows


def write_csv(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for row in rows:
            w.writerow({h: row.get(h, "") for h in headers})


def load_supported_languages(prompts_dir: Path) -> set[str]:
    langs: set[str] = set()
    for p in prompts_dir.glob("*.txt"):
        stem = p.stem.strip().lower()
        mapped = PROMPT_STEM_TO_LANGUAGE.get(stem)
        if mapped:
            langs.add(mapped)
    return langs


def to_prompt_language(value: str, supported: set[str]) -> str | None:
    lang = normalize_text(value)
    if not lang:
        return None
    if lang in supported:
        return lang
    mapped = LANGUAGE_SYNONYMS.get(lang.lower())
    if mapped and mapped in supported:
        return mapped
    return None


def build_repo_majority_map(full_rows: list[dict[str, str]], supported: set[str]) -> dict[str, str]:
    buckets: dict[str, Counter[str]] = defaultdict(Counter)
    for row in full_rows:
        repo = normalize_text(row.get("repo_name", "")).lower()
        if not repo:
            continue
        prompt_lang = to_prompt_language(row.get("language", ""), supported)
        if not prompt_lang:
            continue
        buckets[repo][prompt_lang] += 1
    out: dict[str, str] = {}
    for repo, counter in buckets.items():
        ranked = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
        out[repo] = ranked[0][0]
    return out


def parse_commit_urls(raw: str) -> list[str]:
    text = normalize_text(raw)
    if not text:
        return []
    parts = [p for p in re.split(r"[;\s,]+", text) if p]
    urls: list[str] = []
    for p in parts:
        if p.startswith("http://") or p.startswith("https://"):
            urls.append(p.split("#", 1)[0])
    return urls


def github_owner_repo_from_row(row: dict[str, str]) -> tuple[str, str] | None:
    for url in parse_commit_urls(row.get("commit_urls", "")):
        m = GITHUB_COMMIT_URL_RE.match(url)
        if m:
            return (m.group("owner"), m.group("repo").removesuffix(".git"))

    repo_url = normalize_text(row.get("repo_url", ""))
    if not repo_url:
        return None
    parsed = urlparse(repo_url)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    return (parts[0], parts[1].removesuffix(".git"))


def source_repo_from_row(row: dict[str, str]) -> tuple[str, str] | None:
    repo_url = normalize_text(row.get("repo_url", ""))
    if repo_url:
        parsed = urlparse(repo_url)
        host = parsed.netloc.lower()
        path = parsed.path.strip("/")
        if host and path:
            return host, path

    repo_name = normalize_text(row.get("repo_name", ""))
    if "/" not in repo_name:
        return None
    host, path = repo_name.split("/", 1)
    host = normalize_text(host).lower()
    path = normalize_text(path).strip("/")
    if not host or not path:
        return None
    return host, path


def project_name_from_repo_path(path: str) -> str:
    cleaned = normalize_text(path).split("?", 1)[0].split("#", 1)[0].strip("/")
    if not cleaned:
        return ""
    parts = [p for p in cleaned.split("/") if p]
    if not parts:
        return ""
    return parts[-1].removesuffix(".git")


def language_from_path(path: str) -> str | None:
    p = normalize_text(path)
    if not p:
        return None
    low = p.lower()
    base = low.rsplit("/", 1)[-1]
    if base == "dockerfile":
        return "Dockerfile"
    if base.startswith("makefile"):
        return "Makefile"
    idx = base.rfind(".")
    if idx < 0:
        return None
    return EXT_TO_LANGUAGE.get(base[idx:])


def generate_candidate_urls(url: str) -> list[str]:
    base = normalize_text(url).split("#", 1)[0]
    if not base:
        return []

    cands: list[str] = []

    def add(u: str) -> None:
        u = normalize_text(u)
        if u and u not in cands:
            cands.append(u)

    parsed = urlparse(base)
    host = parsed.netloc.lower()

    # Preferred direct diff endpoints first.
    # Many cgit-style hosts (including git.spip.net) support commit URL suffixes.
    if "/commit/" in parsed.path:
        add(base + ".diff")
        add(base + ".patch")
    if "gitee.com" in host and "/commit/" in parsed.path:
        add(base + ".diff")

    # GoogleSource text format for commit pages.
    if "googlesource.com" in host and "/+/" in parsed.path and "format=" not in parsed.query:
        sep = "&" if parsed.query else "?"
        add(base + sep + "format=TEXT")

    # Generic gitweb/cgit style transformations.
    replacements = [
        ("%3Ba=commit%3B", "%3Ba=commitdiff%3B"),
        (";a=commit;", ";a=commitdiff;"),
        ("?a=commit&", "?a=commitdiff&"),
        ("&a=commit&", "&a=commitdiff&"),
    ]
    transformed = base
    for old, new in replacements:
        if old in transformed:
            add(transformed.replace(old, new))

    # cgit patch/diff path alternatives.
    if "/commit/" in parsed.path:
        add(base.replace("/commit/", "/patch/"))
        add(base.replace("/commit/", "/diff/"))

    # Original URL last.
    add(base)
    return cands


def canonicalize_path_token(token: str) -> str:
    t = unquote(token)
    t = t.strip().strip("\"'`[](){}<>,;:")
    t = t.replace("\\", "/")
    if t.startswith("a/") or t.startswith("b/"):
        t = t[2:]
    if t.startswith("./"):
        t = t[2:]
    return t


def ignored_path(path: str) -> bool:
    low = path.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return True
    if low.startswith(("assets/webpack/", "app/assets/", "vendor/assets/", "node_modules/", "dist/", "build/", "static/")):
        return True
    if "/assets/webpack/" in low:
        return True
    if low.endswith((".min.js", ".min.css")):
        return True
    return False


def extract_paths_from_text(text: str, source_url: str) -> set[str]:
    paths: set[str] = set()

    for m in DIFF_GIT_RE.finditer(text):
        p = canonicalize_path_token(m.group(2))
        if p and not ignored_path(p):
            paths.add(p)

    for m in PLUS_PLUS_RE.finditer(text):
        p = canonicalize_path_token(m.group(1))
        if p and not ignored_path(p):
            paths.add(p)

    if paths:
        return paths

    # HTML / rendered commit pages fallback: host-scoped patterns only.
    decoded = html.unescape(text)
    host = urlparse(source_url).netloc.lower()

    if "googlesource.com" in host:
        for m in GOOGLESOURCE_PATH_RE.finditer(decoded):
            p = canonicalize_path_token(m.group(1))
            if p and not ignored_path(p):
                paths.add(p)

    # gitweb/cgit links often embed file path via `f=...`.
    if any(tag in host for tag in ("git.", "cgit", "repo.or.cz", "pagure.io", "w1.fi", "code.call-cc.org")):
        for m in F_PARAM_RE.finditer(decoded):
            p = canonicalize_path_token(unquote(m.group(1)))
            if p and not ignored_path(p):
                paths.add(p)
        for m in TREE_PATH_RE.finditer(decoded):
            p = canonicalize_path_token(m.group(1))
            if p and not ignored_path(p):
                paths.add(p)

    return paths


def choose_primary(counter: Counter[str]) -> tuple[str | None, list[str]]:
    if not counter:
        return None, []
    ranked = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return ranked[0][0], [k for k, _ in ranked]


class Fetcher:
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self._local = threading.local()
        self.failures = 0
        self.lock = threading.Lock()

    def _session(self) -> requests.Session:
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.headers.update(
                {
                    "User-Agent": "dataset-pipeline-language-fixer/1.0",
                    "Accept": "text/plain, text/html, */*",
                }
            )
            self._local.session = sess
        return sess

    def get_text(self, url: str) -> str | None:
        tries = 2
        for _ in range(tries):
            try:
                resp = self._session().get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue
            if resp.status_code != 200:
                continue
            txt = resp.text or ""
            if url.endswith("format=TEXT"):
                try:
                    raw = base64.b64decode(txt, validate=False)
                    txt = raw.decode("utf-8", "ignore")
                except Exception:
                    pass
            return txt
        with self.lock:
            self.failures += 1
        return None


class GitHubRepoLanguageResolver:
    def __init__(self, timeout: float, token: str | None = None) -> None:
        self.timeout = timeout
        self.token = (token or "").strip()
        self._local = threading.local()
        self._cache: dict[str, str | None] = {}
        self._lock = threading.Lock()

    def _session(self) -> requests.Session:
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.headers.update(
                {
                    "User-Agent": "dataset-pipeline-language-fixer/1.0",
                    "Accept": "application/vnd.github+json, text/html, */*",
                }
            )
            if self.token:
                sess.headers["Authorization"] = f"Bearer {self.token}"
            self._local.session = sess
        return sess

    def _request_text(self, url: str) -> str | None:
        for _ in range(2):
            try:
                resp = self._session().get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue
            if resp.status_code == 200 and resp.text:
                return resp.text
        return None

    def resolve_prompt_language(self, owner: str, repo: str, supported: set[str]) -> str | None:
        key = f"{owner.lower()}/{repo.lower()}"
        with self._lock:
            if key in self._cache:
                return self._cache[key]

        # Prefer HTML language bar to avoid strict unauthenticated REST API rate limits.
        repo_html = self._request_text(f"https://github.com/{owner}/{repo}")
        selected: str | None = None
        if repo_html:
            langs = GITHUB_REPO_LANG_RE.findall(repo_html)
            for lang_name, _pct in langs:
                mapped = to_prompt_language(lang_name, supported)
                if mapped:
                    selected = mapped
                    break

        with self._lock:
            self._cache[key] = selected
        return selected


class GitHubMirrorResolver:
    """Resolve non-GitHub repos to a verified GitHub mirror using commit SHA presence."""

    def __init__(self, timeout: float, token: str | None = None) -> None:
        self.timeout = timeout
        self.token = (token or "").strip()
        self._local = threading.local()
        self._repo_cache: dict[str, tuple[str, str] | None] = {}
        self._search_cache: dict[str, list[tuple[str, str]]] = {}
        self._commit_cache: dict[str, bool] = {}
        self._lock = threading.Lock()

    def _session(self) -> requests.Session:
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.headers.update(
                {
                    "User-Agent": "dataset-pipeline-language-fixer/1.0",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
            )
            if self.token:
                sess.headers["Authorization"] = f"Bearer {self.token}"
            self._local.session = sess
        return sess

    def _request_json(self, url: str) -> dict[str, Any] | None:
        for _ in range(2):
            try:
                resp = self._session().get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue
            if resp.status_code != 200:
                continue
            try:
                payload = resp.json()
            except ValueError:
                continue
            if isinstance(payload, dict):
                return payload
        return None

    def _search_candidates(self, project: str) -> list[tuple[str, str]]:
        key = project.lower()
        with self._lock:
            if key in self._search_cache:
                return self._search_cache[key]

        candidates: list[tuple[str, str]] = []
        seen: set[str] = set()
        queries = [f"{project} in:name", f"{project} in:name mirror:true"]
        for query in queries:
            url = f"https://api.github.com/search/repositories?q={quote_plus(query)}&per_page=10"
            payload = self._request_json(url)
            if not payload:
                continue
            items = payload.get("items")
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = normalize_text(str(item.get("name", "")))
                if name.lower() != key:
                    continue
                owner_data = item.get("owner")
                owner = ""
                if isinstance(owner_data, dict):
                    owner = normalize_text(str(owner_data.get("login", "")))
                if not owner or not name:
                    continue
                full = f"{owner.lower()}/{name.lower()}"
                if full in seen:
                    continue
                seen.add(full)
                candidates.append((owner, name))
            if len(candidates) >= 12:
                break

        with self._lock:
            self._search_cache[key] = candidates
        return candidates

    def _commit_exists(self, owner: str, repo: str, sha: str) -> bool:
        if not sha:
            return False
        k = f"{owner.lower()}/{repo.lower()}@{sha.lower()}"
        with self._lock:
            if k in self._commit_cache:
                return self._commit_cache[k]

        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        exists = False
        for _ in range(2):
            try:
                resp = self._session().get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue
            if resp.status_code == 200:
                exists = True
                break
            if resp.status_code in (404, 422):
                exists = False
                break

        with self._lock:
            self._commit_cache[k] = exists
        return exists

    def resolve_owner_repo(self, row: dict[str, str]) -> tuple[str, str] | None:
        source = source_repo_from_row(row)
        if not source:
            return None
        host, repo_path = source
        if host == "github.com":
            return None

        cache_key = f"{host}/{repo_path}".lower()
        with self._lock:
            if cache_key in self._repo_cache:
                return self._repo_cache[cache_key]

        project = project_name_from_repo_path(repo_path)
        sha = normalize_text(row.get("commit_hash", ""))
        resolved: tuple[str, str] | None = None

        if project and sha:
            for owner, repo in self._search_candidates(project):
                if self._commit_exists(owner, repo, sha):
                    resolved = (owner, repo)
                    break

        # Cache positive resolutions, and cache structural misses (no project/sha).
        # Do not cache unresolved network/search misses as permanent negatives.
        if resolved is not None or not project or not sha:
            with self._lock:
                self._repo_cache[cache_key] = resolved
        return resolved


def main() -> int:
    args = parse_args()

    input_csv = Path(args.input_csv).expanduser().resolve()
    full_csv = Path(args.full_csv).expanduser().resolve()
    prompts_dir = Path(args.prompts_dir).expanduser().resolve()
    out_csv = Path(args.out_csv).expanduser().resolve() if args.out_csv else input_csv
    cache_json = Path(args.cache_json).expanduser().resolve() if args.cache_json else None
    summary_json = Path(args.summary_json).expanduser().resolve() if args.summary_json else None
    github_token = os.environ.get(args.github_token_env, "").strip()

    supported = load_supported_languages(prompts_dir)
    if not supported:
        raise SystemExit(f"No supported languages found in prompts dir: {prompts_dir}")

    headers, rows = parse_csv(input_csv)
    _, full_rows = parse_csv(full_csv)
    repo_majority = build_repo_majority_map(full_rows, supported)

    cache: dict[str, dict[str, Any]] = {}
    if cache_json and cache_json.is_file():
        try:
            payload = json.loads(cache_json.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                cache = {str(k): v for k, v in payload.items() if isinstance(v, dict)}
        except json.JSONDecodeError:
            cache = {}

    fetcher = Fetcher(timeout=args.timeout_seconds)
    github_repo_lang = GitHubRepoLanguageResolver(timeout=max(3.0, args.timeout_seconds), token=github_token)
    github_mirror = GitHubMirrorResolver(timeout=max(3.0, args.timeout_seconds), token=github_token)
    cache_lock = threading.Lock()
    method_stats: Counter[str] = Counter()

    before_counter = Counter(normalize_text(r.get("language", "")) for r in rows)

    def resolve_row(index: int) -> tuple[int, str, list[str], str]:
        row = rows[index]
        repo_name = normalize_text(row.get("repo_name", "")).lower()
        commit_hash = normalize_text(row.get("commit_hash", "")).lower()
        commit_urls = parse_commit_urls(row.get("commit_urls", ""))
        if not commit_urls:
            repo_url = normalize_text(row.get("repo_url", ""))
            if repo_url and commit_hash:
                commit_urls = [repo_url.rstrip("/") + "/commit/" + commit_hash]

        cache_key = "||".join([repo_name, commit_hash, "|".join(commit_urls)])

        with cache_lock:
            cached = cache.get(cache_key)
        if cached:
            lang = normalize_text(str(cached.get("language", "")))
            langs = [str(x) for x in cached.get("languages", []) if normalize_text(str(x))]
            method = normalize_text(str(cached.get("method", "cache"))) or "cache"
            if lang:
                return index, lang, langs, method

        def infer_prompt_languages_from_urls(urls: list[str]) -> Counter[str]:
            prompt_counter: Counter[str] = Counter()
            found_prompt = False
            for base_url in urls[: max(1, args.max_commit_urls)]:
                for candidate in generate_candidate_urls(base_url)[: max(1, args.max_candidates_per_url)]:
                    text = fetcher.get_text(candidate)
                    if not text:
                        continue
                    paths = extract_paths_from_text(text, candidate)
                    if not paths:
                        continue
                    for path in paths:
                        raw_lang = language_from_path(path)
                        if not raw_lang:
                            continue
                        prompt_lang = to_prompt_language(raw_lang, supported)
                        if prompt_lang:
                            prompt_counter[prompt_lang] += 1
                    if prompt_counter:
                        found_prompt = True
                        break
                if found_prompt:
                    break
            return prompt_counter

        prompt_counter = infer_prompt_languages_from_urls(commit_urls)

        if prompt_counter:
            lang, ranked = choose_primary(prompt_counter)
            assert lang is not None
            result = (index, lang, ranked, "commit_files")
            with cache_lock:
                cache[cache_key] = {"language": lang, "languages": ranked, "method": "commit_files"}
            return result

        if repo_name in repo_majority:
            lang = repo_majority[repo_name]
            result = (index, lang, [lang], "repo_majority")
            with cache_lock:
                cache[cache_key] = {"language": lang, "languages": [lang], "method": "repo_majority"}
            return result

        gh_target = github_owner_repo_from_row(row)
        if gh_target:
            gh_lang = github_repo_lang.resolve_prompt_language(gh_target[0], gh_target[1], supported)
            if gh_lang:
                result = (index, gh_lang, [gh_lang], "github_repo_majority")
                with cache_lock:
                    cache[cache_key] = {"language": gh_lang, "languages": [gh_lang], "method": "github_repo_majority"}
                return result

        # Optional strict mirror fallback: only when the same commit SHA exists in a GitHub repo.
        if github_mirror is not None:
            mirror_target = github_mirror.resolve_owner_repo(row)
            if mirror_target:
                sha = normalize_text(row.get("commit_hash", ""))
                if sha:
                    mirror_commit_urls = [f"https://github.com/{mirror_target[0]}/{mirror_target[1]}/commit/{sha}"]
                    mirror_counter = infer_prompt_languages_from_urls(mirror_commit_urls)
                    if mirror_counter:
                        lang, ranked = choose_primary(mirror_counter)
                        assert lang is not None
                        result = (index, lang, ranked, "commit_files_github_mirror")
                        with cache_lock:
                            cache[cache_key] = {
                                "language": lang,
                                "languages": ranked,
                                "method": "commit_files_github_mirror",
                            }
                        return result

                mirror_lang = github_repo_lang.resolve_prompt_language(mirror_target[0], mirror_target[1], supported)
                if mirror_lang:
                    result = (index, mirror_lang, [mirror_lang], "github_mirror_repo_majority")
                    with cache_lock:
                        cache[cache_key] = {
                            "language": mirror_lang,
                            "languages": [mirror_lang],
                            "method": "github_mirror_repo_majority",
                        }
                    return result

        existing_prompt = to_prompt_language(row.get("language", ""), supported)
        if existing_prompt:
            result = (index, existing_prompt, [existing_prompt], "existing_prompt")
            with cache_lock:
                cache[cache_key] = {"language": existing_prompt, "languages": [existing_prompt], "method": "existing_prompt"}
            return result

        current = normalize_text(row.get("language", ""))
        result = (index, current, [current] if current else [], "unchanged")
        with cache_lock:
            cache[cache_key] = {"language": current, "languages": [current] if current else [], "method": "unchanged"}
        return result

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as exe:
        futures = [exe.submit(resolve_row, i) for i in range(len(rows))]
        done = 0
        for fut in as_completed(futures):
            i, lang, langs, method = fut.result()
            row = rows[i]
            row["language"] = lang
            if "_language" in row:
                row["_language"] = lang
            if "_language_source" in row:
                row["_language_source"] = method
            if "multiple_language" in row:
                row["multiple_language"] = "true" if len(set([x for x in langs if x])) > 1 else "false"
            method_stats[method] += 1
            done += 1
            if done % 400 == 0:
                print(f"[progress] resolved={done}/{len(rows)}")

    after_counter = Counter(normalize_text(r.get("language", "")) for r in rows)

    write_csv(out_csv, headers, rows)

    summary = {
        "input_csv": str(input_csv),
        "out_csv": str(out_csv),
        "full_csv": str(full_csv),
        "prompts_dir": str(prompts_dir),
        "supported_languages": sorted(supported),
        "counts": {
            "rows_total": len(rows),
            "http_failures": fetcher.failures,
            "methods": dict(method_stats),
            "before_top_20": before_counter.most_common(20),
            "after_top_20": after_counter.most_common(20),
        },
        "generated_at_unix": int(time.time()),
    }

    if summary_json:
        summary_json.parent.mkdir(parents=True, exist_ok=True)
        summary_json.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")

    if cache_json:
        cache_json.parent.mkdir(parents=True, exist_ok=True)
        cache_json.write_text(json.dumps(cache, ensure_ascii=True, indent=2), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
