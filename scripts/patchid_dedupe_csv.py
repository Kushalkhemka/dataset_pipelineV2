#!/usr/bin/env python3
"""Dedupe CVE CSV rows by git patch-id (--stable) within each CVE.

Policy:
- Exact input rows are assumed already hash-level deduped.
- For each cve_id group, keep one row per unique patch-id.
- If patch-id cannot be computed for a hash, fallback key is commit hash
  (so unresolved hashes are preserved rather than collapsed incorrectly).

Outputs:
- Deduped CSV with same columns as input.
- JSON report with counts and cache stats.
- On-disk cache (JSONL) to avoid refetching patch-id for known commit hashes.
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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

URL_RE = re.compile(r"https?://[^\s,;]+")


@dataclass
class PatchResult:
    patch_id: Optional[str]
    status: str
    source_url: Optional[str] = None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Dedupe CVE CSV by git patch-id --stable")
    p.add_argument("--input", required=True, help="Input CSV path")
    p.add_argument("--output", required=True, help="Output deduped CSV path")
    p.add_argument("--report", required=True, help="Output JSON report path")
    p.add_argument(
        "--cache",
        required=True,
        help="JSONL cache path for commit_hash -> patch_id/status",
    )
    p.add_argument("--workers", type=int, default=24, help="Parallel workers for fetch")
    p.add_argument("--timeout", type=int, default=12, help="HTTP timeout seconds")
    p.add_argument(
        "--max-candidates",
        type=int,
        default=12,
        help="Max candidate patch URLs tested per hash",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="How many hashes to submit to the thread pool at a time",
    )
    return p.parse_args()


def read_csv_rows(path: Path) -> Tuple[List[Dict[str, str]], List[str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        if reader.fieldnames is None:
            raise ValueError("Input CSV has no header")
        return rows, reader.fieldnames


def extract_urls(text: str) -> List[str]:
    return [u.rstrip("),]") for u in URL_RE.findall(text or "")]


def set_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


def kernel_stable_patch_url(commit_hash: str) -> str:
    return (
        "https://git.kernel.org/pub/scm/linux/kernel/git/stable/"
        f"linux.git/patch/?id={commit_hash}"
    )


def patch_url_candidates(row: Dict[str, str]) -> List[str]:
    commit_hash = (row.get("commit_hash") or "").strip()
    repo_url = (row.get("repo_url") or "").strip().rstrip("/")
    commit_urls = (row.get("commit_urls") or "").strip()

    cands: List[str] = []
    for u in extract_urls(commit_urls):
        base = u.split("#", 1)[0]
        cands.append(base)

        if "/commit/" in base or "/-/commit/" in base:
            cands.append(base + ".patch")
            cands.append(base + ".diff")

        # gitweb/cgit patterns
        if "a=commit" in base:
            cands.append(set_query_param(base, "a", "patch"))
            cands.append(set_query_param(base, "a", "commitdiff"))
        if "a=commitdiff" in base:
            cands.append(set_query_param(base, "a", "patch"))

        # encoded gitweb parameters
        if "%3Ba=commit" in base:
            cands.append(base.replace("%3Ba=commit", "%3Ba=patch"))
            cands.append(base.replace("%3Ba=commit", "%3Ba=commitdiff"))
        if "%3Ba=commitdiff" in base:
            cands.append(base.replace("%3Ba=commitdiff", "%3Ba=patch"))

    if commit_hash and "git.kernel.org" in commit_urls and "/stable/c/" in commit_urls:
        cands.append(kernel_stable_patch_url(commit_hash))

    if commit_hash and repo_url and "git.kernel.org" in repo_url:
        repo = repo_url if repo_url.endswith(".git") else (repo_url + ".git")
        cands.append(f"{repo}/patch/?id={commit_hash}")

    if commit_hash and repo_url:
        cands.append(f"{repo_url}/commit/{commit_hash}.patch")
        cands.append(f"{repo_url}/commit/{commit_hash}.diff")

    # keep order, remove duplicates
    seen = set()
    out: List[str] = []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def looks_like_patch(text: str) -> bool:
    if not text or not text.strip():
        return False
    head = text[:400].lower()
    if "<!doctype html" in head or "<html" in head:
        return False
    return text.startswith("From ") or "\ndiff --git " in text


def fetch_text(url: str, timeout_s: int) -> Tuple[Optional[str], str]:
    req = Request(
        url,
        headers={
            "User-Agent": "dataset-patchid-dedupe/1.0",
            "Accept": "text/plain,*/*",
        },
    )
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            content = resp.read()
            # keep replacement to survive odd bytes
            return content.decode("utf-8", errors="replace"), "ok"
    except HTTPError as e:
        return None, f"http_{e.code}"
    except URLError:
        return None, "url_error"
    except TimeoutError:
        return None, "timeout"
    except Exception:
        return None, "error"


def compute_patch_id(patch_text: str) -> Optional[str]:
    proc = subprocess.run(
        ["git", "patch-id", "--stable"],
        input=patch_text,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    if not out:
        return None
    return out.split()[0]


def load_cache(path: Path) -> Dict[str, PatchResult]:
    cache: Dict[str, PatchResult] = {}
    if not path.exists():
        return cache
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                h = obj.get("commit_hash")
                if not h:
                    continue
                cache[h] = PatchResult(
                    patch_id=obj.get("patch_id"),
                    status=obj.get("status", "unknown"),
                    source_url=obj.get("source_url"),
                )
            except Exception:
                continue
    return cache


def append_cache(path: Path, commit_hash: str, result: PatchResult, lock: threading.Lock) -> None:
    rec = {
        "commit_hash": commit_hash,
        "patch_id": result.patch_id,
        "status": result.status,
        "source_url": result.source_url,
    }
    line = json.dumps(rec, ensure_ascii=True)
    with lock:
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def resolve_hash(
    commit_hash: str,
    row: Dict[str, str],
    timeout_s: int,
    max_candidates: int,
) -> PatchResult:
    candidates = patch_url_candidates(row)[:max_candidates]
    if not candidates:
        return PatchResult(patch_id=None, status="no_candidate", source_url=None)

    last_status = "not_patch"
    for url in candidates:
        txt, st = fetch_text(url, timeout_s)
        if txt is None:
            last_status = st
            continue
        if not looks_like_patch(txt):
            last_status = "not_patch"
            continue
        pid = compute_patch_id(txt)
        if not pid:
            last_status = "patch_id_failed"
            continue
        return PatchResult(patch_id=pid, status="ok", source_url=url)

    return PatchResult(patch_id=None, status=last_status, source_url=None)


def batched(items: List[str], size: int) -> Iterable[List[str]]:
    if size <= 0:
        size = 1000
    for i in range(0, len(items), size):
        yield items[i : i + size]


def main() -> int:
    args = parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    report_path = Path(args.report)
    cache_path = Path(args.cache)

    rows, fieldnames = read_csv_rows(input_path)

    by_cve: Dict[str, List[int]] = defaultdict(list)
    for i, row in enumerate(rows):
        cve = (row.get("cve_id") or "").strip()
        by_cve[cve].append(i)

    # Only hashes in CVEs with multiple unique hashes need patch-id.
    hash_row: Dict[str, Dict[str, str]] = {}
    for cve, idxs in by_cve.items():
        if len(idxs) < 2:
            continue
        hashes = []
        for idx in idxs:
            h = (rows[idx].get("commit_hash") or "").strip()
            if h:
                hashes.append(h)
                hash_row.setdefault(h, rows[idx])
        if len(set(hashes)) < 2:
            # Single unique hash: nothing to dedupe by patch-id
            continue

    cache = load_cache(cache_path)
    missing_hashes = [h for h in hash_row.keys() if h not in cache]

    cache_lock = threading.Lock()
    resolved = 0

    if missing_hashes:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            for batch in batched(missing_hashes, int(args.batch_size)):
                fut_to_hash = {
                    ex.submit(
                        resolve_hash,
                        h,
                        hash_row[h],
                        int(args.timeout),
                        int(args.max_candidates),
                    ): h
                    for h in batch
                }
                for fut in as_completed(fut_to_hash):
                    h = fut_to_hash[fut]
                    try:
                        res = fut.result()
                    except Exception:
                        res = PatchResult(patch_id=None, status="worker_error", source_url=None)
                    cache[h] = res
                    append_cache(cache_path, h, res, cache_lock)
                    resolved += 1
                    if resolved % 500 == 0:
                        print(f"resolved {resolved}/{len(missing_hashes)}", file=sys.stderr)

    # Deduplicate within each CVE by patch-id if available, else by hash.
    kept_rows: List[Dict[str, str]] = []
    dropped_rows = 0
    dropped_same_patchid = 0

    for cve, idxs in by_cve.items():
        seen_keys = set()
        for idx in idxs:
            row = rows[idx]
            h = (row.get("commit_hash") or "").strip()
            res = cache.get(h)
            if res and res.patch_id:
                key = f"pid:{res.patch_id}"
            elif h:
                key = f"hash:{h}"
            else:
                key = f"row:{idx}"

            if key in seen_keys:
                dropped_rows += 1
                if key.startswith("pid:"):
                    dropped_same_patchid += 1
                continue

            seen_keys.add(key)
            kept_rows.append(row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(kept_rows)

    status_counts: Dict[str, int] = defaultdict(int)
    ok_with_pid = 0
    for r in cache.values():
        status_counts[r.status] += 1
        if r.patch_id:
            ok_with_pid += 1

    report = {
        "input_csv": str(input_path),
        "output_csv": str(output_path),
        "cache_file": str(cache_path),
        "input_rows": len(rows),
        "output_rows": len(kept_rows),
        "dropped_rows_total": dropped_rows,
        "dropped_rows_same_patchid": dropped_same_patchid,
        "hashes_considered": len(hash_row),
        "hashes_from_cache": len(hash_row) - len(missing_hashes),
        "hashes_resolved_this_run": resolved,
        "hashes_with_patch_id": ok_with_pid,
        "patch_fetch_status_counts": dict(sorted(status_counts.items())),
        "workers": args.workers,
        "timeout": args.timeout,
        "max_candidates": args.max_candidates,
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
