# opencode-cli-wrapper

Minimal headless wrapper around `opencode` for programmatic use.

This wrapper is intentionally thin:
- It does not rewrite your prompt.
- It does not add policy/restriction layers.
- It forwards unknown flags directly to native `opencode run` / `opencode serve`.
- It keeps native features working (`tool` calls, TODO/task flows, session continuity, plugins, etc.) because execution still happens inside real `opencode`.

Permission behavior:
- `ocw` injects full permission allow by default for `opencode` runtime:
  - `edit=allow`
  - `bash=allow`
  - `webfetch=allow`
  - `doom_loop=allow`
  - `external_directory=allow`
- To disable that behavior for a specific call, add `--respect-opencode-permissions`.

## Requirements

- `opencode` installed and authenticated.
- Python 3.9+.

## Commands

```bash
./ocw run [wrapper flags] [prompt words] [-- opencode run flags...]
./ocw batch -i prompts.txt [wrapper flags] [-- opencode run flags...]
./ocw trajectory -i raw_events.jsonl [wrapper flags]
./ocw_driver.py [driver flags]
./ocw serve [wrapper flags] [-- opencode serve flags...]
```

## Quick Start

Run one prompt:

```bash
./ocw run --prompt "scan this code for memory corruption bugs" -- --continue --agent default
```

Run one prompt against an already-running headless server:

```bash
./ocw run --prompt "make a TODO plan and start executing" -- --attach http://127.0.0.1:4096
```

Start a headless server:

```bash
./ocw serve -- --hostname 0.0.0.0 --port 4096
```

Run with isolated opencode DB for one worker:

```bash
./ocw batch \
  --input ./shards/shard_01.jsonl \
  --output ./results/shard_01.jsonl \
  --isolate-db \
  --worker-id shard_01
```

## Batch Mode (dataset generation)

Input formats:
- `.txt`: one prompt per non-empty line
- `.jsonl`: each line is either a string prompt or an object with `prompt` / `message`
- `.json`: array of string prompts or objects with `prompt` / `message`
- `.csv`: header row required; use `--csv-column` or `--csv-template`

Example:

```bash
./ocw batch \
  --input ./examples/prompts.txt \
  --output ./results/results.jsonl \
  --workers 8 \
  --json-events \
  -- --attach http://127.0.0.1:4096 --agent default
```

CSV rows + X workers:

```bash
./ocw batch \
  --input ./dataset.csv \
  --csv-column prompt \
  --offset 0 \
  --limit 30000 \
  --workers 16 \
  --output ./results/run_0001.jsonl
```

Each output JSONL record includes:
- `prompt`
- `command`
- `exit_code`
- `worker_slot`
- `xdg_data_home`
- `stdout`
- `stderr`
- timestamps and duration

## Deterministic Trajectory Extraction

Convert raw `opencode run --format json` events into deterministic tool-call
training rows:

```bash
./ocw trajectory \
  --input ./output/raw_events.jsonl \
  --output ./output/trajectories.jsonl
```

Deterministic behavior:
- Stable ordering by input line order
- Session/call/message/part IDs normalized to `s1`, `c1`, `m1`, `p1` by first appearance
- Sorted JSON keys
- Deterministic truncation for long strings (default `--max-output-chars 12000`)

Useful flags:
- `--context-window N` include last N assistant text chunks before each tool call
- `--history-window N` include last N prior tool turns in each record context
- `--max-output-chars N` truncate long text fields (use `-1` to disable)
- `--raw-ids` keep original IDs instead of normalized ones
- `--append` append to an existing output file

## DB Isolation For Parallel Runs

To avoid cross-shard memory/context bleed and SQLite contention, isolate each
worker's DB location.

Option 1 (recommended): wrapper-managed paths

```bash
./ocw batch -i shard_02.jsonl -o out_02.jsonl \
  --isolate-db --worker-id shard_02
```

This creates/uses:

```text
/tmp/ocw_xdg/shard_02/opencode/opencode.db
```

When `--workers > 1`, `ocw batch` auto-enables isolation if you did not
provide `--xdg-data-home` or `--isolate-db`, creating per-worker DB roots like:

```text
/tmp/ocw_xdg/worker-001/opencode/opencode.db
/tmp/ocw_xdg/worker-002/opencode/opencode.db
...
```

Option 2: explicit path

```bash
./ocw run --prompt "..." --xdg-data-home /tmp/ocw_xdg/custom_worker
```

Isolation flags are available on `run`, `batch`, and `serve`:
- `--isolate-db`
- `--worker-id <id>`
- `--isolation-root <dir>` (default: `/tmp/ocw_xdg`)
- `--xdg-data-home <dir>` (mutually exclusive with `--isolate-db`)

## Interactive Driver (Language Menu)

Use the interactive driver to:
- read your CSV dataset
- exclude Linux-heavy rows by default
- view language and CWE distributions
- choose one or multiple languages
- choose row count + worker count
- run `ocw batch` with isolated DB workers

```bash
./ocw_driver.py \
  --csv "/Users/kushalkhemka/Desktop/untitled folder 3/check_exhaustive_out.csv" \
  --prompt-dir "/Users/kushalkhemka/Desktop/untitled folder 3/opencode-cli-wrapper/language-prompts"
```

Template files should be named by language stem, for example:
- `language-prompts/python.txt`
- `language-prompts/go.txt`
- `language-prompts/java.txt`
- `language-prompts/php.txt`

Templates are rendered with CSV fields like:
`{cve_id}`, `{commit_hash}`, `{repo_name}`, `{repo_url}`, `{commit_urls}`, `{source_file}`, `{cwe_ids}`, `{cwe_tokens}`

## Notes

- To preserve ongoing task/TODO/session behavior between calls, pass native `opencode` session flags through the wrapper (for example `--continue` or `--session <id>`).
- You can switch binary with `--binary` if needed.
- Use `--respect-opencode-permissions` on `run`, `batch`, or `serve` if you want to honor existing `opencode` permission settings.
