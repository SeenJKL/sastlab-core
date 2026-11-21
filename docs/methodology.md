# Design and How It Works

How SASTLab is built and what rules it follows: the test condition, input program rules, behavior checker, 18 rewrites, scanner wrappers, search methods, LLM client, saved file formats, and scoring rules.

## Contents

- [1. Test Rule and Evasion Definition](#1-test-rule-and-evasion-definition)
- [2. Seed Program Rules and Test Sets](#2-seed-program-rules-and-test-sets)
- [3. Behavior Checker](#3-behavior-checker)
- [4. Code Rewrites and Bitmask IDs](#4-code-rewrites-and-bitmask-ids)
- [5. Scanner Wrappers and Commands](#5-scanner-wrappers-and-commands)
- [6. Search Methods and Distance Metrics](#6-search-methods-and-distance-metrics)
- [7. LLM Client and API Format](#7-llm-client-and-api-format)
- [8. Running, Resuming, Output Files, and Scoring](#8-running-resuming-output-files-and-scoring)
- [9. Main Design Choices and Trade-offs](#9-main-design-choices-and-trade-offs)

---

## 1. Test Rule and Evasion Definition

SASTLab tests one scanner at a time (same-behavior / metamorphic testing, rather than comparing outputs across different tools). Given a rule $R$, a vulnerable seed program $P$, and a rewritten version $T(P)$ that keeps the same behavior:

$$\text{flagged}_R(P) \;\land\; \text{behavior}(T(P)) = \text{behavior}(P) \implies \text{flagged}_R(T(P))$$

If this check breaks, we have found a missed bug (false negative) where the vulnerability still works:

1. **Qualifying seed:** On the original program $P$, the scanner finishes cleanly (`scan.status == "ok"`), rule $R$ flags it, and the behavior checker confirms the attack succeeds on normal vs. attack inputs.
2. **Verified evasion:** On $T(P)$, the behavior checker sees identical output on both inputs (`equivalent == True`), the scanner finishes cleanly (`scan.status == "ok"`), and rule $R$ no longer reports an alert.

Any scanner crash, parse error, or timeout counts as a failure (`error`), never as a clean scan. When testing multi-rule setups (such as Pysa SQL injection), `evasion: "any"` (default) marks an evasion if at least one qualifying rule stops firing, while `evasion: "all"` requires **every** qualifying rule to stop firing. Exhaustive runs always save `scan_rules` and `bypassed_rules` for each rule so either view can be checked afterward.

Unlike TaintCC (Christakis et al., ISSTA), which keeps reported taint paths identical without running the code, SASTLab executes every candidate because an evasion only matters if the vulnerability still works.

---

## 2. Seed Program Rules and Test Sets

### Seed Contract

Every Python seed across all three bug classes (SQL injection CWE-89, command injection CWE-78, path traversal CWE-22) defines one top-level entry function:

```python
def get_user_profile(db_conn, user_id):
    ...
    return rows  # list of rows/values
```

Rules enforced by `sastlab/transforms.py` and `sastlab/oracle_worker.py`:

- **Reserved names:** Seed code must not define `_mt_*` identifiers or put nested functions inside `get_user_profile`.
- **Query assignment (`query_assignment`):** Operators that rewrite the query (`format_swap`, `literal_slice`, `extract_1`, `extract_2`, `branch_split`) expect a top-level `query = ...` assignment before `.execute(query)`. Inline calls like `cursor.execute(f"...")` lack that assignment: `rename` and `dead_padding` still run (anchoring on the sink line), while the five query-rewriting operators reject the seed as `"invalid"` instead of silently skipping.
- **Supported string building:** Queries use f-strings (no custom format specs), `%`, `str.format()`, or `+` string joining.
- **Per-seed database and attack inputs:** A seed can define `SASTLAB_FIXTURE` (SQLite setup SQL) and `SASTLAB_EXPLOIT` (the attack input string). Without them, the default SQLite table and SQLi attack string are used.
- **One checker across three bug classes:** CWE-78 command-injection seeds run `echo` and return output lines (`SASTLAB_EXPLOIT = "1; echo PWNED"` returns 2 lines instead of 1); CWE-22 path-traversal seeds read files inside a temp folder (`"../secret"` reads a longer file than `"1"`). Bug classes needing a browser, TLS server, or web server (CWE-79, CWE-295, CWE-200) were left out.

### Test Sets

| Folder | Bug Class | Seeds | Source and Notes |
| --- | --- | ---: | --- |
| `seeds/` | CWE-89 | 15 | Custom f-string SQLite test programs (`seed_01`–`seed_15`); shared template |
| `seeds_diverse/` | CWE-89 | 12 | Custom varied shapes (`+`, `%`, `.format()`, f-strings, inline calls, etc.) |
| `seeds_fstring/` | CWE-89 | 3 | Subset of f-string seeds used for restricted Semgrep runs |
| `corpus_official/seeds/` | CWE-89 | 9 | Adapted from Semgrep (`a84ff9cc24`) and CodeQL (`codeql-cli/v2.27.1`) official test suites |
| `corpus_real/seeds/` | CWE-89 | 6 | Hand-adapted from OWASP BenchmarkPython (5) and `vulpy` (1) |
| `corpus_apps/seeds/` | CWE-89 | 5 | Hand-adapted functions from `parsl` `2025.12.22` (3), `scitokens` `1.8.1` (1), `pyload-ng` `0.5.0b3.dev90` (1) |
| `seeds_cmd/` | CWE-78 | 8 | Custom command-injection programs (`subprocess.*` and `os.popen`) |
| `seeds_path/` | CWE-22 | 8 | Custom path-traversal programs using built-in `open` |
| `seeds_pysa_hard/` | CWE-89 | 3 | Subset used for restricted Pysa searches |
| `seeds_pysa_hard2/` | CWE-89 | 3 | Second Pysa search check (`o03_semgrep`, `o18_semgrep`, `o24_codeql`) |
| `seeds_rerun_s05/` | CWE-89 | 1 | Single seed folder (`seed_05`) for campaign rerun |

#### Adapting Official and Real-World Programs

- **Official test suites (`corpus_official/seeds/`):** An external harvest script filtered upstream tests using the steps saved in `corpus_official/seeds/funnel.json`: 19 upstream files → 122 `.execute(...)` calls → 102 single-argument calls → 82 string-built queries → 53 straight-line slices with one user input → 24 unique programs → **9** runnable programs where the attack succeeds in SQLite. The script keeps the original SQL text and assignments, renames the user input to `user_id`, and runs the query on `db_conn.cursor()`. Parameterized queries, `INSERT`/`UPDATE` statements, table-name injections, and driver-specific syntax are dropped. These seeds therefore test how rules handle the query shapes from official tests, not the original database libraries. Origins are listed in `corpus_official/seeds/manifest.json`.
- **Benchmark programs (`corpus_real/seeds/`):** Adapted by hand because OWASP BenchmarkPython uses stateful helper methods; web request and DB wrappers were swapped out while keeping data flow intact.
- **Deployed apps (`corpus_apps/seeds/`):** Copied from vulnerable PyPI wheel packages (`corpus_apps/SOURCE.txt` lists SHA-256 hashes). SQL strings stay unchanged; DB calls run on SQLite, and the `pyLoad` function wraps returned IDs in 1-tuples to match row output.

---

## 3. Behavior Checker

Implemented in [`sastlab/oracle.py`](../sastlab/oracle.py) and [`sastlab/oracle_worker.py`](../sastlab/oracle_worker.py).

- **Isolated worker process:** `Oracle.evaluate(source)` creates a private temp folder (`tempfile.TemporaryDirectory(prefix="sastlab-oracle-...")`), sets `TMPDIR`/`TMP`/`TEMP` to it, and runs `python -I -B oracle_worker.py` with JSON `{"source": source}` on `stdin` and a default 5-second limit (`oracle_timeout`). The temp folder is deleted as soon as the call finishes or times out. This isolates files and state between runs, not untrusted code: run only trusted programs.
- **Default SQLite table and inputs:**
  - `DEFAULT_FIXTURE`: creates `users(id TEXT, username TEXT, role TEXT)` with `('1','alice','admin')`, `('2','bob','user')`, and `('3','carol','user')`.
  - Normal input: `"1"`.
  - Attack input: `SASTLAB_EXPLOIT` if defined by the seed, otherwise `"1' OR '1'='1"`.
- **Pass checks:**
  - **Working vulnerability (`Oracle.exploitable`):** `ok` is true, normal input returns `1` row, attack input returns more rows than normal input, and every normal row appears in the attack output.
  - **Same behavior (`Oracle.compare`):** baseline is exploitable, candidate `ok` is true, and `evaluated["outputs"] == baseline["outputs"]` (exact match in row values and order). Crashes and timeouts count as failures (`ok: False`, `equivalent: False`).
  - Because runtime checks run on 2 inputs per campaign attempt (and 20 inputs in follow-up scripts), they prove equal behavior on those tested inputs rather than for every possible Python input.

---

## 4. Code Rewrites and Bitmask IDs

Implemented in [`sastlab/transforms.py`](../sastlab/transforms.py).

### Bitmask Design

Each rewritten candidate is identified by `(seed, mask)` and its SHA-256 hash. Masks range from `0` to $2^{18} - 1$ (`262,143` non-empty sets). `candidate(source, mask)` always starts from the original seed AST and applies selected operators in fixed ascending bit order ($i = 0, 1, \dots, 17$). New operators are only added at the end of the list so older mask numbers always keep the exact same meaning.

### Supported Sinks and Rejections

- **Method sinks (`SINK_NAMES`):** `execute`, `check_output`, `run`, `call`, `check_call`, `popen`, `Popen`, `getoutput`.
- **Function sinks (`SINK_FUNCTIONS`):** `open`.
- **Rejected as `"invalid"` (when a rewrite does not apply):**
  - `format_swap` rejects queries that do not use f-strings or `+` concatenation (such as `%` or `.format()`).
  - Query rewrites (`format_swap`, `literal_slice`, `extract_1`, `extract_2`, `branch_split`) reject inline queries that lack a `query = ...` assignment.
  - `methodcaller_sink` rejects plain function calls (`open`) and non-variable receivers.
  - `unbound_sink` rejects plain functions (`open`) and module calls (`subprocess.run`, since `type(module).run` does not work), including modules imported locally inside the function or via `from ... import`.

### All 18 Operators

Search campaigns use operators `0..12`; all `18` (`0..17`) run in exhaustive checks and unit tests.

| Bit | Mask (`1<<bit`) | Operator | Group | What the Rewrite Does |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | `rename` | `control` | Renames parameters, locals, comprehension variables, and `except ... as` names to `_mt_*` names (without changing global names shadowed inside comprehensions). |
| 1 | 2 | `format_swap` | `control` | Rewrites f-strings (keeping conversion flags) to positional `str.format(...)`, or turns `+` joining into `"".join([...])`. |
| 2 | 4 | `literal_slice` | `control` | Adds `#` before SQL string constants and slices `[1:]` (inside f-strings, embeds as `{("#..."[1:])}` to keep valid syntax). |
| 3 | 8 | `dead_padding` | `control` | Inserts an always-false `if` block before the query assignment (or sink line if inline). |
| 4 | 16 | `extract_1` | `interprocedural` | Moves query building into one helper function, passing needed local variables (ignoring comprehension variables); keeps docstrings. |
| 5 | 32 | `extract_2` | `interprocedural` | Moves query building through two helper functions (adds three helper calls total when combined with `extract_1`). |
| 6 | 64 | `branch_split` | `control-flow` | Duplicates the query assignment across normal vs. non-normal `if`/`else` branches. |
| 7 | 128 | `dict_dispatch` | `sink-resolution` | Looks up the sink method in a literal dictionary before calling it. |
| 8 | 256 | `dynamic_sink` | `sink-resolution` | Replaces `.execute` (or other sinks) with `getattr(obj, "exe" + "cute")` (or split builtin `open`). |
| 9 | 512 | `char_launder` | `value-propagation` | Rebuilds user input at function entry via `"".join(chr(ord(c)) for c in x)`. |
| 10 | 1024 | `deep_nest` | `container` | Puts user input into 8 nested lists and reads it back via 8 `[0]` lookups. |
| 11 | 2048 | `db_roundtrip` | `second-order-storage` | Adds `import sqlite3 as _mt_sqlite3`, stores user input in an in-memory SQLite table, and reads it back. *(SQLite text columns would change invalid Unicode surrogate characters; none appear in tested inputs.)* |
| 12 | 4096 | `queue_roundtrip` | `container` | Adds `import queue as _mt_queue` and passes input through `queue.Queue`. |
| 13 | 8192 | `simplequeue_roundtrip` | `container` | Passes input through `queue.SimpleQueue` (exhaustive checks only). |
| 14 | 16384 | `pickle_roundtrip` | `value-propagation` | Adds `import pickle as _mt_pickle` and runs `pickle.loads(pickle.dumps(...))` (exhaustive checks only). |
| 15 | 32768 | `partial_sink` | `sink-resolution` | Adds `import functools as _mt_functools` and calls sink via `functools.partial(sink)(...)` (exhaustive checks only). |
| 16 | 65536 | `methodcaller_sink` | `sink-resolution` | Adds `import operator as _mt_operator` and calls `operator.methodcaller("<method>", ...)(receiver)` (exhaustive checks only). |
| 17 | 131072 | `unbound_sink` | `sink-resolution` | Calls method through its class: `type(receiver).<method>(receiver, ...)` (exhaustive checks only). |

---

## 5. Scanner Wrappers and Commands

Implemented in [`sastlab/scanners.py`](../sastlab/scanners.py). Each scan runs in its own folder under `work_dir` (default `.sastlab/runs/<uuid>/`). Any unexpected exit code, malformed JSON/SARIF, missing `subject.py` scan entry, or tool error notification yields `Scan("error", ...)` — errors never count as clean scans.

| Engine | Pinned Version | Files Given to Scanner | Exact CLI Command and Flags | Target Rules / Queries |
| --- | --- | --- | --- | --- |
| `semgrep` | `1.178.0` | `src/subject.py` (optionally adding `@app.route("/<user_input>")` if `semgrep_route: true`) + `src/web_entry.py` (Flask wrapper) | `semgrep scan --config <rules.yaml> --json --quiet --metrics=off --disable-version-check --no-git-ignore --no-rewrite-rule-ids <src>` (`SEMGREP_ENABLE_VERSION_CHECK=0` on `--version`) | CWE-89 pattern: `formatted-sql-query`<br>CWE-89 taint: `tainted-sql-string`<br>CWE-78: `dangerous-subprocess-use-audit`<br>CWE-22: `path-traversal-open` |
| `codeql` | CLI `2.27.1`, `python-queries` `1.8.11` | `src/subject.py` + `src/web_entry.py` (Flask wrapper) | 1. `codeql database create <db> --language=python --source-root=<src> --threads=1`<br>2. `codeql database analyze <db> <query> --format=sarifv2.1.0 --output=<sarif> --threads=1` | CWE-89: `py/sql-injection`<br>CWE-78: `py/command-line-injection`<br>CWE-22: `py/path-injection` |
| `pysa` | `pyre-check` `0.10.0`, stock models `d5614e0a` | `src/subject.py` typed with `sqlite3.Connection` (`typed_for_pysa`), `models/entry.pysa` (`TaintSource[UserControlled]`) OR `src/entry.py` (`BaseHTTPRequestHandler.path` if `pysa_source="http-server"`), plus local `pyrefly.toml` & `.pyre_configuration` | `pyre --noninteractive analyze --no-verify --save-results-to out` (`pyrefly.toml` stops Pyrefly from reading the repo's `.gitignore`/`pyproject.toml`) | CWE-89: `pysa/5005` (flow), `pysa/5051` (string combine)<br>CWE-78: `pysa/5001`, `pysa/6065`<br>CWE-22: `pysa/5011` |
| `bandit` | `1.9.4` | `src/subject.py` only (no Flask wrapper) | `bandit -q -f json <src>/subject.py` | CWE-89: `bandit/B608`<br>CWE-78: `bandit/B602`<br>*(No default CWE-22 rule)* |

### Wrapper Notes and Caching

- **Pysa setup choices:** `typed_for_pysa` adds `import sqlite3` and annotates the first parameter of `get_user_profile` as `sqlite3.Connection` so stock `sqlite3_sinks.pysa` recognizes `.execute`. `--no-verify` skips missing-library checks. `parse_pysa` requires a generated model for `subject.get_user_profile` or fails with an error. Unless `keep_database: true`, large temporary Pysa graphs (`call-graph.json`, `dependency-graph.json`, `invariants.json`, `taint-metadata.json`) and CodeQL `database/` folders (~10 MB each) are deleted after scanning.
- **Disk scan cache (`scan_cache`):** `scan_cache_settings(config, scanner)` hashes `(engine, scanner_version, rule_sha256, query, semgrep_route, pysa_source, pysa_codes)` plus `tree_digest(models)` for Pysa. Only passing (`status == "ok"`) scans are cached atomically by candidate SHA-256. Caching only avoids duplicate scanner work and never changes attempt counts.
- **Newer versions spot-checked:** Semgrep `1.182.1` and CodeQL `2.27.3` (`python-queries` `1.8.13`) were tested separately; all main runs use the pinned versions above.

---

## 6. Search Methods and Distance Metrics

Implemented in [`sastlab/search.py`](../sastlab/search.py).

Each walk $k \in \{1, \dots, T\}$ uses `random.Random(base_seed + k)` (default `base_seed = 6223`), allowed operators `operators` (or all 18), and order mode `order` (`"increasing"` default: only operators with higher index than the last applied bit can be added; `"any"`: any unused operator in the pool).

| ID | Code Name | How It Picks and Accepts Steps |
| ---: | --- | --- |
| `1` | `naive` (Random) | Picks uniformly from valid next operators; resets to `mask = 0` (at zero attempt cost) when none are left. Always accepts moves. |
| `2` | `blackbox` (Heuristic) | Scores valid next operators by `(child_mask not in visited, -uses_in_history, clean_verdicts_in_history)`, breaking ties randomly. |
| `3` | `blackbox_agent` (History-only) | Calls the LLM with `observation()` (`available` shuffled per call, `diff`, `verdict`, last 3 `history` entries) — **without** `diagnostics`. |
| `4` | `static_greybox` (Static ranking) | Asks the LLM **once per walk** to rank all operators using `rule_metadata`, then picks valid operators in that fixed rank order. |
| `5` | `trace_agent` (Diagnostic agent) | Calls the LLM with the exact same `observation()` fields as Strategy 3 **plus** `diagnostics` (filtered by `target_rules` and `diagnostic_fields`: `rule`, `message`, `sink`, `snippet`, `trace`). |
| `6` | `metric_syntax` (AST-distance Metropolis) | Toggles one operator bit uniformly (never picking `mask = 0`) and accepts with probability $\min(1, \exp(\Delta d_{\text{syntax}} / \tau))$, $\tau = 0.25$. |
| `7` | `metric_depth` (Call-depth Metropolis) | Same toggle and acceptance formula using $\Delta d_{\text{depth}}$, falling back to $\Delta d_{\text{syntax}}$ when call depth does not change. |

### Distance Scores and Restarts

- **`d_syntax` (`syntax_distance`):** Exact normalized edit distance (insertions/deletions via longest common subsequence) between AST token lists in preorder (node types and scalar values, ignoring line/column numbers).
- **`d_depth` (`call_depth`):** Longest chain of calls to generated helper functions starting from `get_user_profile`, ignoring library calls. Flow operators add no helper functions, so Strategy 7 falls back to `d_syntax` for flow steps.
- **Why Metropolis is a heuristic:** Because moves never target `mask = 0`, 1-operator subsets have one fewer neighbor than larger subsets and no Hastings correction is applied; Strategies 6 and 7 are search heuristics, not uniform samplers.
- **`metropolis_restart`:** When `metropolis_restart: true` (default in all saved runs except `semgrep-hard30-walk` and `pysa-hard-walk`), reaching the last operator of `order` (`available(mask)` empty) resets `mask = 0` before toggling a bit. Older saved runs recorded these resets as `restarted: false` (visible via `parent_mask`); current runs set `restarted: true`. Setting `metropolis_restart: false` toggles any bit from the current mask without restarting.

### Order Shuffling

`shuffled(names, seed)` shuffles candidate names using `call_seed = trajectory_seed * 100000 + attempt * 3` for Strategies 3 and 5, while `system_prompt` shuffles definitions with `f"system-{call_seed}"` so list order gives no hint.

---

## 7. LLM Client and API Format

Implemented in [`sastlab/llm.py`](../sastlab/llm.py). Exact prompt texts and `llm.prompt_extra` strings are listed in [`docs/prompts.md`](prompts.md).

- **API setup:** OpenAI-compatible `POST /v1/chat/completions` to NUS SoCLaaS (`https://soclaas-api.comp.nus.edu.sg/v1`) using `llama3.1:8b`, `qwen3-coder-next`, or `qwen3.6:35b`, `temperature = 0.2`, `stream = False`, `max_tokens = 160`, a fixed `seed`, and strict `response_format.type = "json_schema"`. API keys are read directly without running shell code, sent only in `Authorization: Bearer ...`, never followed across redirects (`NoRedirect`), and never written to logs or manifests.
- **Model version note:** SoCLaaS `/v1/models` returns model names with no weight checksum (`digest: None`, `identity_verified: False`). Do not assume another server with the same model name has identical weights.
- **Token limits and fair trimming (`bounded_observation`):** Reserves `128` tokens for chat headers, `len(SYSTEM.encode())` (safe UTF-8 byte upper bound covering all 18 operators), and `len(prompt_extra.encode())`, keeping `260` bytes reserved for diagnostics so Strategies 3 and 5 see **identical** `diff`, `history`, `verdict`, and `available` fields. If the prompt exceeds budget, `diff` halves, then `metadata` trims to 60 chars, oldest `history` drops, and `diff` empties. Diagnostics drop extra findings, shorten long traces (`compact_trace` keeps first 3, last 3, and `call_boundary` steps), trim messages to 40 chars, and drop code snippets. Returned `usage.prompt_tokens` is checked against `max_prompt_tokens` (`2,500` in original runs, `3,000` in informed runs and `pysa-hard-any`).
- **Retries and fallbacks:**
  - **Rate limits (`HTTP 429`):** Waits for `Retry-After` or doubles wait time up to `60 s` (max 8 waits), logging `rate_limit_waits` without spending validation retries.
  - **Invalid answers:** Missing `finish_reason == "stop"`, missing/over-limit `prompt_tokens`, invalid JSON, or invalid choices allow 3 total tries (`seed + retry`), then fall back to a uniform random choice marked `fallback: true`.

---

## 8. Running, Resuming, Output Files, and Scoring

Implemented in [`sastlab/runner.py`](../sastlab/runner.py), [`sastlab/exhaustive.py`](../sastlab/exhaustive.py), and [`sastlab/report.py`](../sastlab/report.py).

### Output Files in a Run Folder

| File | Created By | Fields Recorded |
| --- | --- | --- |
| `manifest.json` | `run` / `exhaustive` | `engine`, `config` / `identity`, `scanner_version`, `llm`, `python`, `platform`, `operators`, `state`, `rule_sha256`, `framework_sha256`, `seed_sha256`, `started`, `finished`, `resumes` |
| `qualifications.json` | `run` / `exhaustive` | List of `{seed, sha256, oracle, scan, qualifying_rules, artifacts}` |
| `attempts.jsonl` | `run` | `{seed, strategy, trajectory, trajectory_seed, attempt, parent_mask, mask, operator, operators, restarted, accepted, metric, candidate_sha256, duplicate_candidate, cache_hit, scanner_invoked, artifacts, scan, oracle, error, bypassed_rules, charged_seconds, elapsed_seconds}` |
| `evaluations.jsonl` | `exhaustive` | `{seed, mask, operators, status, equivalent, scan_status, scan_rules, findings, bypassed_rules, error, candidate_sha256, scan_seconds, elapsed_seconds}` |
| `llm.jsonl` | `run` | `{seed, strategy, trajectory, attempt, request, retry, fallback, response, decision}` (plus `rate_limit_waits`/`error` when triggered) |
| `trajectories.json` | `run` | List of `{seed, strategy, trajectory, masks, duplicate_of_trajectory}` |
| `summary.json` | `run` / `exhaustive` / `report` | Search: `{engine, report_cards, strategy_metrics, qualification_failures}`; exhaustive: `{seeds, total_evaluated, total_evading, total_scan_errors, complete}` |
| `discarded-partial.jsonl` | `run --resume` | Incomplete walks discarded on resume so interrupted runs never mix walks |
| `bypasses/<seed>/<mask>.{py,json}` | `run` | Rewritten evading code and its check record |

### Resuming Runs Safely

- **Checkpoint unit:** `run` checkpoints complete walks `(seed, strategy, trajectory)` and restarts unfinished walks from scratch so two runs are never mixed. `exhaustive` checkpoints every completed `(seed, mask)` row.
- **Checks on `--resume` / `--rerun-errors`:** Confirms `engine`, `scanner_version`, `llm`, `rule_sha256`, `seed_sha256`, `config` (ignoring `scanner_timeout`), and `operators` match (later added operators are allowed if `config["operators"]` pins an earlier pool). Baseline scan failures stop `exhaustive` safely (resumable via `--resume`) and make `run` exit `1` after finishing other seeds (`--rerun-errors` repairs missed baselines/scans).
- **Check order (`subset_masks`):** Checks non-empty subsets of `operators` (up to `max_ops`) from fewest rewrites to most, then by bitmask integer.

### Report-Card Labels and Statistics

Implemented in `summarize` (`sastlab/report.py`) and `analysis/common.py`:

1. **Qualifying seeds ($S_{\text{rule}}$):** Seeds where baseline scan is `"ok"`, the target rule fires, and the exploit passes the behavior check.
2. **Threshold ($\tau$):** $\tau = \lceil S_{\text{rule}} / 2 \rceil$. Runs with $3 \le S_{\text{rule}} \le 5$ set `"exploratory": true` (small sample); fewer than 3 seeds are `"excluded"`.
3. **Rule labels (checked in order):**
   - `incomplete`: `manifest["state"] != "complete"`, missing strategies, failed baseline/qualifying scans or behavior checks, or budget $\neq 30 \times 5$.
   - `weak`: Strategy `1` (random) or Strategy `2` (heuristic) alone bypasses $\ge \tau$ seeds.
   - `guidance-sensitive`: any of Strategies `3..7` alone—or all 7 combined—bypasses $\ge \tau$ seeds.
   - `robust`: completed full-budget run where no strategy or union reaches $\tau$.
   - Records `individual_crossing` and `portfolio_first_crossing_after_strategy` in strategy ID order `1..7`.
4. **Statistical intervals (`analysis/common.py`):**
   - **Full campaigns:** Counts unique evading candidates per walk, using paired 95% percentile bootstrap (`5,000` resamples, seed `11`) and sign-flip tests across `(seed, trajectory)` pairs.
   - **Restricted pools:** Counts attempts to first evasion (no evasion = `budget + 1`), averaged per walk stream ($k \in \{1..T\}$) before computing the 5,000-resample paired bootstrap interval. Because synthetic seeds share structure, streams—not seeds—are treated as independent samples.

---

## 9. Main Design Choices and Trade-offs

| Topic | Choice Made | Why |
| --- | --- | --- |
| Append-only bitmasks | `CORE_OPERATORS` (8) + `FLOW_OPERATORS` (5→7) + `SINK_OPERATORS` (3) | Expanding from 8 → 13 → 18 operators keeps every existing mask number valid. |
| Shuffled prompt order | Per-request shuffle via `system-{seed}` and `call_seed` | Fixed ordering (`rename` first in full campaigns) caused strong first-item bias (`prompt-order-probe`). |
| Two comparison metrics | Unique evasions/walk (full); attempts to first evasion (restricted) | On unrestricted Semgrep, one rewrite succeeds right away so time-to-first cannot separate strategies. |
| Bit-flip Metropolis | Toggle bits on non-zero masks + optional `metropolis_restart` | Add-only steps cannot shrink syntax distance, turning Strategies 6 and 7 into plain random walks. |
| Isolated checker subprocess | `-I -B` Python subprocess + temp `TMPDIR` per check | Stops path-traversal/DB state from leaking between checks using only Python's standard library. |
| Scanner isolation | Per-scan `pyrefly.toml` + `work_dir` outside repo tree | Prevents Pysa/Pyrefly from scanning the whole repo and avoids git overhead in Semgrep. |
