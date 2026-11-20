# Technical Specification and Methodology

Architecture, data contracts, operator definitions, scanner adapters, search algorithms, and evaluation rules required to understand or re-implement SASTLab.

## Contents

- [1. Problem Formulation and Metamorphic Relation](#1-problem-formulation-and-metamorphic-relation)
- [2. Seed Contract and Corpora](#2-seed-contract-and-corpora)
- [3. Behavior-Equivalence Oracle](#3-behavior-equivalence-oracle)
- [4. AST Rewrite Operators and Bitmask Encoding](#4-ast-rewrite-operators-and-bitmask-encoding)
- [5. Scanner Adapters and Invocation Contracts](#5-scanner-adapters-and-invocation-contracts)
- [6. Search Strategies and Distance Metrics](#6-search-strategies-and-distance-metrics)
- [7. LLM Client and Wire Protocol](#7-llm-client-and-wire-protocol)
- [8. Execution, Checkpointing, Artifacts, and Report-Card Rules](#8-execution-checkpointing-artifacts-and-report-card-rules)
- [9. Key Design Decisions and Trade-offs](#9-key-design-decisions-and-trade-offs)

---

## 1. Problem Formulation and Metamorphic Relation

SASTLab performs single-engine **metamorphic testing** (not differential testing across scanners). For a target scanner rule $R$, seed program $P$, and composition $T$ of behavior-preserving AST operators:

$$\text{flagged}_R(P) \;\land\; \text{behavior}(T(P)) = \text{behavior}(P) \implies \text{flagged}_R(T(P))$$

Every violation is a verified false negative on code whose tested exploit behavior still matches $P$:

1. **Qualification (precondition):** On $P$, the scanner executes cleanly (`scan.status == "ok"`), rule $R$ fires, and the oracle confirms the vulnerability is live on the nominal and injection inputs.
2. **Evasion (violation):** On $T(P)$, the oracle confirms identical output on both inputs (`equivalent == True`), the scanner finishes cleanly (`scan.status == "ok"`), and $R$ no longer reports a finding.

A scanner timeout, parse failure, or crash fails closed and never counts as an evasion. In multi-rule configurations (such as Pysa SQL injection), `evasion: "any"` (default) succeeds when at least one qualifying rule stops firing, whereas `evasion: "all"` requires **every** qualifying rule on $P$ to stop firing. Exhaustive evaluations always record `scan_rules` and per-rule `bypassed_rules` so either view can be computed afterward.

Unlike TaintCC (Christakis et al., ISSTA), which holds reported source-to-sink flows invariant without requiring runtime equivalence, SASTLab checks runtime behavior because an evasion only demonstrates a missed vulnerability if the exploit remains live.

---

## 2. Seed Contract and Corpora

### Python Entry-Point Contract

Every seed program across all three vulnerability classes (CWE-89 SQL injection, CWE-78 command injection, CWE-22 path traversal) implements one top-level function:

```python
def get_user_profile(db_conn, user_id):
    ...
    return rows  # list of sequences/values
```

Constraints and behavior rules enforced by `sastlab/transforms.py` and `sastlab/oracle_worker.py`:

- **Reserved identifiers:** Seeds must not define names prefixed with `_mt_` or contain nested function definitions inside `get_user_profile`.
- **Query assignment (`query_assignment`):** Assignment-dependent operators (`format_swap`, `literal_slice`, `extract_1`, `extract_2`, `branch_split`) expect a top-level `query = ...` statement feeding `.execute(query)`. Inline calls (such as `cursor.execute(f"...")`) have no such assignment: `rename` and `dead_padding` still apply (anchoring on the sink statement), while the five query-rewriting operators reject the seed as `"invalid"` rather than silently skipping.
- **Supported formatting:** String formatting uses f-strings (without format specs), `%`, `str.format()`, or `+` concatenation.
- **Custom oracle fixtures:** A seed may define module constants `SASTLAB_FIXTURE` (SQLite schema/data setup script) and `SASTLAB_EXPLOIT` (class-appropriate injection payload). Seeds without them use the default SQLite fixture and SQLi payload.
- **Reused oracle across vulnerability classes:** CWE-78 seeds execute `echo` commands and return output lines (`SASTLAB_EXPLOIT = "1; echo PWNED"` produces 2 lines vs. 1 for `"1"`); CWE-22 seeds open files inside a per-seed temporary fixture directory (`"../secret"` reads a file with more lines than `"1"`). Classes requiring fundamentally different exploit checks (CWE-79 XSS rendering, CWE-295 TLS validation, CWE-200 HTTP metadata) were excluded.

### Corpora

| Directory | Class | Count | Origin and Notes |
| --- | --- | ---: | --- |
| `seeds/` | CWE-89 | 15 | Synthetic f-string SQLite fixtures (`seed_01`–`seed_15`); shared structure |
| `seeds_diverse/` | CWE-89 | 12 | Synthetic varied constructions (`+`, `%`, `.format()`, f-strings, inline, etc.) |
| `seeds_fstring/` | CWE-89 | 3 | Subset of f-string seeds used for restricted Semgrep search campaigns |
| `corpus_official/seeds/` | CWE-89 | 9 | Harvested from Semgrep (`a84ff9cc24`) and CodeQL (`codeql-cli/v2.27.1`) suites |
| `corpus_real/seeds/` | CWE-89 | 6 | Hand-adapted from OWASP BenchmarkPython (5) and `vulpy` (1) |
| `corpus_apps/seeds/` | CWE-89 | 5 | Hand-adapted from `parsl` `2025.12.22` (3), `scitokens` `1.8.1` (1), `pyload-ng` `0.5.0b3.dev90` (1) |
| `seeds_cmd/` | CWE-78 | 8 | Synthetic command-injection programs (`subprocess.*` and `os.popen`) |
| `seeds_path/` | CWE-22 | 8 | Synthetic path-traversal programs using built-in `open` |
| `seeds_pysa_hard/` | CWE-89 | 3 | Synthetic hard-pool seed subset for Pysa search |
| `seeds_pysa_hard2/` | CWE-89 | 3 | Official-suite check subset (`o03_semgrep`, `o18_semgrep`, `o24_codeql`) for Pysa search |
| `seeds_rerun_s05/` | CWE-89 | 1 | Single-seed rerun directory (`seed_05`) |

#### Adaptation of Official, Benchmark, and Deployed Corpora

- **Official-suite harvest (`corpus_official/seeds/`):** An unshipped harvest script filtered upstream test suites using the funnel recorded in `corpus_official/seeds/funnel.json`: 19 upstream files → 122 `.execute(...)` calls → 102 single-argument calls → 82 string-constructed queries → 53 straight-line slices with one external input → 24 distinct adapted programs → **9** executable and exploit-live under the SQLite oracle. Adaptation preserves the backward slice and exact SQL text while normalizing input to `user_id` and execution to `db_conn.cursor()`. Parameterized queries, `INSERT`/`UPDATE` statements, table-name injections, and driver-specific syntax were dropped. Consequently, official seeds evaluate the query shapes from upstream tests rather than upstream framework/driver models. Each seed's origin is recorded in `corpus_official/seeds/manifest.json`.
- **Independent benchmark (`corpus_real/seeds/`):** Hand-adapted rather than sliced because BenchmarkPython flows pass through stateful helper methods; request/response wrappers were replaced while value propagation was kept intact.
- **Deployed projects (`corpus_apps/seeds/`):** Extracted from vulnerable PyPI wheels (`corpus_apps/SOURCE.txt` records SHA-256 digests). SQL text is untouched; driver connections use the oracle's SQLite cursor, and `pyLoad` returns IDs as 1-tuples to match row output.

---

## 3. Behavior-Equivalence Oracle

Implemented in [`sastlab/oracle.py`](../sastlab/oracle.py) and [`sastlab/oracle_worker.py`](../sastlab/oracle_worker.py).

- **Isolated worker execution:** `Oracle.evaluate(source)` creates a private temporary directory (`tempfile.TemporaryDirectory(prefix="sastlab-oracle-...")`), exports `TMPDIR`/`TMP`/`TEMP` to that scratch folder, and invokes `python -I -B oracle_worker.py` with a JSON payload `{"source": source}` on `stdin` and a default 5-second timeout (`oracle_timeout`). The worker isolates state and runtime, not untrusted code: run only trusted programs. Temporary directories are always removed on exit or timeout.
- **Default database & payloads:**
  - `DEFAULT_FIXTURE`: creates `users(id TEXT, username TEXT, role TEXT)` with `('1','alice','admin')`, `('2','bob','user')`, `('3','carol','user')`.
  - Nominal payload: `"1"`.
  - Injection payload: `SASTLAB_EXPLOIT` if defined by the seed, else `"1' OR '1'='1"`.
- **Exploitability & equivalence predicates:**
  - **Exploitable baseline (`Oracle.exploitable`):** `ok` is true, `len(nominal) == 1`, `len(exploit) > len(nominal)`, and every row in `nominal` appears in `exploit`.
  - **Equivalence (`Oracle.compare`):** `Oracle.exploitable(baseline)` holds, candidate `ok` is true, and `evaluated["outputs"] == baseline["outputs"]` (exact equality on row lists, order, and projected values). Exceptions and timeouts fail closed (`ok: False`, `equivalent: False`).
  - Because runtime equality is verified on two inputs per run (and 20 inputs in post-hoc checks), equivalence is **input-bounded**, not a universal proof over all Python inputs.

---

## 4. AST Rewrite Operators and Bitmask Encoding

Implemented in [`sastlab/transforms.py`](../sastlab/transforms.py).

### Canonical Bitmask Construction

A candidate program is uniquely identified by `(seed, mask)` and its SHA-256 hash. Valid masks span `0` to $2^{18} - 1$ (`262,143` non-empty subsets). `candidate(source, mask)` always starts from the unmodified `seed` AST and applies each selected operator $i$ (where bit `(mask >> i) & 1` is `1`) in canonical ascending order $i = 0, 1, \dots, 17$. New operators are strictly appended at higher bit indices so existing mask integers never change meaning.

### Supported Sinks and Rejection Rules

- **Attribute sinks (`SINK_NAMES`):** `execute`, `check_output`, `run`, `call`, `check_call`, `popen`, `Popen`, `getoutput`.
- **Plain-function sinks (`SINK_FUNCTIONS`):** `open`.
- **Inapplicability (rejected as `"invalid"`):**
  - `format_swap` rejects non-f-string, non-`+`-concatenation queries (e.g., `%` or `.format()`).
  - Query-rewriting operators (`format_swap`, `literal_slice`, `extract_1`, `extract_2`, `branch_split`) reject inline queries without a top-level `query` assignment.
  - `methodcaller_sink` rejects plain-function calls (`open`) and non-variable receivers.
  - `unbound_sink` rejects plain functions (`open`) and module receivers (`subprocess.run`, etc., because `type(module).run` is not the module function), including locally imported modules and `from ... import`.

### Operator Catalog

The first 13 operators (bits `0..12`) were active in the full search campaigns; all 18 (including bits `13..17`) are covered by exhaustive runs and tests.

| Bit | Mask (`1<<bit`) | Operator | Taxonomy Group | Transformation Specification |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | `rename` | `control` | Renames parameters, locals, comprehension targets, and `except ... as` names to deterministic `_mt_*` identifiers (preserving globals shadowed inside comprehensions). |
| 1 | 2 | `format_swap` | `control` | Rewrites f-strings (preserving conversion flags) to positional `str.format(...)`, or flattens `+` additions into `"".join([...])`. |
| 2 | 4 | `literal_slice` | `control` | Prefixes query string literals with `#` and slices `[1:]` (inside f-strings, embeds as a formatted expression so the AST remains valid). |
| 3 | 8 | `dead_padding` | `control` | Inserts an always-false conditional branch immediately before the query assignment (or sink statement if inline). |
| 4 | 16 | `extract_1` | `interprocedural` | Moves query construction into one generated helper function, passing referenced locals (excluding comprehension-bound names); preserves docstrings. |
| 5 | 32 | `extract_2` | `interprocedural` | Moves current query construction through two generated helper functions (three local call hops when combined with `extract_1`). |
| 6 | 64 | `branch_split` | `control-flow` | Duplicates the query assignment across nominal vs. non-nominal conditional branches. |
| 7 | 128 | `dict_dispatch` | `sink-resolution` | Routes sink method invocation through a constant-key literal dictionary lookup. |
| 8 | 256 | `dynamic_sink` | `sink-resolution` | Replaces `.execute` (or `SINK_NAMES`/`SINK_FUNCTIONS`) with `getattr(obj, "exe" + "cute")` (or split builtin `open` lookup). |
| 9 | 512 | `char_launder` | `value-propagation` | Rebinds user input at function entry to `"".join(chr(ord(c)) for c in x)`. |
| 10 | 1024 | `deep_nest` | `container` | Boxes user input in 8 nested lists and unboxes via 8 constant `[0]` indices. |
| 11 | 2048 | `db_roundtrip` | `second-order-storage` | Inserts `import sqlite3 as _mt_sqlite3`, stores input in an in-memory SQLite table, and reads it back. *(Note: SQLite text storage would alter lone UTF-16 surrogates; none appear in tested inputs.)* |
| 12 | 4096 | `queue_roundtrip` | `container` | Inserts `import queue as _mt_queue` and passes input through `queue.Queue`. |
| 13 | 8192 | `simplequeue_roundtrip` | `container` | Passes input through `queue.SimpleQueue` (exhaustive-only). |
| 14 | 16384 | `pickle_roundtrip` | `value-propagation` | Inserts `import pickle as _mt_pickle` and round-trips input via `pickle.loads(pickle.dumps(...))` (exhaustive-only). |
| 15 | 32768 | `partial_sink` | `sink-resolution` | Inserts `import functools as _mt_functools` and calls sink via `functools.partial(sink)(...)` (exhaustive-only). |
| 16 | 65536 | `methodcaller_sink` | `sink-resolution` | Inserts `import operator as _mt_operator` and calls `operator.methodcaller("<method>", ...)(receiver)` (exhaustive-only). |
| 17 | 131072 | `unbound_sink` | `sink-resolution` | Calls bound method via `type(receiver).<method>(receiver, ...)` (exhaustive-only). |

---

## 5. Scanner Adapters and Invocation Contracts

Implemented in [`sastlab/scanners.py`](../sastlab/scanners.py). Every scan writes isolated per-attempt files under `work_dir` (default `.sastlab/runs/<uuid>/`), invokes the pinned binary, and parses structured output **fail-closed** (any non-zero unexpected exit code, malformed output, missing `subject.py` scan metric/path, or tool execution notification yields `Scan("error", ...)`).

| Engine | Pinned Version | Files Provided to Scanner | Exact CLI Invocation & Key Flags | Rules / Query Targets |
| --- | --- | --- | --- | --- |
| `semgrep` | `1.178.0` | `src/subject.py` (optionally prefixed with `@app.route("/<user_input>")` when `semgrep_route: true`) + `src/web_entry.py` (Flask route wrapper) | `semgrep scan --config <rules.yaml> --json --quiet --metrics=off --disable-version-check --no-git-ignore --no-rewrite-rule-ids <src>` (`SEMGREP_ENABLE_VERSION_CHECK=0` for `--version`) | CWE-89 pattern: `formatted-sql-query`<br>CWE-89 taint: `tainted-sql-string`<br>CWE-78: `dangerous-subprocess-use-audit`<br>CWE-22: `path-traversal-open` |
| `codeql` | CLI `2.27.1`, `python-queries` `1.8.11` | `src/subject.py` + `src/web_entry.py` (Flask route wrapper) | 1. `codeql database create <db> --language=python --source-root=<src> --threads=1`<br>2. `codeql database analyze <db> <query> --format=sarifv2.1.0 --output=<sarif> --threads=1` | CWE-89: `py/sql-injection`<br>CWE-78: `py/command-line-injection`<br>CWE-22: `py/path-injection` |
| `pysa` | `pyre-check` `0.10.0`, stock models `d5614e0a` | `src/subject.py` annotated with `sqlite3.Connection` (`typed_for_pysa`), generated `models/entry.pysa` (`TaintSource[UserControlled]`) OR `src/entry.py` (`BaseHTTPRequestHandler.path` when `pysa_source="http-server"`), plus isolated `pyrefly.toml` & `.pyre_configuration` | `pyre --noninteractive analyze --no-verify --save-results-to out` (isolated from repo `pyproject.toml`/`.gitignore` via local `pyrefly.toml`) | CWE-89: `pysa/5005` (flow), `pysa/5051` (string combine)<br>CWE-78: `pysa/5001`, `pysa/6065`<br>CWE-22: `pysa/5011` |
| `bandit` | `1.9.4` | `src/subject.py` alone (no Flask wrapper) | `bandit -q -f json <src>/subject.py` | CWE-89: `bandit/B608`<br>CWE-78: `bandit/B602`<br>*(No default CWE-22 check)* |

### Key Implementation Details

- **Pysa adapter design choices:** `typed_for_pysa` adds `import sqlite3` and annotates the first parameter of `get_user_profile` as `sqlite3.Connection` so stock `sqlite3_sinks.pysa` resolves `.execute`; `--no-verify` disables verification against uninstalled third-party stubs; `parse_pysa` verifies a `model` entry exists for `subject.get_user_profile` and fails closed otherwise. Unless `keep_database: true`, large Pysa intermediate artifacts (`call-graph.json`, `dependency-graph.json`, `invariants.json`, `taint-metadata.json`) and CodeQL `database/` directories (~10 MB each) are removed after parsing.
- **Persistent scan cache (`scan_cache`):** When enabled, `scan_cache_settings(config, scanner)` hashes `(engine, scanner_version, rule_sha256, query, semgrep_route, pysa_source, pysa_codes)` plus `tree_digest(models)` for Pysa. Cached entries are written atomically and store only successful (`status == "ok"`) scans keyed by candidate SHA-256. Caching changes physical compute time only, never attempt accounting.
- **Newer-release verification:** Standalone checks also tested Semgrep `1.182.1` and CodeQL `2.27.3` (`python-queries` `1.8.13`); all primary results use the pinned versions in the table above.

---

## 6. Search Strategies and Distance Metrics

Implemented in [`sastlab/search.py`](../sastlab/search.py).

Each trajectory $k \in \{1, \dots, T\}$ runs with deterministic PRNG `random.Random(base_seed + k)` (`base_seed = 6223` by default), candidate pool `operators` (or all 18), and order constraint `order` (`"increasing"` default: only operators with higher index than the highest set bit; `"any"`: any unset operator in `pool`).

| ID | Code Name | Selection & Acceptance Rule |
| ---: | --- | --- |
| `1` | `naive` (Random) | Uniformly samples from valid next operators; restarts from `mask = 0` (at no attempt cost) when no valid operator remains. Always accepts moves. |
| `2` | `blackbox` (Heuristic) | Scores each valid next operator by tuple `(child_mask not in visited, -uses_in_history, clean_verdicts_in_history)`, breaking ties with trajectory PRNG. |
| `3` | `blackbox_agent` (History-only) | Queries the LLM with `observation()` (`available` shuffled per call, `diff`, `verdict`, last 3 `history` entries) — **no** `diagnostics` field. |
| `4` | `static_greybox` (Static ranking) | Queries the LLM **once per trajectory** (`Rank all operators once` using `rule_metadata` and shuffled `available`) and deterministically follows that ranking across steps. |
| `5` | `trace_agent` (Diagnostic agent) | Queries the LLM with the identical `observation()` fields as Strategy 3 **plus** `diagnostics` (filtered by `target_rules` and optional `diagnostic_fields`: `rule`, `message`, `sink`, `snippet`, `trace`). |
| `6` | `metric_syntax` (AST-distance Metropolis) | Toggles one operator bit uniformly from `flips` (excluding transition to `mask = 0`) and accepts with probability $\min(1, \exp(\Delta d_{\text{syntax}} / \tau))$, $\tau = 0.25$. |
| `7` | `metric_depth` (Call-depth Metropolis) | Same toggle and acceptance rule using $\Delta d_{\text{depth}}$ (fallback to $\Delta d_{\text{syntax}}$ when call depth is unchanged). |

### Distance Metrics and Metropolis Restarts

- **`d_syntax` (`syntax_distance`):** Exact normalized insertion/deletion distance computed via longest common subsequence over AST preorder token sequences (node types and scalar fields; line/column offsets excluded). This is a sequence metric over AST tokens, not tree-edit distance.
- **`d_depth` (`call_depth`):** Maximum reachable local helper-call chain length starting from `get_user_profile`, ignoring library/database calls. Flow operators do not add local helper calls, so Strategy 7 falls back to `d_syntax` on flow-only moves.
- **No Hastings correction:** Because proposals never target `mask = 0`, single-operator states have one fewer neighbor than multi-operator states and no correction factor is applied; Metropolis serves as an optimization heuristic, not a uniform sampler.
- **`metropolis_restart`:** With `metropolis_restart: true` (default, active in all saved runs except `semgrep-hard30-walk` and `pysa-hard-walk`), when `available(mask)` is empty (state holds the last operator of `order`), `Search.select` resets parent to `mask = 0` before proposing a flip. Saved pre-flag runs recorded those jumps with `restarted: false` (`parent_mask` reveals the reset); current runs record `restarted: true`. Setting `metropolis_restart: false` toggles any bit from the current mask without restarting.

### Deterministic Shuffling

To eliminate positional bias, `shuffled(names, seed)` samples candidate choices with `call_seed = trajectory_seed * 100000 + attempt * 3` for Strategies 3 & 5, while `system_prompt` uses `f"system-{call_seed}"` so definition order and choice list order vary independently.

---

## 7. LLM Client and Wire Protocol

Implemented in [`sastlab/llm.py`](../sastlab/llm.py). Exact prompt texts and `llm.prompt_extra` configurations are documented in [`docs/prompts.md`](prompts.md).

- **Endpoint & parameters:** OpenAI-compatible `POST /v1/chat/completions` against NUS SoCLaaS (`https://soclaas-api.comp.nus.edu.sg/v1`) for models `llama3.1:8b`, `qwen3-coder-next`, and `qwen3.6:35b`, with `temperature = 0.2`, `stream = False`, `max_tokens = 160`, deterministic `seed`, and `response_format.type = "json_schema"` (`strict: true`). Credentials are read from environment/env-file without shell execution, sent only in `Authorization: Bearer ...`, blocked across HTTP redirects (`NoRedirect`), and omitted from logs/manifests.
- **Model identity caveat:** SoCLaaS `/v1/models` exposes model IDs without weight digests (`digest: None`, `identity_verified: False`). Cross-stack comparisons must not assume identical server weights or sampling without pinned weight digests.
- **Token budget & symmetric truncation (`bounded_observation`):** Reserves `128` tokens for chat framing, `len(SYSTEM.encode())` (worst-case all-18-operator UTF-8 byte bound), and `len(prompt_extra.encode())`, leaving `260` bytes reserved for diagnostics so that Strategy 3 and Strategy 5 receive **byte-identical** common fields (`diff`, `history`, `verdict`, `available`). If over budget, `diff` halves, then `metadata` trims to 60 chars, then oldest `history` entries drop, then `diff` empties. Diagnostics trim extra findings, collapse long `trace` lists via `compact_trace` (keeping first 3, last 3, and `call_boundary` steps), shorten messages to 40 chars, and drop snippets. Server-returned `usage.prompt_tokens` is verified post-response against `max_prompt_tokens` (`2,500` in original-prompt runs, `3,000` in informed runs and `pysa-hard-any`).
- **Retries & fallbacks:**
  - **HTTP 429:** Waits honoring `Retry-After` or exponential backoff (`backoff_base * 2**k`, capped at `60 s`, max 8 waits), logging `rate_limit_waits` without consuming validation retries.
  - **Validation errors & fallback:** Missing `finish_reason == "stop"`, missing/over-budget `prompt_tokens`, non-schema JSON, or invalid operator/permutation triggers up to 3 total attempts (`seed + retry`), followed by a uniform trajectory-PRNG fallback logged with `fallback: true`.

---

## 8. Execution, Checkpointing, Artifacts, and Report-Card Rules

Implemented in [`sastlab/runner.py`](../sastlab/runner.py), [`sastlab/exhaustive.py`](../sastlab/exhaustive.py), and [`sastlab/report.py`](../sastlab/report.py).

### Artifact Directory Layout & Schemas

| File | Produced By | Key Schema Fields |
| --- | --- | --- |
| `manifest.json` | `run` / `exhaustive` | `engine`, `config` / `identity`, `scanner_version`, `llm`, `python`, `platform`, `operators`, `state`, `rule_sha256`, `framework_sha256`, `seed_sha256`, `started`, `finished`, `resumes` |
| `qualifications.json` | `run` / `exhaustive` | List of `{seed, sha256, oracle, scan, qualifying_rules, artifacts}` |
| `attempts.jsonl` | `run` | `{seed, strategy, trajectory, trajectory_seed, attempt, parent_mask, mask, operator, operators, restarted, accepted, metric, candidate_sha256, duplicate_candidate, cache_hit, scanner_invoked, artifacts, scan, oracle, error, bypassed_rules, charged_seconds, elapsed_seconds}` |
| `evaluations.jsonl` | `exhaustive` | `{seed, mask, operators, status, equivalent, scan_status, scan_rules, findings, bypassed_rules, error, candidate_sha256, scan_seconds, elapsed_seconds}` |
| `llm.jsonl` | `run` | `{seed, strategy, trajectory, attempt, request, retry, fallback, response, decision}` (plus `rate_limit_waits`/`error` if raised) |
| `trajectories.json` | `run` | List of `{seed, strategy, trajectory, masks, duplicate_of_trajectory}` |
| `summary.json` | `run` / `exhaustive` / `report` | For search: `{engine, report_cards, strategy_metrics, qualification_failures}`; for exhaustive: `{seeds, total_evaluated, total_evading, total_scan_errors, complete}` |
| `discarded-partial.jsonl` | `run --resume` | Incomplete trajectories discarded on resume so walks never splice across runs |
| `bypasses/<seed>/<mask>.{py,json}` | `run` | Saved evading candidate source and evidence record |

### Checkpointing & Resume Guarantees

- **Unit of checkpointing:** An entire trajectory `(seed, strategy, trajectory)` in `run` (discarded and restarted from scratch if incomplete, preserving complete walks cleanly) and individual `(seed, mask)` rows in `exhaustive`.
- **Resume validation (`--resume`, `--rerun-errors`):** Verifies `engine`, `scanner_version`, `llm`, `rule_sha256`, `seed_sha256`, `config` (ignoring `scanner_timeout`), and `operators` (allowing appended operators only when `config["operators"]` explicitly pins a previously recorded pool). Baseline scan failures halt `exhaustive` cleanly (resumable via `--resume`) and cause `run` to exit `1` cleanly after finishing other seeds (`--rerun-errors` repairs failed scans/trajectories).
- **Exhaustive order (`subset_masks`):** Enumerates non-empty subsets of `operators` (up to `max_ops` if specified) sorted by cardinality `bin(mask).count("1")`, then bitmask integer.

### Report-Card & Statistical Evaluation Rules

Implemented in `summarize` (`sastlab/report.py`) and `analysis/common.py`:

1. **Qualification count ($S_{\text{rule}}$):** Number of seeds where the baseline scan is `"ok"`, the rule fired, and the baseline exploit is live.
2. **Threshold ($\tau$):** $\tau = \lceil S_{\text{rule}} / 2 \rceil$. Corpora with $3 \le S_{\text{rule}} \le 5$ are flagged `exploratory: true`; fewer than 3 qualifying seeds classify as `excluded`.
3. **Rule classification (evaluated in priority order):**
   - `incomplete` if `manifest["state"] != "complete"`, fewer than all 7 strategies ran, any baseline/qualifying-seed scan or oracle call failed, or budget $\neq 30 \times 5$.
   - `weak` if Strategy `1` or Strategy `2` individually bypasses $\ge \tau$ seeds.
   - `guidance-sensitive` if any of Strategies `3..7` individually—or the 7-strategy portfolio union—bypasses $\ge \tau$ seeds.
   - `robust` if none of the above crossed $\tau$ on a completed full-budget campaign.
   - Reports record `individual_crossing` and `portfolio_first_crossing_after_strategy` in strategy-ID order `1..7` (portfolio order, not chronological order).
4. **Statistical comparisons (`analysis/common.py`):**
   - **Full campaigns:** Distinct evading candidates per trajectory, compared across paired `(seed, trajectory)` units with 95% percentile bootstrap intervals (`5,000` resamples, RNG seed `11`) and sign-flip permutation tests.
   - **Restricted pools:** Attempts to first evasion (missing evasion encoded as `budget + 1`), averaged across seeds per trajectory stream ($k \in \{1..T\}$) before computing the 5,000-resample stream-paired bootstrap interval. Because synthetic seeds share structure, streams—not individual seeds—are treated as independent units.

---

## 9. Key Design Decisions and Trade-offs

| Area | Design Decision | Engineering Rationale |
| --- | --- | --- |
| Append-only operators | `CORE_OPERATORS` (8) + `FLOW_OPERATORS` (5→7) + `SINK_OPERATORS` (3) | Expanding from 8 → 13 → 18 operators preserves all historical bitmask integers (`mask`). |
| Prompt order randomization | Per-request shuffling via `system-{seed}` and `call_seed` | Fixed canonical ordering (`rename` first in full campaigns) induced heavy first-item bias (`prompt-order-probe`). |
| Evasion metric choice | Distinct evasions/trajectory (full); attempts-to-first (restricted) | One operator suffices against Semgrep pattern rules, saturating first-evasion latency on unrestricted pools. |
| Metropolis toggling | Bit-flip proposals on non-zero masks + optional `metropolis_restart` | Forward-only addition cannot decrease syntactic distance and degenerated strategies 6 & 7 into random walks. |
| Process-isolated oracle | `-I -B` subprocess + disposable `TMPDIR` per check | Prevents filesystem/module state bleed between path-traversal and DB evaluations while keeping zero non-stdlib dependencies. |
| Scanner isolation | Per-attempt `pyrefly.toml` + temporary `work_dir` outside repo tree | Prevents Pysa/Pyrefly from crawling repo `.gitignore`/`pyproject.toml` and avoids git-tree overhead on Semgrep. |
