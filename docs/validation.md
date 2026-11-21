# Verification and Integrity Checks

Record of all checks verifying the scanners, unit tests, behavior preservation, consistent verdicts, independent re-scans, and saved campaign files.

- **Environment:** Linux x86-64 (2 CPU cores, Python `3.14.4`), Semgrep `1.178.0`, CodeQL CLI `2.27.1` (`codeql/python-queries` `1.8.11`), Pysa (`pyre-check` `0.10.0`, stock models `d5614e0a`), Bandit `1.9.4`, and `llama3.1:8b`, `qwen3-coder-next`, `qwen3.6:35b` on NUS SoCLaaS.
- **Included vs. external scripts:** The offline analysis scripts (`analysis/run_all.sh`), mechanism re-scans (`analysis/run_mechanism.sh`), and unit tests (`pytest`) are included here. External helper scripts mentioned below (`harvest.py`, `validate_*_suite.py`, `queue_*.py`/`.sh`, `rescan_*.py`, `check_candidates_unchanged.py`, `reproduce.sh`) were used during collection and checking and are not part of this repository.

## Contents

- [1. Checking Scanners Against Their Own Test Suites](#1-checking-scanners-against-their-own-test-suites)
- [2. Automated Test Suite](#2-automated-test-suite)
- [3. Same-Behavior and Unchanged-Output Checks](#3-same-behavior-and-unchanged-output-checks)
- [4. Repeatable Verdicts, Independent Re-scans, and Scan Cache](#4-repeatable-verdicts-independent-re-scans-and-scan-cache)
- [5. Run Traceability, Manifests, and Campaign Checks](#5-run-traceability-manifests-and-campaign-checks)
- [6. Known Limits and What Was Not Checked](#6-known-limits-and-what-was-not-checked)

---

## 1. Checking Scanners Against Their Own Test Suites

| Scanner / Asset | Check Run | Result |
| --- | --- | --- |
| Semgrep `1.178.0` | `formatted-sql-query` official suite (`semgrep --test`) | Passes: matches expected alert lines `32` and `39`, with safe cases clean (`results/official-validation/`). |
| Semgrep `1.178.0` | `dangerous-subprocess-use-audit`, `path-traversal-open`, `flask-tainted-sql-string` | All pass their official tests (`8` expected lines for CWE-78; `12` each for path traversal and taint SQL). |
| CodeQL `2.27.1` | Download checksum | Bundle SHA-256 `ea86393c6c812542ae5a3a7122bcc760873707a50b25cc47d2fd7cfd514b0cb0` matches GitHub's release and [Dockerfile](../Dockerfile). |
| CodeQL `2.27.1` | Official query tests (`py/sql-injection`, `py/command-line-injection`, `py/path-injection`) | Matches expected alerts exactly: `20/20` SQL (`SqlInjection.expected`), `13/13` command injection, `21/21` path injection; adapted `app.py` (`unsafe`) and `sql_injection.py` (`show_user`) flagged. |
| Pysa `0.10.0` | `pyre-check` `d5614e0a` integration tests (33 tests with their own config) | `32/33` match expected findings (`entrypoint` reports 1 extra rule-`1006` global-state alert unrelated to SQL). |
| Pysa `0.10.0` | Built-in HTTP source check (`pysa-http-*`) | `576` candidates scanned using `BaseHTTPRequestHandler.path`; same rules fire and same seeds qualify. |
| Bandit `1.9.4` | Unit & check-all runs (`B608`, `B602`) | Checked with [test_bandit.py](../tests/test_bandit.py) and `7,700` exhaustive scans (Bandit's own upstream suite was not run separately). |
| Docker image | `docker run --rm sastlab` | Runs the test suite offline: `181 passed, 6 skipped` (image leaves out `results/` and API keys). |

Qualifying SQL baselines across test sets: `15/15` main seeds qualify under Semgrep, CodeQL, and Pysa; `10/12` varied seeds qualify under CodeQL and Pysa (`8/12` under Semgrep); `9/9` official-suite seeds qualify under CodeQL and Pysa (`7/9` under Semgrep).

---

## 2. Automated Test Suite

Run locally with all scanner tools installed under `.sastlab/`:

```sh
PYTHONDONTWRITEBYTECODE=1 .sastlab/.venv/bin/python -m pytest -q -p no:cacheprovider
```

Total: **187 tests** (`182 passed, 5 skipped` when optional scanner binaries are absent or inside Docker without `results/`).

| Test File | What It Checks |
| --- | --- |
| [test_framework.py](../tests/test_framework.py) | Same outputs across all 256 core masks and flow subsets on 15 seeds; bitmask graph reachability and sink rejections; AST distance/depth metrics; rejection of fixed/broken/timed-out code; Semgrep/SARIF error handling (errors fail closed); full 7-strategy replay, Metropolis rejection & `metropolis_restart`; fair prompt trimming; safe resume & `--rerun-errors`; `evasion: "all"` and `diagnostic_fields`. |
| [test_chat_api.py](../tests/test_chat_api.py) | Keeps SoCLaaS API keys out of logs/manifests; request audit trail; `.env` loading; served model check; strict JSON/ranking validation; HTTP `429` waits (`Retry-After` and capped exponential backoff without wasting validation retries); fallback counts; `min_interval`. |
| [test_extensions.py](../tests/test_extensions.py) | `order: "any"` pool selection, `llm.prompt_extra` token counting, `@app.route` injection for Semgrep taint mode, scan-cache hit consistency (`8/8` repeated hits). |
| [test_harvest.py](../tests/test_harvest.py) | Custom per-seed `SASTLAB_FIXTURE` and `SASTLAB_EXPLOIT` constants stay intact through rewrites and fall back to the default `users` table when absent. |
| [test_pysa.py](../tests/test_pysa.py) | `typed_for_pysa` type annotation across renames and all 18 single rewrites; error handling in Pysa parser (`5005`, `5051`, missing entry model, missing binary); local `pyrefly.toml` isolation (stops crawling repo `.gitignore`/`pyproject.toml`); `http-server` source mode. |
| [test_bandit.py](../tests/test_bandit.py) | Bandit JSON error checks (`subject.py` check, parse errors) and live scan (`seed_01` flagged by `B608`, silenced by `literal_slice`). |
| [test_command_class.py](../tests/test_command_class.py) | CWE-78 command-injection seeds keep outputs under applicable rewrites and reject module-level sinks for `unbound_sink`. |
| [test_path_class.py](../tests/test_path_class.py) | CWE-22 path-traversal seeds, `open` sink rewrites, and official-rule test matching. |
| [test_robustness.py](../tests/test_robustness.py) | Deletes worker temp folders on finish or timeout; `path_equivalence.py` isolation; `rename`/`dead_padding` on inline queries; `unbound_sink` with local imports; `summarize_exhaustive` mask counts; read-only `report` command; standalone query pack in `mechanism_codeql_probe.py`; `sqlite3` type annotation harmless on CWE-78/22 Pysa scans; `cmd_equivalence.py` shell error tracking; Pysa model hashes in scan-cache keys. |
| [test_edge_cases.py](../tests/test_edge_cases.py) | Comprehension scoping and `except ... as` names in `rename`/`extract_*`; keeps docstrings in flow rewrites; filters `target_rules` in agent verdicts/diagnostics; `exhaustive` `work_dir`; path-free CodeQL version ID; order-independent `report`; full-campaign replay configs (`semgrep-v6`, `codeql-v6`). |
| [test_reproduction.py](../tests/test_reproduction.py) | Recomputes every exhaustive `summary.json` from `evaluations.jsonl`, `qualifications.json`, and manifest mask lists (including `complete`); verifies every file path in `configs/*.json` exists; checks `analysis/*.py`, `analysis/*.sh`, and `scripts/*.py` stay inside the repo and write no `.tex` files in `analysis/`. |

---

## 3. Same-Behavior and Unchanged-Output Checks

### Multi-Input Behavior Checks (`analysis/`)

| Bug Class | Script | Candidates Checked | Inputs Tested | Mismatches | Notes |
| --- | --- | ---: | ---: | ---: | --- |
| SQL injection | [extended_equivalence.py](../analysis/extended_equivalence.py) | `21,264` unique (`16,562` evading, `4,702` detected) | 20 inputs + larger DB (empty, quotes, Unicode, 5,000-char, `OR`, `UNION`, numeric, double-quote) | `0` | Covers official, real, apps, taint, latest, Pysa, Bandit, and cached runs. `52/54` seeds work with standard `OR` attacks; `a05_pyload_update_link_info` and `r06_vulpy_login` use their own attack strings. Leaves out rewrite catalog and path probe. |
| Command injection | [cmd_equivalence.py](../analysis/cmd_equivalence.py) | `1,150` unique | 12 inputs (empty, spaces, quotes, `;`, `&&`, `$(...)`, backticks, Unicode, 300-char) | `0` | Checks both return value and process exit code. Input `it's` fails shell parsing (exit `2`) for the seed itself on all `8/8` seeds (`4` raise, `4` return); candidates match seed exit status on `8/96` pairs and outputs on the `11` working inputs per seed. |
| Path traversal | [path_equivalence.py](../analysis/path_equivalence.py) | `890` unique (`*-path-*`) | 14 inputs (existing/missing files, traversal, null byte, 300-char path) | `0` | Each check runs in a clean temp directory; `../secret` reads the secret file on `7/7` baseline seeds. |

Note: Bandit runs (`bandit-*-pairs`) add `656` unique SQL candidates to `extended_equivalence.py`; the Bandit command-injection run adds no new candidates.

### Unchanged Code Hashes and Oracle Replay

- **Adding command injection:** `6,192` SQL candidates rebuilt before and after updating `transforms.py` had `0` SHA-256 differences.
- **Adding built-in `open`:** `12,058` previously saved candidates rebuilt with `0` SHA-256 differences.
- **Full saved candidate rebuild:** `13,832` unique saved candidates across SQL and path runs rebuilt from seed + bitmask with `0` missing seeds and `0` SHA-256 mismatches.
- **Baseline oracle match:** Across all `30` seeds with saved baseline records, current `Oracle.evaluate` produces identical outputs.

---

## 4. Repeatable Verdicts, Independent Re-scans, and Scan Cache

- **Same verdict across runs (`analysis/rq1.py`):** No `(seed, mask)` pair received conflicting verdicts from the same scanner across saved runs:
  - Semgrep `1.178.0`: `12,532` unique pairs (`0` conflicts).
  - CodeQL `2.27.1` + `2.27.3`: `3,945` unique pairs across 26 runs (`3,780` under `2.27.1`; `0` conflicts).
  - Pysa `0.10.0`: `3,994` unique pairs, `428` scanned twice across singles/pairs runs (`0` conflicts).
- **Independent fresh re-scans without cache:** Random samples rebuilt from seed + mask and scanned live matched saved SHA-256 hashes, behavior checks, and scanner rule alerts with **0 mismatches** across all samples:
  - Main SQL campaigns: `130` Semgrep + `36` CodeQL candidates (`0` mismatches).
  - Official-suite runs: `80` Semgrep (`40` evading + `40` detected) + `30` CodeQL (`15` + `15`) (`0` mismatches).
  - Pysa main/official/varied runs: `120` candidates (`40` silent, `40` one-rule, `40` both rules) (`0` differences).
  - Command injection & independent SQL: `100` Semgrep (`25+25` each), `32` CodeQL (`8+8` each), `75` Pysa across `pysa-real-pairs` & `pysa-cmd-pairs` (`0` mismatches).
  - Semgrep taint mode: `50` main + `50` official (`25+25` each) (`0` mismatches).
  - Path traversal, deployed apps & Pysa triples: `100` Semgrep (`25+25` path, `25+25` apps), `32` CodeQL (`8+8` path, `8+8` apps), `75` Pysa (`25` per set across `pysa-path-pairs`, `pysa-apps-pairs`, `pysa-triples`) (`0` mismatches).
  - Bandit: `480` candidates (`40+40` across each of the 6 runs) (`0` mismatches).
  - Cached search steps: `228` logged attempts across `15` agent runs (Semgrep `100`, Pysa `96`, CodeQL `32`; `147` originally answered by `scan_cache`) re-scanned fresh without cache (`0` mismatches).
- **Newer scanner versions:** Semgrep `1.182.1` agreed with `1.178.0` on `392/392` single rewrites. CodeQL `2.27.3` (`python-queries` `1.8.13`, zip SHA-256 `845075a2...` matching GitHub) checked `428` singles on `24` seeds (`0` errors, evading whenever a flow rewrite is present).
- **Disk scan cache:** Keyed on `(engine, version, rule/query, route/source/codes, pysa_models_digest)`; verified `8/8` repeated cache hits with unchanged attempt accounting in [test_extensions.py](../tests/test_extensions.py) and [test_robustness.py](../tests/test_robustness.py).

---

## 5. Run Traceability, Manifests, and Campaign Checks

### Command Matching and Re-running Past Checks

- **Tracing runs to commands:** Every one of the `115` folders in `results/` matches a campaign run or helper script (`111` queue runs + `4` probe/validation/mechanism runs). Across all `110` manifest-backed runs, recorded settings match saved configs and identities (ignoring `config_dir`, `evasion`, and optional `scan_cache` added in later experiments).
- **Re-executed subsets:** Five check-all runs (`semgrep-official-qual` `7/7`, `codeql-flow-ops-seed01` `31/31`, `codeql-flow-ops-15seeds` `225/225` with 1 resume, first 3 seeds of `semgrep-diverse-singles` `26/26`, first 2 of `codeql-official-qual` `2/2`) re-ran with identical manifest identities (aside from operator count expanding 13 → 18) and `0` row differences. Three search configs (`semgrep-hard30`, `codeql-hard15` with `--seed-limit 1`, `codeql-v6-seed05-rerun`) match `configs/`.
- **Offline scripts & mechanism checks:** All 15 scripts in `analysis/run_all.sh` exit `0` from any working directory and write only plain text (no `.tex`). `analysis/run_mechanism.sh` reproduces `results/mechanism/{pysa,pysa_callgraph,codeql_library,codeql_flow,codeql_probe}.txt` byte for byte.

### Full-Campaign Checks (`semgrep-v6` and `codeql-v6`)

| Metric | `semgrep-v6` | `codeql-v6` |
| --- | --- | --- |
| Logged attempts | `15,750` | `5,250` |
| Scanner errors | `0` | `0` (after 3 timeouts rerun; see below) |
| Behavior mismatches | `0` | `0` |
| Model fallbacks | `0` (`4,576` calls) | `0` (`1,525` calls) |
| Same `(seed, mask)` verdict conflicts | `0 / 5,563` pairs | `0 / 1,873` pairs |
| Seed SHA-256 hashes match current files | Yes | Yes |
| Framework file hashes match current files | No | No |

- **Why `framework_sha256` differs across runs:** Because features were added across experiment stages (per-call shuffled prompts in `llm.py`, operator pools, bits 13–17, custom oracle constants), early campaign manifests record earlier framework hashes. Checks confirm identical behavior: `Oracle` produces identical outputs on all `30` saved qualification records, and replaying `seed_05` Strategy 1 matches `145/150` candidate hashes (the `5` differences follow a failed scan) with identical verdicts on all `143` shared scanned candidates.
- **CodeQL timeout rerun (`seed_05`):** Three attempts timed out due to host CPU throttling in Strategy 1 (`seed_05`, trajectories 3 and 4). Both walks re-ran under `results/codeql-v6-seed05-rerun` (pinned to the original 13-operator pool) and merged into `codeql-v6` (replaced rows kept in `discarded-partial.jsonl`). Report card is complete (`weak`, `"exploratory": true`). **Important note:** files `bypasses/seed_05/1089.{py,json}` and `5185.{py,json}` belong to lines 284–285 of `discarded-partial.jsonl`, not `attempts.jsonl`; always count evasions from `attempts.jsonl`.
- **Errors and timeouts across all runs:**
  - `0` oracle crashes across all `115` saved folders.
  - `0` scanner errors in all saved runs **except** `codeql-hard-qwen`, where `2` scans of `d02_str_format` (Strategy 5) timed out after `120 s` (excluded from evasions; `complete: false`, report card `excluded`).
  - One earlier timed-out CodeQL command-injection scan was re-run (saved in `discarded-timeouts.jsonl`). Timing comparisons are skipped for `pysa-hard-qwen*` due to shared host CPU load.
  - An interrupted `pysa-*-pairs` run resumed cleanly with `0` duplicate `(seed, mask)` rows across `4,716` Pysa rows. Early misconfigured pilot launches failed safely (`0` false passes) and were deleted before final runs.
- **LLM API checks and fallbacks:** `./run.sh doctor` verified SoCLaaS model access. `0` fallbacks occurred in `semgrep-v6` and `codeql-v6`; `79` fallbacks occurred out of `76,045` model choices in restricted runs (`semgrep-informed-8b`: `37`, `semgrep-rep1-8b`: `25`, `pysa-hard-informed-8b`: `11`, `pysa-rep1-35b`: `6`), counted directly from `results/*/llm.jsonl` (`fallback: true`). HTTP `429` waits were verified both in a live pilot (not kept) and in unit tests.

---

## 6. Known Limits and What Was Not Checked

- **Real-world apps:** `corpus_apps` adapts 5 single functions from 3 PyPI packages onto SQLite; full applications and CI pipelines were not scanned. Remaining corpora keep query-building code without original database drivers.
- **Old manifest file hashes:** As noted in [Section 5](#5-run-traceability-manifests-and-campaign-checks), early manifests store hashes from before operators 14–18 and prompt shuffling were added.
- **Root-cause coverage:** Added-model repairs in `results/mechanism/` cover 5 rewrite mechanisms and 6 `(scanner, rewrite)` pairs on 1–2 seeds, plus CodeQL sink-node dumps, `deep_nest` depth limit (`6`), and Pysa call graphs; other rewrite pairs were observed in scan outputs without manual tracing.
- **LLM weights unknown:** SoCLaaS hides weight checksums, and `qwen3-coder-next` parameter size is not exposed by the API.
- **Tested inputs vs. full proofs:** Same-behavior checks ran on 2 inputs per campaign step and 12–20 inputs afterward, not by formal proof across every possible input.
- **Public reporting:** Nothing here has been reported to the Semgrep or CodeQL teams.
