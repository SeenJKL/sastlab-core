# Validation and Integrity Record

Verification record for scanner configuration, automated tests, runtime behavior preservation, verdict determinism, independent re-scans, and saved campaign artifacts.

- **Platform:** Linux x86-64 (2 CPU cores, Python `3.14.4`), Semgrep `1.178.0`, CodeQL CLI `2.27.1` (`codeql/python-queries` `1.8.11`), Pysa (`pyre-check` `0.10.0`, stock models at `d5614e0a`), Bandit `1.9.4`, `llama3.1:8b`, `qwen3-coder-next`, and `qwen3.6:35b` on NUS SoCLaaS.
- **Shipped vs. historical external scripts:** The offline analysis scripts (`analysis/run_all.sh`), mechanism re-scans (`analysis/run_mechanism.sh`), and automated suite (`pytest`) ship in this repository. External helper scripts cited below (`harvest.py`, `validate_*_suite.py`, `queue_*.py`/`.sh`, `rescan_*.py`, `check_candidates_unchanged.py`, `reproduce.sh`) were used during data collection/auditing and are omitted from this archive.

## Contents

- [1. Upstream Scanner and Suite Validation](#1-upstream-scanner-and-suite-validation)
- [2. Automated Test Suite](#2-automated-test-suite)
- [3. Behavior Equivalence and Transform Invariance](#3-behavior-equivalence-and-transform-invariance)
- [4. Verdict Determinism, Independent Re-scans, and Scan Cache](#4-verdict-determinism-independent-re-scans-and-scan-cache)
- [5. Run Traceability, Manifests, and Campaign Integrity](#5-run-traceability-manifests-and-campaign-integrity)
- [6. Known Limits and Unverified Scope](#6-known-limits-and-unverified-scope)

---

## 1. Upstream Scanner and Suite Validation

| Analyzer / Asset | Validation Check | Outcome |
| --- | --- | --- |
| Semgrep `1.178.0` | `formatted-sql-query` upstream test (`semgrep --test`) | Passes: expected/reported match lines `32` and `39`; safe cases silent (`results/official-validation/`). |
| Semgrep `1.178.0` | `dangerous-subprocess-use-audit`, `path-traversal-open`, `flask-tainted-sql-string` | All pass their upstream tests (`8` expected lines for CWE-78; `12` each for path and taint SQL). |
| CodeQL `2.27.1` | Bundle SHA-256 verification | Archive digest `ea86393c6c812542ae5a3a7122bcc760873707a50b25cc47d2fd7cfd514b0cb0` matches upstream release and [Dockerfile](../Dockerfile). |
| CodeQL `2.27.1` | Upstream test suites (`py/sql-injection`, `py/command-line-injection`, `py/path-injection`) | Reproduces exact expected alerts: `20/20` SQL (`SqlInjection.expected`), `13/13` command injection, `21/21` path injection; adapted `app.py` (`unsafe`) and `sql_injection.py` (`show_user`) flagged. |
| Pysa `0.10.0` | `pyre-check` `d5614e0a` integration tests (33 tests with own config) | `32/33` reproduce expected issues exactly (`entrypoint` reports 1 extra rule-`1006` global-state finding, unrelated to SQL). |
| Pysa `0.10.0` | Stock HTTP source check (`pysa-http-*`) | `576` candidates scanned with `BaseHTTPRequestHandler.path`; identical rule set and seed qualifications. |
| Bandit `1.9.4` | Unit & exhaustive checks (`B608`, `B602`) | Verified via [test_bandit.py](../tests/test_bandit.py) and `7,700` exhaustive candidates (Bandit's upstream suite was not run separately). |
| Container build | `docker run --rm sastlab` | Executes the test suite offline: `181 passed, 6 skipped` (image omits `results/` and model API key). |

Baseline qualification across SQL corpora: `15/15` main seeds qualify under Semgrep, CodeQL, and Pysa; `10/12` varied seeds qualify under CodeQL and Pysa (`8/12` under Semgrep); `9/9` official-suite seeds qualify under CodeQL and Pysa (`7/9` under Semgrep).

---

## 2. Automated Test Suite

Run locally with all scanner environments under `.sastlab/`:

```sh
PYTHONDONTWRITEBYTECODE=1 .sastlab/.venv/bin/python -m pytest -q -p no:cacheprovider
```

Total: **187 tests** (`182 passed, 5 skipped` when run without external tool paths for Pysa/Bandit or in Docker without `results/`).

| Test File | Scope Verified |
| --- | --- |
| [test_framework.py](../tests/test_framework.py) | Behavior preservation across all 256 core masks and flow subsets on 15 seeds; candidate DAG reachability and sink rejections; AST distance/depth metrics; oracle rejection of fixed/broken/timed-out programs; Semgrep/SARIF parsers (fail-closed); full 7-strategy budgets, replay, Metropolis rejection & `metropolis_restart`; feedback isolation under prompt truncation; resume equivalence & `--rerun-errors`; `evasion: "all"` and `diagnostic_fields`. |
| [test_chat_api.py](../tests/test_chat_api.py) | SoCLaaS credential exclusion from logs/manifests, request auditing, `env_file` resolution, model identity checks, strict JSON schema/ranking validation, HTTP `429` `Retry-After` / capped exponential backoff without burning validation retries, fallback counting, `min_interval`. |
| [test_extensions.py](../tests/test_extensions.py) | `order: "any"` operator pools, `llm.prompt_extra` budget accounting, `@app.route` injection for Semgrep taint mode, scan-cache hit equivalence (`8/8` repeated hits). |
| [test_harvest.py](../tests/test_harvest.py) | Per-seed `SASTLAB_FIXTURE` and `SASTLAB_EXPLOIT` handling and preservation across rewrites vs. default `users` table fallback. |
| [test_pysa.py](../tests/test_pysa.py) | `typed_for_pysa` parameter annotation across renames and all 18 singles; fail-closed Pysa parser (`5005`, `5051`, missing entry model, unavailable binary); Pyrefly workspace isolation (`pyrefly.toml` prevents crawling repo `.gitignore`/`pyproject.toml`); `http-server` stock source mode. |
| [test_bandit.py](../tests/test_bandit.py) | Fail-closed Bandit JSON parser (`subject.py` presence, errors) and live check (`seed_01` flagged by `B608`, silenced by `literal_slice`). |
| [test_command_class.py](../tests/test_command_class.py) | CWE-78 command-injection seed equivalence across applicable rewrites and module-level sink rejections. |
| [test_path_class.py](../tests/test_path_class.py) | CWE-22 path-traversal seeds, built-in `open` sink rewrites, and rule test validation. |
| [test_robustness.py](../tests/test_robustness.py) | Worker temp-directory cleanup on success and timeout; `path_equivalence.py` isolation; `rename`/`dead_padding` on inline queries; `unbound_sink` with local imports; `summarize_exhaustive` required count; read-only `report` CLI; standalone query-pack generation in `mechanism_codeql_probe.py`; `sqlite3` annotation invariance on CWE-78/22 Pysa scans; `cmd_equivalence.py` shell failure accounting; Pysa model digests in scan-cache keys. |
| [test_edge_cases.py](../tests/test_edge_cases.py) | Comprehension/shadowed global scoping and `except ... as` targets in `rename`/`extract_*`; docstring preservation in flow operators; `target_rules` filtering in agent verdict/diagnostics; `exhaustive` `work_dir` honoring; path-free CodeQL version identity; order-independent `report`; full-campaign replay configs (`semgrep-v6`, `codeql-v6`). |
| [test_reproduction.py](../tests/test_reproduction.py) | Recomputes every exhaustive `summary.json` from `evaluations.jsonl`, `qualifications.json`, and manifest enumeration (including `complete`); verifies all `configs/*.json` asset paths exist; checks all `analysis/*.py`, `analysis/*.sh`, and `scripts/*.py` stay self-contained and write no `.tex` files in `analysis/`. |

---

## 3. Behavior Equivalence and Transform Invariance

### Extended Input-Bounded Behavior Checks (`analysis/`)

| Class | Script | Candidates Checked | Inputs Tested | Discrepancies | Notes |
| --- | --- | ---: | ---: | ---: | --- |
| SQL injection | [extended_equivalence.py](../analysis/extended_equivalence.py) | `21,264` unique (`16,562` evading, `4,702` detected) | 20 inputs + larger DB (empty, quotes, unicode, 5,000-char, `OR`, `UNION`, numeric, double-quote) | `0` | Covers official, real, apps, taint, latest, Pysa, Bandit, and cached agent runs. `52/54` seeds live on standard `OR` payloads; `a05_pyload_update_link_info` and `r06_vulpy_login` on their own exploit strings. Excludes rewrite catalog and path probe. |
| Command injection | [cmd_equivalence.py](../analysis/cmd_equivalence.py) | `1,150` unique | 12 inputs (empty, spaces, quotes, `;`, `&&`, `$(...)`, backticks, unicode, 300-char) | `0` | Checks return value and spawned-process exit status. Input `it's` fails shell parsing (exit `2`) for the baseline on all `8/8` seeds (`4` raise, `4` return); candidates match seed failure/exit status on `8/96` pairs and match outputs on the `11` working inputs per seed. |
| Path traversal | [path_equivalence.py](../analysis/path_equivalence.py) | `890` unique (`*-path-*`) | 14 inputs (existing/missing paths, traversal, null byte, 300-char name) | `0` | Runs each check in an isolated temp directory; `../secret` reads the secret file on `7/7` baseline seeds. |

Note: Bandit runs (`bandit-*-pairs`) contribute `656` unique SQL candidates to `extended_equivalence.py`; the Bandit command-injection run adds no unseen candidates.

### Hash Invariance and Oracle Replay

- **Command-injection generalization:** `6,192` SQL candidates regenerated before and after generalizing `transforms.py` showed `0` SHA-256 differences.
- **Built-in `open` sink addition:** `12,058` logged candidates regenerated and compared by SHA-256 showed `0` differences.
- **Full logged regeneration:** `13,832` distinct logged candidates across saved SQL and path runs regenerated from seed + bitmask with `0` missing seeds and `0` SHA-256 mismatches.
- **Baseline oracle check:** For all `30` seeds with saved baseline qualification records, current `Oracle.evaluate` matches saved baseline outputs identically.

---

## 4. Verdict Determinism, Independent Re-scans, and Scan Cache

- **Verdict determinism across saved runs (`analysis/rq1.py`):** Zero `(seed, mask)` pairs received conflicting verdicts within the same scanner across runs:
  - Semgrep `1.178.0`: `12,532` distinct pairs (`0` conflicts).
  - CodeQL `2.27.1` + `2.27.3`: `3,945` distinct pairs across 26 runs (`3,780` under `2.27.1`; `0` conflicts).
  - Pysa `0.10.0`: `3,994` distinct pairs, `428` rescanned across singles/pairs runs (`0` conflicts).
- **Independent uncached re-scans:** Fixed-seed random samples regenerated directly from seed + bitmask and scanned without cache matched saved candidate hashes, oracle equivalence, and scanner rule sets with **0 disagreements** across all checks:
  - Earlier SQL campaigns: `130` Semgrep + `36` CodeQL candidates (`0` mismatches).
  - Official-suite runs: `80` Semgrep (`40` evading + `40` detected) + `30` CodeQL (`15` + `15`) (`0` mismatches).
  - Pysa main/official/varied runs: `120` candidates (`40` silent, `40` single-rule, `40` both rules) (`0` rule-set differences).
  - Command injection & independent SQL: `100` Semgrep (`25+25` each), `32` CodeQL (`8+8` each), `75` Pysa across `pysa-real-pairs` & `pysa-cmd-pairs` (`0` mismatches).
  - Semgrep taint mode: `50` main + `50` official (`25+25` each) (`0` mismatches).
  - Path traversal, deployed projects & Pysa triples: `100` Semgrep (`25+25` path, `25+25` apps), `32` CodeQL (`8+8` path, `8+8` apps), `75` Pysa (`25` per class across `pysa-path-pairs`, `pysa-apps-pairs`, `pysa-triples`) (`0` mismatches).
  - Bandit: `480` candidates (`40+40` across each of the 6 runs) (`0` mismatches).
  - Cached search attempts: `228` logged agent attempts across `15` runs (Semgrep `100`, Pysa `96`, CodeQL `32`; `147` originally served from `scan_cache`) rescanned live without cache (`0` mismatches).
- **Newer scanner releases:** Semgrep `1.182.1` agreed with `1.178.0` on `392/392` single-rewrite candidates. CodeQL `2.27.3` (`python-queries` `1.8.13`, zip SHA-256 `845075a2...` matching GitHub) produced `428` evaluations (`0` errors, evading iff a flow rewrite is present).
- **Persistent scan cache:** Keyed on `(engine, version, rule/query, route/source/codes, pysa_models_digest)`; verified `8/8` deterministic hits and unchanged attempt accounting in [test_extensions.py](../tests/test_extensions.py) and [test_robustness.py](../tests/test_robustness.py).

---

## 5. Run Traceability, Manifests, and Campaign Integrity

### Traceability and Re-execution Audits

- **Command traceability:** Every one of the `115` directories in `results/` traces to a campaign queue or helper script (`111` queue runs + `4` probe/validation/mechanism runs). Across all `110` manifest-backed runs, recorded configurations match stored configs and identities (`config_dir`, `evasion`, and optional `scan_cache` excluded where added for later experiments).
- **Re-executed subset checks:** Five exhaustive runs (`semgrep-official-qual` `7/7`, `codeql-flow-ops-seed01` `31/31`, `codeql-flow-ops-15seeds` `225/225` with 1 resume, first 3 seeds of `semgrep-diverse-singles` `26/26`, first 2 of `codeql-official-qual` `2/2`) re-executed with identical manifest identities (aside from toolbox expansion 13 → 18) and `0` row differences. Three search configs (`semgrep-hard30`, `codeql-hard15` with `--seed-limit 1`, `codeql-v6-seed05-rerun`) match `configs/`.
- **Offline analysis & mechanism reproduction:** All 15 scripts in `analysis/run_all.sh` exit `0` from arbitrary working directories with plain-text output (no `.tex` output). `analysis/run_mechanism.sh` reproduces `results/mechanism/{pysa,pysa_callgraph,codeql_library,codeql_flow,codeql_probe}.txt` byte for byte.

### Full-Campaign Integrity (`semgrep-v6` and `codeql-v6`)

| Measurement | `semgrep-v6` | `codeql-v6` |
| --- | --- | --- |
| Recorded attempts | `15,750` | `5,250` |
| Scanner errors | `0` | `0` (after 3 timeouts rerun; see below) |
| Behavior differences | `0` | `0` |
| Model fallbacks | `0` (`4,576` calls) | `0` (`1,525` calls) |
| Same `(seed, mask)` verdict conflicts | `0 / 5,563` pairs | `0 / 1,873` pairs |
| Seed SHA-256 hashes match current files | Yes | Yes |
| Framework file hashes match current files | No | No |

- **Framework hashes across campaigns (`framework_sha256`):** Because the framework expanded across experiment phases (per-call shuffled system prompts in `llm.py`, operator pools, bits 13–17 appended, per-seed oracle constants), `framework_sha256` in early campaign manifests differs from current source files. Cross-checks confirm behavioral continuity: `Oracle` matches all `30` saved qualification outputs identically, and replaying `seed_05` Strategy 1 reproduces `145/150` candidate hashes (all `5` differences follow a failed scan) with identical verdicts on all `143` shared scanned candidates.
- **CodeQL campaign timeout rerun (`seed_05`):** Three attempts timed out under host CPU throttling in Strategy 1 (`seed_05`, trajectories 3 and 4). Both trajectories were re-executed under `results/codeql-v6-seed05-rerun` (restricted to the original 13-operator pool) and merged cleanly into `codeql-v6` (replaced rows preserved in `discarded-partial.jsonl`). Report card is complete (`weak`, exploratory). **Artifact note:** files `bypasses/seed_05/1089.{py,json}` and `5185.{py,json}` correspond to lines 284–285 of `discarded-partial.jsonl` rather than `attempts.jsonl`; always count evasions from `attempts.jsonl`.
- **Scanner/timeout/error accounting across all runs:**
  - `0` oracle failures across all `115` saved folders.
  - `0` scanner errors in all saved runs **except** `codeql-hard-qwen`, where `2` scans of `d02_str_format` (Strategy 5) timed out after `120 s`. Neither counts as an evasion; analyses use scanned rows only (`complete: false`, report card `excluded`).
  - One earlier timed-out CodeQL command-injection scan was re-evaluated (preserved in `discarded-timeouts.jsonl`). Timing claims are omitted for `pysa-hard-qwen*` due to shared host load.
  - Interrupted `pysa-*-pairs` run resumed cleanly with `0` duplicate `(seed, mask)` rows across `4,716` Pysa evaluation rows. Initial failed pilot launches caused by misconfigured rule/model settings failed closed (`0` false clean verdicts) and were discarded before final runs.
- **LLM API reliability & fallbacks:** `./run.sh doctor` verified SoCLaaS availability. `0` fallbacks occurred in `semgrep-v6` and `codeql-v6`; `79` fallbacks occurred out of `76,045` model decisions in restricted runs (`semgrep-informed-8b`: `37`, `semgrep-rep1-8b`: `25`, `pysa-hard-informed-8b`: `11`, `pysa-rep1-35b`: `6`), all counted directly from `results/*/llm.jsonl` (`fallback: true`). HTTP `429` handling was verified live during a pilot run (data not retained) and in unit tests.

---

## 6. Known Limits and Unverified Scope

- **Real-world validity:** `corpus_apps` adapts 5 isolated functions from 3 PyPI releases onto an in-memory SQLite cursor; no full application or CI pipeline was tested. Remaining corpora are synthetic or adapted test/benchmark slices retaining query construction without database driver libraries.
- **Code provenance of early campaigns:** As noted in [Section 5](#5-run-traceability-manifests-and-campaign-integrity), early manifests record historical framework hashes before operators 14–18 and prompt-order shuffling were added.
- **Mechanism coverage:** Root-cause repairs in `results/mechanism/` cover 5 rewrite mechanisms and 6 `(tool, rewrite)` pairs on 1–2 seeds, plus CodeQL sink-node listings, `deep_nest` depth limit (`6`), and Pysa call-graph inspections; other rewrite/corpus interactions are reported empirically without manual root-cause tracing.
- **Model identity:** SoCLaaS exposes no model weight digest; `qwen3-coder-next` parameter size is unreported by the endpoint.
- **General equivalence:** Runtime equivalence is verified over 2 inputs during campaigns and 12–20 inputs afterward, not by formal proof over arbitrary inputs.
- **Responsible disclosure:** No vulnerability/false-negative reports have been filed with Semgrep or CodeQL maintainers.
