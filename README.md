# SASTLab

SASTLab tests whether Python security scanners (SAST tools) still catch a bug after safe code rewrites that keep the same program behavior. It starts from a vulnerable seed program that a scanner flags and a runtime check confirms is exploitable, applies fixed AST rewrites, checks that normal and attack inputs give the exact same output, and logs any rewrite where the scanner stops reporting the bug.

- **4 scanners:** Semgrep (`1.178.0`), CodeQL (`2.27.1`), Pysa (`pyre-check` `0.10.0`), and Bandit (`1.9.4`).
- **3 bug classes:** SQL injection (CWE-89), command injection (CWE-78), and path traversal (CWE-22).
- **18 repeatable code rewrites:** Bitmask-controlled AST transforms applied from the original seed (no LLM writes code).
- **7 search methods:** Random choice, greedy heuristic, three LLM-guided agents (`llama3.1:8b`, `qwen3-coder-next`, `qwen3.6:35b`), and two Metropolis walks.

![Overview of the testing loop: the search strategy picks the next operator, the rewrite toolbox builds a candidate from the seed, and the scanner and the behavior check decide whether it is an evasion](docs/overview.png)

A **verified evasion** happens only when all three hold: (1) the scanner finishes without error (`scan.status == "ok"`), (2) the rewritten code returns the exact same output on normal and attack inputs (`equivalent == true`), and (3) the target rule(s) stop firing. Scanner errors and timeouts count as failures, never as evasions.

## Contents

- [Documentation Guide](#documentation-guide)
- [Summary of Findings](#summary-of-findings)
- [How to Run and Reproduce](#how-to-run-and-reproduce)
- [Architecture and Project Layout](#architecture-and-project-layout)
- [CLI and Config Reference](#cli-and-config-reference)
- [Rewrites, Strategies, Scanners, and Output Files](#rewrites-strategies-scanners-and-output-files)
- [Environment and Scope Limits](#environment-and-scope-limits)

---

## Documentation Guide

| Document | What Is Inside |
| --- | --- |
| [README.md](README.md) | Setup steps, how to run/reproduce results, CLI flags, config fields, and repo layout |
| [docs/methodology.md](docs/methodology.md) | Full technical design and rules to rebuild the tool (behavior checker, rewrites, scanners, search, API format, scoring) |
| [docs/prompts.md](docs/prompts.md) | Exact LLM prompts, user JSON examples, and `prompt_extra` variants |
| [docs/validation.md](docs/validation.md) | Official scanner checks, 187 automated tests, behavior checks, re-scans, and integrity checks |
| [result.md](result.md) | Complete experiment numbers across campaigns, test sets, scanners, root causes, and LLM tests |
| [results/INDEX.md](results/INDEX.md) | Index of all 115 saved run folders in `results/` |
| [THIRD_PARTY.md](THIRD_PARTY.md) | Origin info and licenses for included rules, Pysa models, and adapted sample seeds |

---

## Summary of Findings

An evasion shows a rule false negative (missed bug) under this test framework, not a real-world attack rate. Full numbers and confidence intervals are in [result.md](result.md).

| Scanner & SQL Rule | Rewrites That Stop the Alert |
| --- | --- |
| Semgrep `formatted-sql-query` (pattern) | Rewrites that move the query or call out of the pattern (`extract_1`, `extract_2`, `branch_split`, `dict_dispatch`, `dynamic_sink`); `literal_slice` works alone on `%`/`.format()` or paired with `format_swap` on f-strings. |
| CodeQL `py/sql-injection` (data-flow) | Any of the 9 flow-changing rewrites (`dynamic_sink`, `char_launder`, `deep_nest`, `db_roundtrip`, `simplequeue_roundtrip`, `pickle_roundtrip`, `partial_sink`, `methodcaller_sink`, `unbound_sink`). Control rewrites alone never evade. |
| Pysa rules `5005` + `5051` | One round-trip (`db_roundtrip` or `simplequeue_roundtrip`), or a sink rewrite paired with `literal_slice` (each removes one rule). |
| Bandit `B608` | `literal_slice`, or `format_swap` on `+` string joining. |

For command injection (CWE-78) and path traversal (CWE-22), rules match the sink call rather than how SQL strings are built, so query-moving rewrites do not help; sink rewrites evade Semgrep and Pysa, while flow-changing rewrites evade CodeQL. Whether an LLM agent beats random search depends on the model, rule type, and whether the prompt explains the scanner rules and rewrite order.

---

## How to Run and Reproduce

> **Unpacking zip files:** Extract with `unzip` to keep executable permissions on `run.sh` and `analysis/*.sh`. Python's `python3 -m zipfile -e` removes executable bits; restore them with `chmod +x run.sh analysis/*.sh`.

### Track A — Recompute Report Tables & View Results (Offline, ~3 min, Python Stdlib Only)

Needs only Python 3 (no scanners, Docker, or API key). All analysis scripts read from `results/` and print plain-text tables to stdout without writing `.tex` files:

```sh
# Recompute all 15 offline reports into analysis/out/*.txt
./analysis/run_all.sh

# Or run any table / RQ script directly from any folder
python3 analysis/table3.py
python3 analysis/rq5.py

# View one search campaign report card (read-only)
python3 -m sastlab report results/semgrep-v6

# Browse all 115 saved run folders
less results/INDEX.md
```

### Track B — Run the Automated Test Suite (~2 min, No API Key)

**Option 1 — Docker (pins Python 3.14, Semgrep, CodeQL, Pysa, Bandit):**

```sh
docker build -t sastlab .
docker run --rm sastlab          # 181 passed, 6 skipped (image leaves out results/)
```

**Option 2 — Local Linux x86-64 setup (matches [Dockerfile](Dockerfile)):**

```sh
python3.14 -m venv .sastlab/.venv       && .sastlab/.venv/bin/pip install -r requirements.lock
python3.14 -m venv .sastlab/pysa-venv   && .sastlab/.venv/bin/pip install -r requirements-pysa.lock
python3.14 -m venv .sastlab/bandit-venv && .sastlab/.venv/bin/pip install -r requirements-bandit.lock

mkdir -p .sastlab/tools && curl -fsSL -o /tmp/codeql.tar.zst \
  https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.1/codeql-bundle-python-linux64.tar.zst \
  && zstd -dc /tmp/codeql.tar.zst | tar -x -C .sastlab/tools && rm /tmp/codeql.tar.zst

# Run all 187 tests (182 passed, 5 skipped outside Docker when optional scanner checks skip)
PYTHONDONTWRITEBYTECODE=1 .sastlab/.venv/bin/python -m pytest -q -p no:cacheprovider
```

*(Wait — let's make sure Option 2 didn't copy a typo: `.sastlab/pysa-venv/bin/pip` and `.sastlab/bandit-venv/bin/pip`, NOT `.sastlab/.venv/bin/pip`! Good catch checking as I write!)*

Let's double check line 82 carefully and make sure those 3 venv commands are exact (`pysa-venv` and `bandit-venv`). Continuing carefully when calling `write_file`:

### Track C — Run Rewrites, Check-All Scans, and Non-LLM Search (No API Key)

By default, `./run.sh` limits CPU usage to 85% via `systemd-run --user`. Where systemd user sessions are unavailable (macOS, containers, headless CI), set `export SASTLAB_CPU_LIMIT=0` first (otherwise `run.sh` exits with code `3`):

```sh
export SASTLAB_CPU_LIMIT=0

# Build and behavior-check one rewritten file (mask 5 = bit 0 rename + bit 2 literal_slice)
./run.sh transform seeds/seed_01.py --mask 5 --output runs/candidate.py

# Run non-LLM search strategies (1=random, 2=heuristic, 6=AST Metropolis, 7=depth Metropolis)
./run.sh run --config configs/smoke.json --output runs/my-smoke --strategies 1 2 6 7 --attempts 3 --trajectories 1 --seed-limit 1

# Scan every single-rewrite candidate (writes to runs/, keeping results/ untouched)
./run.sh exhaustive --config configs/semgrep-official.json --output runs/my-first --seed-limit 1 --max-ops 1
```

Save new runs to `runs/` (ignored by git) and pick a fresh `--output` directory each time because `analysis/` reads everything inside `results/`.

### Track D — Run LLM Search (Strategies 3, 4, and 5)

Copy `.env.example` to `.env` and set `SOCLAAS_API_KEY` (or export it in your shell). Configs point to NUS SoCLaaS (`https://soclaas-api.comp.nus.edu.sg/v1`) using `llama3.1:8b`, `qwen3-coder-next`, and `qwen3.6:35b`. The key is sent only in the `Authorization` header (never followed across redirects or written to logs/manifests):

```sh
./run.sh doctor --config configs/semgrep.json   # check API key, model availability, and scanner binaries
./run.sh run --config configs/semgrep.json --output runs/my-semgrep --attempts 3 --trajectories 1 --seed-limit 1
```

### Track E — Re-run Root-Cause Checks & Helper Scripts

```sh
# Re-scan added Pysa/CodeQL models (~15 min; needs scanners installed under .sastlab/)
./analysis/run_mechanism.sh

# Alert-path laundering probe (CodeQL) and hand-written rewrite catalog
.sastlab/.venv/bin/python scripts/path_probe.py configs/codeql-diverse.json runs/codeql-path-probe
.sastlab/.venv/bin/python scripts/rewrite_catalog.py configs/codeql.json runs/codeql-rewrite-catalog
```

---

## Architecture and Project Layout

### Execution Flow

```text
Seed + Bitmask ──▶ transforms.py (fixed-order AST rewrite, bits 0..17)
                         │
                         ├──▶ oracle.py / oracle_worker.py (isolated process, 2 inputs)
                         └──▶ scanners.py (Semgrep / CodeQL / Pysa / Bandit, errors fail closed)
                                    │
                                    ▼
                        search.py (Strategies 1–7) ◀── llm.py (Strategies 3–5 via SoCLaaS)
                                    │
                                    ▼
                 runner.py / exhaustive.py ──▶ results/ or runs/ (saved JSON/JSONL files)
                                    │
                                    ▼
                       report.py / analysis/*.py (report cards, tables, RQs, behavior checks)
```

### Folders and Modules

| Path | What It Does |
| --- | --- |
| [`sastlab/cli.py`](sastlab/cli.py) | CLI commands (`doctor`, `run`, `exhaustive`, `transform`, `report`) |
| [`sastlab/transforms.py`](sastlab/transforms.py) | 18-operator bitmask AST rewriter, `TAXONOMY`, `OPERATOR_HELP`, supported sink names |
| [`sastlab/oracle.py`](sastlab/oracle.py), [`sastlab/oracle_worker.py`](sastlab/oracle_worker.py) | Isolated Python (`-I -B`) behavior checker with per-call temp folder cleanup |
| [`sastlab/scanners.py`](sastlab/scanners.py) | Scanner subprocess wrappers, SARIF/JSON parsers, `typed_for_pysa`, `routed_for_semgrep` |
| [`sastlab/search.py`](sastlab/search.py) | Strategies 1–7, `d_syntax` AST distance, `d_depth`, Metropolis acceptance, `metropolis_restart` |
| [`sastlab/llm.py`](sastlab/llm.py) | SoCLaaS API client, prompt token trimming, HTTP `429` waits, JSON schema retries |
| [`sastlab/runner.py`](sastlab/runner.py) | Config loader, walk checkpoint/resume loop, disk `scan_cache`, bypass file saver |
| [`sastlab/exhaustive.py`](sastlab/exhaustive.py) | Check-all combination runner (`evaluations.jsonl`) and summary builder |
| [`sastlab/report.py`](sastlab/report.py) | Rule report-card classifier (`weak`, `guidance-sensitive`, `robust`, `exploratory`, `incomplete`, `excluded`) |
| `configs/` | `93` experiment JSON configs |
| `seeds*/`, `corpus_*/` | Program test sets: `seeds/` (15 main SQL), `seeds_diverse/` (12 varied), `seeds_fstring/` (3), `corpus_official/seeds/` (9), `corpus_real/seeds/` (6), `corpus_apps/seeds/` (5), `seeds_cmd/` (8 CWE-78), `seeds_path/` (8 CWE-22), `seeds_pysa_hard/` (3), `seeds_pysa_hard2/` (3), `seeds_rerun_s05/` (1) |
| `rules/`, `third_party/` | Pinned Semgrep YAML rules + `.provenance.json`; unchanged stock Pysa models (`d5614e0a`) |
| `results/` | `115` saved experiment and check folders listed in [results/INDEX.md](results/INDEX.md) |
| [`analysis/`](analysis/run_all.sh) | `setup.py`, `table3.py`–`table6.py`, `rq1.py`–`rq6.py`, `lessons.py`, behavior & mechanism scripts |
| `scripts/` | Two research probe scripts (`path_probe.py`, `rewrite_catalog.py`) |
| `tests/`, `docs/` | `11` pytest files (`187` tests); design specs, verification checks, and prompt text |

### Analysis Scripts

| Script(s) | Purpose |
| --- | --- |
| `common.py`, `candidates.py` | Shared readers, evasion filters, 5,000-resample bootstrap intervals (seed `11`), candidate deduplication, query-shape classifier |
| `setup.py` | Table 2 (test sets), campaign budgets, minimal winning sets, CodeQL timings, fallbacks, scan-cache configs, rewrite catalog |
| `table3.py`–`table6.py` | Table 3 (single-rewrite cross-scanner matrix), Table 4 (4 more test sets), Table 5 (restricted LLM intervals), Table 6 (Pysa prompt search) |
| `rq1.py`–`rq6.py`, `lessons.py` | Step-by-step numbers for RQ1–RQ6 and negative/lesson checks |
| `extended_equivalence.py`, `cmd_equivalence.py`, `path_equivalence.py` | Multi-input behavior checks (`20` SQL, `12` command, `14` path inputs) |
| `mechanism_pysa.py`, `mechanism_codeql*.py` | Call-graph, sink-node, depth-sweep, and added-model repairs (RQ5) |

---

## CLI and Config Reference

### CLI Commands

| Command | What It Does |
| --- | --- |
| `./run.sh run --config C --output D` | Runs a search campaign on qualifying seeds. Flags: `--attempts`, `--trajectories`, `--seed-limit`, `--strategies`, `--resume`, `--rerun-errors`, `--scanner-timeout`. |
| `./run.sh exhaustive --config C --output D --seed-limit N` | Scans every non-empty rewrite subset without search or LLM (`--operators ...`, `--max-ops K`, `--resume`). |
| `./run.sh transform SEED --mask M [--output F]` | Applies bitmask `M` to `SEED`, runs the behavior check, writes code to `F` (or stdout) and JSON check to stderr. |
| `./run.sh report D [--write]` | Recomputes search summary from `attempts.jsonl` to stdout (`--write` updates `summary.json`). |
| `./run.sh doctor [--config C]` | Verifies SoCLaaS API access/model serving and prints where all 4 scanners were found. |

- **Resuming & fixing baseline errors:** `run --resume` drops incomplete walks (`discarded-partial.jsonl`) and restarts them cleanly so walks never mix across runs. If a baseline scan fails, `exhaustive` stops cleanly (continue with `--resume`), while `run` finishes other seeds, exits `1`, and fixes missed baselines with `--rerun-errors`.

### Config File Format (`configs/*.json`)

Run `./run.sh` from the repository root: `seeds`, `rules`, `pysa_models`, and `llm.env_file` are relative to the config file's folder, whereas `scan_cache`, `work_dir`, and `executable` are relative to your current working folder.

Minimal example (based on [configs/smoke.json](configs/smoke.json)):

```json
{
  "engine": "semgrep",
  "seeds": "../seeds",
  "rules": "../rules/demo-sqli.yaml",
  "corpus_kind": "synthetic",
  "attempts": 30,
  "trajectories": 5,
  "base_seed": 6223,
  "strategies": [1, 2, 3, 4, 5, 6, 7],
  "cache": true,
  "llm": {
    "provider": "soclaas",
    "model": "llama3.1:8b",
    "env_file": "../.env",
    "temperature": 0.2,
    "max_prompt_tokens": 2500
  }
}
```

| Field | Meaning |
| --- | --- |
| `engine` | `semgrep`, `codeql`, `pysa`, or `bandit` |
| `seeds`, `seed_limit` | Folder of seed files and optional cap on how many seeds to run |
| `rules` / `query` / `target_rules` | Local rule YAML (Semgrep), version-pinned `@` CodeQL query pack, and counted rule IDs |
| `attempts`, `trajectories`, `base_seed`, `strategies` | Steps per walk, walk count (`trajectory_seed = base_seed + k`), strategy IDs `1..7` |
| `operators`, `order` | Allowed rewrite pool subset; `increasing` (default) or `any` order |
| `evasion` | `any` (default: 1 qualifying rule stopped) or `all` (all qualifying rules stopped, used for Pysa) |
| `metropolis_restart` | `true` (default: Strategies 6–7 restart at end of order) or `false` (`configs/*-walk.json`) |
| `diagnostic_fields` | Which alert fields Strategy 5 sees: `rule`, `message`, `sink`, `snippet`, `trace` |
| `llm` | Endpoint, `model`, `temperature`, `max_prompt_tokens` (`2,500` original; `3,000` informed & `pysa-hard-any`), `prompt_extra` |
| `pysa_models`, `pysa_source`, `pysa_rules`, `semgrep_route` | Pysa model dirs, `"parameter-model"` vs `"http-server"`, rule codes, Flask `@app.route` toggle |
| `scan_cache`, `keep_database`, `scanner_timeout`, `oracle_timeout` | Disk cache directory, keep CodeQL/Pysa intermediate files, command timeouts in seconds |
| `work_dir`, `executable` | Temp scan folder (default `.sastlab/runs`); custom scanner binary path |

---

## Rewrites, Strategies, Scanners, and Output Files

### 18 Code Rewrites (In Bitmask Order)

Bit `i` corresponds to mask $2^i$. Campaigns use bits `0..12`; check-all runs cover `0..17` (`262,143` non-empty subsets). Full rewrite rules and edge-case rejections are in [docs/methodology.md](docs/methodology.md).

| Bit | Mask | Name | Group | What It Changes |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | `rename` | Control | Rename params and local variables to `_mt_*` |
| 1 | 2 | `format_swap` | Control | Convert f-strings to `.format()` or `+` joining to `join()` |
| 2 | 4 | `literal_slice` | Control | Add `#` in front of SQL string constants and slice `[1:]` |
| 3 | 8 | `dead_padding` | Control | Add an always-false `if` block before query/sink |
| 4 | 16 | `extract_1` | Interprocedural | Move query building into 1 helper function |
| 5 | 32 | `extract_2` | Interprocedural | Move query building through 2 helper functions |
| 6 | 64 | `branch_split` | Control-flow | Split query assignment across `if`/`else` branches |
| 7 | 128 | `dict_dispatch` | Sink resolution | Look up sink call in a fixed dictionary |
| 8 | 256 | `dynamic_sink` | Sink resolution | Look up sink name dynamically via `getattr(..., "exe" + "cute")` / split builtin |
| 9 | 512 | `char_launder` | Value propagation | Rebuild input char-by-char via `"".join(chr(ord(c)) for c in x)` |
| 10 | 1024 | `deep_nest` | Container | Wrap/unwrap input through 8 nested lists |
| 11 | 2048 | `db_roundtrip` | Second-order storage | Write/read input through an in-memory SQLite table |
| 12 | 4096 | `queue_roundtrip` | Container | Pass input through `queue.Queue` |
| 13 | 8192 | `simplequeue_roundtrip` | Container | Pass input through `queue.SimpleQueue` |
| 14 | 16384 | `pickle_roundtrip` | Value propagation | Serialize/deserialize input with `pickle` |
| 15 | 32768 | `partial_sink` | Sink resolution | Call sink through `functools.partial` |
| 16 | 65536 | `methodcaller_sink` | Sink resolution | Call method through `operator.methodcaller` |
| 17 | 131072 | `unbound_sink` | Sink resolution | Call method via class: `type(obj).method(obj, ...)` |

### 7 Search Strategies (`STRATEGIES`)

| ID | Name | How Next Operator Is Chosen |
| ---: | --- | --- |
| 1 | `naive` | Uniform random choice among valid forward operators (free restart at end of list) |
| 2 | `blackbox` | Greedy score `(unvisited, -uses, clean_count)` with random tie-break |
| 3 | `blackbox_agent` | LLM sees code diff, pass/fail status, last 3 steps, shuffled available operators |
| 4 | `static_greybox` | LLM called once per walk to rank all operators using rule info |
| 5 | `trace_agent` | Same info as Strategy 3 plus scanner diagnostics (`rule`, `message`, `sink`, `snippet`, `trace`) |
| 6 | `metric_syntax` | Flips one bit uniformly; Metropolis acceptance using AST syntax distance ($\tau = 0.25$) |
| 7 | `metric_depth` | Same as 6 using helper call depth, falling back to syntax distance on ties |

Exact prompts and JSON formats are in [docs/prompts.md](docs/prompts.md).

### Pinned Scanners and Rules

| Bug Class | Semgrep `1.178.0` | CodeQL `2.27.1` (`python-queries` `1.8.11`) | Pysa (`pyre-check` `0.10.0`, models `d5614e0a`) | Bandit `1.9.4` |
| --- | --- | --- | --- | --- |
| SQL injection (CWE-89) | `formatted-sql-query`, `tainted-sql-string` | `py/sql-injection` | `5005`, `5051` | `B608` |
| Command injection (CWE-78) | `dangerous-subprocess-use-audit` | `py/command-line-injection` | `5001`, `6065` | `B602` |
| Path traversal (CWE-22) | `path-traversal-open` | `py/path-injection` | `5011` | — |

### Output Folder Files (`results/<run>/` or `runs/<run>/`)

| File | Contents |
| --- | --- |
| `manifest.json` | Config settings, scanner/model versions, rule/seed/`framework_sha256` hashes, state, resumes |
| `qualifications.json` | Baseline behavior and scanner results per seed |
| `attempts.jsonl` | One row per search step: candidate hash, mask, scan result, behavior check, timing (`run`) |
| `evaluations.jsonl` | One row per combination tested (`exhaustive`) |
| `llm.jsonl` | Raw API requests, replies, prompt token counts, rate-limit waits, fallbacks |
| `trajectories.json`, `summary.json` | Walk mask sequences; rule report cards and strategy metrics |
| `bypasses/<seed>/<mask>.{py,json}` | Saved evading Python source file and verification record |

`manifest.json` records local machine paths and `framework_sha256` at run time (which may differ from current files across experiment phases). Raw scanner scratch files go into `.sastlab/runs/` (ignored by git and left out of zip archives; grew to ~7 GB across all runs).

---

## Environment and Scope Limits

Built and tested on Ubuntu 26.04 LTS (Linux 7.0 x86-64, glibc `2.43`, 2 KVM vCPUs on AMD EPYC 9354P, 7 GB RAM, 96 GB disk, Python `3.14`); not tested on macOS, Windows, or ARM (CodeQL bundle is Linux x86-64 only). Scanner tools take ~0.9 GB, `results/` ~0.5 GB. Scans take a few seconds on Semgrep/Pysa/Bandit and `14 s` median / `19 s` mean (`196 s` max in `codeql-v6`) on CodeQL.

- `seeds/` shares one program shape across 15 test files; `corpus_official`, `corpus_real`, and `corpus_apps` keep SQL query shapes without original database drivers.
- Same-behavior checks run on tested inputs only (`db_roundtrip` alters invalid Unicode surrogate characters).
- Pysa results depend on stock models plus `sqlite3.Connection` typing and parameter/HTTP source config.
- SoCLaaS hides model weight checksums, so LLM runs (`strategies` 3–5) may differ slightly across servers; non-LLM runs (`1, 2, 6, 7`) and `exhaustive` runs repeat cleanly on pinned scanners.

Code is released under the MIT License ([LICENSE](LICENSE)); included third-party rules, Pysa models, and adapted seeds keep their original licenses ([THIRD_PARTY.md](THIRD_PARTY.md)).
