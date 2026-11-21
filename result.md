# Experiment Results

Every number below is recomputed directly from the saved JSON/JSONL files in [`results/`](results/INDEX.md). To recompute all tables and checks locally (~3 minutes, offline), run `analysis/run_all.sh`; to view one search run's report card, run `./run.sh report results/<folder>`.

External helper scripts noted in the text (`harvest.py`, `validate_*_suite.py`, `rescan_*.py`, `check_candidates_unchanged.py`, `queue_*.sh`, `merge_rerun.py`) are not included in this archive; all report numbers and mechanism checks are reproduced by [`analysis/`](analysis/run_all.sh) and `sastlab`.

## Contents

- [1. Main Findings](#1-main-findings)
- [2. Baseline Setup](#2-baseline-setup)
- [3. Full Search Campaigns (Semgrep and CodeQL)](#3-full-search-campaigns-semgrep-and-codeql)
- [4. Check-All Scans Across Scanners, Test Sets, and Bug Classes](#4-check-all-scans-across-scanners-test-sets-and-bug-classes)
- [5. Why Evasions Happen (Root Causes)](#5-why-evasions-happen-root-causes)
- [6. LLM Search on Restricted Operator Pools](#6-llm-search-on-restricted-operator-pools)
- [7. Integrity Summary, Limits, and Reproduction Commands](#7-integrity-summary-limits-and-reproduction-commands)

---

## 1. Main Findings

1. **Semgrep `formatted-sql-query` is easily bypassed (`weak`).** In a full search campaign (`15` seeds × `7` strategies × `5` walks × `30` tries = `15,750` tries), every strategy evaded Semgrep on all `15/15` seeds and all `75/75` walks; Strategy 1 (random choice) alone passed the threshold (`weak`). Overall, `87.1%` of `5,563` unique candidates evaded Semgrep with `0` behavior differences.
2. **CodeQL `py/sql-injection` resists structural changes but fails when data flow is broken.** None of the `255` combinations of the first 8 core operators evaded CodeQL on 3 seeds (`765` candidates; early unarchived check). Four of the five campaign flow operators evade alone on `15/15` seeds (`dynamic_sink`, `char_launder`, `deep_nest`, `db_roundtrip`), while `queue_roundtrip` alone does not; all `15` combinations of those four evade (`225/225`).
3. **Semgrep and CodeQL fail on different rewrites.** Semgrep is bypassed individually by `extract_1`, `extract_2`, `branch_split`, `dict_dispatch`, and `dynamic_sink`; CodeQL by `dynamic_sink`, `char_launder`, `deep_nest`, and `db_roundtrip`. Only `dynamic_sink` bypasses both alone.
4. **LLM agents help only with the right model, rule info, and prompt.** In the unrestricted `8B` campaigns, history-only found fewer unique evasions per walk on Semgrep than random (`12.7` vs. `16.0`) and diagnostics matched random (`16.2` vs. `16.0`), while heuristic and Metropolis reached `22.6`–`24.8`. On restricted operator pools, larger models (`qwen3-coder-next`, `qwen3.6:35b`) with diagnostics or clear prompts beat random choice on Semgrep (`-4.32`, 95% CI `[-5.47, -3.20]` vs. heuristic for `coder`) and CodeQL, while on Pysa agents scored `0/45` until told the increasing-only operator order and at best matched (never beat) heuristic and Metropolis.

*Scope note:* Findings 1–4 come from two rules on 15 synthetic programs that share one template (`seeds/`). Broader test sets, scanners, and bug classes follow in [Section 4](#4-check-all-scans-across-scanners-test-sets-and-bug-classes).

---

## 2. Baseline Setup

| Setting | Value Used |
| --- | --- |
| Machine | Linux x86-64 (`glibc` `2.43`), 2 CPU cores, Python `3.14.4` |
| Semgrep | `1.178.0`, standalone `formatted-sql-query` at commit `a84ff9cc2453ca91d581380de4b8b3f272f6f4be` |
| CodeQL | CLI `2.27.1`, query `codeql/python-queries@1.8.11:Security/CWE-089/SqlInjection.ql` (`py/sql-injection`) |
| LLM Serving | `llama3.1:8b` on NUS SoCLaaS, `temperature = 0.2`, prompt limit `2,500` tokens (no weight checksum) |
| Test Seeds | 15 synthetic SQLite programs (`seed_01`–`seed_15`) |
| Operator Pool | 13 operators (`8` core + `5` flow), `8,192` subsets per seed |
| Walk RNG Seed | `base_seed = 6223 + walk_number` |
| Cache & Inputs | Scan cache off; tested with `"1"` vs. `"1' OR '1'='1"` on a 3-row SQLite DB |

| Campaign | Folder | Budget | Status |
| --- | --- | --- | --- |
| Semgrep search | `results/semgrep-v6` | `30 × 5 × 15 × 7` (`15,750` tries) | Complete (`0` errors) |
| CodeQL 4-op check | `results/codeql-flow-ops-15seeds` | `15` subsets × `15` seeds (`225` candidates) | Complete (`225/225` evade) |
| CodeQL 5-op check | `results/codeql-flow-ops-seed01` | `31` subsets × `seed_01` (`31` candidates) | Complete (`30/31` evade) |
| CodeQL search | `results/codeql-v6` | `30 × 5 × 5 × 7` (`5,250` tries) | Complete (`0` errors after rerun) |

*Note:* Direct comparisons between `semgrep-v6` and `codeql-v6` are not valid because they ran on different rules, scanners, and seed counts (`15` vs. `5`).

---

## 3. Full Search Campaigns (Semgrep and CodeQL)

### Semgrep (`semgrep-v6`)

- **Report card (`formatted-sql-query`):** `15` qualifying seeds, threshold `8`, rating **`weak`** (all `75/75` walks find an evasion for every strategy; `0` scanner errors and `0` behavior errors in `15,750` tries).

| Strategy | Unique Evasions / Walk | Unique Tried | Evading Tries (of 2,250) | Mean First Evasion | Wall s to First |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1. Random baseline | `16.0` | `1,320` | `1,410` | `2.00` | `3.9` |
| 2. Blackbox heuristic | `24.8` | `1,770` | `1,860` | `2.00` | `4.0` |
| 3. History-only agent | `12.7` | `790` | `1,352` | `2.07` | `6.3` |
| 4. Static LLM ranking | `3.4` | `300` | `1,920` | `1.88` | `5.7` |
| 5. Diagnostic agent | `16.2` | `982` | `1,586` | `1.80` | `5.5` |
| 6. AST-distance Metropolis | `22.6` | `1,890` | `1,875` | `1.60` | `3.1` |
| 7. Call-depth Metropolis | `22.6` | `1,920` | `1,875` | `1.60` | `3.2` |

Paired differences across 75 `(seed, walk)` pairs (95% bootstrap interval and sign-flip p-value; small-sample note because seeds share one template):

| Comparison | Mean Diff | 95% CI | p-value |
| --- | ---: | --- | ---: |
| Strategy 2 − Strategy 1 | `+8.80` | `+8.20` to `+9.33` | `< 0.001` |
| Strategy 6 − Strategy 1 | `+6.60` | `+5.48` to `+7.81` | `< 0.001` |
| Strategy 3 − Strategy 1 | `−3.31` | `−4.36` to `−2.24` | `< 0.001` |
| Strategy 5 − Strategy 1 | `+0.24` | `−0.85` to `+1.31` | `0.68` |
| Strategy 5 − Strategy 3 | `+3.55` | `+2.65` to `+4.44` | `< 0.001` |
| Strategy 7 − Strategy 6 | `0.00` | `−0.15` to `+0.15` | `1.00` |

Key takeaways:
- **Strategy behavior:** Because one rewrite already hides the bug from Semgrep, every strategy finds a first evasion within ~2 tries. Broad searchers (2, 6, 7) find the most unique evasions (`22.6`–`24.8`). Diagnostics help Strategy 5 beat Strategy 3 (`+3.55`), without beating random (`+0.24`). Each 30-step walk took `59`–`61 s` without an LLM vs. `92`–`95 s` with an LLM (~`35 s` model wait).
- **Operator impact:** Of `5,563` unique `(seed, mask)` candidates, `87.1%` evaded (`extract_1`, `extract_2`, `branch_split`, `dict_dispatch`, `dynamic_sink` evade on `15/15` seeds alone; the other 8 evade on `0/15`).
- **Metropolis & ranking notes:** Strategy 6 rejected `6.0%` of proposals (lowest accept chance `0.35`); Strategy 7 rejected `13.3%` (lowest `0.0003`); they picked the same mask on `83%` of steps and `0/75` full walks were identical. Strategy 4 produced only 7 distinct rankings across 75 walks (`literal_slice` ranked first in `24`, `dict_dispatch`/`extract_1`/`extract_2` `15` each, `rename` `6`).
- **LLM stats:** `4,576` requests, `0` fallbacks, `0` rate-limit waits, `1` retried network timeout; average prompt `473` tokens (max `659`). Strategies 3 & 5 chose `queue_roundtrip` `22%`, `rename` `19%`, `extract_2` `18%`, `deep_nest` `12%`, `db_roundtrip` `11%`, `extract_1` `9%`.

### CodeQL (`codeql-v6` and Check-All Flow Runs)

- **Flow combinations:** All `15` subsets of `{dynamic_sink, char_launder, deep_nest, db_roundtrip}` evaded `py/sql-injection` across all `15` seeds (`225/225` candidates, `0` errors, `0` behavior differences). Across all 5 campaign flow operators on `seed_01`, `30/31` evaded (only `queue_roundtrip` alone stayed detected). Average CodeQL scan took `24 s`.

Example evading code on `seed_01` (both still return all 3 rows on the attack input while CodeQL reports nothing):

```python
# dynamic_sink
getattr(cursor, 'exe' + 'cute')(query)

# char_launder
user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
cursor.execute(query)
```

- **Search campaign (`codeql-v6`, `5,250` tries):** `2,896` tries evaded (`1,423` of `1,873` unique `(seed, mask)` pairs; `0` verdict conflicts; `0` behavior errors). Every candidate with any of the four working flow operators evaded, and none without them did (`0` exceptions across `5,250` scans). Rating: **`weak`** (`"exploratory": true`: `S_rule = 5`, threshold `3`).
- **Timeout recovery (`seed_05`):** Host CPU throttling initially caused `240` discarded timeouts; three remaining Strategy-1 timeouts on `seed_05` (walks 3 and 4) were rerun in `results/codeql-v6-seed05-rerun` (locked to the original 13-operator pool) and merged into `codeql-v6` (old rows saved in `discarded-partial.jsonl`). Replaying `seed_05` Strategy 1 reproduced `145/150` candidate hashes (differences follow a failed scan) and matched `143/143` shared verdicts.

| Strategy | Walks Used | With Evasion | Mean First Evasion | Unique Evasions / Walk |
| --- | ---: | ---: | ---: | ---: |
| 1. Random baseline | `25` | `25` | `2.80` | `16.8` |
| 2. Blackbox heuristic | `25` | `25` | `2.60` | `19.0` |
| 3. History-only agent | `25` | `25` | `5.04` | `9.5` |
| 4. Static LLM ranking | `25` | `16` | `3.25` (`13.24` counting miss as `31`) | `2.0` |
| 5. Diagnostic agent | `25` | `25` | `7.84` | `9.1` |
| 6. AST-distance Metropolis | `25` | `25` | `2.00` | `19.8` |
| 7. Call-depth Metropolis | `25` | `25` | `2.00` | `19.8` |

*Note:* Strategies 3 & 5 in `codeql-v6` used the fixed definition order; shuffled-prompt results are in [Section 6.1](#61-prompt-definition-order).

---

## 4. Check-All Scans Across Scanners, Test Sets, and Bug Classes

### 4.1 Official-Suite SQL Seeds (`corpus_official/seeds/`)

- **Filtering pipeline (`corpus_official/seeds/funnel.json`):** From upstream `semgrep-rules` (`a84ff9cc24`, 15 SQL files) and `codeql` (`codeql-cli/v2.27.1`, 4 SQL files): `19` files → `122` `.execute` calls → `102` single-argument → `82` string-built → `53` straight-line slices with 1 input → `24` unique programs → **`9` working SQLite attacks** (`9/9` flagged by CodeQL; `7/9` by Semgrep, which misses the 2 `+` concatenation programs).
- **Official test suite checks:** Semgrep `1.178.0` passes `semgrep --test` on `formatted-sql-query` (match lines `32`, `39`). CodeQL `2.27.1` matches all `20/20` alerts in `SqlInjection.expected` (`results/official-validation/`). Adapted upstream positive cases (`app.py` `unsafe`, `sql_injection.py` `show_user`) are flagged by SASTLab.
- **Check-all runs (`codeql-official-*`, `semgrep-official-*`):**

| Scanner (Qualifying Seeds) | Unique Candidates | Valid & Scanned | Rejected Invalid | Exact Pattern (`0` exceptions) |
| --- | ---: | ---: | ---: | --- |
| CodeQL (`9/9`) | `486` | `450` | `36` | `81/81` with a flow rewrite evade; `369/369` without are caught. All `9` flow rewrites evade alone (`9/9`). |
| Semgrep (`7/7`) | `2,744` | `2,407` | `337` | `1,858/1,858` with any of the `8` structural/sink rewrites evade; all other `109` evading candidates use `literal_slice` (alone on `%`/`.format` seeds `4/4`, with `format_swap` on f-string seeds `3/3`). |

All `21,264` unique SQL candidates across saved runs pass `analysis/extended_equivalence.py` on `20` inputs (`0` differences).

### 4.2 Benchmark and Deployed App SQL Programs

- **Benchmark programs (`corpus_real/seeds/`, 6 programs):** `5` OWASP BenchmarkPython SQLi tests + `1` `vulpy` login (`semgrep-real-pairs`, `codeql-real-*`, `pysa-real-pairs`). Qualifying baselines: Semgrep `6/6`, CodeQL `5/6`, Pysa `5/6` (`r01` using `configparser` is missed at baseline by CodeQL and Pysa).
- **Deployed apps (`corpus_apps/seeds/`, 5 functions):** `parsl` `2025.12.22` (3), `scitokens` `1.8.1` (1), `pyload-ng` `0.5.0b3.dev90` (1); all `5/5` are exploitable and flagged by Semgrep pattern, CodeQL, and Pysa (`4/5` flagged by Semgrep taint).

| Test Set | Scanner | Scanned Candidates | Evasions / Silent | Exact Pattern (`0` exceptions) |
| --- | --- | ---: | ---: | --- |
| `corpus_real` | Semgrep (pattern) | `954` | `648` | `634/634` with structural/sink rewrite + `14` containing `literal_slice` |
| `corpus_real` | CodeQL | `261` | `45` | `45/45` with a flow rewrite; `0/216` without |
| `corpus_real` | Pysa (`all` rules) | `792` | `198` | `173/173` round-trip (`db_roundtrip`/`simplequeue_roundtrip`) + `25/25` sink-hider + `literal_slice` |
| `corpus_apps` | Semgrep (pattern) | `552` | `396` | `369/369` structural/sink + `27` `literal_slice` |
| `corpus_apps` | Semgrep (taint, `4/5`) | `492` | `144` | `144` matching taint-mode pattern (`0` exceptions) |
| `corpus_apps` | CodeQL | `165` | `45` | `45/45` flow-changing; `0` exceptions |
| `corpus_apps` | Pysa (`all` rules) | `552` | `156` | Round-trip or sink-hider + `literal_slice` (`0` exceptions) |

### 4.3 Third Analyzer: Pysa

Tested using `pyre-check` `0.10.0` with stock models (`d5614e0a`) across rules `5005` (flow) and `5051` (string combine) on `34` qualifying seeds (`15/15` main, `10/12` diverse, `9/9` official; `d08_like` and `d11_fetchone` dropped by exploit check). Across `pysa-{official,main,diverse}-singles` and `pysa-{official,main}-pairs`: `4,716` rows, `3,994` unique scanned candidates (`606` singles, `3,388` pairs), `0` scan errors, `0` behavior differences, `5.2 s` average scan time (`analysis/table3.py`, `analysis/rq5.py`).

**Single rewrites (`34` qualifying seeds; silent = neither `5005` nor `5051` fires):**

| Operator(s) | Rule 5005 Removed | Rule 5051 Removed | Silent (Both Stopped) |
| --- | ---: | ---: | ---: |
| `db_roundtrip`, `simplequeue_roundtrip` | `68/68` | `68/68` | `68/68` |
| `dict_dispatch`, `dynamic_sink`, `methodcaller_sink`, `partial_sink`, `unbound_sink` | `170/170` | `0/170` | `0/170` |
| `literal_slice` | `0/34` | `34/34` | `0/34` |
| `format_swap` | `0/28` | `4/28` | `0/28` |
| `extract_1`, `extract_2` | `0/68` | `2/68` | `0/68` |
| Other `7` operators (`rename`, `dead_padding`, `branch_split`, `char_launder`, `deep_nest`, `pickle_roundtrip`, `queue_roundtrip`) | `0` | `0` | `0` |

- **Pairs (`24` main & official seeds, `3,388` candidates):** `914/3,388` are silent: `784/784` with a round trip (`db_roundtrip`/`simplequeue_roundtrip`), `120/120` pairing a sink-hider with `literal_slice`, and `10/100` pairing a sink-hider with `format_swap` (on the 2 concatenation seeds where `format_swap` stops rule `5051`). Notice `130` pairs silence Pysa even though neither rewrite works alone. Zero of `712` candidates built only from core controls + `extract_*` + `branch_split` stop rule `5005`.
- **Triples (`results/pysa-triples/evaluations.jsonl`, checked in `analysis/extended_equivalence.py`):** All subsets of up to 3 of the 16 non-round-trip rewrites on `o03`, `o18`, `o24`: `1,510` unique candidates (`578` invalid subsets), `0` errors, `20/303` pairs and `189/1,161` triples silent (`0` new ways to evade beyond pairs).
- **Agreement with other scanners:** Shared candidates vs. CodeQL (`1,091`): both flag `631`, both silent `129`, CodeQL-only silent `315`, Pysa-only silent `16`. Shared vs. Semgrep (`1,973`): both flag `583`, both silent `164`, Semgrep-only silent `1,049`, Pysa-only silent `177`. Only `db_roundtrip` and `simplequeue_roundtrip` silence both CodeQL and Pysa alone.
- **Built-in HTTP source check (`pysa-http-*`):** Using `BaseHTTPRequestHandler.path` (`576` candidates), Pysa produces the exact same rule set on all `576` scans with `0` errors.

### 4.4 Semgrep Taint Mode and Newer Scanner Versions

- **Semgrep taint mode (`flask-tainted-sql-string` at `17e31e11`):** With `@app.route("/<user_input>")` added at scan time, qualifying seeds are `15/15` main, `9/9` official, `10/12` diverse, `3/6` real (`4,462` candidates, `1,424` evading). Evasion happens iff `literal_slice`, `extract_1`, `extract_2`, or (`format_swap` on concatenation seeds `o18_semgrep`, `o23_codeql`, `d01_concat`, `d12_concat_parts`) is present (`0` exceptions). Across `22` seeds flagged by both rules (pattern vs. taint singles): `literal_slice` evades `4/22` vs. `4/22`; `extract_1` & `extract_2` evade `22/22` vs. `22/22`; `branch_split` & 5 sink-hiders evade pattern `22/22` vs. taint `0/22`; remaining 9 operators evade `0/22` on both.
- **Newer releases (`*-latest-*`):** Semgrep `1.182.1` matched `1.178.0` on `392/392` singles. CodeQL `2.27.3` (`python-queries` `1.8.13`, zip SHA-256 `845075a2...`) checked `428` singles on `24` seeds (`0` errors, `216` evading — matching the exact `9` flow rewrites). `pyre-check` `0.10.0` matched upstream `main` (`d5614e0a`).

### 4.5 Bandit (AST Linter, Version 1.9.4)

Single and pair check-all scans across 6 test sets (`50` qualifying seeds, `7,700` total candidates, `0` scan errors, `0` behavior differences, `1,166` silent; `analysis/rq2.py`):

| Test Set | Seeds | Candidates | Silent |
| --- | ---: | ---: | ---: |
| Main SQL (`B608`) | `15` | `2,430` | `270` |
| Varied SQL (`B608`) | `10` | `1,584` | `212` |
| Official SQL (`B608`) | `9` | `1,386` | `192` |
| Benchmark SQL (`B608`) | `6` | `954` | `107` |
| Deployed SQL (`B608`) | `4` | `492` | `51` |
| Command injection (`B602`) | `6` | `854` | `334` |

- **`B608` (SQL):** Silent iff `literal_slice` is used, or `format_swap` on a `+` query (`''.join([...])`), `0` exceptions in `6,846` SQL candidates. Flow and sink rewrites have no effect.
- **`B602` (`subprocess` shell):** Silent iff `dict_dispatch`, `dynamic_sink`, `partial_sink`, or `methodcaller_sink` is used (`0` exceptions in `854` candidates).
- **Worked example (`seed_01` + `char_launder` + `dynamic_sink`):** Semgrep and CodeQL go silent; Pysa still reports rule `5051`; Bandit still reports `B608`.

### 4.6 Command Injection (CWE-78) and Path Traversal (CWE-22)

- **Command injection (`seeds_cmd`, 8 seeds):** Qualifying baselines: Semgrep `7/8` (`os.popen` unmatched), CodeQL `8/8`, Pysa `8/8` (`6` under `6065`, `2` under `5001`). Zero errors, `0` behavior differences.
- **Path traversal (`seeds_path`, 8 seeds with `open`):** Qualifying baselines: Semgrep `6/8` (`p05`, `p08` missed), CodeQL `8/8` (`6` scanned for time/cost), Pysa `8/8` (`6` scanned for time/cost). Adding `SINK_FUNCTIONS = ("open",)` left SHA-256 hashes unchanged across `12,058` previously saved candidates.

| Bug Class | Scanner | Scanned Candidates | Evasions / Silent | Exact Pattern (`0` exceptions) |
| --- | --- | ---: | ---: | --- |
| CWE-78 | Semgrep (`dangerous-subprocess-use-audit`) | `1,002` | `391` | Sink-resolution rewrites evade (`391/391`); `extract_*` and `branch_split` do **not** evade |
| CWE-78 | CodeQL (`py/command-line-injection`) | `406` | `64` | Flow-changing rewrites evade (`64/64`) |
| CWE-78 | Pysa (`6065` or `5001`) | `1,150` | `644` | Round-trip or sink-resolution rewrite (1 rule/seed, so no pair needed) |
| CWE-22 | Semgrep (`path-traversal-open` + route) | `756` | `249` | `dict_dispatch`, `dynamic_sink`, or `partial_sink` present (`249/249`); `extract_*`/`branch_split` stay caught |
| CWE-22 | CodeQL (`py/path-injection`) | `285` | `42` | Flow-changing rewrites evade (`42/42`) |
| CWE-22 | Pysa (`5011`) | `756` | `393` | Sink-resolution rewrite or round-trip (`393/393`) |

### 4.7 New Operators, Path Probe, and Rewrite Catalog

- **New 18-operator checks (`semgrep-newops`, `codeql-newops`):** Singles and pairs of bits 13–17 on `12` varied seeds had `0` behavior or scan errors; all `5` evade CodeQL on `10/10` qualifying seeds; the `3` sink operators evade Semgrep on `8/8`.
- **Placing rewrites along the path (`codeql-path-probe`, [`scripts/path_probe.py`](scripts/path_probe.py)):** Laundering code inserted directly at CodeQL alert-path steps (parameter, query assignment, sink) evaded in `155/155` cases vs. `31/31` identity controls caught (`d08`, `d11` excluded); placing code mid-path gives no benefit over function entry.
- **Control-only matrix (`semgrep-controls-main`, `analysis/rq1.py`, `analysis/lessons.py`):** All 15 combinations of `{rename, format_swap, literal_slice, dead_padding}` on 15 main seeds (`225` scans): only the `60` candidates containing both `format_swap` and `literal_slice` evade; across all pinned SQL runs, `134/473` unique control-only candidates evade (every one uses `literal_slice`).
- **Rewrite catalog (`codeql-rewrite-catalog`, [`scripts/rewrite_catalog.py`](scripts/rewrite_catalog.py)):** `59` behavior-checked hand-written variants probing CodeQL limits that led to operators 14–18.

---

## 5. Why Evasions Happen (Root Causes)

Re-checked by `analysis/run_mechanism.sh` into `results/mechanism/` (`seed_01` and `o05_semgrep`):

- **Pysa call-graph and argument bugs (`mechanism_pysa.py`):**
  - `dynamic_sink` and `methodcaller_sink` leave **no call link** to `sqlite3.Cursor.execute` in `get_user_profile`'s call graph.
  - `dict_dispatch` and `partial_sink` leave the target call unresolved (`UnexpectedCalleeExpression`; only attribute access is recorded).
  - `unbound_sink` (`type(cursor).execute(cursor, query)`) resolves as a bound call and **shifts arguments by 1** (shown because rule `5005` fires on invalid `type(cursor).execute(query)` and `sqlite3.Cursor.execute(cursor, query)`).
- **Pysa missing standard-library models (`mechanism_pysa.py`):** Stock models cover `queue.Queue.put/get` but leave out `_queue.SimpleQueue`. Adding `2` model lines for `_queue.SimpleQueue` restores rules `5005` + `5051` on `simplequeue_roundtrip`; adding `3` SQLite summary lines (`Connection.execute` → `self` → `Cursor` → `Cursor.fetchone`) restores both rules on `db_roundtrip`.
- **CodeQL missing sink nodes and depth limit (`mechanism_codeql_probe.py`):** Listing `SqlInjection::Sink` nodes directly shows the sink-resolution rewrites produce **no sink node**, whereas `deep_nest` and `db_roundtrip` keep the sink node and lose taint along the path. Depth checks show `deep_nest` flags up to depth `5` and stops at depth `≥ 6` (the operator uses depth `8`), matching `accessPathLimit() = 5` in CodeQL's shared data-flow library.
- **CodeQL missing summary rules (`mechanism_codeql.py`, `mechanism_codeql_flow.py`):** Adding `2` model-pack rows per rewrite restores `py/sql-injection` for `simplequeue_roundtrip`, `pickle_roundtrip` (`pickle.dumps`/`loads`), and `char_launder` (`chr`/`ord`) on `2/2` seeds each. Adding `3` summary rows attached to `sqlite3.connect()`'s return value (type `sqlite3.Connection` alone did not match) restores the alert on `db_roundtrip`.

---

## 6. LLM Search on Restricted Operator Pools

### 6.1 Prompt Definition Order

- **`prompt-order-probe`:** Fixed definition order (`rename` first) made `llama3.1:8b` pick `rename` `34/60` times vs. `13/60` when shuffled. Per-call shuffling was added to `sastlab/llm.py`.
- **`codeql-promptfix` vs. `codeql-v6` (`5` walks):** With shuffled definitions, `8B` Strategy 3 (history-only) and Strategy 5 (diagnostic) needed `3.64` and `4.20` tries on average to first evasion vs. `5.04` and `7.84` with fixed order in `codeql-v6`. Strategy 4 was not rerun.

### 6.2 Semgrep and CodeQL Restricted Pools + Single-Field Tests

- **Semgrep (`semgrep-hard`, `semgrep-hard30`, `semgrep-hard30-qwen`, `semgrep-hard30-q36`):** 9-operator pool whose minimal winning sets are `{extract_1}` or `{format_swap, literal_slice}` (3 seeds × 30 streams, budget `15`).
  - `llama3.1:8b`: History-only (`9.16`, `64/90`) and diagnostic (`8.82`, `64/90`) match random (`8.37`, `66/90`) and lag behind heuristic (`~5.47`).
  - `qwen3-coder-next`: Diagnostic reaches `1.14` (`90/90`, picking `extract_1` first in `86/90`) vs. history-only `4.47` (`88/90`).
  - `qwen3.6:35b`: Diagnostic reaches `3.16` (`89/90`) vs. history-only `9.92` (`52/90`).
- **Diagnostic single-field tests (`semgrep-abl-message|snippet|sink`, `qwen3-coder-next`, Strategy 5):** Message only `1.06` (`90/90`), all fields `1.14` (`90/90`), snippet only `4.43`, line only `4.52`, none `4.47`. **Semgrep's alert message text drives nearly all of the feedback gain.**
- **CodeQL (`codeql-hard`, `codeql-hard15`):** 9-operator pool where only `char_launder` evades (budget `12`). On `seed_01` (`15` streams): `llama3.1:8b` history-only `8.27` (`10/15`) and diagnostic `8.87` (`9/15`) trail random `4.20` (`15/15`), heuristic `4.07` (`15/15`), and Metropolis `7.47` (`11/15`). With `qwen3-coder-next`, history-only hits `1.87` (`15/15`) and diagnostic hits `2.07` (`15/15`; diff `+0.20`, CI `[-0.07, +0.47]`): unlike Semgrep, CodeQL diagnostics add no improvement over history alone.

### 6.3 Pysa Restricted Search and Prompt Variants

9-operator pool without round trips (`3` seeds × `15` streams = `45` streams, budget `15`, `evasion: "all"`; minimal winning pairs are `{dict_dispatch|dynamic_sink, literal_slice}`).

**Original prompt (`pysa-hard-qwen`, `pysa-hard-qwen-rule`, `qwen3-coder-next`):**

| Strategy | Mean Tries to First (miss = 16) | 95% Interval | Walks Solved |
| --- | ---: | --- | ---: |
| 1. Random baseline | `13.33` | `[10.67, 15.60]` | `15/45` |
| 2. Blackbox heuristic | `10.13` | `[7.40, 12.67]` | `36/45` |
| 3. History-only agent | `16.00` | — | `0/45` |
| 5. Diagnostic agent | `16.00` | — | `0/45` |
| 5 (rule ID only) | `16.00` | — | `0/45` |
| 6. AST-distance Metropolis | `9.20` | `[6.67, 11.80]` | `33/45` |

Why original-prompt agents scored `0/45`: not knowing that operators must be added in **strict increasing order**, agents kept picking `char_launder` (`234` and `221` of `675` tries vs. `108` random) past `literal_slice` and the sink-hiders, blocking those needed rewrites until restart.

**Prompt & order comparison on `qwen3-coder-next` (Set A):**

| Prompt Variant (`order: "increasing"`) | History-Only (Strat. 3) | Diagnostic (Strat. 5) |
| --- | ---: | ---: |
| Original (no tool, no order) | `0/45`, mean `16.00` | `0/45`, mean `16.00` |
| Tool-aware (`noorder`: names Pysa + 2 rules) | `0/45`, mean `16.00` | `1/45`, mean `15.71` |
| Informed (tool + rules + fixed operator order) | `20/45`, mean `12.53` | `34/45`, mean `10.42` |

Under the informed prompt, Strategy 5 differs from random by `−2.91` (`[−6.31, +0.73]`, `p = 0.13`) and from heuristic by `+0.29` (`[−3.24, +3.53]`, `p = 0.87`). Under `order: "any"` (free order; important note: candidates grow to ~5–6 operators so random already hits `45/45` at `5.87`), original-prompt agents hit `45/45` (`6.00`, `5.02`) and `35B` informed hits `45/45` (`5.07`, `4.02`).

**Multi-model & two-seed-set test (Set A = `seeds_pysa_hard`, random `15/45` mean `13.33`; Set B = `o03,o18,o24`, random `23/45` mean `11.93`):**

| Set | Model | History-Only (Solved, Mean, vs. Random [95% CI]) | Diagnostic (Solved, Mean, vs. Random [95% CI]) |
| --- | --- | --- | --- |
| A | `qwen3-coder-next` | `20/45`, `12.53`, `−0.80 [−3.73, +2.09]` | `34/45`, `10.42`, `−2.91 [−6.31, +0.73]` |
| A | `qwen3.6:35b` | `1/45`, `15.69`, `+2.36 [−0.00, +5.13]` | `9/45`, `13.42`, `+0.09 [−3.44, +3.69]` |
| A | `llama3.1:8b` | `10/45`, `13.73`, `+0.40 [−3.27, +4.13]` | `18/45`, `13.42`, `+0.09 [−3.00, +3.53]` |
| B | `qwen3-coder-next` | `22/45`, `12.51`, `+0.58 [−1.93, +3.24]` | `38/45`, `9.69`, `−2.24 [−5.53, +1.11]` |
| B | `qwen3.6:35b` | `5/45`, `14.98`, `+3.04 [+0.27, +5.78]` | `12/45`, `13.62`, `+1.69 [−0.96, +4.27]` |

Only `coder` diagnostic scores below random in both seed sets, and both 95% intervals overlap `0`.

### 6.4 Informed Prompts on Semgrep and CodeQL

Comparing original vs. informed (`llm.prompt_extra`) prompts on identical streams (`semgrep-informed-*`: 3 seeds × 30 streams; `codeql-more-*` / `codeql-informed-*`: `d01` + `d02` × 15 streams = 30 streams):

| Seed Set / Scanner | Model | Agent | Original Mean (Solved) | Informed Mean (Solved) | Informed − Random [95% CI] |
| --- | --- | --- | ---: | ---: | ---: |
| Semgrep (pattern) | Random | — | — | `8.37` (`66/90`) | — |
| Semgrep (pattern) | `8B` | History-only | `9.16` (`64/90`) | `6.04` (`84/90`) | `−2.32 [−4.52, −0.17]` |
| Semgrep (pattern) | `8B` | Diagnostic | `8.82` (`64/90`) | `6.13` (`83/90`) | `−2.23 [−4.63, +0.10]` |
| Semgrep (pattern) | `Coder` | History-only | `4.47` (`88/90`) | `3.28` (`90/90`) | `−5.09 [−7.28, −2.98]` |
| Semgrep (pattern) | `Coder` | Diagnostic | `1.14` (`90/90`) | `2.71` (`90/90`) | `−5.66 [−7.70, −3.71]` |
| Semgrep (pattern) | `35B` | History-only | `9.92` (`52/90`) | `3.47` (`89/90`) | `−4.90 [−7.00, −2.79]` |
| Semgrep (pattern) | `35B` | Diagnostic | `3.16` (`89/90`) | `2.64` (`90/90`) | `−5.72 [−7.77, −3.74]` |
| CodeQL (data-flow) | Random | — | — | `4.30` (`30/30`) | — |
| CodeQL (data-flow) | `8B` | History-only | `8.43` (`18/30`) | `7.13` (`24/30`) | `+2.83 [+1.33, +4.30]` |
| CodeQL (data-flow) | `8B` | Diagnostic | `8.27` (`20/30`) | `7.67` (`24/30`) | `+3.37 [+1.77, +5.07]` |
| CodeQL (data-flow) | `Coder` | History-only | `3.77` (`30/30`) | `6.40` (`28/30`) | `+2.10 [+0.57, +3.70]` |
| CodeQL (data-flow) | `Coder` | Diagnostic | `2.60` (`30/30`) | `5.70` (`28/30`) | `+1.40 [−0.17, +3.10]` |
| CodeQL (data-flow) | `35B` | History-only | `2.70` (`30/30`) | `1.63` (`30/30`) | `−2.67 [−3.80, −1.63]` |
| CodeQL (data-flow) | `35B` | Diagnostic | `1.47` (`30/30`) | `1.50` (`30/30`) | `−2.80 [−4.00, −1.67]` |

Feedback gain (`Diagnostic − History-only`) on Semgrep drops sharply once the prompt explains the rule: original prompt `Coder −3.32 [−4.57, −2.16]`, `35B −6.77 [−8.58, −5.04]`, `8B −0.33 [−1.79, +1.11]` vs. informed `Coder −0.57 [−1.02, −0.20]`, `35B −0.82 [−1.71, −0.09]`, `8B +0.09 [−1.01, +1.12]`.

### 6.5 Extra CodeQL Walks and Seed Repeats

- **CodeQL (`d01` + `d02`, 30 streams, `codeql-more-*`):** `35B` beats random under both prompts (`−1.6` to `−2.8`); `8B` does worse (`+2.8` to `+4.1`); `Coder` beats random only with original-prompt diagnostics (`−1.70`) and does worse with informed prompts (`+2.10`, `+1.40`).
- **Base-seed repeats (`7001`, `7002` in `semgrep-rep*`, `pysa-rep*`):** Semgrep cells stay within `0.4` tries of initial runs (below random in `18/18` runs; 95% CI below `0` in `13/18`). On Pysa, `coder` diagnostic beats random in `3/3` (pooled `−5.01 [−6.87, −3.04]`), `coder` history-only in `3/3` (`−2.26 [−4.03, −0.48]`), `35B` history-only does worse (`+1.33 [+0.20, +2.56]`), and `8B` diagnostic overlaps random (`−1.04 [−2.59, +0.58]`).

### 6.6 Metropolis Restarts Check

With default `metropolis_restart: true`, Strategies 6 and 7 reset to `mask = 0` at the end of `available(mask)` (`analysis/rq3.py` confirms every jump goes back to the seed when no later operator remains):

| Run | Tries | Restarts | Restarts ≤ First Evasion | Walks With a Restart |
| --- | ---: | ---: | ---: | ---: |
| `semgrep-v6` (full) | `4,500` | `300` | `0` | `0 / 150` |
| `codeql-v6` (full) | `1,500` | `100` | `0` | `0 / 50` |
| `semgrep-hard` (pilot) | `1,200` | `184` | `136` | `60 / 80` |
| `codeql-hard` (pilot) | `480` | `80` | `32` | `24 / 40` |
| `semgrep-hard30` | `1,350` | `164` | `63` | `42 / 90` |
| `codeql-hard15` | `180` | `20` | `11` | `8 / 15` |
| `pysa-hard-qwen` | `675` | `78` | `48` | `30 / 45` |

Control runs with `metropolis_restart: false` (Strategy 6, `0` restarts, `0` errors) show restarts make no measurable difference:

| Run (`metropolis_restart: false`) | Solved | Mean (miss = 16) | Saved Walk | Without Restart − Saved | Without Restart − Heuristic |
| --- | ---: | ---: | --- | --- | --- |
| `semgrep-hard30-walk` | `90/90` | `5.28` | `90/90`, `5.23` | `+0.04 [−0.80, +0.78]` | `−0.19 [−1.42, +0.91]` |
| `pysa-hard-walk` | `36/45` | `9.27` | `33/45`, `9.20` | `+0.07 [−1.47, +1.93]` | `−0.87 [−4.00, +2.07]` |

### 6.7 Statistical Checks

Bootstrap intervals are 95% percentile intervals using `5,000` resamples (`analysis/common.py`, RNG seed `11`) over independent walk streams (paired differences averaged across seeds per stream for restricted pools) or `(seed, trajectory)` pairs (full Semgrep campaign). Sign-flip p-values use `5,000` random sign flips over per-stream differences.

---

## 7. Integrity Summary, Limits, and Reproduction Commands

### Validation Summary

| Check | Measured Result |
| --- | --- |
| Automated tests | `187` tests (`181 passed, 6 skipped` in Docker) ([docs/validation.md](docs/validation.md)) |
| Same-behavior checks | `0` differences across all campaigns (`5,563` Semgrep, `225 + 31` flow checks, `5,250` CodeQL) and `21,264` SQL candidates on 20 inputs |
| Consistent verdicts | `0` conflicts across `12,532` Semgrep pairs and `3,945` CodeQL pairs (`analysis/rq1.py`) |
| Scanner / checker errors | `0` oracle failures; `0` scanner errors except `2` timeouts in `codeql-hard-qwen` (`d02_str_format`, Strategy 5, marked `excluded`) |
| Model fallbacks | `0` fallbacks in `semgrep-v6` and `codeql-v6`; `79` fallbacks in `76,045` restricted-run decisions (`semgrep-informed-8b` `37`, `semgrep-rep1-8b` `25`, `pysa-hard-informed-8b` `11`, `pysa-rep1-35b` `6`) |

### Key Limits

- **Synthetic test sets:** `seeds/` shares one code structure across 15 seeds; `seeds_diverse/`, `seeds_cmd/`, and `seeds_path/` are synthetic; adapted sets (`9` official, `6` OWASP/vulpy, `5` PyPI app functions) swap out original database drivers and skip full app pipelines.
- **Easy baseline on Semgrep:** One operator already works on unrestricted Semgrep, so time-to-first-evasion cannot rank strategies there.
- **Hand-picked flow rewrites:** Flow operators were designed to stress known scanner weaknesses; the finding is what each scanner misses, not blind attack discovery.
- **Tested-input checks only:** Checked on 2 inputs (up to 20 offline), not a formal proof across all inputs (`db_roundtrip` alters invalid Unicode surrogates).
- **Focused rule set:** Root-cause checks cover 5 rewrite types and 6 `(tool, rewrite)` pairs; overall tests cover 14 rules across 4 Python scanners and 3 bug classes.
- **Unchecked LLM server weights:** SoCLaaS hides weight checksums (`semgrep-v6` and `codeql-v6` also used fixed prompt order).

### Commands to Reproduce

From the repository root (set `SOCLAAS_API_KEY` for Strategies `3`–`5`, and write new runs into fresh folders):

```sh
# Offline table & claim verification (~3 min, no scanners or API key)
analysis/run_all.sh

# Root-cause mechanism checks (~15 min, scanners required)
analysis/run_mechanism.sh

# Campaign and check-all runs (write new experiments to runs/)
./run.sh run --config configs/semgrep-v6.json --output runs/semgrep-v6
./run.sh exhaustive --config configs/codeql.json --output runs/codeql-flow-ops-15seeds \
    --seed-limit 15 --operators dynamic_sink char_launder deep_nest db_roundtrip
./run.sh run --config configs/codeql-v6.json --output runs/codeql-v6
./run.sh report runs/codeql-v6 --write
```

See [docs/methodology.md](docs/methodology.md) for system rules and [README.md](README.md) for setup steps.
