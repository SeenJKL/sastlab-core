# Experimental Results

Every figure below is recomputed from the saved JSON/JSONL records in [`results/`](results/INDEX.md). To recompute all tables and claim breakdowns locally (~3 minutes, offline), run `analysis/run_all.sh`; to inspect an individual search run, run `./run.sh report results/<folder>`.

Historical helper scripts cited in methodology notes (`harvest.py`, `validate_*_suite.py`, `rescan_*.py`, `check_candidates_unchanged.py`, `queue_*.sh`, `merge_rerun.py`) are external to this archive; reproduction of all numbers and mechanism checks uses [`analysis/`](analysis/run_all.sh) and `sastlab`.

## Contents

- [1. Executive Summary](#1-executive-summary)
- [2. Baseline Experimental Setup](#2-baseline-experimental-setup)
- [3. Full Search Campaigns (Semgrep and CodeQL)](#3-full-search-campaigns-semgrep-and-codeql)
- [4. Exhaustive Evaluations Across Analyzers, Corpora, and Classes](#4-exhaustive-evaluations-across-analyzers-corpora-and-classes)
- [5. Root-Cause Mechanisms](#5-root-cause-mechanisms)
- [6. Agent Search on Restricted Pools](#6-agent-search-on-restricted-pools)
- [7. Integrity Summary, Limitations, and Reproduction Commands](#7-integrity-summary-limitations-and-reproduction-commands)

---

## 1. Executive Summary

1. **Semgrep `formatted-sql-query` is weak against these operators.** In a complete full-budget campaign (`15` seeds × `7` strategies × `5` trajectories × `30` attempts = `15,750` attempts), every strategy evaded the rule on all `15/15` seeds and `75/75` trajectories; Strategy 1 (random) alone crossed the threshold (`weak`). Overall, `87.1%` of `5,563` distinct candidates evaded Semgrep with `0` behavior differences.
2. **CodeQL `py/sql-injection` resists structural rewrites but fails on flow-breaking ones.** None of the `255` combinations of the first 8 core operators evaded CodeQL across 3 seeds (`765` candidates; unarchived pilot check). Four of the five campaign flow operators evade alone on `15/15` seeds (`dynamic_sink`, `char_launder`, `deep_nest`, `db_roundtrip`), while `queue_roundtrip` alone does not; all `15` non-empty subsets of those four evade (`225/225`).
3. **Semgrep and CodeQL fail on nearly disjoint mechanisms.** Semgrep is silenced individually by `extract_1`, `extract_2`, `branch_split`, `dict_dispatch`, and `dynamic_sink`; CodeQL by `dynamic_sink`, `char_launder`, `deep_nest`, and `db_roundtrip`. Only `dynamic_sink` evades both alone.
4. **LLM guidance depends strongly on model capability, analyzer, and prompt design.** In the unrestricted `8B` campaigns, history-only found fewer distinct evasions/trajectory on Semgrep than random (`12.7` vs. `16.0`) and diagnostics matched random (`16.2` vs. `16.0`), while heuristic and Metropolis reached `22.6`–`24.8`. On restricted pools, larger models (`qwen3-coder-next`, `qwen3.6:35b`) with diagnostics or informed prompts beat random choice on Semgrep (`-4.32` CI `[-5.47, -3.20]` vs. heuristic for `coder` on Semgrep) and CodeQL, whereas on Pysa agents initially scored `0/45` without being told the monotonic operator order and matched (never beat) heuristic/Metropolis once informed.

*Scope note:* Findings 1–4 reflect two rules on 15 synthetic structurally uniform programs (`seeds/`). Multi-corpus, multi-analyzer, and multi-class generalizations follow in [Section 4](#4-exhaustive-evaluations-across-analyzers-corpora-and-classes).

---

## 2. Baseline Experimental Setup

| Parameter | Configuration |
| --- | --- |
| Platform | Linux x86-64 (`glibc` `2.43`), 2 CPU cores, Python `3.14.4` |
| Semgrep | `1.178.0`, standalone `formatted-sql-query` at commit `a84ff9cc2453ca91d581380de4b8b3f272f6f4be` |
| CodeQL | CLI `2.27.1`, query `codeql/python-queries@1.8.11:Security/CWE-089/SqlInjection.ql` (`py/sql-injection`) |
| LLM Serving | `llama3.1:8b` on NUS SoCLaaS, `temperature = 0.2`, prompt cap `2,500` tokens (no weight digest published) |
| Corpus | 15 synthetic SQLite fixtures (`seed_01`–`seed_15`) |
| Operator Pool | 13 operators (`8` core + `5` flow), `8,192` subsets/seed |
| Trajectory PRNG | `base_seed = 6223 + trajectory_index` |
| Scan Cache & Oracle | Cache disabled; inputs `"1"` vs. `"1' OR '1'='1"` on 3-row SQLite DB |

| Campaign | Directory | Budget | State |
| --- | --- | --- | --- |
| Semgrep search | `results/semgrep-v6` | `30 × 5 × 15 × 7` (`15,750` attempts) | Complete (`0` errors) |
| CodeQL 4-op check | `results/codeql-flow-ops-15seeds` | `15` subsets × `15` seeds (`225` candidates) | Complete (`225/225` evade) |
| CodeQL 5-op check | `results/codeql-flow-ops-seed01` | `31` subsets × `seed_01` (`31` candidates) | Complete (`30/31` evade) |
| CodeQL search | `results/codeql-v6` | `30 × 5 × 5 × 7` (`5,250` attempts) | Complete (`0` errors after rerun) |

*Note:* Direct cross-engine comparisons between `semgrep-v6` and `codeql-v6` are invalid due to differing budgets (`15` vs. `5` seeds), rules, and scan mechanisms.

---

## 3. Full Search Campaigns (Semgrep and CodeQL)

### Semgrep (`semgrep-v6`)

- **Report card (`formatted-sql-query`):** `15` qualifying seeds, threshold `8`, classification **`weak`** (`75/75` trajectories find an evasion for every strategy; `0` scanner errors, `0` oracle failures across `15,750` attempts).

| Strategy | Distinct Evading / Traj | Distinct Tried | Evading Attempts (of 2,250) | Mean First Evasion | Wall s to First |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1. Random baseline | `16.0` | `1,320` | `1,410` | `2.00` | `3.9` |
| 2. Blackbox heuristic | `24.8` | `1,770` | `1,860` | `2.00` | `4.0` |
| 3. History-only agent | `12.7` | `790` | `1,352` | `2.07` | `6.3` |
| 4. Static LLM ranking | `3.4` | `300` | `1,920` | `1.88` | `5.7` |
| 5. Diagnostic agent | `16.2` | `982` | `1,586` | `1.80` | `5.5` |
| 6. AST-distance Metropolis | `22.6` | `1,890` | `1,875` | `1.60` | `3.1` |
| 7. Call-depth Metropolis | `22.6` | `1,920` | `1,875` | `1.60` | `3.2` |

Paired differences across 75 `(seed, trajectory)` units (95% bootstrap CI, sign-flip p-value; exploratory because seeds share structure):

| Comparison | Mean Diff | 95% CI | p-value |
| --- | ---: | --- | ---: |
| Strategy 2 − Strategy 1 | `+8.80` | `+8.20` to `+9.33` | `< 0.001` |
| Strategy 6 − Strategy 1 | `+6.60` | `+5.48` to `+7.81` | `< 0.001` |
| Strategy 3 − Strategy 1 | `−3.31` | `−4.36` to `−2.24` | `< 0.001` |
| Strategy 5 − Strategy 1 | `+0.24` | `−0.85` to `+1.31` | `0.68` |
| Strategy 5 − Strategy 3 | `+3.55` | `+2.65` to `+4.44` | `< 0.001` |
| Strategy 7 − Strategy 6 | `0.00` | `−0.15` to `+0.15` | `1.00` |

Key observations:
- **Strategy behavior:** One operator suffices against Semgrep, so all strategies find a first evasion within ~2 attempts. Strategies exploring broadly (2, 6, 7) collect the most distinct evasions (`22.6`–`24.8`). Diagnostic feedback improves Strategy 5 over Strategy 3 (`+3.55`) without exceeding random (`+0.24`). Trajectory duration was `59`–`61 s` (non-LLM) vs. `92`–`95 s` (Strategies 3 & 5, ~`35 s` LLM latency).
- **Operator effects:** Of `5,563` distinct `(seed, mask)` pairs, `87.1%` evaded (`extract_1`, `extract_2`, `branch_split`, `dict_dispatch`, `dynamic_sink` evade on `15/15` alone; the other 8 operators `0/15`).
- **Metropolis & ranking details:** Strategy 6 rejected `6.0%` of moves (min acceptance prob. `0.35`); Strategy 7 rejected `13.3%` (min `0.0003`); they matched masks in `83%` of steps and `0/75` identical full trajectories. Strategy 4 produced 7 distinct rankings over 75 trajectories (`literal_slice` ranked first in `24`, `dict_dispatch`/`extract_1`/`extract_2` `15` each, `rename` `6`).
- **Model telemetry:** `4,576` requests, `0` fallbacks, `0` rate-limit waits, `1` retried TLS timeout; average prompt `473` tokens (max `659`). Strategies 3 & 5 picked `queue_roundtrip` `22%`, `rename` `19%`, `extract_2` `18%`, `deep_nest` `12%`, `db_roundtrip` `11%`, `extract_1` `9%`.

### CodeQL (`codeql-v6` and Exhaustive Flow Checks)

- **Exhaustive flow subsets:** All `15` subsets of `{dynamic_sink, char_launder, deep_nest, db_roundtrip}` evaded `py/sql-injection` across all `15` seeds (`225/225` candidates, `0` errors, `0` behavior differences). Across all 5 campaign flow operators on `seed_01`, `30/31` evaded (only `queue_roundtrip` alone remained detected). Average CodeQL scan time was `24 s`.

Example evading transformations on `seed_01` (both keep all 3 returned injection rows while CodeQL goes silent):

```python
# dynamic_sink
getattr(cursor, 'exe' + 'cute')(query)

# char_launder
user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
cursor.execute(query)
```

- **Search campaign (`codeql-v6`, `5,250` attempts):** `2,896` attempts evaded (`1,423` of `1,873` distinct `(seed, mask)` pairs; `0` verdict conflicts; `0` behavior errors). Every attempt containing any of the four working flow operators evaded and none without them did (`0` exceptions in `5,250` scans). Classification: **`weak`** (exploratory: `S_rule = 5`, threshold `3`).
- **Timeout recovery (`seed_05`):** After initial CPU throttling caused `240` discarded timeouts, three Strategy-1 timeouts on `seed_05` (trajectories 3 and 4) were rerun in `results/codeql-v6-seed05-rerun` (restricted to the 13-operator pool) and merged cleanly (old rows preserved in `discarded-partial.jsonl`). Replaying `seed_05` Strategy 1 matched `145/150` candidate hashes (differences follow a failed scan) and `143/143` shared verdicts.

| Strategy | Trajectories | With Evasion | Mean First Evasion | Distinct Evading / Traj |
| --- | ---: | ---: | ---: | ---: |
| 1. Random baseline | `25` | `25` | `2.80` | `16.8` |
| 2. Blackbox heuristic | `25` | `25` | `2.60` | `19.0` |
| 3. History-only agent | `25` | `25` | `5.04` | `9.5` |
| 4. Static LLM ranking | `25` | `16` | `3.25` (`13.24` with miss = `31`) | `2.0` |
| 5. Diagnostic agent | `25` | `25` | `7.84` | `9.1` |
| 6. AST-distance Metropolis | `25` | `25` | `2.00` | `19.8` |
| 7. Call-depth Metropolis | `25` | `25` | `2.00` | `19.8` |

*Note:* Strategies 3 & 5 in `codeql-v6` used the fixed definition order; shuffled-definition comparisons appear in [Section 6.1](#61-prompt-definition-order).

---

## 4. Exhaustive Evaluations Across Analyzers, Corpora, and Classes

### 4.1 Official-Suite SQL Seeds (`corpus_official/seeds/`)

- **Harvest funnel (`corpus_official/seeds/funnel.json`):** From upstream `semgrep-rules` (`a84ff9cc24`, 15 SQL files) and `codeql` (`codeql-cli/v2.27.1`, 4 SQL files): `19` files → `122` `.execute` calls → `102` single-argument → `82` string-built → `53` straight-line slices with 1 input → `24` distinct programs → **`9` exploit-live** under the SQLite oracle (`9/9` flagged by CodeQL; `7/9` by Semgrep, which misses the 2 concatenation cases).
- **Upstream test reproduction:** Semgrep `1.178.0` passes `semgrep --test` on `formatted-sql-query` (match lines `32`, `39`). CodeQL `2.27.1` reproduces exact `20/20` alerts in `SqlInjection.expected` (`results/official-validation/`). Adapted upstream positive cases (`app.py` `unsafe`, `sql_injection.py` `show_user`) are flagged by the harness.
- **Exhaustive results (`codeql-official-*`, `semgrep-official-*`):**

| Scanner (Qualifying Seeds) | Distinct Candidates | Equivalent & Scanned | Rejected Invalid | Exact Evasion Characterization (`0` exceptions) |
| --- | ---: | ---: | ---: | --- |
| CodeQL (`9/9`) | `486` | `450` | `36` | `81/81` with a flow rewrite evade; `369/369` without are detected. All `9` flow rewrites evade alone (`9/9`). |
| Semgrep (`7/7`) | `2,744` | `2,407` | `337` | `1,858/1,858` with any of the `8` restructuring/sink rewrites evade; all other `109` evading candidates use `literal_slice` (alone on `%`/`.format` seeds `4/4`, with `format_swap` on f-string seeds `3/3`). |

All `21,264` unique SQL candidates across saved runs pass `analysis/extended_equivalence.py` on `20` inputs (`0` differences).

### 4.2 Independent and Deployed SQL Programs

- **Independent programs (`corpus_real/seeds/`, 6 programs):** `5` OWASP BenchmarkPython SQLi tests + `1` `vulpy` login (`semgrep-real-pairs`, `codeql-real-*`, `pysa-real-pairs`). Qualifying seeds: Semgrep `6/6`, CodeQL `5/6`, Pysa `5/6` (`r01` with `configparser` missed at baseline by CodeQL and Pysa).
- **Deployed projects (`corpus_apps/seeds/`, 5 functions):** `parsl` `2025.12.22` (3), `scitokens` `1.8.1` (1), `pyload-ng` `0.5.0b3.dev90` (1); all `5/5` exploitable and flagged by Semgrep pattern, CodeQL, and Pysa (`4/5` flagged by Semgrep taint).

| Corpus | Analyzer | Scanned Candidates | Evasions / Silent | Exact Characterization (`0` exceptions) |
| --- | --- | ---: | ---: | --- |
| `corpus_real` | Semgrep (pattern) | `954` | `648` | `634/634` with restructuring/sink rewrite + `14` containing `literal_slice` |
| `corpus_real` | CodeQL | `261` | `45` | `45/45` with a flow-changing rewrite; `0/216` without |
| `corpus_real` | Pysa (`all` rules) | `792` | `198` | `173/173` round-trip (`db_roundtrip`/`simplequeue_roundtrip`) + `25/25` sink-hider + `literal_slice` |
| `corpus_apps` | Semgrep (pattern) | `552` | `396` | `369/369` restructuring/sink + `27` `literal_slice` |
| `corpus_apps` | Semgrep (taint, `4/5`) | `492` | `144` | `144` matching taint-mode rule (`0` exceptions) |
| `corpus_apps` | CodeQL | `165` | `45` | `45/45` flow-changing; `0` exceptions |
| `corpus_apps` | Pysa (`all` rules) | `552` | `156` | Round-trip or sink-hider + `literal_slice` (`0` exceptions) |

### 4.3 Multi-Analyzer Comparison: Pysa

Evaluated using `pyre-check` `0.10.0` with stock models (`d5614e0a`) across rules `5005` (flow) and `5051` (string-combine) on `34` qualifying seeds (`15/15` main, `10/12` diverse, `9/9` official; `d08_like` and `d11_fetchone` dropped by exploit check). Across `pysa-{official,main,diverse}-singles` and `pysa-{official,main}-pairs`: `4,716` rows, `3,994` distinct scanned candidates (`606` singles, `3,388` pairs), `0` scan errors, `0` behavior differences, `5.2 s` mean scan time (`analysis/table3.py`, `analysis/rq5.py`).

**Single rewrites (`34` qualifying seeds; silent = neither `5005` nor `5051` fires):**

| Operator(s) | Rule 5005 Removed | Rule 5051 Removed | Silent (Both Stopped) |
| --- | ---: | ---: | ---: |
| `db_roundtrip`, `simplequeue_roundtrip` | `68/68` | `68/68` | `68/68` |
| `dict_dispatch`, `dynamic_sink`, `methodcaller_sink`, `partial_sink`, `unbound_sink` | `170/170` | `0/170` | `0/170` |
| `literal_slice` | `0/34` | `34/34` | `0/34` |
| `format_swap` | `0/28` | `4/28` | `0/28` |
| `extract_1`, `extract_2` | `0/68` | `2/68` | `0/68` |
| Remaining `7` operators (`rename`, `dead_padding`, `branch_split`, `char_launder`, `deep_nest`, `pickle_roundtrip`, `queue_roundtrip`) | `0` | `0` | `0` |

- **Pairs (`24` main & official seeds, `3,388` candidates):** `914/3,388` are silent: `784/784` with a round trip (`db_roundtrip`/`simplequeue_roundtrip`), `120/120` pairing a sink-hider with `literal_slice`, and `10/100` pairing a sink-hider with `format_swap` (on the 2 concatenation seeds where `format_swap` drops rule `5051`). Notice `130` pairs silence Pysa even though neither rewrite alone does. Zero of `712` candidates using only core controls + `extract_*` + `branch_split` drop rule `5005`.
- **Triples (`results/pysa-triples/evaluations.jsonl`, checked in `analysis/extended_equivalence.py`):** All subsets of up to 3 of the 16 non-round-trip rewrites on `o03`, `o18`, `o24`: `1,510` distinct candidates (`578` invalid subsets), `0` errors, `20/303` pairs and `189/1,161` triples silent (`0` new mechanisms beyond the pair rules).
- **Cross-analyzer agreement:** Shared candidates vs. CodeQL (`1,091`): both detect `631`, both silent `129`, CodeQL-only silent `315`, Pysa-only silent `16`. Shared vs. Semgrep (`1,973`): both detect `583`, both silent `164`, Semgrep-only silent `1,049`, Pysa-only silent `177`. Only `db_roundtrip` and `simplequeue_roundtrip` silence both CodeQL and Pysa alone.
- **Stock HTTP source check (`pysa-http-*`):** Using `BaseHTTPRequestHandler.path` (`576` candidates), Pysa produces the identical rule set across all `576` scans with `0` errors.

### 4.4 Semgrep Taint Mode and Newer Scanner Releases

- **Semgrep taint mode (`flask-tainted-sql-string` at `17e31e11`):** With `@app.route("/<user_input>")` injected at scan time, qualifying seeds are `15/15` main, `9/9` official, `10/12` diverse, `3/6` real (`4,462` candidates, `1,424` evading). Evasion occurs iff `literal_slice`, `extract_1`, `extract_2`, or (`format_swap` on concatenation seeds `o18_semgrep`, `o23_codeql`, `d01_concat`, `d12_concat_parts`) is present (`0` exceptions). Across `22` doubly-flagged seeds (pattern vs. taint singles): `literal_slice` evades `4/22` vs. `4/22`; `extract_1` & `extract_2` evade `22/22` vs. `22/22`; `branch_split` & 5 sink-hiders evade pattern `22/22` vs. taint `0/22`; remaining 9 operators evade `0/22` on both.
- **Newer scanner releases (`*-latest-*`):** Semgrep `1.182.1` matched `1.178.0` on `392/392` singles. CodeQL `2.27.3` (`python-queries` `1.8.13`, zip SHA-256 `845075a2...`) evaluated `428` singles on `24` seeds (`0` errors, `216` evading — exact match to the `9` flow-changing rewrites). `pyre-check` `0.10.0` matched upstream `main` (`d5614e0a`).

### 4.5 Bandit (AST Linter, Version 1.9.4)

Single and pair exhaustive scans across 6 corpora (`50` qualifying baseline seeds, `7,700` total candidates, `0` scan errors, `0` behavior differences, `1,166` silent; `analysis/rq2.py`):

| Corpus | Seeds | Candidates | Silent |
| --- | ---: | ---: | ---: |
| Main SQL (`B608`) | `15` | `2,430` | `270` |
| Varied SQL (`B608`) | `10` | `1,584` | `212` |
| Official SQL (`B608`) | `9` | `1,386` | `192` |
| Independent SQL (`B608`) | `6` | `954` | `107` |
| Deployed SQL (`B608`) | `4` | `492` | `51` |
| Command injection (`B602`) | `6` | `854` | `334` |

- **`B608` (SQL):** Silent iff `literal_slice` is present, or `format_swap` on a `+` query (`''.join([...])`), `0` exceptions in `6,846` SQL candidates. Flow and sink rewrites have no effect.
- **`B602` (`subprocess` shell):** Silent iff `dict_dispatch`, `dynamic_sink`, `partial_sink`, or `methodcaller_sink` is present (`0` exceptions in `854` candidates).
- **Worked example (`seed_01` + `char_launder` + `dynamic_sink`):** Semgrep and CodeQL go silent; Pysa still reports rule `5051`; Bandit still reports `B608`.

### 4.6 Command Injection (CWE-78) and Path Traversal (CWE-22)

- **Command injection (`seeds_cmd`, 8 seeds):** Qualifying baselines: Semgrep `7/8` (`os.popen` unmatched), CodeQL `8/8`, Pysa `8/8` (`6` under `6065`, `2` under `5001`). Zero errors, `0` behavior differences.
- **Path traversal (`seeds_path`, 8 seeds with `open`):** Qualifying baselines: Semgrep `6/8` (`p05`, `p08` missed), CodeQL `8/8` (`6` run for cost), Pysa `8/8` (`6` run for cost). Adding `SINK_FUNCTIONS = ("open",)` preserved SHA-256 digests across `12,058` previously logged candidates.

| Class | Analyzer | Scanned Candidates | Evasions / Silent | Exact Characterization (`0` exceptions) |
| --- | --- | ---: | ---: | --- |
| CWE-78 | Semgrep (`dangerous-subprocess-use-audit`) | `1,002` | `391` | Sink-resolution rewrites evade (`391/391`); `extract_*` and `branch_split` do **not** evade |
| CWE-78 | CodeQL (`py/command-line-injection`) | `406` | `64` | Flow-changing rewrites evade (`64/64`) |
| CWE-78 | Pysa (`6065` or `5001`) | `1,150` | `644` | Round-trip or sink-resolution rewrite (1 rule/seed, so no pair needed) |
| CWE-22 | Semgrep (`path-traversal-open` + route) | `756` | `249` | `dict_dispatch`, `dynamic_sink`, or `partial_sink` present (`249/249`); `extract_*`/`branch_split` stay detected |
| CWE-22 | CodeQL (`py/path-injection`) | `285` | `42` | Flow-changing rewrites evade (`42/42`) |
| CWE-22 | Pysa (`5011`) | `756` | `393` | Sink-resolution rewrite or round-trip (`393/393`) |

### 4.7 Operator Taxonomy, Witness-Path Probe, and Rewrite Catalog

- **Expanded 18-operator checks (`semgrep-newops`, `codeql-newops`):** All singles/pairs of bits 13–17 on `12` varied seeds had `0` behavior/scanner errors; all `5` evade CodeQL on `10/10` qualifying seeds; the `3` sink operators evade Semgrep on `8/8`.
- **Witness-path placement (`codeql-path-probe`, [`scripts/path_probe.py`](scripts/path_probe.py)):** Laundering rewrites inserted directly at CodeQL witness nodes (parameter, query assignment, sink) evaded in `155/155` cases vs. `31/31` identity controls detected (`d08`, `d11` excluded); mid-path placement adds no advantage over function entry.
- **Control-only matrix (`semgrep-controls-main`, `analysis/rq1.py`, `analysis/lessons.py`):** All 15 subsets of `{rename, format_swap, literal_slice, dead_padding}` on 15 main seeds (`225` scans): exactly the `60` candidates containing both `format_swap` and `literal_slice` evade; across all pinned SQL runs, `134/473` distinct control-only candidates evade (every one contains `literal_slice`).
- **Rewrite catalog (`codeql-rewrite-catalog`, [`scripts/rewrite_catalog.py`](scripts/rewrite_catalog.py)):** `59` behavior-checked hand-written variants probing CodeQL taint boundaries that guided operators 14–18.

---

## 5. Root-Cause Mechanisms

Reproduced by `analysis/run_mechanism.sh` into `results/mechanism/` (`seed_01` and `o05_semgrep`):

- **Pysa call-graph and argument resolution (`mechanism_pysa.py`):**
  - `dynamic_sink` and `methodcaller_sink` leave **no call edge** to `sqlite3.Cursor.execute` in `get_user_profile`'s call graph.
  - `dict_dispatch` and `partial_sink` leave the callee unresolved (`UnexpectedCalleeExpression`; only attribute lookup appears).
  - `unbound_sink` (`type(cursor).execute(cursor, query)`) resolves the method as a bound call and **shifts arguments by 1** (confirmed because rule `5005` fires on incorrect `type(cursor).execute(query)` and `sqlite3.Cursor.execute(cursor, query)`).
- **Pysa missing stdlib models (`mechanism_pysa.py`):** Stock models cover `queue.Queue.put/get` (no `_queue.SimpleQueue`). Adding `2` model lines for `_queue.SimpleQueue` restores rules `5005` + `5051` on `simplequeue_roundtrip`; adding `3` SQLite summary lines (`Connection.execute` → `self` → `Cursor` → `Cursor.fetchone`) restores both rules on `db_roundtrip`.
- **CodeQL sink enumeration and access-path limits (`mechanism_codeql_probe.py`):** Querying `SqlInjection::Sink` nodes directly shows the sink-resolution rewrites emit **no sink node**, whereas `deep_nest` and `db_roundtrip` keep the sink node and break taint flow. Depth sweeps show `deep_nest` alerts up to depth `5` and stops alerting at depth `≥ 6` (operator uses depth `8`), matching `accessPathLimit() = 5` in CodeQL's shared data-flow library.
- **CodeQL missing summary models (`mechanism_codeql.py`, `mechanism_codeql_flow.py`):** Adding `2` model-pack data-extension rows per mechanism restores `py/sql-injection` for `simplequeue_roundtrip`, `pickle_roundtrip` (`pickle.dumps`/`loads`), and `char_launder` (`chr`/`ord`) on `2/2` seeds each. Adding `3` summary rows targeted at `sqlite3.connect()`'s return value (type `sqlite3.Connection` alone did not match) restores the alert on `db_roundtrip`.

---

## 6. Agent Search on Restricted Pools

### 6.1 Prompt Definition Order

- **`prompt-order-probe`:** Fixed canonical definition ordering (`rename` first) caused `llama3.1:8b` to select `rename` in `34/60` calls vs. `13/60` when shuffled. Per-call shuffling was applied to `sastlab/llm.py`.
- **`codeql-promptfix` vs. `codeql-v6` (`5` streams):** With shuffled definitions, `8B` Strategy 3 (history-only) and Strategy 5 (diagnostic) needed `3.64` and `4.20` mean attempts to first evasion vs. `5.04` and `7.84` under fixed order in `codeql-v6`. Strategy 4 was not rerun.

### 6.2 Semgrep and CodeQL Restricted Pools + Diagnostic Ablation

- **Semgrep (`semgrep-hard`, `semgrep-hard30`, `semgrep-hard30-qwen`, `semgrep-hard30-q36`):** 9-operator pool whose minimal evading sets are `{extract_1}` or `{format_swap, literal_slice}` (3 seeds × 30 streams, budget `15`).
  - `llama3.1:8b`: History-only (`9.16`, `64/90`) and diagnostic (`8.82`, `64/90`) match random (`8.37`, `66/90`) and trail heuristic (`~5.47`).
  - `qwen3-coder-next`: Diagnostic hits `1.14` (`90/90`, picking `extract_1` first in `86/90`) vs. history-only `4.47` (`88/90`).
  - `qwen3.6:35b`: Diagnostic hits `3.16` (`89/90`) vs. history-only `9.92` (`52/90`).
- **Diagnostic-field ablation (`semgrep-abl-message|snippet|sink`, `qwen3-coder-next`, Strategy 5):** Message only `1.06` (`90/90`), all fields `1.14` (`90/90`), snippet only `4.43`, line only `4.52`, none `4.47`. **Semgrep's diagnostic message text drives the entire feedback gain.**
- **CodeQL (`codeql-hard`, `codeql-hard15`):** 9-operator pool where only `char_launder` evades (budget `12`). On `seed_01` (`15` streams): `llama3.1:8b` history-only `8.27` (`10/15`) and diagnostic `8.87` (`9/15`) trail random `4.20` (`15/15`), heuristic `4.07` (`15/15`), and Metropolis `7.47` (`11/15`). With `qwen3-coder-next`, history-only hits `1.87` (`15/15`) and diagnostic hits `2.07` (`15/15`; diff `+0.20`, CI `[-0.07, +0.47]`): unlike Semgrep, CodeQL diagnostics add no improvement over history alone.

### 6.3 Pysa Restricted Search and Prompt Variants

9-operator pool without round trips (`3` seeds × `15` streams = `45` streams, budget `15`, `evasion: "all"`; minimal evading pairs are `{dict_dispatch|dynamic_sink, literal_slice}`).

**Original prompt (`pysa-hard-qwen`, `pysa-hard-qwen-rule`, `qwen3-coder-next`):**

| Strategy | Mean Attempts (miss = 16) | 95% Interval | Streams Solved |
| --- | ---: | --- | ---: |
| 1. Random baseline | `13.33` | `[10.67, 15.60]` | `15/45` |
| 2. Blackbox heuristic | `10.13` | `[7.40, 12.67]` | `36/45` |
| 3. History-only agent | `16.00` | — | `0/45` |
| 5. Diagnostic agent | `16.00` | — | `0/45` |
| 5 (rule ID only) | `16.00` | — | `0/45` |
| 6. AST-distance Metropolis | `9.20` | `[6.67, 11.80]` | `33/45` |

Root cause of `0/45` under original prompt: without knowing candidates can only append operators **later** in fixed order, agents selected `char_launder` (234 & 221 of 675 attempts vs. 108 random) after missing/skipping `literal_slice` or sink-hiders, preventing either missing piece from being added until restart.

**Prompt & order comparison on `qwen3-coder-next` (Set A):**

| Prompt Variant (`order: "increasing"`) | History-Only (Strat. 3) | Diagnostic (Strat. 5) |
| --- | ---: | ---: |
| Original (no tool, no order) | `0/45`, mean `16.00` | `0/45`, mean `16.00` |
| Tool-aware (`noorder`: names Pysa + 2 rules) | `0/45`, mean `16.00` | `1/45`, mean `15.71` |
| Informed (tool + rules + fixed operator order) | `20/45`, mean `12.53` | `34/45`, mean `10.42` |

Under the informed prompt, Strategy 5 differs from random by `−2.91` (`[−6.31, +0.73]`, `p = 0.13`) and from heuristic by `+0.29` (`[−3.24, +3.53]`, `p = 0.87`). Under `order: "any"` (free order; caveat: candidates accumulate ~5–6 operators so random already hits `45/45` at `5.87`), original-prompt agents hit `45/45` (`6.00`, `5.02`) and `35B` informed hits `45/45` (`5.07`, `4.02`).

**Multi-model & two-seed-set evaluation (Set A = `seeds_pysa_hard`, random `15/45` mean `13.33`; Set B = `o03,o18,o24`, random `23/45` mean `11.93`):**

| Set | Model | History-Only (Found, Mean, vs. Random [95% CI]) | Diagnostic (Found, Mean, vs. Random [95% CI]) |
| --- | --- | --- | --- |
| A | `qwen3-coder-next` | `20/45`, `12.53`, `−0.80 [−3.73, +2.09]` | `34/45`, `10.42`, `−2.91 [−6.31, +0.73]` |
| A | `qwen3.6:35b` | `1/45`, `15.69`, `+2.36 [−0.00, +5.13]` | `9/45`, `13.42`, `+0.09 [−3.44, +3.69]` |
| A | `llama3.1:8b` | `10/45`, `13.73`, `+0.40 [−3.27, +4.13]` | `18/45`, `13.42`, `+0.09 [−3.00, +3.53]` |
| B | `qwen3-coder-next` | `22/45`, `12.51`, `+0.58 [−1.93, +3.24]` | `38/45`, `9.69`, `−2.24 [−5.53, +1.11]` |
| B | `qwen3.6:35b` | `5/45`, `14.98`, `+3.04 [+0.27, +5.78]` | `12/45`, `13.62`, `+1.69 [−0.96, +4.27]` |

Only `coder` diagnostic beats random numerically in both seed sets, and both 95% intervals include `0`.

### 6.4 Informed Prompts on Semgrep and CodeQL

Comparing original vs. informed (`llm.prompt_extra`) prompts across identical streams (`semgrep-informed-*`: 3 seeds × 30 streams; `codeql-more-*` / `codeql-informed-*`: `d01` + `d02` × 15 streams = 30 streams):

| Corpus / Scanner | Model | Agent | Original Mean (Found) | Informed Mean (Found) | Informed − Random [95% CI] |
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

Feedback gain (`Diagnostic − History-only`) on Semgrep pattern shrinks sharply once the rule is explained: original prompt `Coder −3.32 [−4.57, −2.16]`, `35B −6.77 [−8.58, −5.04]`, `8B −0.33 [−1.79, +1.11]` vs. informed `Coder −0.57 [−1.02, −0.20]`, `35B −0.82 [−1.71, −0.09]`, `8B +0.09 [−1.01, +1.12]`.

### 6.5 Extended CodeQL Streams and Seed Repeats

- **CodeQL (`d01` + `d02`, 30 streams, `codeql-more-*`):** `35B` beats random under both prompts (`−1.6` to `−2.8`); `8B` is worse (`+2.8` to `+4.1`); `Coder` beats random only with original-prompt diagnostics (`−1.70`) and worsens under informed prompts (`+2.10`, `+1.40`).
- **Base-seed repeats (`7001`, `7002` in `semgrep-rep*`, `pysa-rep*`):** Semgrep cells stay within `0.4` attempts of initial runs (below random in `18/18` runs; 95% CI below `0` in `13/18`). On Pysa, `coder` diagnostic stays below random in `3/3` (pooled `−5.01 [−6.87, −3.04]`), `coder` history-only in `3/3` (`−2.26 [−4.03, −0.48]`), `35B` history-only is worse (`+1.33 [+0.20, +2.56]`), and `8B` diagnostic overlaps random (`−1.04 [−2.59, +0.58]`).

### 6.6 Metropolis Restarts Check

In runs with default `metropolis_restart: true`, Strategies 6 and 7 reset to `mask = 0` when `available(mask)` is empty (`analysis/rq3.py` verifies every jump goes to seed at the end of the order):

| Run | Attempts | Restarts | Restarts ≤ First Evasion | Trajectories With Restart |
| --- | ---: | ---: | ---: | ---: |
| `semgrep-v6` (full) | `4,500` | `300` | `0` | `0 / 150` |
| `codeql-v6` (full) | `1,500` | `100` | `0` | `0 / 50` |
| `semgrep-hard` (pilot) | `1,200` | `184` | `136` | `60 / 80` |
| `codeql-hard` (pilot) | `480` | `80` | `32` | `24 / 40` |
| `semgrep-hard30` | `1,350` | `164` | `63` | `42 / 90` |
| `codeql-hard15` | `180` | `20` | `11` | `8 / 15` |
| `pysa-hard-qwen` | `675` | `78` | `48` | `30 / 45` |

Control reruns with `metropolis_restart: false` (Strategy 6, `0` restarts, `0` errors) confirm restarting has no measurable effect:

| Run (`metropolis_restart: false`) | Found | Mean (miss = 16) | Saved Walk | Without Restart − Saved | Without Restart − Heuristic |
| --- | ---: | ---: | --- | --- | --- |
| `semgrep-hard30-walk` | `90/90` | `5.28` | `90/90`, `5.23` | `+0.04 [−0.80, +0.78]` | `−0.19 [−1.42, +0.91]` |
| `pysa-hard-walk` | `36/45` | `9.27` | `33/45`, `9.20` | `+0.07 [−1.47, +1.93]` | `−0.87 [−4.00, +2.07]` |

### 6.7 Statistical Methods

Bootstrap intervals are 95% percentile intervals using `5,000` resamples (generator in `analysis/common.py`, RNG seed `11`) over independent trajectory streams (paired difference averaged across seeds per stream for restricted pools) or paired `(seed, trajectory)` units (full Semgrep campaign). Sign-flip p-values apply `5,000` random sign flips over per-stream differences. Trajectory counts like `34/45` denote `seed × stream` units.

---

## 7. Integrity Summary, Limitations, and Reproduction Commands

### Validation Summary

| Check | Verified Outcome |
| --- | --- |
| Automated tests | `187` tests (`181 passed, 6 skipped` in Docker image) ([docs/validation.md](docs/validation.md)) |
| Behavior preservation | `0` differences across all campaigns (`5,563` Semgrep, `225 + 31` flow checks, `5,250` CodeQL) and `21,264` SQL candidates on 20 inputs |
| Verdict determinism | `0` conflicts across `12,532` Semgrep pairs and `3,945` CodeQL pairs (`analysis/rq1.py`) |
| Scanner / oracle errors | `0` oracle failures; `0` scanner errors except `2` timeouts in `codeql-hard-qwen` (`d02_str_format`, Strategy 5, marked `excluded`) |
| Model fallbacks | `0` fallbacks in `semgrep-v6` and `codeql-v6`; `79` fallbacks in `76,045` restricted-run decisions (`semgrep-informed-8b` `37`, `semgrep-rep1-8b` `25`, `pysa-hard-informed-8b` `11`, `pysa-rep1-35b` `6`) |

### Key Limitations

- **Synthetic corpus concentration:** `seeds/` shares one code template across 15 seeds; `seeds_diverse/`, `seeds_cmd/`, and `seeds_path/` are synthetic; adapted corpora (`9` official, `6` OWASP/vulpy, `5` PyPI app functions) replace original DB drivers and omit full application pipelines.
- **Saturation on Semgrep:** One operator suffices, preventing first-evasion latency from separating strategies in the full campaign.
- **Knowledge-guided operators:** Flow operators were engineered to probe known taint weaknesses; the contribution is empirical measurement of analyzer blind spots rather than blind discovery.
- **Input-bounded equivalence:** Verified on 2 inputs (up to 20 offline), not universal Python equivalence (`db_roundtrip` omits lone surrogates).
- **Scoped mechanisms & rule set:** Mechanisms cover 5 rewrite types and 6 `(tool, rewrite)` pairs; experiments cover 14 rules across 4 Python analyzers and 3 CWE classes.
- **Unverified LLM server weights:** SoCLaaS publishes no weight digest (`semgrep-v6` and `codeql-v6` also used fixed definition order).

### Reproduction Commands

From the repository root (set `SOCLAAS_API_KEY` for search strategies `3`–`5`, and write new outputs to fresh folders):

```sh
# Offline table & claim verification (~3 min, no scanners or API key)
analysis/run_all.sh

# Mechanism probes (~15 min, scanners required)
analysis/run_mechanism.sh

# Campaign and exhaustive runs (use runs/ for new experiments)
./run.sh run --config configs/semgrep-v6.json --output runs/semgrep-v6
./run.sh exhaustive --config configs/codeql.json --output runs/codeql-flow-ops-15seeds \
    --seed-limit 15 --operators dynamic_sink char_launder deep_nest db_roundtrip
./run.sh run --config configs/codeql-v6.json --output runs/codeql-v6
./run.sh report runs/codeql-v6 --write
```

See [docs/methodology.md](docs/methodology.md) for formal contracts and [README.md](README.md) for environment setup.
