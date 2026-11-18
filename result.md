# SASTLab: Results

All figures are recomputed from the saved `attempts.jsonl`, `llm.jsonl`, `evaluations.jsonl` and `summary.json` files in `results/`; `./run.sh report <folder>` recomputes the summary of a search run (`--write` saves it). The analysis, queue and validation scripts and the upstream test suites named below were used to compute and check these results; they are not part of this repository, which keeps the framework, the configs, the seeds and the saved results. `results/INDEX.md` lists every saved folder.

## Main findings

1. **Semgrep `formatted-sql-query` is weak against these operators.** In a completed full-budget campaign (15 seeds × 7 strategies × 5 trajectories × 30 attempts = 15,750 attempts) every strategy evaded the rule on all 15 seeds and in all 75 of its trajectories, and strategy 1 (random) alone crossed the threshold. The report card is **weak**. 87% of the 5,563 distinct candidates evaded Semgrep, and none of them changed the program's behavior on the two tested inputs.
2. **CodeQL `py/sql-injection` resists structural rewrites but not flow-breaking ones.** With the first eight operators, no candidate evaded CodeQL in an exhaustive run of all 255 combinations on three seeds (765 candidates; the data of that run was not kept). Four of the five flow operators of the search campaigns evade CodeQL on their own on all 15 seeds (`dynamic_sink`, `char_launder`, `deep_nest`, `db_roundtrip`); `queue_roundtrip` alone does not. Every combination of these four evaded (225 of 225).
3. **The two engines fail on different operators.** Semgrep is evaded by `extract_1`, `extract_2`, `branch_split`, `dict_dispatch` and `dynamic_sink` individually; CodeQL by `dynamic_sink`, `char_launder`, `deep_nest` and `db_roundtrip`. Only `dynamic_sink` evades both on its own.
4. **Model guidance depends on the model, the scanner and the prompt.** In the first full campaigns (8B model, original prompt) it did not beat simple baselines: against Semgrep the history-only agent found fewer distinct evasions than random (12.7 vs 16.0 per trajectory), the diagnostic agent matched random (16.2 vs 16.0), and the heuristic and the Metropolis searches found the most (22.6 to 24.8). Restricted searches with larger models and an informed prompt change this (sections on agent search below): with the original prompt the coder and 35B diagnostic agents need fewer attempts to the first evasion than random choice and than the heuristic on Semgrep and CodeQL (for example -4.32 [-5.47, -3.20] against the heuristic for the coder model on the pattern rule); on Pysa the agents found nothing with the original prompt, and with an informed prompt the best agent matches the heuristic and the Metropolis walk and does not beat them. Attempts to the first evasion cannot separate strategies in the full Semgrep campaign, because one operator is enough.

The first four findings concern **two rules on a synthetic corpus of 15 structurally identical programs**. They show what the operators and strategies do on this fixture and do not establish that Semgrep or CodeQL are weak or robust in general. The later sections extend them to more corpora, rules and analyzers.

## Experimental setup

| Item | Recorded configuration |
| --- | --- |
| Platform | Linux x86-64 (glibc 2.43), 2 CPU cores; Python 3.14.4 |
| Semgrep | 1.178.0, standalone upstream `formatted-sql-query` at commit `a84ff9cc2453ca91d581380de4b8b3f272f6f4be` |
| CodeQL | CLI 2.27.1, query `codeql/python-queries@1.8.11:Security/CWE-089/SqlInjection.ql` (rule `py/sql-injection`) |
| Model | `llama3.1:8b` on NUS SoCLaaS, temperature 0.2, prompt cap 2,500 tokens, identity unverified (no weight digest) |
| Corpus | 15 bundled synthetic SQLite fixtures (`seed_01` to `seed_15`) |
| Operators | 13 (8 core + 5 flow), 8,192 subsets per seed |
| Trajectory seeds | `base_seed` 6223 + trajectory number |
| Scanner cache | Disabled |
| Inputs | Nominal `1`; injection `1' OR '1'='1`; fixed three-row database |

| Campaign | Directory | Budget | State |
| --- | --- | --- | --- |
| Semgrep search | `results/semgrep-v6` | 30 attempts × 5 trajectories × 15 seeds × 7 strategies | complete, 15,750 attempts |
| CodeQL operator check | `results/codeql-flow-ops-15seeds` | all 15 subsets of 4 flow operators × 15 seeds | complete, 225 candidates |
| CodeQL operator check, five operators | `results/codeql-flow-ops-seed01` | all 31 subsets of 5 flow operators × `seed_01` | complete, 31 candidates |
| CodeQL search | `results/codeql-v6` | 30 × 5 × **5 seeds** × 7 strategies (5,250 attempts) | complete, 5,250 attempts, 0 scanner errors (3 timeouts rerun, see below) |

A seed qualifies only if its original program triggers the target rule and the injection returns additional rows. An evasion requires a successful candidate scan in which that rule disappears and exact agreement with the original program's output for both inputs. This is input-bounded equivalence, not a proof for all inputs. The Semgrep and CodeQL campaigns differ in rule, scanner and budget; comparing their numbers directly is not valid.

## Full search campaigns

### Semgrep

Report card for `formatted-sql-query`: 15 qualifying seeds, threshold 8, classification **weak** (complete, full 30-by-5 budget; strategy 1 individually crosses the threshold). 0 scanner errors and 0 oracle failures in 15,750 attempts.

| Strategy | Distinct evading candidates / trajectory | Distinct candidates tried | Evading attempts (of 2,250) | First evasion (attempt) | Wall s to first evasion |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1. Random baseline | 16.0 | 1,320 | 1,410 | 2.00 | 3.9 |
| 2. Blackbox heuristic | 24.8 | 1,770 | 1,860 | 2.00 | 4.0 |
| 3. History-only agent | 12.7 | 790 | 1,352 | 2.07 | 6.3 |
| 4. Static LLM ranking | 3.4 | 300 | 1,920 | 1.88 | 5.7 |
| 5. Diagnostic agent | 16.2 | 982 | 1,586 | 1.80 | 5.5 |
| 6. AST-distance Metropolis | 22.6 | 1,890 | 1,875 | 1.60 | 3.1 |
| 7. Call-depth Metropolis | 22.6 | 1,920 | 1,875 | 1.60 | 3.2 |

"Distinct candidates tried" counts unique (seed, candidate) pairs over the 75 trajectories of the strategy. First evasion is the mean attempt of the first verified evasion per trajectory; all 75 trajectories of every strategy found one. A 30-attempt trajectory took about 59 to 61 s for strategies 1, 2, 4, 6 and 7 and 92 to 95 s for strategies 3 and 5 (which call the model every attempt), so per-attempt model guidance cost about 35 s per trajectory (model latency; no rate-limit waits).

Paired differences in distinct evasions per trajectory over the 75 (seed, trajectory) units, with 95% bootstrap intervals and sign-flip permutation tests (exploratory; the seeds share one program structure, so these are not independent samples of programs):

| Comparison | Mean difference | 95% CI | p |
| --- | ---: | --- | ---: |
| Strategy 2 − strategy 1 | +8.80 | +8.20 to +9.33 | < 0.001 |
| Strategy 6 − strategy 1 | +6.60 | +5.48 to +7.81 | < 0.001 |
| Strategy 3 − strategy 1 | −3.31 | −4.36 to −2.24 | < 0.001 |
| Strategy 5 − strategy 1 | +0.24 | −0.85 to +1.31 | 0.68 |
| Strategy 5 − strategy 3 | +3.55 | +2.65 to +4.44 | < 0.001 |
| Strategy 7 − strategy 6 | 0.00 | −0.15 to +0.15 | 1.00 |

**Reading the table.** Strategies do not differ in whether they find an evasion, since all do within about two attempts. They differ in how many distinct evasions they accumulate. Strategies that propose widely (2, 6, 7) found the most; the model-guided strategies repeated candidates more. Diagnostic feedback helped relative to history only, but the diagnostic agent did no better than random choice, so this does not show that diagnostics add information beyond what random search finds. Strategy 4 followed one ranking per trajectory and so tried few candidates.

**Operator effects against Semgrep.** Among the 5,563 distinct (seed, subset) candidates, 87.1% evaded and none changed behavior. As single operators, `extract_1`, `extract_2`, `branch_split`, `dict_dispatch` and `dynamic_sink` evade on 15 of 15 seeds; `rename`, `format_swap`, `literal_slice`, `dead_padding`, `char_launder`, `deep_nest`, `db_roundtrip` and `queue_roundtrip` evade on 0 of 15. The rule matches a formatted query inside a function, so moving the query or the `execute` call out of that pattern defeats it; rewriting only the data path does not.

**Metric search and ranking.** Metropolis rejects moves (6.0% of strategy 6 moves and 13.3% of strategy 7 moves were rejected; the lowest acceptance probability was 0.35 for strategy 6 and 0.0003 for strategy 7). Strategies 6 and 7 visit the same mask at 83% of steps and take identical walks in 0 of 75 trajectories. Strategy 4's rankings have 7 distinct values over 75 trajectories. The top-ranked operators were `literal_slice` (24 trajectories), `dict_dispatch`, `extract_1` and `extract_2` (15 each) and `rename` (6).

**Model behavior.** 4,576 requests, 0 fallbacks, 0 rate-limit waits, one failed request (a TLS handshake timeout) that succeeded on retry. Prompt size averaged 473 tokens (maximum 659; cap 2,500). Strategies 3 and 5 chose `queue_roundtrip` 22%, `rename` 19%, `extract_2` 18%, `deep_nest` 12%, `db_roundtrip` 11% and `extract_1` 9% of the time.

### CodeQL

**Exhaustive operator check.** On all 15 seeds, every one of the 15 subsets of `dynamic_sink`, `char_launder`, `deep_nest` and `db_roundtrip` evaded `py/sql-injection`: 225 of 225 candidates, 0 scanner errors, 0 behavior differences. Adding `queue_roundtrip` on `seed_01` (31 subsets): 30 evaded; the only candidate still detected was `queue_roundtrip` alone. A CodeQL scan averaged 24 s.

The evading candidates change only how the value reaches the query, while the SQL string is still built by interpolating the input. For example, `dynamic_sink` and `char_launder` on `seed_01`:

```python
# dynamic_sink
getattr(cursor, 'exe' + 'cute')(query)

# char_launder
user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
cursor.execute(query)
```

Both programs still return all three rows for the injection input, and CodeQL reports no `py/sql-injection` finding for them.

Why each operator evades is examined under Mechanisms below: `deep_nest` stops alerting at 6 nested lists, and 3 added summary rows restore the alert for `db_roundtrip`.

**Search campaign (`codeql-v6`, complete).** 5 seeds × 7 strategies × 5 trajectories × 30 attempts = 5,250 attempts; 2,896 evaded CodeQL, 0 behavior differences. Every attempt that used at least one of the four working flow operators evaded, and no attempt without one did (0 exceptions either way, over 5,250 completed scans). No (seed, subset) pair received two different verdicts (1,873 distinct pairs). 1,423 of the 1,873 distinct (seed, candidate) pairs evaded.

**Three scanner timeouts, rerun.** The campaign lost attempts to scanner timeouts while the host throttled its CPU; the failed parts were rerun with a 240 s scan timeout (240 attempts discarded and rerun). Three attempts still timed out, all random-baseline (strategy 1) on `seed_05` (trajectory 3 attempts 29 and 30, trajectory 4 attempt 1). Both trajectories were rerun as a separate run (`results/codeql-v6-seed05-rerun`, same config restricted to the original 13-operator pool, because an unrestricted resume is refused once the operator list has grown). It reproduced 145 of the 150 original attempts of `seed_05` strategy 1 with the same candidate hash, the 5 that differ being the attempts after a failed scan, and gave the same verdict on all 143 shared scanned candidates. `scripts/merge_rerun.py` replaced the 60 rows of the two trajectories with the rerun's and moved the old rows to `discarded-partial.jsonl`; the manifest records the merge. `codeql-v6` now has 5,250 of 5,250 scans completed, and its report card is complete (classification `weak`: strategy 1 evades on all 5 seeds; `S_rule` = 5, threshold 3, exploratory).

| Strategy | Trajectories used | With an evasion | First evasion (mean attempt) | Distinct evading / trajectory |
| --- | ---: | ---: | ---: | ---: |
| 1. Random baseline | 25 | 25 | 2.80 | 16.8 |
| 2. Blackbox heuristic | 25 | 25 | 2.60 | 19.0 |
| 3. History-only agent | 25 | 25 | 5.04 | 9.5 |
| 4. Static LLM ranking | 25 | 16 | 3.25 | 2.0 |
| 5. Diagnostic agent | 25 | 25 | 7.84 | 9.1 |
| 6. AST-distance Metropolis | 25 | 25 | 2.00 | 19.8 |
| 7. Call-depth Metropolis | 25 | 25 | 2.00 | 19.8 |

This agrees with the Semgrep pattern: the model-guided strategies reach a first evasion later and accumulate fewer distinct evasions, and the static ranking found no evasion in 9 of 25 trajectories. Strategies 3 and 5 ran with the fixed-order operator prompt (see "Prompt order" below), so their numbers carry that bias. The five seeds share one program structure, and the report card (`S_rule` = 5, threshold 3) is exploratory. Confidence intervals were not recomputed for this table.

## Exhaustive checks by analyzer and corpus

### Official-suite seeds

Corpus built by `scripts/harvest.py` from the unmodified test files of the two rules: the Semgrep rules repository at commit `a84ff9cc24` (15 Python files that call `.execute` and carry `ruleid` annotations) and the CodeQL repository at tag `codeql-cli/v2.27.1` (the 4 Python files of the CWE-089 query test). Funnel (`corpus_official/seeds/funnel.json`, drop reasons in the same file): 19 files, 122 calls to `.execute`, 102 with a single argument, 82 that build the query from strings, 53 with exactly one external input reaching the query and a straight-line definition, 24 distinct programs after adaptation, 9 executable and exploit-live on SQLite under the framework's oracle. Semgrep flags 7 of the 9 (it misses the 2 concatenation programs, as on the varied seeds); CodeQL flags all 9.

**Does the setup reproduce the upstream tests?** Yes, for both scanners on the unmodified suites. `scripts/validate_semgrep_suite.py`: `semgrep --test` passes for `formatted-sql-query` (expected and reported match lines 32 and 39; Semgrep 1.178.0). `scripts/validate_codeql_suite.py`: the pinned query reports exactly the 20 alerts of `SqlInjection.expected` (same file, line and column, none missing, none extra). Output in `results/official-validation/`. Both programs adapted from alerts that the CodeQL suite expects (`app.py` `unsafe`, `sql_injection.py` `show_user`) are flagged by our harness. The CodeQL suite's known miss (`unsafe3`, connection through a class attribute) yields the same adapted program as 3 detected cases, so it is not tested.

**Exhaustive checks on the 9 programs** (`scripts/queue_official.sh`; runs `codeql-official-singles`, `codeql-official-nonflow-pairs`, `semgrep-official-newops`, `semgrep-official-triples`; 0 scan errors, 0 behavior differences):

| Scanner | Distinct candidates | Scanned and equivalent | Rejected as inapplicable |
| --- | ---: | ---: | ---: |
| CodeQL (9 programs) | 486 | 450 | 36 |
| Semgrep (7 programs) | 2,744 | 2,407 | 337 |

- **CodeQL.** The 81 candidates that contain a flow-changing rewrite all evade; the 369 that do not are all detected (0 exceptions). The 9 flow rewrites (`dynamic_sink`, `char_launder`, `deep_nest`, `db_roundtrip`, `simplequeue_roundtrip`, `pickle_roundtrip`, `partial_sink`, `methodcaller_sink`, `unbound_sink`) evade alone on 9 of 9 programs; no other single rewrite does.
- **Semgrep.** `extract_1`, `extract_2`, `branch_split`, `dict_dispatch`, `dynamic_sink`, `partial_sink`, `methodcaller_sink` and `unbound_sink` evade alone on 7 of 7; all 1,858 candidates containing one of them evade. The other 109 evading candidates all contain `literal_slice`, which evades alone on the 4 programs that use `%` or `.format` and needs `format_swap` on the 3 f-string programs, as on the varied seeds.

**Independent re-scan** (`rescan_sample.py`, fixed RNG seed): 40 evading + 40 detected Semgrep candidates regenerated from seed and rewrite set and scanned again: 0 hash mismatches, 0 verdict disagreements. CodeQL sample: see `docs/validation.md`. **Extended behavior check** (`extended_equivalence.py`): all 21,264 unique SQL candidates of all saved runs (16,562 evading, 4,702 detected; for Pysa evading means at least 1 of its 2 rules stopped firing), including the official-seed and Pysa runs, re-run on 20 inputs and a larger database: 0 differences; 52 of the 54 baseline seed files are exploit-live under the 3 standard injection strings, and the other 2 (`r06_vulpy_login`, `a05_pyload_update_link_info`) under their own exploit string.

**Limits.** 9 programs; the adapter replaces the database driver, the receiver of `execute` and the input source, and keeps the SQL text; INSERT/UPDATE statements, parameterized queries and table-name injection are outside the exploit check and were dropped. The corpus tests the two rules on the query shapes of the official suites, not on the libraries those suites model.

### Pysa: singles, pairs and triples

Third analyzer: Pysa (pyre-check 0.10.0) with the stock models at commit `d5614e0a` and its 2 SQL rules (5005 flow, 5051 string-combine); see README for the adapter. Runs (no model calls, no search; scripts `pysa_numbers.py` and `pysa_tables.py` compute every number below from the saved runs): `pysa-official-singles`, `pysa-main-singles`, `pysa-diverse-singles`, `pysa-official-pairs`, `pysa-main-pairs`. 4,716 evaluation rows, 3,994 distinct scanned candidates (606 single, 3,388 pair), 0 scan errors, 0 behavior-check differences (invalid, i.e. inapplicable, candidates are recorded separately). Scan time 5.2 s.

**Qualification.** 15 of 15 main seeds, 10 of 12 varied seeds, 9 of 9 official seeds (both rules fire and the exploit stays live). The 2 dropped varied seeds (`d08_like`, `d11_fetchone`) are flagged by Pysa, as by Semgrep and CodeQL, and dropped by the exploit check.

**Single rewrites** (34 seeds; silent = neither rule fires):

| Rewrites | Rule 5005 (flow) removed | Rule 5051 (string) removed | Silent |
| --- | ---: | ---: | ---: |
| `db_roundtrip`, `simplequeue_roundtrip` | 68/68 | 68/68 | 68/68 |
| `dict_dispatch`, `dynamic_sink`, `methodcaller_sink`, `partial_sink`, `unbound_sink` | 170/170 | 0/170 | 0/170 |
| `literal_slice` | 0/34 | 34/34 | 0/34 |
| `format_swap` | 0/28 | 4/28 | 0/28 |
| `extract_1`, `extract_2` | 0/68 | 2/68 | 0/68 |
| `rename`, `dead_padding`, `branch_split`, `char_launder`, `deep_nest`, `pickle_roundtrip`, `queue_roundtrip` | 0 | 0 | 0 |

**Pairs** (24 main and official seeds, 3,388 candidates): all 784 pairs with a round trip through a database or `SimpleQueue` are silent; 120 of 120 pairs of a sink-resolution rewrite with `literal_slice` are silent; sink-resolution with `format_swap`: 10 of 100 (the 2 seeds on which `format_swap` alone removes rule 5051); none of the other 2,384 pairs. 914 of 3,388 pairs are silent, 130 of them although neither rewrite is silent alone. No pair removed rule 5051 where neither member did. None of the 712 candidates built only from the 4 controls and `extract_1`, `extract_2`, `branch_split` is silent or removes rule 5005.

**Against the other analyzers** (same seed and rewrite set): CodeQL, 1,091 shared candidates: both detect 631, both silent 129, only CodeQL silent 315, only Pysa silent 16. Semgrep, 1,898 shared: both detect 568, both silent 164, only Semgrep silent 1,004, only Pysa silent 162. The round trips are the only single rewrites that silence both CodeQL and Pysa.

**Independent checks.** `rescan_pysa.py` (fixed RNG seed): 120 candidates regenerated and scanned again (40 silent, 40 that lost 1 rule, 40 that kept both), 0 hash mismatches, 0 behavior-check disagreements, 0 differences in the set of rules that fire. No (seed, rewrite set) pair received 2 different Pysa verdicts across the 5 runs (3,994 distinct pairs, 428 of them scanned in both a singles and a pairs run). The extended behavior check now includes the Pysa candidates (see above).

**Limits.** Stock models and our setup (annotation of the connection, a source model on the entry parameter) define what Pysa sees; a tuned configuration could differ. Rule 5051 is a string-combine rule in the model configuration, which fits the pattern above; the two round-trip cases were not traced through Pysa's analysis. Unflagged shapes are absent (baseline must fire).

**Pysa triples** (`pysa-triples`, `pysa_triples.py`): all subsets of up to 3 of the 16 non-round-trip rewrites on `o03`, `o18`, `o24`. 1,510 distinct candidates (578 subsets contain a rewrite that does not apply), 0 errors, 0 behavior differences; 20 of 303 pairs and 189 of 1,161 triples silent; every silent triple contains a silent pair (0 new). Silent iff one of the 5 sink-resolution rewrites and `literal_slice` (or `format_swap` on the concatenation seed `o18`) are present: 0 exceptions.

### Semgrep taint mode and newer releases

**Semgrep taint mode** (stock rule `python/flask/security/injection/tainted-sql-string` at semgrep-rules `17e31e11`, vendored in `rules/` with provenance; scan-time change: one `@app.route("/<user_input>")` line before the entry function; runs `semgrep-taint-{main,official,real}-pairs`, `semgrep-taint-diverse-singles`). Qualifying seeds: 15/15 main, 9/9 official, 10/12 varied, 3/6 independent-project. 4,462 distinct candidates, 1,424 evading. A candidate evades iff it contains `literal_slice`, `extract_1` or `extract_2`, or `format_swap` on a seed that builds the query by concatenation (`o18_semgrep`, `o23_codeql`, `d01_concat`, `d12_concat_parts`; this clause was added after looking at the 32 candidates the first three rewrites do not explain, so it is a description and not a prediction); 0 exceptions. On the 22 seeds both Semgrep rules flag, single rewrites that evade (pattern rule / taint rule): `literal_slice` 4/22, `extract_1` and `extract_2` 22/22 both, `branch_split`, `dict_dispatch`, `dynamic_sink`, `partial_sink`, `methodcaller_sink`, `unbound_sink` 22/22 against 0/22; the other 9 rewrites 0 and 0. The pattern-rule singles were rescanned with the pinned Semgrep for this table (`semgrep-pattern-{main,official}-singles`).

**Newer releases.** Semgrep 1.182.1 (pinned 1.178.0): same verdict on 392 of 392 identical single-rewrite candidates. CodeQL 2.27.3 with python-queries 1.8.13 (pinned 2.27.1 and 1.8.11), `codeql-linux64.zip` SHA-256 `845075a2...` matches GitHub's digest: 428 single-rewrite candidates on 24 seeds, 0 errors, 216 evading, exactly those with one of the 9 flow-changing rewrites (0 exceptions). Pysa: pyre-check 0.10.0 is still the newest release and the vendored models equal pyre-check `main` (`d5614e0a`) at the time of the check.

### Independent and deployed programs

**Programs from independent projects** (`corpus_real/seeds`, 6 hand-adapted programs: 5 OWASP BenchmarkPython SQL-injection tests marked real vulnerabilities, 1 `vulpy` login; runs `semgrep-real-pairs`, `codeql-real-singles`, `codeql-real-nonflow-pairs`, `pysa-real-pairs`; 0 scan errors, 0 behavior differences). Qualifying programs: Semgrep 6 of 6, CodeQL 5 of 6, Pysa 5 of 6 (the original `configparser` program `r01` is missed by CodeQL and Pysa).

| Analyzer | Candidates | Result |
| --- | ---: | --- |
| Semgrep | 954 | 634 of 634 containing a restructuring or sink-resolution rewrite evade; the other 14 evading candidates all contain `literal_slice` |
| CodeQL | 261 | 45 of 45 containing a flow-changing rewrite evade, none of the others does (0 exceptions) |
| Pysa | 792 | 198 silent: 173 of 173 round-trip candidates and 25 of 25 pairs of a sink-hider with `literal_slice`; 0 other (0 exceptions) |

**Programs from deployed projects** (`corpus_apps`, 5 functions from 3 projects with a published advisory; each is the last vulnerable PyPI release; wheel SHA-256 in `corpus_apps/SOURCE.txt`; Parsl 2025.12.22 x3, SciTokens 1.8.1, pyload-ng 0.5.0b3.dev90). All 5 exploitable and flagged by all 3 analyzers. Semgrep pattern 552 candidates, 396 evading, 369 contain a restructuring or sink-resolution rewrite and all evade, the other 27 evading candidates contain `literal_slice`; Semgrep taint (4 of 5 qualify) 492 candidates, 144 evading, 0 exceptions to the taint rule; CodeQL 165 candidates, 45 evading, exactly those with a flow rewrite (0 exceptions); Pysa 552 candidates, 156 silent, exactly the predicted ones (0 exceptions).

### Command injection and path traversal

**Command injection** (`seeds_cmd`, 8 synthetic CWE-78 seeds; Semgrep `dangerous-subprocess-use-audit`, CodeQL `py/command-line-injection`, Pysa rules 6065 and 5001; runs `semgrep-cmd-pairs`, `codeql-cmd-singles`, `codeql-cmd-nonflow-pairs`, `pysa-cmd-pairs`; 0 scan errors, 0 behavior differences). Qualifying programs: Semgrep 7 of 8 (the rule does not match `os.popen`), CodeQL 8 of 8, Pysa 8 of 8 (6 under rule 6065 and 2 under 5001).

| Analyzer | Candidates | Result |
| --- | ---: | --- |
| Semgrep | 1,002 | 391 of 391 containing a sink-resolution rewrite (`dict_dispatch`, `dynamic_sink`, `partial_sink`, `methodcaller_sink`) evade, 611 detected (0 exceptions); `extract_1`, `extract_2`, `branch_split` do not evade, unlike on the SQL rule |
| CodeQL | 406 | 64 of 64 containing a flow-changing rewrite evade, 342 detected (0 exceptions) |
| Pysa | 1,150 | 644 silent, all predicted: a round trip or a sink-resolution rewrite (one rule per seed, so no pair is needed); 0 exceptions |

**Path traversal, third class** (`seeds_path`, 8 synthetic seeds with builtin `open`; Semgrep `path-traversal-open` with the route decorator line, CodeQL `py/path-injection`, Pysa rule 5011; `scripts/queue_path.sh`; 0 scan errors and 0 behavior differences in every run). Semgrep flags 6 of 8 (not the `with open(path)` seed `p05` and the two-step seed `p08`); CodeQL and Pysa flag all 8 and were run on the first 6 for cost.

| Analyzer | Candidates | Result |
| --- | ---: | --- |
| Semgrep (pattern) | 756 | evades iff `dict_dispatch`, `dynamic_sink` or `partial_sink` is present (249 of 249; 0 exceptions); `extract_*` and `branch_split`, which evade the SQL pattern rule, do not evade this rule |
| CodeQL | 285 | 42 evading, exactly those with a flow-changing rewrite (0 exceptions) |
| Pysa | 756 | 393 silent, exactly those with a sink-resolution rewrite or a round trip (0 exceptions; one rule per seed, as for command injection) |

**Official-suite validation of the added rules.** Semgrep `path-traversal-open` (semgrep-rules `16b9e6d4`, 12 expected lines) and the taint rule `tainted-sql-string` (12 expected lines) pass their own tests (`validate_semgrep_suite.py <rule>`); CodeQL `py/command-line-injection` and `py/path-injection` reproduce their own `.expected` (13 of 13 and 21 of 21 alerts; `validate_codeql_suite.py cmd|path`, tests at github/codeql `6e9f9e38`).

**Transform change for builtin sinks.** `transforms.py` gained `SINK_FUNCTIONS = ("open",)`: `dict_dispatch`, `dynamic_sink` (`getattr(builtins, 'op' + 'en')`) and `partial_sink` apply to a plain-name sink, `methodcaller_sink` and `unbound_sink` raise. `scripts/check_candidates_unchanged.py` regenerates every logged candidate and compares its SHA-256: 12,058 distinct candidates, 0 differences before and after the change.

### Bandit

Bandit 1.9.4 (`.sastlab/bandit-venv`, `requirements-bandit.lock`) is a per-file AST linter without taint tracking. Rules: B608 (SQL built by string formatting or concatenation, CWE-89) and B602 (`subprocess` with `shell=True`, CWE-78). Bandit has no default test for the path-traversal class, so that class is not run. All single and pair rewrites (`scripts/queue_bandit.sh`, configs `configs/bandit-*.json`, results `results/bandit-*-pairs`), 6 corpora, 50 seeds that Bandit flags before any rewrite, 7,700 candidates, 0 scan errors, 0 behavior differences, 1,166 silent (`bandit_numbers.py`):

| Corpus | Seeds | Candidates | Silent |
| --- | ---: | ---: | ---: |
| Main (SQL) | 15 | 2,430 | 270 |
| Varied (SQL) | 10 | 1,584 | 212 |
| Official (SQL) | 9 | 1,386 | 192 |
| Independent (SQL) | 6 | 954 | 107 |
| Deployed (SQL) | 4 | 492 | 51 |
| Command injection | 6 | 854 | 334 |

- **B608** is silent iff the candidate contains `literal_slice`, or `format_swap` on a query built with `+` (`format_swap` turns the concatenation into `''.join([...])`, checked by scanning the candidate by hand). 0 exceptions in 6,846 SQL candidates. Restructuring, sink-resolution and flow-changing rewrites do not matter: the rule matches how the string is built.
- **B602** is silent iff the candidate contains `dict_dispatch`, `dynamic_sink`, `partial_sink` or `methodcaller_sink` (0 exceptions in 854). `unbound_sink` does not apply to a module function.
- On the worked example (`seed_01` with `char_launder` and `dynamic_sink`) Semgrep and CodeQL are silent, Pysa still reports 5051 and Bandit still reports B608.
- Independent rescans without cache (`rescan_sample.py`, 40 evading + 40 detected per corpus, 480 candidates): 0 hash mismatches, 0 behavior disagreements, 0 verdict disagreements.
- Not done: search strategies and agents on Bandit (exhaustive checks only), and CWE-79, CWE-295 and CWE-200, which need their own execution check of the exploit.

### Operator taxonomy and rewrite catalog

Operators are grouped by the taint-analysis weakness they stress (`TAXONOMY` in `sastlab/transforms.py`), and five operators suggested by the rewrite catalog bring the toolbox to 18 (masks 0-8191 keep their meaning). `semgrep-newops` and `codeql-newops` hold all singles and pairs of the new operators on the 12 varied seeds: 0 behavior differences, 0 scanner errors. All five evade CodeQL alone on 10/10 qualifying seeds; the three sink operators evade Semgrep alone on 8/8, the other two do not. Search campaigns still use the first 13 operators.

`codeql-path-probe`: laundering rewrites inserted at each node of CodeQL's witness path (parameter, query definition, query at sink): 155/155 evade, 31/31 identity controls detected, so placement on the path gives no advantage over the function entry. Seeds d08 and d11 excluded (exploit not live under the oracle). Script: `scripts/path_probe.py`.

`semgrep-controls-main` (`queue_pattern_singles.sh`): all 15 subsets of the 4 control rewrites on the 15 main seeds, pinned Semgrep 1.178.0, 225 candidates, 0 scan errors, 0 behavior differences. 60 evade, exactly the 4 subsets that contain both `format_swap` and `literal_slice` (15 of 15 seeds each); the other 11 subsets, with or without `rename` and `dead_padding`, never evade. Across all saved pinned-rule runs on SQL seeds, 134 of 473 distinct control-only candidates evade and every one contains `literal_slice` (`controls_main.py`).

`codeql-diverse-*`, `semgrep-diverse-triples`: 12 structurally varied seeds (`seeds_diverse/`). CodeQL: evasion iff a flow operator is present, on all 10 qualifying seeds. Semgrep: depends on code shape.

`codeql-rewrite-catalog`: 59 behavior-checked variants showing what CodeQL's query tracks.

### Mechanisms

**Mechanism checks** (`mechanism_pysa.py`, `mechanism_codeql.py`; Pysa on `seed_01`, CodeQL on `seed_01` and `o05_semgrep`). Pysa call graph of the entry function: no edge to `sqlite3.Cursor.execute` for `dynamic_sink` and `methodcaller_sink`; the edge exists for `dict_dispatch`, `partial_sink` and `unbound_sink` and rule 5005 still does not fire (cause unknown). Pysa stock models have `queue.Queue.put/get` and nothing for `_queue.SimpleQueue`; adding 2 lines for `_queue.SimpleQueue` restores both rules on `simplequeue_roundtrip`, and 3 lines (`Connection.execute` parameters into self, self into the returned cursor, `Cursor.fetchone`) restore them on `db_roundtrip`. CodeQL `Stdlib.model.yml` has `queue.Queue` put/get and no `SimpleQueue`; a data extension (model pack) with 2 rows restores the alert on `simplequeue_roundtrip`, 2 rows for `pickle.dumps/loads` on `pickle_roundtrip`, 2 rows for `chr`/`ord` on `char_launder` (2 of 2 seeds each). Not traced: CodeQL `dynamic_sink`, `deep_nest`, `db_roundtrip`, `partial_sink`, `methodcaller_sink`, `unbound_sink`.

**Mechanisms (scripts `mechanism_pysa.py`, `mechanism_codeql_probe.py`, `mechanism_codeql_flow.py`; seed_01).** Pysa call graph: `dynamic_sink` and `methodcaller_sink` have no call to `sqlite3.Cursor.execute`; `dict_dispatch` and `partial_sink` leave the callee unresolved (`UnexpectedCalleeExpression`, the `execute` entry is only the attribute access); `unbound_sink` resolves but Pysa treats `type(cursor).execute(...)` as a bound call and shifts the arguments by 1 (rule 5005 fires on `type(cursor).execute(query)` and on `sqlite3.Cursor.execute(cursor, query)`). CodeQL, listing the nodes of `SqlInjection::Sink`: the 4 sink-resolution rewrites leave no sink node; `deep_nest` and `db_roundtrip` keep the sink and lose the flow. `deep_nest` alerts up to 5 nested lists and not at 6 or more (the rewrite uses 8), matching `accessPathLimit() = 5` in the shared data-flow library (not overridden by Python; not tested directly). `db_roundtrip`: 3 summary rows written against `sqlite3.connect()`'s return value restore the alert (the same rows written for the type `sqlite3.Connection` did not).

**Pysa against its own tests** (`scripts/validate_pysa_suite.py`, pyre-check `d5614e0a`, 33 integration tests that carry their own configuration, a stub `pysa` module for the helper imports): 32 of 33 reproduce the expected issues exactly. `entrypoint` reports 1 extra issue (rule 1006, global state, unrelated to SQL). The tests of the string-combine rules (`multiple_sources_string_operations*`) pass.

**Pysa with the stock source** (`pysa-http-main-singles`, `pysa-http-main-pairs-s01`, `pysa-http-official-pairs-o03`): 576 candidates, the same set of rules fires on all 576, 0 scan errors, no difference in which seeds qualify.

## Agent search on restricted pools

### Prompt order

`prompt-order-probe`: fixed-order operator definitions made the model pick `rename` 34/60 times, shuffled 13/60. Fixed in `sastlab/llm.py`; the LLM-strategy results of the full campaigns used the fixed-order prompt.

`codeql-promptfix`, `semgrep-promptfix`: strategies 3 and 5 rerun with the shuffled prompt (15 attempts, 5 trajectories). On CodeQL (5 streams) the 8B history-only and diagnostic agents need 3.64 and 4.20 attempts to the first evasion with the shuffled definitions, against 5.04 and 7.84 in `codeql-v6`; the static ranking (strategy 4) was not rerun, so its 16 of 25 comes from the fixed-order prompt.

### Semgrep and CodeQL

`semgrep-hard`, `semgrep-hard30`: restricted operator pool of nine (two minimal evading sets: `extract_1`, or `format_swap`+`literal_slice`). With 30 trajectories, both LLM strategies are no better than random and slower than the heuristic and Metropolis search.

`semgrep-hard30-qwen`: with `qwen3-coder-next`, the diagnostic agent finds an evasion at attempt 1.14 on average (90/90; `extract_1` first in 86/90), history-only 4.47 (88/90), against heuristic 5.47 and `llama3.1:8b` agents 8.8-9.2 (64/90). So the null result for diagnostic feedback is specific to the 8B model.

`codeql-hard`: restricted 9-operator pool where only `char_launder` evades CodeQL; 4 seeds x 5 trajectories x 12 attempts. llama3.1:8b strategies 3/4/5 found an evasion in 14/8/13 of 20 trajectories (mean first 8.5/9.4/8.9); random 4.0, heuristic 4.5, Metropolis 6.0 (all 20/20).

`codeql-hard15`: seed d01, 15 streams, 12 attempts, llama3.1:8b. Found/15 and mean attempts to first: random 15/4.20, heuristic 15/4.07, history-only 10/8.27, diagnostic 9/8.87, Metropolis 11/7.47. With `qwen3-coder-next` on the same seed and streams: history-only 15/1.87, diagnostic 15/2.07 (diagnostic - history-only +0.20, CI [-0.07,+0.47]). So on CodeQL the larger model beats the baselines but diagnostics add nothing, unlike Semgrep.

Diagnostic-field ablation (`semgrep-abl-message|snippet|sink`, qwen3-coder-next, strategy 5): message only 1.06 attempts (90/90), snippet only 4.43, line only 4.52, all fields 1.14, none 4.47. `semgrep-hard30-q36` (qwen3.6:35b): diagnostics 3.16 (89/90) vs history-only 9.92 (52/90). The Semgrep rule message is what helps.

### Pysa agents

**Restricted search on Pysa** (`pysa-hard-qwen`, `pysa-hard-qwen-rule`; `evasion: all`, pool of 9 rewrites without the 2 round trips, 3 main seeds x 15 streams = 45 streams, 15 attempts, `qwen3-coder-next`; 3,375 + 675 attempts, 0 scan errors, 1,350 model calls in the main run, 0 fallbacks). Minimal evading sets from the exhaustive pairs: `dict_dispatch` or `dynamic_sink` together with `literal_slice` (larger sets not enumerated).

| Strategy | Mean attempts to first evasion (16 = none) | 95% interval | Streams with an evasion |
| --- | ---: | --- | ---: |
| 1. Random baseline | 13.33 | [10.67, 15.60] | 15/45 |
| 2. Blackbox heuristic | 10.13 | [7.40, 12.67] | 36/45 |
| 3. History-only agent | 16.00 | | 0/45 |
| 5. Diagnostic agent | 16.00 | | 0/45 |
| 6. AST-distance Metropolis | 9.20 | [6.67, 11.80] | 33/45 |
| 5, rule id only | 16.00 | | 0/45 |

Paired differences against random choice: heuristic -3.20 [-5.80, -0.73] (sign-flip p = 0.043), Metropolis -4.13 [-6.47, -1.87] (p = 0.005), agents +2.67 [+0.40, +5.33] (p = 0.059). The agents tried `literal_slice` in 21 (history-only) and 40 (diagnostic) of 45 streams and a sink-resolution rewrite in 35 and 23, never both in one candidate, and added `char_launder` in 234 and 221 of 675 attempts against 108 for random choice. A candidate adds only operators with a higher index than its last, so after `char_launder` neither `literal_slice` nor the sink-hiders can be added until the walk restarts; the prompt does not say so, and no prompt that does was tried. Reported as agent behavior with this prompt and model, not as a cause.

**Pysa agent search, prompt variants** (`pysa-hard-qwen`, `pysa-hard-informed-noorder`, `pysa-hard-informed`, `pysa-hard-any`, `pysa-hard-informed-any`, `pysa-hard-informed-any-35b`; 3 hard seeds x 15 streams = 45, 15 attempts, `qwen3-coder-next` except the 35B run, `evasion: all`; scan cache on for the new runs, which changes compute but not attempt counts). The earlier 0 of 45 was a protocol effect: the agents were not told how a candidate grows (a candidate adds only operators later in the fixed order than the last one added).

| Prompt (increasing order) | History-only agent | Diagnostic agent |
| --- | ---: | ---: |
| Original (no tool, no order) | 0/45, mean 16.00 | 0/45, mean 16.00 |
| Tool-aware (names Pysa and its 2 rules, says both must stop; order not stated) | 0/45, 16.00 | 1/45, 15.71 |
| Informed (tool-aware plus the fixed operator order and the rule) | 20/45, 12.53 | 34/45, 10.42 |

Random 15/45 (13.33), heuristic 36/45 (10.13). Paired differences, informed prompt: diagnostic minus random -2.91 [-6.31, +0.73] (sign-flip p=0.13), diagnostic minus heuristic +0.29 [-3.24, +3.53] (p=0.87), history-only minus random -0.80 [-3.73, +2.09] (p=0.61), history-only minus heuristic +2.40 [-1.22, +5.71] (p=0.21). Mean number of rewrites in the first evading candidate: diagnostic 3.7, history-only 4.3, random 2.6. Free order (any operator, any order): random 45/45 at 5.87 attempts (about 5.9 rewrites per candidate), original-prompt agents 45/45 at 6.00 and 5.02, 35B informed 45/45 at 5.07 and 4.02; the protocol is trivial because large candidates contain both ingredients, so it is reported as a caveat only. `rule id only` and the other earlier results are unchanged.

**Informed prompt on Pysa, 3 models and 2 seed sets** (increasing order, budget 15, 45 streams per cell; set A = the 3 hard seeds, set B = `o03`, `o18`, `o24` with their own random and heuristic baselines). Found / mean attempts; difference to random with 95% interval.

| Set | Model | History-only | Diagnostic |
| --- | --- | --- | --- |
| A | coder | 20/45, 12.53, -0.80 [-3.73, +2.09] | 34/45, 10.42, -2.91 [-6.31, +0.73] |
| A | 35B | 1/45, 15.69, +2.36 [-0.00, +5.13] | 9/45, 13.42, +0.09 [-3.44, +3.69] |
| A | 8B | 10/45, 13.73, +0.40 [-3.27, +4.13] | 18/45, 13.42, +0.09 [-3.00, +3.53] |
| B | coder | 22/45, 12.51, +0.58 [-1.93, +3.24] | 38/45, 9.69, -2.24 [-5.53, +1.11] |
| B | 35B | 5/45, 14.98, +3.04 [+0.27, +5.78] | 12/45, 13.62, +1.69 [-0.96, +4.27] |

Random: A 15/45 (13.33), B 23/45 (11.93). Only the coder diagnostic agent is below random choice in both seed sets (-2.91 and -2.24), and its interval includes 0 in both.

### Informed prompts on Semgrep and CodeQL

**Informed prompt on Semgrep (pattern rule, 3 seeds x 30 streams) and CodeQL (seeds d01 and d02, 15 streams each)**, 3 models, same streams and pools as the original runs (`semgrep-informed-*`, `codeql-informed-*`, `codeql-more-*`; prompt: scanner and rule description plus the operator order; `scripts/queue_informed.sh`, `queue_more_codeql.sh`). Mean attempts (trajectories with an evasion), original -> informed; informed minus random, interval resampled over streams:

| Scanner | Model | Agent | Original | Informed | vs random |
| --- | --- | --- | --- | --- | --- |
| Pattern | Random | - | - | 8.37 (66/90) | - |
| Pattern | 8B | History-only | 9.16 (64/90) | 6.04 (84/90) | -2.32 [-4.52, -0.17] |
| Pattern | 8B | Diagnostic | 8.82 (64/90) | 6.13 (83/90) | -2.23 [-4.63, +0.10] |
| Pattern | Coder | History-only | 4.47 (88/90) | 3.28 (90/90) | -5.09 [-7.28, -2.98] |
| Pattern | Coder | Diagnostic | 1.14 (90/90) | 2.71 (90/90) | -5.66 [-7.70, -3.71] |
| Pattern | 35B | History-only | 9.92 (52/90) | 3.47 (89/90) | -4.90 [-7.00, -2.79] |
| Pattern | 35B | Diagnostic | 3.16 (89/90) | 2.64 (90/90) | -5.72 [-7.77, -3.74] |
| Data-flow | Random | - | - | 4.30 (30/30) | - |
| Data-flow | 8B | History-only | 8.43 (18/30) | 7.13 (24/30) | +2.83 [+1.33, +4.30] |
| Data-flow | 8B | Diagnostic | 8.27 (20/30) | 7.67 (24/30) | +3.37 [+1.77, +5.07] |
| Data-flow | Coder | History-only | 3.77 (30/30) | 6.40 (28/30) | +2.10 [+0.57, +3.70] |
| Data-flow | Coder | Diagnostic | 2.60 (30/30) | 5.70 (28/30) | +1.40 [-0.17, +3.10] |
| Data-flow | 35B | History-only | 2.70 (30/30) | 1.63 (30/30) | -2.67 [-3.80, -1.63] |
| Data-flow | 35B | Diagnostic | 1.47 (30/30) | 1.50 (30/30) | -2.80 [-4.00, -1.67] |

Random: pattern 8.37 (66/90), data-flow 4.30 (30/30). Original prompt, 8B minus random: pattern +0.79 [-2.11, +3.58] (not worse than random; worse than the heuristic by +3.69), data-flow +4.13 [+1.57, +6.63]. Feedback gain on the pattern rule (diagnostic minus history-only): with the original prompt coder -3.32 [-4.57, -2.16], 35B -6.77 [-8.58, -5.04], 8B -0.33 [-1.79, +1.11]; with the informed prompt coder -0.57 [-1.02, -0.20], 35B -0.82 [-1.71, -0.09], 8B +0.09 [-1.01, +1.12]. On the data-flow query with the original prompt: coder -1.17, 35B -1.23, 8B -0.17. Consequence: the 8B model is worse than random only on the data-flow query; on the pattern rule it is no better than random with the original prompt and below random with the informed one (the interval of its diagnostic agent reaches 0), and most of the feedback gain on the pattern rule is a missing description of the rule.

### More streams and repeats

**More streams and repeats** (`scripts/queue_more_codeql.sh`, `scripts/queue_repeats.sh`, `more_streams.py`). CodeQL agent comparison on seeds `d01` and `d02` (30 streams per cell, 3 models, original and informed prompt, shared random and heuristic baselines in `codeql-more-base`): the 35B agents beat random choice with both prompts (about -1.6 to -2.8 attempts), the 8B agents are worse (+2.8 to +4.1), the coder agents beat random only in the diagnostic form with the original prompt (-1.70) and are worse with the informed prompt (+2.10, +1.40). Repeats with base seeds 7001 and 7002 (`semgrep-rep*`, `pysa-rep*`): the 6 pattern-rule cells stay within 0.4 attempts of the first run and are below random in all 18 runs, with the interval below 0 in 13 of them; on Pysa the coder diagnostic agent is below random in 3 of 3 runs (interval below 0 in 2; pooled -5.01 [-6.87, -3.04]), the coder history-only agent in 3 of 3 (interval below 0 in 1; pooled -2.26 [-4.03, -0.48]), the 35B history-only agent is worse (pooled +1.33 [+0.20, +2.56]) and the 8B diagnostic agent does not differ from random (pooled -1.04 [-2.59, +0.58]). The persistent scan cache (`scan_cache` config key) changes compute only.

### Metropolis restarts

Found after the runs (review of the report): in every saved run except the two walk checks below, strategies 6 and 7 also restart from the seed, like strategies 1 to 5, when the current subset holds the last operator of the order. `Search.select` sets the mask to 0 before the strategy 6/7 branch, and the runner records `restarted` only for strategies 1 to 5, so in `attempts.jsonl` a restart shows only as a `parent_mask` that is not the last accepted mask. `analysis/metropolis_restarts.py` finds them in the saved rows and asserts that each one goes to the seed and happens exactly when no later operator is left.

| Run | Attempts | Restarts | Restarts before the first evasion | Trajectories with one |
| --- | ---: | ---: | ---: | ---: |
| `semgrep-v6` (full campaign) | 4,500 | 300 | 0 | 0 of 150 |
| `codeql-v6` (full campaign) | 1,500 | 100 | 0 | 0 of 50 |
| `semgrep-hard` (pilot) | 1,200 | 184 | 136 | 60 of 80 |
| `codeql-hard` (pilot) | 480 | 80 | 32 | 24 of 40 |
| `semgrep-hard30` | 1,350 | 164 | 63 | 42 of 90 |
| `codeql-hard15` | 180 | 20 | 11 | 8 of 15 |
| `pysa-hard-qwen` | 675 | 78 | 48 | 30 of 45 |

The full campaigns are unaffected, because attempts to the first evasion are counted only up to the first evasion. On the restricted pools and in the pilots the walk results describe the walk with restarts. The config key `metropolis_restart` (default `true`, so the saved configs replay) turns the restart off. Check reruns with `false`: strategy 6 only, the same pools, seeds, trajectory seeds and budgets, no model calls (`scripts/queue_walk_check.sh`; 0 scan errors, 0 behavior differences, 0 restarts):

| Run | Found | Mean attempts (miss = 16) | Saved walk | Without restart − saved walk | Without restart − heuristic |
| --- | ---: | ---: | --- | --- | --- |
| `semgrep-hard30-walk` | 90/90 | 5.28 | 90/90, 5.23 | +0.04 [-0.80, +0.78] | -0.19 [-1.42, +0.91] |
| `pysa-hard-walk` | 36/45 | 9.27 | 33/45, 9.20 | +0.07 [-1.47, +1.93] | -0.87 [-4.00, +2.07] |

The restart makes no measurable difference on either pool, and the walk without it still cannot be told apart from the heuristic. Intervals: paired over 30 and 15 streams, 5,000 resamples, the generator of `vs_heuristic.py`.

### Statistics

Intervals are 95% percentile bootstrap intervals with 5,000 resamples over streams (trajectory indices), after the paired difference is averaged over the seeds of a stream, because the seeds of a corpus share one program structure and so are not independent samples. Sign-flip p-values use 5,000 random sign changes of the same per-stream differences. Counts such as 34 of 45 are trajectory counts (seed x stream). The table of the full Semgrep campaign reports intervals over (seed, trajectory) units instead, and the CodeQL campaign table reports none. All of these are exploratory.

## Framework and integration validation

| Check | Result |
| --- | --- |
| Unit and integration suite | 168 tests passed (165 passed and 3 skipped in the Docker image) on the current tree, which differs from the tree the early campaigns ran on ([validation record](docs/validation.md)) |
| Behavior preservation | Every evaluated candidate in the saved campaigns matched the original on both inputs: 0 differences in 5,563 Semgrep candidates, 225 + 31 operator-check candidates and 5,250 CodeQL search attempts |
| Verdict determinism | No (seed, subset) pair received two different verdicts in any saved run: 12,532 distinct Semgrep pairs (pinned 1.178.0, main, varied and official seeds, `controls_main.py`) and 3,945 distinct CodeQL pairs (same corpora, 26 runs, 3,780 without the 2 runs of CodeQL 2.27.3, `codeql_rule.py`) |
| Scanner and oracle errors | 0 oracle failures in all campaigns; 0 scanner errors in every campaign except `codeql-hard-qwen` (2 timed-out scans of `d02_str_format`, strategy 5, not counted as evasions; its report card is `excluded`); `codeql-v6` has none after the rerun of its 3 timed-out scans |
| Model requests | 0 fallbacks in the two full campaigns; 79 in the restricted runs, out of 76,045 distinct model decisions (73 with the 8B model: `semgrep-informed-8b` 37, `semgrep-rep1-8b` 25, `pysa-hard-informed-8b` 11; 6 with the 35B model: `pysa-rep1-35b`). Counted over all `results/*/llm.jsonl` records with `fallback: true` (1,525 model records in `codeql-v6`, 0 fallbacks) |

## Limitations

- **Corpus validity.** The 15 main fixtures are one program in 15 variants (the share of distinct candidates that evade Semgrep is 0.86 to 0.88 on every seed), so "15 of 15 seeds" is closer to one result than fifteen. The 12 varied seeds were written by us. The 9 official-suite seeds, 6 independent programs and 5 functions from deployed projects are the only programs we did not write, but there are few of them, and the adaptation keeps their query construction and not the database libraries they use (see Official-suite seeds). No full application or CI pipeline was tested.
- **Saturation.** One operator suffices against Semgrep, so success rates and first-evasion times cannot rank strategies. Distinct evasions per trajectory is a better measure but depends on the size of the operator set.
- **Operators were chosen with knowledge of the scanners.** The flow operators were designed to break taint tracking; the finding is what they do, not that a strategy discovered them.
- **Input-bounded equivalence.** Two inputs and one database (20 inputs in the extended check, see `docs/validation.md`) do not establish general behavior preservation, though `char_launder`, `deep_nest` and `dynamic_sink` preserve behavior for any string input.
- **Mechanisms.** The causes of 6 evasion types were checked by adding the missing model (outputs in `results/mechanism/`); the other evasions were not investigated.
- **Model identity.** SoCLaaS provides no weight digest, so the model is unverified; model-guided results may not reproduce on a different serving stack.
- **CodeQL campaign.** Complete (0 scanner errors after the rerun) but only on five seeds, and the two history-based LLM strategies (3 and 5) ran with the fixed-order prompt.
- **Rule scope.** The results concern 14 rules of 4 analyzers on 3 vulnerability classes in Python (listed in the README), not the rule packs or all of any tool.

## Reproduction and evidence preservation

Commands used, executed from this directory (each needs a new output directory):

```sh
./run.sh run --config configs/semgrep.json --output results/semgrep-v6
./run.sh exhaustive --config configs/codeql.json --output results/codeql-flow-ops-15seeds --seed-limit 15 \
    --operators dynamic_sink char_launder deep_nest db_roundtrip
./run.sh run --config configs/codeql.json --output results/codeql-v6 --attempts 30 --trajectories 5 --seed-limit 5
./run.sh report results/codeql-v6 --write   # recompute summary.json after the run finishes (without --write it only prints)
```

`SOCLAAS_API_KEY` must be set (see the [README](README.md)). Each manifest records the framework, seed and rule hashes and the scanner versions. Raw scanner reports are in the manifest's `work_dir` (`.sastlab/runs/`); keep it when archiving. See [methodology](docs/methodology.md) for operator, search and report-card definitions and for the design decisions.

The full campaigns above ran with the fixed-order operator prompt and on a corpus that is one program in 15 variants; both are caveats for their agent comparisons.
