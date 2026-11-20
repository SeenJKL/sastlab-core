# Validation record

Platform: Linux x86-64 (2 CPU cores, Python 3.14.4), Semgrep 1.178.0, CodeQL CLI 2.27.1 with `codeql/python-queries` 1.8.11, Pysa (pyre-check 0.10.0, stock models at commit `d5614e0a`), `llama3.1:8b`, `qwen3-coder-next` and `qwen3.6:35b` on NUS SoCLaaS.

The scripts behind the report's tables and numbers are in `analysis/` (see the README). The other scripts named below (queue, re-scan, validation and further analysis scripts) and the upstream test suites were used to compute and check these results; they are not part of this repository.

## Does the setup reproduce what the scanners' authors expect?

| Check | Result |
| --- | --- |
| Semgrep on the upstream test of `formatted-sql-query` (`scripts/validate_semgrep_suite.py`, `semgrep --test`) | passes: expected and reported match lines are 32 and 39, `ok` cases silent |
| CodeQL on the upstream query test for `py/sql-injection` (`scripts/validate_codeql_suite.py`, same CLI calls as the harness) | exactly the 20 alerts of `SqlInjection.expected`, same file, line and column, none missing, none extra |
| Adapted programs from alerts the CodeQL suite expects (`app.py` `unsafe`, `sql_injection.py` `show_user`) | both flagged by the harness (CodeQL and, for `show_user`, Semgrep) |
| Replication image (`docker run sastlab`) | runs the test suite: 181 tests pass and 6 are skipped (the image has no `results/`). An earlier image, built with the validation scripts that are not part of this repository, also ran both suite validations, the seed harvest and a smoke scan of every single rewrite on one official seed per scanner, with the expected evading rewrites for each scanner |

Outputs of the first two checks are in `results/official-validation/`.

## Can every saved result be traced to a command?

| Check | Result |
| --- | --- |
| A command for every folder of `results/` (`scripts/queue_commands.py`) | 115 folders: 111 are written by a stage of a queue script and 4 by one helper script (`path_probe.py`, `prompt_order_probe.py`, `reproduce.sh`, `analysis/run_mechanism.sh`). |
| The command against the manifest | for the 110 folders that have a manifest, the configuration (search runs) or identity (exhaustive runs: engine, enumerated operators, `max_ops`, number of seeds) that the recorded command produces equals the stored one. `config_dir`, `evasion` and `scan_cache` are not compared: the framework recorded the first two only in later runs, and the scan cache changes compute and never results. The saved manifest of `semgrep-rep1-8b` has no `scan_cache`, its config and the 18 sibling configs have |
| Re-checked runs: exhaustive `codeql-flow-ops-15seeds`, `codeql-flow-ops-seed01`, `codeql-official-qual`, `semgrep-official-qual`, `semgrep-diverse-singles`; search `semgrep-hard30`, `codeql-hard15`, `codeql-v6-seed05-rerun` | verified from the manifests. The 5 exhaustive runs were re-executed and the manifest identity equals the saved one (scanner and version, rule or query, seed hashes, enumerated operators, `max_ops`, oracle timeout); the only difference is the toolbox size (13 operators originally, 18 now). Rerun rows equal the saved rows (candidate hash, behavior check, scan verdict, silenced rules, qualifications) for `semgrep-official-qual` (7 of 7), `codeql-flow-ops-seed01` (31 of 31, 30 evading), the first 3 seeds of `semgrep-diverse-singles` (26 of 26), the first 2 seeds of `codeql-official-qual` (2 of 2) and `codeql-flow-ops-15seeds` (225 of 225, all evading; resumed once after stopping at 135 rows). For the 3 search runs the stored configuration equals the config in `configs/` (`codeql-hard15` with `--seed-limit 1`), and their model-guided strategies are not bit-reproducible |
| Mechanism checks (`analysis/run_mechanism.sh`) | rerun from the scripts: `pysa.txt`, `pysa_callgraph.txt`, `codeql_library.txt`, `codeql_flow.txt` and `codeql_probe.txt` equal the saved files byte for byte (`codeql_probe.txt` is the one that `result.md` cites) |
| `analysis/run_all.sh` | 15 scripts (`setup`, `table3`–`table6`, `rq1`–`rq6`, `lessons`, and the 3 equivalence checks), from a different working directory: exit 0 for all; prints plain-text tables and per-claim breakdowns to `<script>.txt` with no `.tex` files generated. The scripts aggregate over every folder in `results/`, so write your own runs to `runs/` |

## Automated tests

187 tests pass, and 181 pass with 6 skipped in the Docker image, which has no `results/` (`.sastlab/.venv/bin/python -m pytest -q -p no:cacheprovider`, about 1.5 minutes). The tests cover:

- **Behavior preservation of every operator.** All 256 core masks, and every subset of the flow operators both alone and combined with all core operators, give exactly the original outputs on all 15 seeds. This is exact agreement on the oracle inputs, not a proof of general equivalence.
- **Candidate graph.** Every subset is reachable exactly once by the forward walk; masks 0 to 255 keep their meaning; out-of-range masks are rejected; operators compose.
- **Oracle.** Fixed, changed and broken programs, timeouts, and per-seed fixtures (`tests/test_harvest.py`): a seed with `SASTLAB_FIXTURE` and `SASTLAB_EXPLOIT` constants is judged on its own database and payload, rewrites keep the constants and stay equivalent, and a seed without them behaves exactly as before.
- **Scanners.** Report parsing, SARIF failures, fail-closed behavior on scanner errors.
- **Search.** Full budgets for all seven strategies, seeded replay, identical prompts for strategies 3 and 5 apart from diagnostics, Metropolis on the subset lattice, operator pools.
- **Pysa adapter** (`tests/test_pysa.py`): the typed scan copy (annotation of the first parameter only, renamed parameters, all 18 single rewrites stay parseable), issue parsing keeps only the 2 SQL rules and fails closed without the entry model, an unavailable binary gives an error scan, and a live scan inside the repository checks that Pyrefly sees only the scanned file (isolating it from the repository's `pyproject.toml` and `.gitignore`).
- **Model adapter.** Validation, retries, fallback, credential handling, 429 handling.
- **Resume and exhaustive evaluation.** Equivalence of an interrupted and resumed run with an uninterrupted one, including pool-restricted runs after the operator list grew. A failed baseline scan stops an exhaustive run, which then resumes to the same rows as an uninterrupted run; a search run with a failed baseline scan exits 1 and `--rerun-errors` repairs it; `complete` is false while any baseline scan did not finish.
- **Reporting.** Threshold, union and incomplete-budget classification.
- **Robustness and CLI checks** (`tests/test_robustness.py`): the behavior check leaves no temporary directory, also after a timeout; `rename` and `dead_padding` on a seed with an inline query; `unbound_sink` with a locally imported receiver; `report` is read-only by default; the CodeQL probe writes its own query pack; Pysa reports the same rules with and without the `sqlite3` annotation on a command and a path seed; scan-cache keys include Pysa model contents.
- **Transform, filtering, and replay edge cases** (`tests/test_edge_cases.py`): comprehension variables in `extract_*` and `rename`, `except ... as` names, docstrings kept by the flow operators, the agent's verdict and diagnostics on the target rules, `work_dir` in `exhaustive`, CodeQL's version identity without paths, `report` independent of the order of the attempts, and the replay configs of the full campaigns.
- **Saved summaries** (`tests/test_reproduction.py`): `summary.json` of every exhaustive run equals the summary recomputed from its `evaluations.jsonl`, `qualifications.json` and the enumeration in its manifest, and its `complete` flag agrees with the manifest state (`complete` ignores seeds whose baseline is not flagged, because they are never enumerated).
- **Config paths and analysis scripts** (`tests/test_reproduction.py`): every path in every config exists; the analysis scripts use repository paths and run from another directory.

The oracle was also checked against saved data: for the 30 seeds that have a saved qualification record, the current oracle returns exactly the saved outputs.

## Behavior preservation and verdict checks

The Bandit runs (`bandit-*-pairs`, 656 candidates that appear in no other run) are included in `extended_equivalence.py` and `cmd_equivalence.py` (the Bandit command-injection run adds no new candidate), with 0 differences. The rewrite-catalog and path-probe candidates are not covered.

| Check | Result |
| --- | --- |
| Extended behavior check (`extended_equivalence.py`) | all 21,264 unique SQL candidates of all saved campaigns and exhaustive runs (16,562 evading, 4,702 detected; for Pysa evading means at least 1 of its 2 rules stopped firing), including the official-seed, independent-program, deployed-project, taint-mode, newest-release, Pysa (pairs and triples) and agent runs (attempts answered from the scan cache included), regenerated from seed and operator subset and re-run on 20 inputs (empty string, quotes, unicode, a 5,000-character string, OR, UNION, numeric and double-quote payloads) and a larger database: 0 differences in rows or exceptions; 52 of the 54 baseline seed files are exploit-live under the 3 standard OR payloads and the other 2 (`a05_pyload_update_link_info`, `r06_vulpy_login`) under their own exploit strings. Candidates of the rewrite catalog and the path probe were not included |
| Independent re-scan, earlier runs | 166 candidates (130 Semgrep, 36 CodeQL), regenerated, hash-checked and scanned again: 0 disagreements |
| Independent re-scan, official-suite runs (`rescan_sample.py`) | 80 Semgrep (40 evading, 40 detected) and 30 CodeQL (15 and 15): 0 hash mismatches, 0 behavior-check disagreements, 0 verdict disagreements |
| Verdict determinism | no (seed, subset) pair received two different verdicts from the same scanner in any saved run: 12,532 distinct Semgrep pairs (pinned 1.178.0, main, varied and official seeds, `analysis/rq1.py`); 3,945 distinct CodeQL pairs on the same corpora from 26 runs (3,780 without the 2 runs of CodeQL 2.27.3), recomputed by `analysis/rq1.py` |
| Scanner and oracle errors | 0 oracle failures in every saved run; 0 scanner errors in every saved campaign and exhaustive run except `codeql-hard-qwen`, where 2 scans of `d02_str_format` (strategy 5) timed out after 120 s. They are not counted as evasions, the analyses use scanned rows only, and the run's report card is `excluded` (`complete: false`) |
| Model requests | 0 fallbacks in the two full campaigns; 79 in the later restricted runs, out of 76,045 distinct model decisions (73 with the 8B model: `semgrep-informed-8b` 37, `semgrep-rep1-8b` 25, `pysa-hard-informed-8b` 11; 6 with the 35B model: `pysa-rep1-35b`). Counted over all `results/*/llm.jsonl` records with `fallback: true` |

## Evidence integrity of the search campaigns

| Measurement | `semgrep-v6` | `codeql-v6` |
| --- | --- | --- |
| Records | 15,750 attempts | 5,250 attempts |
| Scanner errors | 0 | 0 (3 timeouts rerun) |
| Candidates not equivalent to the original | 0 | 0 |
| Model fallbacks | 0 | 0 (1,525 model records) |
| Same (seed, subset) with two verdicts | 0 of 5,563 pairs | 0 of 1,873 pairs |
| Seed hashes match current seeds | yes | yes |
| Framework file hashes match current source | no | no |

**Framework hashes across campaigns.** Because the framework was extended over the course of the experiments (shuffled operator prompts in `llm.py`, operator pools, appended operators, and per-seed fixture constants in the oracle), `framework_sha256` in early campaign manifests does not match the current source files. Evidence of consistency: the oracle returns the saved outputs for all 30 seeds with a saved record, and replaying `seed_05` strategy 1 under the current framework reproduces 145 of 150 original attempts with the same candidate hash (the 5 that differ follow a failed scan) and gives identical verdicts on all 143 shared scanned candidates.

**CodeQL campaign rerun (`seed_05`).** After the original run lost attempts to CPU throttling, the failed trajectories were rerun with a 240 s timeout. Three attempts still timed out (`seed_05`, strategy 1, trajectories 3 and 4). Both trajectories were rerun as `results/codeql-v6-seed05-rerun` (same config, restricted to the 13-operator pool) and merged into `codeql-v6`; the replaced rows are kept in `discarded-partial.jsonl` and the manifest records the merge. The report card of `codeql-v6` is complete (`weak`, exploratory). The evidence pairs `bypasses/seed_05/1089.{py,json}` and `5185.{py,json}` belong to two of the replaced rows (lines 284 and 285 of `discarded-partial.jsonl`; no row of `attempts.jsonl` has those masks for that trajectory) and are not active findings: count evasions from `attempts.jsonl`, not from the files in `bypasses/`.

## Live integration

- **SoCLaaS.** `./run.sh doctor` confirmed the key and the served models. The two full campaigns had 0 fallbacks; later runs had 79 in about 76,000 decisions (see the integrity table). HTTP 429 handling was exercised in the field during a pilot whose data was later deleted.
- **CodeQL.** The CLI came from the python-only bundle of the GitHub `codeql-bundle-v2.27.1` release; the SHA-256 (`ea86393c6c812542ae5a3a7122bcc760873707a50b25cc47d2fd7cfd514b0cb0`) matches the published asset digest, in the Dockerfile too. `codeql resolve qlpacks` lists `codeql/python-queries` 1.8.11.
- **Qualification.** All 15 main seeds are flagged by both scanners; 10 of the 12 varied seeds by CodeQL and 8 by Semgrep; of the 9 official-suite seeds, 9 by CodeQL and 7 by Semgrep.

## Pysa runs

| Check | Result |
| --- | --- |
| Scan errors and behavior-check differences in `pysa-*` runs | 0 and 0 over 4,716 rows (3,994 distinct scanned candidates) |
| Duplicate (seed, mask) rows | 0 |
| Baseline qualification | 15 of 15 main, 10 of 12 varied, 9 of 9 official seeds; both rules fire on every qualifying seed |
| Interrupted run | the pair run was killed once (session restart) and resumed from its saved rows; no duplicates |
| First launch | produced 0 qualifying seeds because every scan failed closed (no entry model); the results were deleted and the adapter fixed, which is the intended behavior of the fail-closed rule |
| Independent re-scan (`rescan_pysa.py`, fixed RNG seed) | 120 candidates (40 silent, 40 that lost 1 rule, 40 that kept both): 0 hash mismatches, 0 behavior-check disagreements, 0 differences in the set of rules that fire |
| Verdict determinism | 3,994 distinct (seed, subset) pairs, 428 scanned in 2 runs, 0 with 2 different verdicts |
| Extended behavior check | Pysa candidates included in the 21,264 above, 0 differences |

Pysa's own integration tests are listed below.

## Further checks: command injection, independent programs, further rules and prompt variants

| Check | Result |
| --- | --- |
| Pysa against its own integration tests (`scripts/validate_pysa_suite.py`, pyre-check `d5614e0a`, 33 tests with their own configuration) | 32 of 33 reproduce the expected issues exactly; `entrypoint` reports 1 extra issue (global-state rule 1006) |
| Semgrep `dangerous-subprocess-use-audit` against its own test | passes (8 expected lines, all reported) |
| Scan errors and behavior-check differences in `semgrep-real-pairs`, `codeql-real-*`, `pysa-real-pairs`, `semgrep-cmd-pairs`, `codeql-cmd-*`, `pysa-cmd-pairs`, `pysa-hard-qwen*`, `pysa-http-*` | 0 and 0 in every run |
| SQL candidates before and after generalising `transforms.py` for command injection | 6,192 candidates compared by SHA-256, 0 differences |
| Extended behavior check, SQL candidates including the independent programs (`extended_equivalence.py`) | 21,264 unique candidates (16,562 evading, 4,702 detected) on 20 inputs, 0 differences; 52 of the 54 baseline seeds are live under the 3 standard injection strings and the other 2 (`r06_vulpy_login`, `a05_pyload_update_link_info`) under their own |
| Extended behavior check, command-injection candidates (`cmd_equivalence.py`) | 1,150 distinct candidates on 12 inputs (empty, spaces, quotes, `;`, `&&`, `$(...)`, backticks, unicode, 300 characters), 0 differences. The input `it's` makes the shell exit with status 2 for the seed itself on all 8 seeds (4 raise, 4 return normally), so there the seed and its candidates are compared only on that failure; the script prints these 8 of 96 seed-input pairs and requires every candidate to start processes with the same exit statuses as its seed, so each seed is compared on 11 working inputs |
| Independent re-scan, Semgrep (`rescan_sample.py`) | cmd 25 + 25 and real 25 + 25: 0 hash mismatches, 0 behavior disagreements, 0 verdict disagreements |
| Independent re-scan, CodeQL | cmd 8 + 8 and real 8 + 8: 0 and 0 and 0 |
| Independent re-scan, Pysa (`rescan_pysa.py`, 25 silent, 25 lost 1 rule, 25 kept all, from 1,942 candidates of `pysa-real-pairs` and `pysa-cmd-pairs`) | 0 hash mismatches, 0 behavior disagreements, 0 differences in the set of rules that fire |
| Semgrep taint mode (`semgrep-taint-*`; stock rule, 4,462 candidates) | 0 scan errors, 0 behavior differences; covered by the extended behavior check above; independent re-scan 25 + 25 on the main seeds and 25 + 25 on the official seeds: 0 hash mismatches, 0 behavior disagreements, 0 verdict disagreements |
| Newer releases (`semgrep-latest-*`, `codeql-latest-*`) | Semgrep 1.182.1: same verdict as 1.178.0 on 392 identical single-rewrite candidates. CodeQL 2.27.3 (zip SHA-256 equals GitHub's digest) with python-queries 1.8.13: 428 candidates, 0 errors, evading iff a flow-changing rewrite is present, re-scan 8 + 8 on each corpus (see result.md) |
| Pysa agent prompt variants (`pysa-hard-informed*`, `pysa-hard-any*`) | 0 scan errors in every run; the original-prompt run is reproduced exactly by the random strategy of the new runs (15 of 45 streams, same mean 13.33), which checks that the seeds and pool are unchanged |
| Semgrep `path-traversal-open` and `tainted-sql-string` against their own tests | both pass (12 of 12 expected lines each; `validate_semgrep_suite.py <rule>`) |
| CodeQL `py/command-line-injection` and `py/path-injection` against their own tests | match (13 of 13 and 21 of 21 expected alerts; `validate_codeql_suite.py cmd|path`) |
| Transform change for builtin sinks | 12,058 distinct logged candidates regenerated and compared by SHA-256 (`scripts/check_candidates_unchanged.py`), 0 differences before and after |
| Informed-prompt arms (`semgrep-informed-*`, `codeql-informed-*`, `pysa-hard*-informed*`) | 0 scan errors; random and heuristic baselines come from the original runs on identical streams (the random arm of the new Pysa runs reproduces the original 15 of 45 and mean 13.33 exactly) |
| `seeds_path` (path traversal, 8 seeds, `semgrep-path-pairs`, `codeql-path-*`, `pysa-path-pairs`) | all exploitable under the oracle; 0 scan errors and 0 behavior differences |
| `corpus_apps` (5 functions from 3 deployed projects) | all exploitable under the oracle; 0 scan errors and 0 behavior differences in `semgrep-apps-pairs`, `semgrep-taint-apps-pairs`, `codeql-apps-*`, `pysa-apps-pairs` |
| Pysa triples (`pysa-triples`) | 1,510 candidates, 0 errors, 0 behavior differences |
| Independent re-scans of the informed-prompt, path-traversal and deployed-project runs | Semgrep path 25 + 25 and apps 25 + 25, CodeQL path 8 + 8 and apps 8 + 8, Pysa 25 per class from 2,812 candidates of `pysa-path-pairs`, `pysa-apps-pairs` and `pysa-triples`: 0 hash mismatches, 0 behavior disagreements, 0 verdict or rule-set disagreements |
| Stock-source check (`pysa-http-*`) | 576 candidates, same rules everywhere |
| Mechanism checks (`mechanism_pysa.py`, `mechanism_codeql.py`, `mechanism_codeql_flow.py`) | alert restored by added models for 2 Pysa and 4 CodeQL rewrite types, 6 tool-and-rewrite pairs (2 or 3 entries each), on `seed_01` (the CodeQL library rows also on one official program); `deep_nest` stops alerting at depth 6; the sink-resolution rewrites leave no sink node or call-graph edge, and `unbound_sink` is read as a bound call (the probe in `pysa.txt` section 3). Outputs are saved in `results/mechanism/`. No claim for the other cases; no maintainer has confirmed any finding |

Integrity notes: the first Pysa command-injection run qualified 0 seeds because of a wrong rule code and was deleted and repeated; one CodeQL scan timed out under load and was re-evaluated (`discarded-timeouts.jsonl`). Search runs `pysa-hard-qwen*` have no timing claim because other work shared the machine.

## What remains unverified

- **Real-world validity.** The 5 programs of `corpus_apps` are functions copied from vulnerable releases of 3 projects (Parsl, SciTokens, pyLoad) with database access replaced by a cursor on the oracle's SQLite connection; no full application or CI pipeline was tested. The other seeds are synthetic or adapted from test suites and training applications, and the official-suite seeds keep the query construction of the tests but not their database libraries.
- **Code provenance of the early campaigns.** See the "Framework hashes across campaigns" note above.
- **Mechanisms.** The mechanism checks cover 5 rewrite types and 6 tool-and-rewrite pairs on 1 or 2 seeds, plus the sink-node listing and the depth limit of `deep_nest` on CodeQL and the call-graph entries on Pysa. The other evasions were found by the catalog and the exhaustive runs and their cause was not investigated. No maintainer has confirmed any finding.
- **Model identity.** SoCLaaS exposes no weight digest, and the size of `qwen3-coder-next` is not reported.
- **General equivalence.** Equivalence is established on 2 inputs during the campaigns and on 20 inputs afterwards, not for all inputs.
- **Disclosure.** Nothing has been reported to the Semgrep or CodeQL maintainers.

## Path-traversal, command-injection and cache checks

| Check | Result |
| --- | --- |
| Path-traversal candidates (`path_equivalence.py`) | 890 distinct candidates of the 4 `*-path-*` runs regenerated and run on 14 inputs (existing and missing names, traversal strings, a null byte, a 300-character name): 0 differences; `../secret` returns the secret file on 7 of 7 baseline seeds |
| Command-injection candidates (`cmd_equivalence.py`) | 1,150 distinct candidates on 12 inputs (11 of them run a working command: the shell rejects `it's` for every seed): 0 differences |
| Regeneration of every logged candidate (`scripts/check_candidates_unchanged.py`, including `seeds_path`) | 13,832 distinct logged candidates, 0 without a seed file, 0 SHA-256 differences |
| Independent re-scan of logged search attempts (`rescan_attempts.py`, fixed RNG seed, no cache) | 228 attempts from 15 agent runs: Semgrep 100 (5 runs), Pysa 96 (6 runs), CodeQL 32 (4 runs); 147 of them were answered from the persistent scan cache in the original run; 0 SHA-256 mismatches, 0 verdict or rule-set disagreements |
| Scan cache (`scan_cache` config key) | key = hash of the scanner settings; a second identical run gave 8 of 8 cache hits and identical verdicts (`tests/test_extensions.py`); the attempt accounting is unchanged |

## Bandit

`tests/test_bandit.py`: report parsing fails closed (parse errors, missing `subject.py`), and a live check that Bandit flags `seeds/seed_01.py` with B608 and `literal_slice` silences it (skipped without `.sastlab/bandit-venv`). Exhaustive runs of all singles and pairs on 6 corpora: 7,700 candidates, 0 scan errors, 0 behavior differences. `rescan_sample.py` on every run (40 evading and 40 detected each): 0 hash mismatches and 0 disagreements. `scripts/reproduce.sh` has a one-seed Bandit smoke scan (`check_smoke.py` requires exactly `literal_slice` to silence B608). Bandit was not validated against its own test suite; its rule behavior is checked only through the candidates above.
