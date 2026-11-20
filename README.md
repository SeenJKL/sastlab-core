# SASTLab

SASTLab tests whether static application security testing (SAST) scanners keep flagging a vulnerable Python program after harmless edits. It takes a program that a scanner flags and that is exploitable, applies behavior-preserving rewrites, checks by execution that the exploit still works, and reports the rewrites after which the scanner goes silent. Each such case is a false negative of that rule.

- **4 scanners:** Semgrep, CodeQL, Pysa and Bandit, each tested on its own rules.
- **3 vulnerability classes:** SQL injection, command injection and path traversal.
- **18 rewrite operators**, applied as deterministic AST transformations. No model writes code.
- **7 search strategies** choose which rewrites to try next. Three of them ask a language model to pick an operator name from a fixed list.

![Overview of the testing loop: the search strategy picks the next operator, the rewrite toolbox builds a candidate from the seed, and the scanner and the behavior check decide whether it is an evasion](docs/overview.png)

An evasion needs a scan that succeeded, unchanged behavior on the tested inputs, and silence from the rule that fired on the seed.

## What it found

An evasion means the tested rules of one scanner stopped firing on a program that behaves the same on the tested inputs. It is a false negative under this harness, not an attack success rate. Numbers and per-corpus detail are in [result.md](result.md), and every saved run is listed in [results/INDEX.md](results/INDEX.md).

| Scanner and rule (SQL injection) | What silences it |
|---|---|
| Semgrep `formatted-sql-query` (pattern rule) | Rewrites that move the query or the call out of the rule's pattern: `extract_1`, `extract_2`, `branch_split`, `dict_dispatch`, `dynamic_sink`. `literal_slice` works only on queries built with `.format()` or `%`, or together with `format_swap` on f-strings. |
| CodeQL `py/sql-injection` (data-flow query) | Any one of 9 flow-changing rewrites: `dynamic_sink`, `char_launder`, `deep_nest`, `db_roundtrip`, `simplequeue_roundtrip`, `pickle_roundtrip`, `partial_sink`, `methodcaller_sink`, `unbound_sink`. A candidate evades if and only if it contains one of them; the 4 control rewrites alone never do. |
| Pysa rules 5005 and 5051 | A round trip through a database or a `SimpleQueue` (`db_roundtrip`, `simplequeue_roundtrip`), or a pair of rewrites: one that hides the call plus `literal_slice`. Each rewrite of the pair removes one of the two rules. |
| Bandit `B608` | `literal_slice`, or `format_swap` on a query built with `+`. |

For command injection and path traversal the rules match the call and not how the string is built, so the restructuring rewrites do not evade there; rewrites that hide the call do for Semgrep and Pysa, and the flow-changing rewrites do for CodeQL. Whether a language-model agent finds evasions faster than random choice depends on the model, the scanner and the prompt; no model wins everywhere.

## Environment

The code was developed and run on the setup below, and the commands in this README were tested on it from a fresh clone. All 110 saved manifests record Linux x86-64 with glibc 2.43.

| | |
|---|---|
| Operating system | Ubuntu 26.04 LTS, Linux 7.0, x86-64 |
| Hardware | virtual machine (KVM) with 2 vCPUs of an AMD EPYC 9354P, 7 GB RAM, 96 GB disk |
| Python | 3.14 |
| Tools | `curl` and `zstd` (to unpack CodeQL), Docker 29.8 (only for the image), `systemd-run --user` (only for the CPU cap, see below) |
| Network | needed to install the scanners and for the model runs; scanning itself runs offline (Semgrep is started with metrics and the version check off, and uses the local rule files) |
| Disk | scanners and virtual environments about 0.9 GB; `results/` 0.5 GB; raw scanner output in `.sastlab/runs/` grew to about 7 GB over all experiments |
| Time | one scan takes a few seconds, CodeQL 14 s at the median and 19 s on average (the slowest of the 5,250 scans of `codeql-v6` took 196 s); `exhaustive --max-ops 1` on one seed is 18 scans (under 2 minutes for Bandit and Pysa, about 10 minutes for CodeQL); the Docker test run takes about 2 minutes; the full campaigns take hours |

Not tested: macOS, Windows and ARM machines. The CodeQL bundle in step 1 is for Linux x86-64 only. The framework itself uses only the standard library, so a machine with its own CodeQL, Semgrep, Pysa and Bandit of the same versions should work, but this was not tried.

## Quick start

Unpack the zip with `unzip` so that `run.sh` stays executable. Python's `python3 -m zipfile -e` drops the executable bit; then run `chmod +x run.sh` once (or start a script as `sh run.sh ...`).

### 0. Read the saved results (no installation)

The saved runs need no scanner and no key to read:

```sh
less results/INDEX.md                          # every run folder: scanner, kind, seeds, records, evading count, state
python3 -m sastlab report results/semgrep-v6   # report card of a search run, recomputed from its attempts.jsonl (read-only)
```

Exhaustive runs (`*-singles`, `*-pairs`, `*-triples`) keep one verdict per rewrite set in `evaluations.jsonl`, and their counts in `summary.json`.

### 1. Install the scanners

With Docker (pins everything):

```sh
docker build -t sastlab .
docker run --rm sastlab        # the test suite, no API key needed (about 2 minutes, after the build)
```

Without Docker, from the repository root (the same steps as the `Dockerfile`):

```sh
python3.14 -m venv .sastlab/.venv       && .sastlab/.venv/bin/pip install -r requirements.lock         # Semgrep 1.178.0, pytest
python3.14 -m venv .sastlab/pysa-venv   && .sastlab/pysa-venv/bin/pip install -r requirements-pysa.lock   # Pysa (pyre-check 0.10.0)
python3.14 -m venv .sastlab/bandit-venv && .sastlab/bandit-venv/bin/pip install -r requirements-bandit.lock  # Bandit 1.9.4
# CodeQL CLI 2.27.1 with the Python query pack 1.8.11 (bundle from github/codeql-action; SHA-256 in the Dockerfile)
mkdir -p .sastlab/tools && curl -fsSL -o /tmp/codeql.tar.zst \
  https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.1/codeql-bundle-python-linux64.tar.zst \
  && zstd -dc /tmp/codeql.tar.zst | tar -x -C .sastlab/tools
```

The framework itself uses only the standard library. `./run.sh` uses `.sastlab/.venv` when it exists and `python3` otherwise, and finds the scanners under `.sastlab/`. `run.sh` also caps the CPU at 85 % with `systemd-run --user`. On a machine without it (macOS, most containers, a Linux without a user session) `run.sh` stops with exit code 3 until you run `export SASTLAB_CPU_LIMIT=0`, which turns the cap off (the Docker image sets it).

### 2. Run without a model

Strategies 1, 2, 6 and 7 and every `exhaustive` run need no API key:

```sh
./run.sh transform seeds/seed_01.py --mask 5 --output candidate.py      # one candidate: rename + literal_slice
./run.sh run --config configs/smoke.json --output runs/my-smoke --strategies 1 2 6 7 --attempts 3 --trajectories 1 --seed-limit 1
./run.sh exhaustive --config configs/semgrep-official.json --output runs/my-first --seed-limit 1 --max-ops 1     # 18 scans, a few minutes
```

`transform` prints the behavior check of the candidate it writes. Each `--output` folder must be new. Write your own runs to `runs/` (ignored by git): `results/` is for the saved runs.

### 3. Run with a model (strategies 3, 4 and 5)

Copy `.env.example` to `.env` and set `SOCLAAS_API_KEY`, or export it. The configs call the NUS SoCLaaS gateway (`https://soclaas-api.comp.nus.edu.sg/v1`, OpenAI-compatible chat completions) with `llama3.1:8b`, `qwen3-coder-next` and `qwen3.6:35b`. That gateway was the only endpoint used, and the models are not pinned by digest. The key is read from the file without executing it and is sent only in the `Authorization` header; it never appears in manifests or logs.

```sh
./run.sh doctor                                   # key works, model is served, scanner paths
./run.sh run --config configs/semgrep.json --output runs/my-semgrep --attempts 3 --trajectories 1 --seed-limit 1
```

## Commands

| Command | Does |
|---|---|
| `run --config C --output D` | search campaign: every strategy in the config, on every qualifying seed. Options: `--attempts`, `--trajectories`, `--seed-limit`, `--strategies`, `--resume`, `--rerun-errors`, `--scanner-timeout` |
| `exhaustive --config C --output D --seed-limit N` | scans every non-empty subset of the operators (`--operators ...`, `--max-ops K`), no search, no model. This is the ground truth the strategies sample from. 18 operators give 262,143 subsets per seed, so restrict them. |
| `transform SEED --mask M` | builds one candidate. Bit `i` of the mask is the `i`-th operator in the table below. |
| `report D [--write]` | recomputes the summary of a search run from the recorded attempts and prints it; `--write` also overwrites `summary.json` in `D` (the default leaves the folder untouched) |
| `doctor [--config C]` | asks the gateway for its model list (so it needs the key and network access), checks that the config's model is served, and prints where the 4 scanners were found |

`run --resume` and `exhaustive --resume` continue an interrupted run in the same folder with the same config. A trajectory counts as done only when all its attempts are recorded; an incomplete one is rerun from scratch, so no walk mixes two runs. A baseline scan that does not finish (for example a timeout on a cold first scan) is not treated as "seed not flagged": `exhaustive` stops with an error and `--resume` continues; `run` finishes the other seeds, names the seeds without a verdict and exits 1, and the same command with `--rerun-errors` repairs them. Scans take from a few seconds to about 25 s each (CodeQL is the slowest), so a full campaign takes hours.

### Configuration

One JSON file per experiment in `configs/`. `seeds`, `rules`, `pysa_models` and the `llm` env file are relative to the config's folder; `scan_cache`, `work_dir` and `executable` are relative to the working directory, so run `./run.sh` from the repository root.

| Key | Meaning |
|---|---|
| `engine` | `semgrep`, `codeql`, `pysa` or `bandit` |
| `seeds` | folder of seed programs |
| `rules` (Semgrep), `query` (CodeQL, version-pinned pack), `target_rules` | what is scanned for and which rule IDs count |
| `attempts`, `trajectories`, `base_seed`, `strategies` | budget per trajectory, number of trajectories (the trajectory seed is `base_seed + k`), strategies 1 to 7 |
| `operators`, `order` | restrict the operator pool; `increasing` (default) or `any` order of addition |
| `evasion` | `any` (default: one qualifying rule stops firing) or `all` (none of them fires, used for Pysa) |
| `metropolis_restart` | `true` (default, and every saved run except the two walk checks): strategies 6 and 7 restart from the seed when the current subset holds the last operator of the order; `false`: every proposal toggles one operator of the current subset (`configs/*-walk.json`) |
| `llm` | endpoint, model, `temperature` (0.2), `max_prompt_tokens` (2,500), `prompt_extra` (text appended to the system prompt) |
| `diagnostic_fields` | which of `rule`, `message`, `sink`, `snippet`, `trace` the diagnostic agent sees (default: all) |
| `pysa_models`, `pysa_source`, `semgrep_route` | Pysa taint models and source model; a Flask route for Semgrep taint rules |
| `scan_cache`, `keep_database`, `scanner_timeout`, `oracle_timeout` | scan cache folder, keep CodeQL databases, time limits in seconds |
| `work_dir` | folder for the per-attempt scan files (default `.sastlab/runs`); a Semgrep scan inside a large git checkout is slower, with the same findings |

## How it works

### Operators

Applied at most once each, in a fixed order, always to the original seed, so a candidate is identified by its operator subset (and its SHA-256). New operators were appended, so old mask numbers keep their meaning. An operator that does not fit a seed (for example `format_swap` on a query built with `%`) is rejected and counts as a failed attempt.

| Group | Operators (in mask order) | Change |
|---|---|---|
| Controls | `rename`, `format_swap`, `literal_slice`, `dead_padding` | leave the source-to-sink flow unchanged |
| Interprocedural and control flow | `extract_1`, `extract_2`, `branch_split` | build the query in helper functions, or in both branches of a condition |
| Sink resolution | `dict_dispatch`, `dynamic_sink`, `partial_sink`, `methodcaller_sink`, `unbound_sink` | call the sink through a dict, a computed attribute name, `functools.partial`, `operator.methodcaller` or an unbound method |
| Value propagation | `char_launder`, `pickle_roundtrip` | rebuild the input character by character; serialize and read it back |
| Containers | `deep_nest`, `queue_roundtrip`, `simplequeue_roundtrip` | box the input in 8 nested lists; pass it through a queue |
| Second-order storage | `db_roundtrip` | store the input in a SQLite table and read it back |

In mask order the list is `rename`, `format_swap`, `literal_slice`, `dead_padding`, `extract_1`, `extract_2`, `branch_split`, `dict_dispatch`, `dynamic_sink`, `char_launder`, `deep_nest`, `db_roundtrip`, `queue_roundtrip`, `simplequeue_roundtrip`, `pickle_roundtrip`, `partial_sink`, `methodcaller_sink`, `unbound_sink`. The search campaigns used the first 13; the last 5 were evaluated by exhaustive enumeration. The sink-resolution operators rewrite `execute` on a cursor, six `subprocess` functions, `os.popen` and the builtin `open`; `methodcaller_sink` and `unbound_sink` do not apply to `open`, and `unbound_sink` does not apply to module functions such as `subprocess.run`. Details and rationale: [docs/methodology.md](docs/methodology.md).

### Search strategies

| # | Strategy | Chooses the next operator by |
|---|---|---|
| 1 | Random | uniform choice |
| 2 | Heuristic | unseen candidates first, then rarely used operators, then operators that earlier gave a silent verdict (verdicts only) |
| 3 | History-only agent | a model, from the diff to the seed, the verdict, the last 3 steps and the available operators |
| 4 | Static ranking | a model, asked once per trajectory to rank all operators from the rule description |
| 5 | Diagnostic agent | as 3, plus the scanner's rule ID, message, line, snippet and (CodeQL) finding path |
| 6 | Metropolis, syntax | toggles one operator and accepts the move with probability min(1, e^(Δd/τ)), τ = 0.25, d = normalized AST edit distance from the seed |
| 7 | Metropolis, depth | the same, with d = the longest chain of calls to functions of the same file from the entry function, and the syntax distance on ties |

Strategies 1 to 5 extend a walk by one operator at a time in increasing operator order and restart from the seed when none is left (a restart costs no attempt). Strategies 6 and 7 toggle one operator on or off, so they can reject moves. With the default `metropolis_restart`, used by every saved run except `semgrep-hard30-walk` and `pysa-hard-walk`, they also restart from the seed when the current subset holds the last operator of the order; the saved runs log these attempts with `restarted: false` (a `parent_mask` that is not the last accepted subset shows them), and the runner now logs them as restarts. A model call returns JSON constrained by a schema: one operator name, or a permutation for strategy 4. An invalid answer is retried twice, then replaced by a uniform random choice (79 of about 76,000 decisions in the saved runs). Operator lists and definitions in the prompt are shuffled per request. HTTP 429 responses wait and retry without using those retries. Prompts are in [docs/prompts.md](docs/prompts.md).

### Behavior check

Every candidate and its seed run in a separate process against a fresh in-memory SQLite database (SQL), with a nominal input and an injection input. A seed is exploitable when the injection returns more items than the nominal input; a candidate must return the seed's output on both. The injection input is `1' OR '1'='1` unless the seed defines its own `SASTLAB_EXPLOIT` (and `SASTLAB_FIXTURE` for its tables); command seeds use `1; echo PWNED`, path seeds `../secret`. Afterwards the saved candidates were rerun on 20 inputs (SQL), 12 (command) and 14 (path) with no difference. The check compares outputs on the tested inputs only; it is not a proof of equivalence. Worker processes isolate time and state but are not a security sandbox: run only trusted programs.

### Scanners and rules

| Class | Semgrep 1.178.0 | CodeQL 2.27.1 (python-queries 1.8.11) | Pysa (pyre-check 0.10.0) | Bandit 1.9.4 |
|---|---|---|---|---|
| SQL injection | `formatted-sql-query`; taint mode `tainted-sql-string` | `py/sql-injection` | 5005 and 5051 | `B608` |
| Command injection | `dangerous-subprocess-use-audit` | `py/command-line-injection` | 5001 and 6065 | `B602` |
| Path traversal | `path-traversal-open` | `py/path-injection` | 5011 | none |

Rule snapshots are in `rules/` (provenance next to each); Pysa uses the stock models of pyre-check commit `d5614e0a` copied unmodified to `third_party/pysa-models/`. A seed qualifies for a rule only if the rule fires on it and the exploit works. A scan that times out or fails is never counted as an evasion.

### Seeds

Each seed defines one top-level `get_user_profile(db_conn, user_id)` that builds a query, command or path from its argument and uses it, and returns a list.

| Folder | Seeds | Origin |
|---|---|---|
| `seeds/` | 15 | synthetic, f-string query, one shared structure |
| `seeds_diverse/` | 12 | synthetic, other query constructions |
| `seeds_fstring/` | 3 | f-string seeds of the restricted Semgrep searches |
| `corpus_official/seeds/` | 9 | adapted from the Semgrep and CodeQL test suites (from 122 `.execute` sites) |
| `corpus_real/seeds/` | 6 | OWASP BenchmarkPython (5), vulpy (1) |
| `corpus_apps/seeds/` | 5 | vulnerable releases of parsl, SciTokens and pyLoad |
| `seeds_cmd/`, `seeds_path/` | 8 + 8 | synthetic command injection and path traversal |
| `seeds_pysa_hard/`, `seeds_pysa_hard2/`, `seeds_rerun_s05/` | 3, 3, 1 | subsets used for the Pysa searches and one rerun |

## Repository layout

| Path | Content |
|---|---|
| `sastlab/` | the framework: operators (`transforms.py`), search strategies (`search.py`), behavior check (`oracle.py`, `oracle_worker.py`), scanner harness (`scanners.py`), run loop (`runner.py`), exhaustive enumeration (`exhaustive.py`), model client (`llm.py`), report cards (`report.py`), command line (`cli.py`) |
| `configs/` | one JSON config per experiment |
| `seeds*/`, `corpus_*/` | the seed programs (table above) |
| `rules/`, `third_party/` | the Semgrep rules and the stock Pysa models, unmodified |
| `results/` | the saved output of every run and check, with an index (`results/INDEX.md`) |
| `tests/`, `docs/` | unit tests; methodology, validation and prompts |

## Saved results

`results/` holds the output of every run and check behind the findings, one folder each. [results/INDEX.md](results/INDEX.md) lists all of them with scanner, kind, number of seeds, records and evading candidates. Names read `<scanner>-<corpus>-<kind>`, where the corpus is `main`, `diverse`, `official`, `real`, `apps`, `cmd` or `path` (the seed folders above):

| Folder pattern | Content |
|---|---|
| `semgrep-v6`, `codeql-v6` | the full campaigns: 7 strategies, 30 attempts, 5 trajectories; 15 seeds for Semgrep, 5 for CodeQL |
| `*-promptfix` | reruns with the operator definitions shuffled in the prompt |
| `*-hard*` | restricted-pool searches, where only a few operator sets evade |
| `*-informed-*`, `*-more-*`, `*-rep1-*`, `*-rep2-*` | agent runs with an informed prompt, extra CodeQL streams, and repeats with two other base seeds |
| `*-abl-*` | which part of the scanner message the diagnostic agent sees |
| `*-singles`, `*-pairs`, `*-triples` | exhaustive evaluations of every subset of 1, 2 or 3 operators; `*-nonflow-pairs`: pairs of operators that leave the flow unchanged |
| `*-taint-*`, `*-latest-*`, `pysa-http-*` | Semgrep taint mode; newest scanner releases; Pysa with a stock source model |
| `mechanism`, `official-validation`, `codeql-rewrite-catalog`, `prompt-order-probe` | explanation checks, validation against the scanners' own tests, hand-written rewrites, a prompt-order probe |

`manifest.json` records each run's configuration, hashes, versions and platform. The manifests also record the absolute paths of the machine that produced them, and `framework_sha256` is the hash of each framework file when the run started (the code has been edited since, so these hashes do not match the current files). Write new runs to new folders and do not `--resume` a saved one.

Files in a run folder:

| File | Content |
|---|---|
| `manifest.json` | configuration, scanner and model identity, hashes of rules, seeds and framework, state, resume history |
| `qualifications.json` | which seeds qualify for which rule |
| `attempts.jsonl` | one record per attempted candidate (`run`) |
| `evaluations.jsonl` | one record per scanned subset (`exhaustive`) |
| `llm.jsonl` | every model request and response, token counts, retries and fallbacks |
| `trajectories.json`, `summary.json` | the walks; per-rule results and strategy measurements |
| `bypasses/<seed>/<mask>.py` and `.json` | each evading candidate and its scanner and behavior evidence |

Raw scanner reports go to `.sastlab/runs/` (not committed). Delete that folder when you no longer need the raw reports; it grew to about 7 GB over all experiments.

## Tests

```sh
PYTHONDONTWRITEBYTECODE=1 .sastlab/.venv/bin/python -m pytest -q -p no:cacheprovider     # 182 tests, about 2 minutes
```

They check that every operator subset the tests cover preserves the behavior on all seeds, canonical candidate identity, scanner failure handling, seeded replay, trajectories, Metropolis rejection, feedback isolation, model validation and fallbacks, resume equivalence and the Pysa integration.

## Limits

- Most seeds are synthetic. The 15 in `seeds/` share one structure, so they behave like one program. Only `corpus_official`, `corpus_real` and `corpus_apps` were not written for this study, and they keep each program's query construction but not its database library.
- The behavior check covers the tested inputs, and `db_roundtrip` would not preserve lone surrogate characters, which none of the inputs contain.
- The Pysa result holds for its stock models and this setup, in which the connection parameter is annotated and the entry parameter is declared a source.
- Python only; 3 vulnerability classes; the rules in the table above.
- Model-guided runs are close to deterministic at temperature 0.2 but not identical, and the gateway does not publish model digests, so strategies 3 to 5 may give different numbers on a rerun. Runs without a model are seeded and should reproduce for the same scanner versions and `base_seed`.

## Documentation and licences

- [docs/methodology.md](docs/methodology.md): design decisions, seed contract, operator and metric definitions, report-card rules.
- [docs/validation.md](docs/validation.md): how the setup and the results were checked.
- [docs/prompts.md](docs/prompts.md): the exact agent prompts.
- [result.md](result.md): the results of the experiments by topic, with numbers.
- [results/INDEX.md](results/INDEX.md): every saved run folder with its outcome counts.
- [THIRD_PARTY.md](THIRD_PARTY.md): origin and licence of the vendored rules, models and adapted programs.

The code is under the MIT licence ([LICENSE](LICENSE)); the third-party material keeps its own licences.
