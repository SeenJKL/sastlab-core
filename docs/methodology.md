# Methodology and design decisions

This document records how the framework works and why it is built this way: the design decisions, the seed contract, the operators, the search strategies, the model interface and the report-card rules.

## Design decisions

1. **Model serving.** Decisions come from `llama3.1:8b` on NUS SoCLaaS (an OpenAI-compatible chat-completions API), not a model pinned by weight digest. SoCLaaS exposes no digest, so model identity is recorded as unverified.
2. **Operator set.** The first eight operators (the core operators) only restructure code and keep the data flow intact. Five *flow* operators were added (`dynamic_sink`, `char_launder`, `deep_nest`, `db_roundtrip`, `queue_roundtrip`) after exhaustive search with the core eight found no evasion of CodeQL on three seeds (765 candidates). The candidate space grew from 256 to 8,192 subsets per seed. Five more operators (`simplequeue_roundtrip`, `pickle_roundtrip`, `partial_sink`, `methodcaller_sink`, `unbound_sink`), suggested by a catalog of 59 hand-written rewrites, bring it to 18 operators and 262,144 subsets per seed. New operators are appended, so earlier mask numbers keep their meaning. The search campaigns use the first 13 operators; the last 5 are evaluated by exhaustive enumeration.
3. **Metric search (strategies 6 and 7).** In forward-only walks every move adds an operator, so both distance metrics only increase and Metropolis never rejects a move: the two strategies degenerated into random walks and produced identical walks. They now toggle one operator on or off, which lets a move lower the metric and be rejected. As implemented, they also restart from the seed, like strategies 1 to 5, when the current subset holds the last operator of the order; this was found after the runs and is now the config key `metropolis_restart` (default `true`, so the saved runs replay; see [results](../result.md#metropolis-restarts)).
4. **Operator presentation order.** The order in which operator names are shown to the model is shuffled per call (strategies 3 and 5) or per trajectory (strategy 4), because the model echoed the canonical order for the static ranking and over-chose the first-listed operator. The operator definitions in the system prompt are shuffled too (`sastlab/llm.py`). The full campaigns `semgrep-v6` and `codeql-v6` used one fixed definition order (`rename` first, in all requests), and `semgrep-promptfix` and `codeql-promptfix` repeat strategies 3 and 5 with shuffled definitions (75 distinct orders). The static ranking (strategy 4) of the full campaigns was not rerun. The restricted searches and pilots use the shuffled prompt.
5. **Primary comparison metric.** The full campaigns use distinct evading candidates per trajectory, because attempts to the first evasion saturate when one operator suffices. That measure rewards walks to larger masks, so strategies are also compared by attempts to the first evasion on restricted operator pools, with a paired bootstrap over streams (see [results](../result.md)); the distinct-evasion measure remains in the run summary.
6. **Exhaustive evaluation.** An `exhaustive` command evaluates all subsets of chosen operators with no search, as ground truth for what the strategies can find.
7. **Budgets.** The full campaigns use 30 attempts and 5 trajectories per seed. Some campaigns use a reduced budget or fewer seeds to fit the available time (a CodeQL scan took 14 s at the median and 19 s on average in `codeql-v6`, 196 s at most, so the CodeQL campaign has 5 seeds). Such runs are labeled incomplete or partial wherever they are reported.
8. **Operational additions with no effect on the design:** trajectory-level checkpoint and resume, 429 rate-limit handling, and deletion of CodeQL databases after analysis.
9. **Toolbox grouping.** The 18 operators are grouped by the part of a taint analysis they stress (`TAXONOMY` in `sastlab/transforms.py`).
10. **Models.** Besides `llama3.1:8b`, the restricted searches use `qwen3-coder-next` and `qwen3.6:35b` on SoCLaaS.
11. **Seed corpus.** Seeds are harvested from the official Semgrep and CodeQL test suites in addition to the synthetic fixtures. The harvest script is not part of this repository; its output is `corpus_official/seeds/` (see below). The Semgrep rule under test is the upstream `formatted-sql-query`, and its own test file is the official suite for it.
12. **Per-seed oracle fixture.** A seed may define the module constants `SASTLAB_FIXTURE` (SQL that creates and fills its tables) and `SASTLAB_EXPLOIT` (the injection string). The worker uses them when present and the original `users` table and quoted payload otherwise, so earlier seeds and results are unchanged.

## Seed contract

Each Python source defines one top-level `get_user_profile(db_conn, user_id)` function with two positional parameters. It returns rows from the provided SQLite connection. A top-level assignment constructs the query, and `.execute(query)` uses that assigned variable. Supported formatting is an f-string without a format specification, or string concatenation. A seed that writes the query inline at the call, such as `.execute(f"...")`, has no such assignment: `rename` and `dead_padding` still apply to it, and the operators that rewrite the query expression (`format_swap`, `literal_slice`, `extract_1`, `extract_2`, `branch_split`) reject it, which is recorded as an invalid attempt and not as an evasion. The seed must not use reserved `_mt_` names or contain nested function scopes in the entry point. Imports needed by additional trusted benchmark programs must be installed in the worker's Python environment.

The default database has three rows: `(1, alice, admin)`, `(2, bob, user)`, and `(3, carol, user)`, with all fields stored as text (a seed can carry its own fixture and exploit string, see decision 12). Baseline qualification requires one nominal row and more rows from the exploit, with the nominal row present in the exploit output. Every candidate must produce exactly the seed's two row lists, including order and projected values. An oracle exception or timeout is an infrastructure failure; successful unequal results are a rejected mutation.

The scanner sees `subject.py` and a generated `web_entry.py`. The latter contains a Flask route calling the entry function with `request.args.get('id', '1')`. The oracle executes only `subject.py`; Flask is not a runtime dependency for the SQLite oracle. The same wrapper is supplied to every candidate and scanner invocation.

## Third analyzer: Pysa

Pysa was chosen as the third analyzer because it is a taint analyzer like CodeQL and appears in the closest related work (TaintCC), while Bandit's B608 is a pattern rule like Semgrep's. Exhaustive checks only: all single rewrites (34 qualifying seeds) and all pairs of the 18 rewrites (24 main and official seeds), no search and no model. Definitions: a seed qualifies when both stock SQL rules (5005 flow, 5051 string-combine) fire on it and the exploit stays live; a candidate is silent when neither fires; each rule is also reported separately. Configuration choices that are ours and not Pysa's defaults: the connection parameter of the entry function is annotated `sqlite3.Connection` in a scan-only copy (the stock sink is resolved from types), the second parameter is declared a `UserControlled` source in a per-candidate model file (no stock Flask source), `--no-verify` skips verification of models for libraries that are not installed, and no Flask wrapper is used. The models are the stock files at pyre-check commit `d5614e0a`, unmodified (`third_party/pysa-models/`).

## Command injection, independent programs and evasion modes

- **Second vulnerability class.** CWE-78 (command injection) was chosen because the stock rules of all three analyzers exist and the oracle needs no change. CWE-79, CWE-295 and CWE-200 (the other classes of the CodeBreaker benchmark) were not done: each needs its own execution check of the exploit, such as a rendered-HTML check or a local HTTPS server with a bad certificate. The 8 seeds in `seeds_cmd` keep the entry function `get_user_profile(db_conn, user_id)` and return the output lines of an `echo` command, so nominal input `1` gives 1 line and the seed's `SASTLAB_EXPLOIT` `1; echo PWNED` gives 2. The sink-resolution rewrites match the `subprocess` functions listed in `SINK_NAMES` (`transforms.py`), `unbound_sink` is rejected for module receivers, and the SQL candidates are unchanged (6,192 compared by hash before and after).
- **Independent programs.** `corpus_real` has 6 programs adapted by hand (not by the harvester, because the BenchmarkPython flows pass through method calls with side effects that a straight-line slice drops): replaced request access, connection helper and response code, kept the code that carries the value. Each seed's docstring records the origin and the change.
- **Evasion for several rules.** `evasion: all` in a search config counts an attempt only when none of the qualifying rules fires (default `any`, unchanged). Exhaustive runs record both views through `scan_rules`.
- **Pysa rules per class.** SQL: 5005 and 5051; command injection: 6065 (arguments of `subprocess` calls) and 5001 (shell sinks). A seed qualifies for the rules that fire on its original program.
- **Search on Pysa.** Pool and protocol as in the other restricted searches; success requires both qualifying rules to be silent; only strategies 1, 2, 3, 5 and 6 (4 and 7 omitted for cost); `qwen3-coder-next` only.

## Prompt options, Semgrep taint mode and newer releases

- **Prompt and order options.** `llm.prompt_extra` appends text to the system prompt (it is counted in the prompt budget), and `order: "any"` lets a candidate add any unused operator (default `increasing`, unchanged). The informed prompts name Pysa and its 2 rules and, in one variant, state the order; they never say which rewrites evade. Strategies 1, 3 and 5 only, 3 hard seeds, 15 streams each; the scan cache is on (`cache: true`), which saves scans for repeated candidates and does not change attempt counts. Free order is reported as a caveat because random choice already succeeds in every stream.
- **Semgrep taint mode.** The stock rule flags the parameters of a Flask route function. The scanner adds one decorator line, `@app.route("/<user_input>")`, before the entry function (`semgrep_route: true`); nothing else changes.
- **Newer releases.** Semgrep 1.182.1 (`.sastlab/semgrep-latest`, `pip install semgrep==1.182.1`) and CodeQL 2.27.3 (`.sastlab/tools-latest`, `codeql-linux64.zip` with its SHA-256 checked against GitHub's digest, plus `codeql pack download codeql/python-queries`, which installed 1.8.13) were used only for the version check; all other results use the pinned versions.

## Informed prompts, further corpora and the path-traversal class

- **Informed prompts for every agent run.** The earlier hard-pool runs (Semgrep, CodeQL, Pysa) used a prompt that named neither the scanner nor its rule and did not state the operator order. Informed arms (`semgrep-informed-*`, `codeql-informed-*`, `pysa-hard*-informed*`) add a description of the scanner and rule and the fixed operator order (`llm.prompt_extra`; the text is in each config), on the same seeds, streams and pools, with the original random and heuristic runs as baselines. They do not say which rewrites evade. Pysa also has a tool-aware arm without the order sentence. CodeQL arms use seed `d01` only (15 streams) because the original CodeQL runs had no more streams.
- **Third seed set for Pysa agents.** `seeds_pysa_hard2` (`o03_semgrep`, `o18_semgrep`, `o24_codeql`) is an independent check of the 3 hard seeds; it has its own random and heuristic runs.
- **Deployed-project seeds.** `corpus_apps` holds 5 functions hand-adapted from 3 projects with a published SQL-injection advisory; the vulnerable PyPI wheel and its SHA-256 are in `corpus_apps/SOURCE.txt`. The query text is unchanged; database access is replaced by a cursor on the oracle's SQLite connection, and the surrounding framework code is removed. The pyLoad function returns its ids as 1-tuples so that the oracle sees rows.
- **Third class: path traversal.** `seeds_path` has 8 synthetic seeds (CWE-22) that read a file under a temporary directory with the builtin `open`; the exploit `../secret` reads a file with one more line. Rules: Semgrep `path-traversal-open` (with the route decorator line, `semgrep_route`), CodeQL `py/path-injection`, Pysa rule 5011. `transforms.py` treats `open` as a plain-name sink (`SINK_FUNCTIONS`). Under limited compute, CodeQL and Pysa use the first 6 seeds and Semgrep all 8.
- **Pysa triples.** All subsets of up to 3 of the 16 non-round-trip rewrites on 3 seeds; round trips are left out because each silences Pysa alone.
- **Execution.** Every stage resumes from its saved rows (`--resume`), and no stage depends on a sample.

## Seeds from the official suites

The harvest script (not part of this repository) read the unmodified upstream test files (Semgrep rules at commit `a84ff9cc24`, the CodeQL CWE-089 query test at tag `codeql-cli/v2.27.1`) and applied this funnel, counting every stage and logging the reason for each drop in `corpus_official/seeds/funnel.json`: parseable file, call to `.execute`, single argument (parameterized queries are dropped), argument that builds the query from strings (f-string, `%`, `+`, `.format`, directly or through a variable), exactly one external input and straight-line definition (adaptable), distinct program, and exploit-live on SQLite under the framework's own oracle.

Adaptation of one call: the harvester keeps the straight-line assignments the argument depends on (backward slice), replaces the single external input by `user_id` (an entry parameter, an unbound name, or an expression rooted at a request-like object such as `request`, `req` or `event`, or at a variable assigned from one), and writes `query = <argument>; cursor = db_conn.cursor(); cursor.execute(query); return cursor.fetchall()`. The SQL text is not edited. The fixture is derived from SQLite's own errors: a table or column the query names is created as `NUMERIC` with 3 rows holding 1, 2 and 3, so the nominal input `1` returns one row. The exploit string is the first of the quoted, double-quoted and numeric payloads that returns more rows. Seeds record origin, function, line, original statement and adaptation in `corpus_official/seeds/manifest.json`; `funnel.json` holds the counts and the drop reasons.

What the adaptation removes: the database driver and the receiver of `execute`, the framework that supplies the input, and unrelated code. Calls that return no rows (INSERT, UPDATE), injection into a table name, and queries that need a driver-specific placeholder or schema are outside the exploit check and are dropped. Hence the seeds test the rules on the query shapes of the official suites, not on the library models those suites check.

Validation of the setup against the suites themselves is described in [validation](validation.md).

## Transform definitions

Operators are numbered by their bit in the mask. Core operators (bits 0 to 7) move the same value around or change the text of the program.

1. `rename`: Rename entry-function arguments and bound local names with deterministic collision-free reserved names.
2. `format_swap`: Convert an f-string to positional `str.format`, preserving conversion flags. For concatenations, flatten additions and join their string operands.
3. `literal_slice`: Replace query literals with prefixed strings sliced from index one. Within f-strings, insert formatted expressions so the AST remains valid.
4. `dead_padding`: Insert a false branch before the query assignment (before the statement that holds the sink call when the query is inline).
5. `extract_1`: Move query construction into one generated helper, passing the referenced entry-function locals.
6. `extract_2`: Move the current query construction through two generated helpers. Combined with `extract_1`, this adds three local call hops.
7. `branch_split`: Duplicate the query assignment into nominal-input and other-input branches.
8. `dict_dispatch`: Route the bound `.execute` method through a constant-key dictionary.

Flow operators (bits 8 to 12) try to make the user value reach the sink by a route that static taint tracking may not follow, while the program's behavior stays the same. They act on the entry function's second parameter and on `.execute` attributes, not on the query assignment, so they compose with any core operator.

9. `dynamic_sink`: Replace each `.execute` attribute load with `getattr(obj, "exe" + "cute")`, so the sink name is built at run time.
10. `char_launder`: At function entry rebind the input to `"".join(chr(ord(c)) for c in input)`, an identity for every string that passes through integers.
11. `deep_nest`: At function entry put the input in eight nested lists and read it back with eight constant indices.
12. `db_roundtrip`: At function entry store the input in a private in-memory SQLite table and read it back (inserts a module-level `import sqlite3 as _mt_sqlite3`). Text storage would not preserve lone surrogate characters; the oracle inputs are unaffected.
13. `queue_roundtrip`: At function entry pass the input through a `queue.Queue` (inserts a module-level `import queue as _mt_queue`).

Two more flow operators (bits 13 and 14) and the sink-resolution operators (bits 15 to 17) are evaluated by exhaustive enumeration only. The sink-resolution group is `dict_dispatch`, `dynamic_sink`, `partial_sink`, `methodcaller_sink` and `unbound_sink`; they rewrite `.execute` on a cursor, the `subprocess` functions and `os.popen` (`SINK_NAMES`) and the builtin `open` (`SINK_FUNCTIONS`).

14. `simplequeue_roundtrip`: As `queue_roundtrip` with `queue.SimpleQueue`, a different standard-library container (inserts `import queue as _mt_queue`).
15. `pickle_roundtrip`: At function entry replace the input by `pickle.loads(pickle.dumps(input))` (inserts `import pickle as _mt_pickle`).
16. `partial_sink`: Call each sink through `functools.partial(sink)(...)` (inserts `import functools as _mt_functools`).
17. `methodcaller_sink`: Call `obj.execute(query)` as `operator.methodcaller("execute", query)(obj)` (inserts `import operator as _mt_operator`). It needs a plain-name receiver and is rejected for a plain function such as `open`.
18. `unbound_sink`: Call `obj.execute(query)` as `type(obj).execute(obj, query)`. It is rejected for plain functions such as `open` and for module receivers, because `type(module).run` is not the module function.

These operators were chosen as hypotheses about what a flow-based scanner does not model; whether each works against a given engine is an empirical result, not an assumption (see [results](../result.md)). Mutations are deterministic within the supported input domain, and the oracle checks every evaluated candidate. This is not a universal Python equivalence proof. Every mask (2^18 = 262,144) is rebuilt from the original source in operator order. Strategies 1 to 5 may only append an operator with a greater index than the previously applied one; strategies 6 and 7 may toggle any operator.

## Search and feedback

Strategy 1 chooses uniformly from available forward operators. Strategy 2 prefers unseen masks, then less-used operators, then operators associated with previous clean verdicts; ties use the trajectory PRNG. Strategy 3 uses candidate diff, pass/fail status, three-step history and available operators. Strategy 4 ranks all operators once using configured static rule metadata and follows that ordering throughout the trajectory. Strategy 5 receives the same common observation as strategy 3, plus scanner-grounded diagnostics.

Strategies 6 and 7 start at the original seed and, at each attempt, propose toggling one operator chosen uniformly (toggling an operator off lowers the distance from the seed; the original seed itself is never proposed) and apply Metropolis acceptance. A rejected move keeps the current parent. With `metropolis_restart: true` (the default, and every saved run except the two walk checks), a state that holds the last operator of the order is treated like the end of a forward walk: the proposal toggles one operator of the seed instead, and the runner logs the attempt with `restarted: false`. With `false`, every proposal toggles one operator of the current state.

The Metropolis probability is one for nonnegative score change and `exp(delta / temperature)` otherwise, with default temperature 0.25. Because the seed is never proposed, a one-operator state has one proposal fewer than the others, and the acceptance has no Hastings correction for this, so the walk is a search heuristic and not a sampler. `d_syntax` is normalized insertion/deletion distance between AST preorder token sequences, computed exactly using longest common subsequence. Tokens include node types and scalar field values, excluding location attributes. This is an explicit sequence metric over ASTs, not tree-edit distance. `d_depth` is maximum reachable local helper-call depth from the entry function, excluding database and library calls. When depth is unchanged, strategy 7 falls back to syntax distance. The depth proxy counts only generated helpers; the flow operators do not change it, so strategy 7 treats them by syntax distance. For more general harvested programs, this depth proxy needs validation before interpreting it as source-to-sink distance.

The model sees operator names in a shuffled order so that list position carries no information. The order is a deterministic function of the trajectory seed and attempt number (strategies 3 and 5, so paired prompts present the same order for the same available set) or of the trajectory seed alone (strategy 4, one shuffled list per trajectory).

All model requests use the same system instruction. Common observation fields are truncated independently of diagnostics and identically for strategies 3 and 5. A fixed separate space is reserved for diagnostics in both arms. Long traces first retain the first three steps, last three steps, and explicitly marked call boundaries. The overall prompt cap can further remove trace detail. Complete raw traces remain in scanner artifacts and attempt records. The model never writes code: it returns an operator name or a permutation, validated against a JSON schema.

### SoCLaaS chat-completions

All model calls use the same model name, temperature 0.2, prompt construction, schema, operator validation, trajectory seeds, and retry/fallback policy. Requests go to `/v1/chat/completions` with `response_format.type = json_schema`, `max_tokens = 160`, and a request seed. Actual prompt usage is checked using `usage.prompt_tokens`; missing usage, incomplete responses, invalid choices, and over-budget prompts trigger retries. HTTP 429 responses wait and retry the same request (honoring `Retry-After`, else exponential backoff capped at 60 s) without using the validation retries, and the waits are recorded. Transport headers and credentials are excluded from the experiment records.

SoCLaaS does not expose model weights, a digest, or server sampling behavior. Manifests therefore record an unverified identity and no digest. The exact returned model metadata remains in each saved response. Runs made with a different serving stack must not be pooled with SoCLaaS runs as if model identity were known to be identical. A stable deployment revision or independently supplied weight digest is needed before claiming a pinned model.

The model-content cap uses a conservative UTF-8 byte bound with 128 tokens reserved for chat framing, against a prompt allowance of 2,500 tokens (the 13 operator names and definitions need more than 1,000; the effect of the cap was not measured). Actual `usage.prompt_tokens` is checked after each response; over-budget responses are rejected and logged. The bound assumes a byte-level tokenizer such as Llama; another model/tokenizer requires checking this policy. Two retries follow the original request, then selection falls back to a uniform valid operator or permutation. The prompt and model output never become executable code.

## Exhaustive evaluation and resumption

`exhaustive` evaluates every non-empty subset of the named operators on each of the first N seeds, with the same oracle and scanner as the search, and records one row per subset. Verdicts are deterministic per (seed, subset): saved campaigns contain no case of one candidate receiving different verdicts. Results of an exhaustive run are directly comparable to search results for the same seed and mask.

A trajectory is the checkpoint unit for `--resume`. It is complete only if every attempt is recorded; incomplete trajectories are discarded to `discarded-partial.jsonl` and rerun from scratch, so a walk is never a splice of two runs. Because a rerun restarts a trajectory's seeded walk, model-guided strategies may choose differently in the rerun if server-side sampling differs; the discarded records are kept for inspection. Resume validates configuration, engine and scanner versions, rule, seed, operator and model identity first.

## Report-card decisions

A rule is eligible only on seeds where the baseline scanner succeeded, that exact rule fired, and the original exploit was live. An evasion additionally requires a successful candidate scan without that exact rule and successful behavior-equivalence check (the precondition of the metamorphic relation: flagged(P) and same behavior on both inputs implies flagged(T(P))). Other rules still firing does not invalidate disappearance of the target rule; each rule is analyzed separately.

For `S_rule >= 3`, the threshold is `ceil(S_rule / 2)`. Three through five qualifying seeds are designated exploratory. Fewer than three are excluded. A rule is weak if strategy 1 or strategy 2 individually crosses the threshold. Otherwise it is guidance-sensitive if a guided strategy or the union across all seven strategies crosses the threshold. Otherwise it is robust only after a completed full-budget campaign without scanner or oracle execution failures. The report records the first individual crossing in strategy-number order and the first cumulative crossing as strategies 1 through 7 are added. This is portfolio order, not chronological discovery order.

A nonterminal manifest, missing strategy, missing attempt, shortened budget, scanner failure, or oracle infrastructure failure prevents a complete classification. Reports do not combine engines. Synthetic corpus status is attached to every card. Timing comparisons are not valid for cache-enabled wall-clock measurements, and wall times of model-guided strategies include model latency.

Report cards classify a rule against the strategies' success on seeds, which saturates when a single operator evades. The per-strategy comparison of the full campaigns therefore uses distinct evading candidates per trajectory (unique candidate hashes with a verified evasion, divided by trajectories), with bootstrap intervals and sign-flip tests over the paired (seed, trajectory) units. Comparisons on restricted pools use attempts to the first evasion, with a bootstrap over streams (trajectory indices, averaged over seeds) and no sign-flip tests. All of these are exploratory: the seeds of a corpus share one program structure, so the streams are the independent units.

## Verification and reproducibility

The model name, Semgrep and CodeQL versions, pinned rule files and query pack, raw responses, test outcomes and actual integration runs form the reproducibility record (see [validation](validation.md)). Results on real-world programs remain unverified; the official-suite seeds are 9 adapted programs. Each run's manifest records the framework file hashes, seed hashes and rule hash it used.


## Metamorphic relation and operator taxonomy

This is metamorphic testing of one scanner at a time, not differential testing. For rule R and a composition T of operators: flagged_R(P) and behavior(T(P)) = behavior(P) on both oracle inputs implies flagged_R(T(P)). A violation is a candidate false negative of R on code that is still exploitable. The behavior check is the precondition of the relation, not the bug detector, and it is input-bounded (two inputs, one database).

Operators are chosen by the part of a taint analysis they stress (`TAXONOMY`): control (no flow change), interprocedural, control-flow, sink-resolution, value-propagation, container, second-order-storage. Related work with the same style of oracle: TaintCC (Christakis et al., ISSTA), which keeps reported source-sink flows constant and need not preserve behavior; we must preserve behavior because an evasion only counts if the exploit stays live.

## Agent prompts

The exact system prompt and every appended text of the informed-prompt runs are in [prompts.md](prompts.md).

## Fourth analyzer: Bandit

Exhaustive checks only (singles and pairs), no search and no model, on SQL injection (B608) and command injection (B602). The scanner adapter writes the candidate alone and runs `bandit -q -f json`; findings are `bandit/<test id>` and the target rules are in each config. A seed qualifies when the target rule fires on it and the exploit works, as for the other scanners. Bandit has no default test for path traversal, so that class is not run.
