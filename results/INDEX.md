# Saved results

One row per folder in `results/`. Every number is read from the saved files; nothing here is rescanned.
`python3 scripts/index_results.py` rewrites this file, and `python3 scripts/queue_commands.py <folder>` prints the exact command line of a folder.

- **Search** runs (`attempts.jsonl`): *records* are logged attempts; *evading* are attempts whose candidate passed the behavior check, was scanned without error, and silenced at least one target rule.
- **Exhaustive** runs (`evaluations.jsonl`): *records* are the enumerated (seed, rewrite set) pairs; *evading* uses the same condition. Exhaustive runs record every rule that stopped firing and ignore `evasion: all`, so for Pysa an evading candidate silenced at least 1 of its 2 rules; the report's silent counts need both.
- Read a search run with `./run.sh report results/<folder>` (prints, changes nothing); the same numbers are in its `summary.json`.
- **Other** folders hold the output of one helper script; their file names say what they contain.

| Folder | Scanner | Kind | Seeds | Records | Evading | State | Produced by |
|---|---|---|---:|---:|---:|---|---|
| bandit-apps-pairs | bandit | exhaustive | 4 | 684 | 51 | complete | `scripts/queue_bandit.sh` |
| bandit-cmd-pairs | bandit | exhaustive | 6 | 1,026 | 334 | complete | `scripts/queue_bandit.sh` |
| bandit-diverse-pairs | bandit | exhaustive | 10 | 1,710 | 212 | complete | `scripts/queue_bandit.sh` |
| bandit-main-pairs | bandit | exhaustive | 15 | 2,565 | 270 | complete | `scripts/queue_bandit.sh` |
| bandit-official-pairs | bandit | exhaustive | 9 | 1,539 | 192 | complete | `scripts/queue_bandit.sh` |
| bandit-real-pairs | bandit | exhaustive | 6 | 1,026 | 107 | complete | `scripts/queue_bandit.sh` |
| codeql-apps-nonflow-pairs | codeql | exhaustive | 5 | 225 | 0 | complete | `scripts/queue_apps.sh` |
| codeql-apps-singles | codeql | exhaustive | 5 | 90 | 45 | complete | `scripts/queue_apps.sh` |
| codeql-cmd-nonflow-pairs | codeql | exhaustive | 8 | 360 | 0 | complete | `scripts/queue_extra.sh` |
| codeql-cmd-singles | codeql | exhaustive | 8 | 144 | 64 | complete | `scripts/queue_extra.sh` |
| codeql-diverse-nonflow-pairs | codeql | exhaustive | 10 | 450 | 0 | complete | `scripts/queue_diverse.sh` |
| codeql-diverse-singles | codeql | exhaustive | 10 | 130 | 40 | complete | `scripts/queue_diverse.sh` |
| codeql-flow-ops-15seeds | codeql | exhaustive | 15 | 225 | 225 | complete | `scripts/queue_flow_ops.sh` |
| codeql-flow-ops-seed01 | codeql | exhaustive | 1 | 31 | 30 | complete | `scripts/queue_flow_ops.sh` |
| codeql-hard | codeql | search | 4 | 1,680 | 393 | complete | `scripts/queue_hard_pools.sh`, `scripts/queue_hard_pools_qwen.sh` |
| codeql-hard-qwen | codeql | search | 2 | 720 | 317 | complete | `scripts/queue_codeql_hard_qwen.sh` |
| codeql-hard15 | codeql | search | 1 | 900 | 225 | complete | `scripts/queue_hard_pools.sh` |
| codeql-informed-8b | codeql | search | 1 | 360 | 82 | complete | `scripts/queue_informed.sh` |
| codeql-informed-q36 | codeql | search | 1 | 360 | 323 | complete | `scripts/queue_informed.sh` |
| codeql-informed-qwen | codeql | search | 1 | 360 | 117 | complete | `scripts/queue_informed.sh` |
| codeql-latest-main-singles | codeql | exhaustive | 15 | 270 | 135 | complete | `scripts/queue_latest.sh` |
| codeql-latest-official-singles | codeql | exhaustive | 9 | 162 | 81 | complete | `scripts/queue_latest.sh` |
| codeql-more-base | codeql | search | 2 | 720 | 230 | complete | `scripts/queue_more_codeql.sh` |
| codeql-more-informed-8b | codeql | search | 2 | 720 | 149 | complete | `scripts/queue_more_codeql.sh` |
| codeql-more-informed-q36 | codeql | search | 2 | 720 | 647 | complete | `scripts/queue_more_codeql.sh` |
| codeql-more-informed-qwen | codeql | search | 2 | 720 | 195 | complete | `scripts/queue_more_codeql.sh` |
| codeql-more-orig-8b | codeql | search | 2 | 720 | 96 | complete | `scripts/queue_more_codeql.sh` |
| codeql-more-orig-q36 | codeql | search | 2 | 720 | 529 | complete | `scripts/queue_more_codeql.sh` |
| codeql-more-orig-qwen | codeql | search | 2 | 720 | 320 | complete | `scripts/queue_more_codeql.sh` |
| codeql-newops | codeql | exhaustive | 10 | 150 | 120 | complete | `scripts/queue_newops.sh` |
| codeql-official-nonflow-pairs | codeql | exhaustive | 9 | 405 | 0 | complete | `scripts/queue_official.sh` |
| codeql-official-qual | codeql | exhaustive | 9 | 9 | 0 | complete | `scripts/queue_official.sh` |
| codeql-official-singles | codeql | exhaustive | 9 | 162 | 81 | complete | `scripts/queue_official.sh` |
| codeql-path-nonflow-pairs | codeql | exhaustive | 6 | 270 | 0 | complete | `scripts/queue_path.sh` |
| codeql-path-probe | - | other | - | - | - | - | `scripts/path_probe.py` |
| codeql-path-singles | codeql | exhaustive | 6 | 108 | 42 | complete | `scripts/queue_path.sh` |
| codeql-promptfix | codeql | search | 5 | 750 | 363 | complete | `scripts/queue_hard_pools.sh` |
| codeql-real-nonflow-pairs | codeql | exhaustive | 5 | 225 | 0 | complete | `scripts/queue_extra.sh` |
| codeql-real-singles | codeql | exhaustive | 5 | 90 | 45 | complete | `scripts/queue_extra.sh` |
| codeql-rewrite-catalog | - | other | - | - | - | - | `scripts/queue_hard_pools.sh` |
| codeql-v6 | codeql | search | 5 | 5,250 | 2,896 | complete | `scripts/queue.sh`, `scripts/queue_codeql_rerun.sh` |
| codeql-v6-seed05-rerun | codeql | search | 1 | 150 | 94 | complete | `scripts/queue_codeql_rerun.sh` |
| mechanism | - | other | - | - | - | - | `analysis/run_mechanism.sh` |
| official-validation | - | other | - | - | - | - | `scripts/reproduce.sh` |
| prompt-order-probe | - | other | - | - | - | - | `scripts/prompt_order_probe.py` |
| pysa-apps-pairs | pysa | exhaustive | 5 | 855 | 391 | complete | `scripts/queue_apps.sh` |
| pysa-cmd-pairs | pysa | exhaustive | 8 | 1,368 | 644 | complete | `scripts/queue_extra.sh` |
| pysa-diverse-singles | pysa | exhaustive | 10 | 180 | 84 | complete | `scripts/queue_pysa.sh` |
| pysa-hard-any | pysa | search | 3 | 2,025 | 838 | complete | `scripts/queue_pysa_prompt.sh` |
| pysa-hard-informed | pysa | search | 3 | 2,025 | 238 | complete | `scripts/queue_pysa_prompt.sh` |
| pysa-hard-informed-35b | pysa | search | 3 | 1,350 | 27 | complete | `scripts/queue_pysa_prompt3.sh` |
| pysa-hard-informed-8b | pysa | search | 3 | 1,350 | 93 | complete | `scripts/queue_pysa_prompt3.sh` |
| pysa-hard-informed-any | pysa | search | 3 | 2,025 | 911 | complete | `scripts/queue_pysa_prompt.sh` |
| pysa-hard-informed-any-35b | pysa | search | 3 | 1,350 | 750 | complete | `scripts/queue_pysa_prompt.sh` |
| pysa-hard-informed-noorder | pysa | search | 3 | 1,350 | 4 | complete | `scripts/queue_pysa_prompt2.sh` |
| pysa-hard-qwen | pysa | search | 3 | 3,375 | 300 | complete | `scripts/queue_pysa_search.sh` |
| pysa-hard-qwen-rule | pysa | search | 3 | 675 | 0 | complete | `scripts/queue_pysa_search.sh` |
| pysa-hard-walk | pysa | search | 3 | 675 | 192 | complete | `scripts/queue_walk_check.sh` |
| pysa-hard2-informed | pysa | search | 3 | 2,700 | 407 | complete | `scripts/queue_pysa_prompt3.sh` |
| pysa-hard2-informed-35b | pysa | search | 3 | 1,350 | 50 | complete | `scripts/queue_pysa_prompt3.sh` |
| pysa-http-main-pairs-s01 | pysa | exhaustive | 1 | 171 | 107 | complete | `scripts/queue_extra.sh` |
| pysa-http-main-singles | pysa | exhaustive | 15 | 270 | 120 | complete | `scripts/queue_extra.sh` |
| pysa-http-official-pairs-o03 | pysa | exhaustive | 1 | 171 | 99 | complete | `scripts/queue_extra.sh` |
| pysa-main-pairs | pysa | exhaustive | 15 | 2,565 | 1,605 | complete | `scripts/queue_pysa.sh` |
| pysa-main-singles | pysa | exhaustive | 15 | 270 | 120 | complete | `scripts/queue_pysa.sh` |
| pysa-official-pairs | pysa | exhaustive | 9 | 1,539 | 951 | complete | `scripts/queue_pysa.sh` |
| pysa-official-singles | pysa | exhaustive | 9 | 162 | 74 | complete | `scripts/queue_pysa.sh` |
| pysa-path-pairs | pysa | exhaustive | 6 | 1,026 | 393 | complete | `scripts/queue_path.sh` |
| pysa-real-pairs | pysa | exhaustive | 5 | 855 | 527 | complete | `scripts/queue_extra.sh` |
| pysa-rep1-35b | pysa | search | 3 | 1,350 | 17 | complete | `scripts/queue_repeats.sh` |
| pysa-rep1-8b | pysa | search | 3 | 1,350 | 97 | complete | `scripts/queue_repeats.sh` |
| pysa-rep1-coder | pysa | search | 3 | 2,700 | 363 | complete | `scripts/queue_repeats.sh` |
| pysa-rep2-35b | pysa | search | 3 | 1,350 | 15 | complete | `scripts/queue_repeats.sh` |
| pysa-rep2-8b | pysa | search | 3 | 1,350 | 95 | complete | `scripts/queue_repeats.sh` |
| pysa-rep2-coder | pysa | search | 3 | 2,700 | 350 | complete | `scripts/queue_repeats.sh` |
| pysa-triples | pysa | exhaustive | 3 | 2,088 | 1,123 | complete | `scripts/queue_triples.sh` |
| semgrep-abl-message | semgrep | search | 3 | 1,350 | 1,321 | complete | `scripts/queue_ablation.sh` |
| semgrep-abl-sink | semgrep | search | 3 | 1,350 | 709 | complete | `scripts/queue_ablation.sh` |
| semgrep-abl-snippet | semgrep | search | 3 | 1,350 | 752 | complete | `scripts/queue_ablation.sh` |
| semgrep-apps-pairs | semgrep | exhaustive | 5 | 855 | 396 | complete | `scripts/queue_apps.sh` |
| semgrep-cmd-pairs | semgrep | exhaustive | 7 | 1,197 | 391 | complete | `scripts/queue_extra.sh` |
| semgrep-controls-main | semgrep | exhaustive | 15 | 225 | 60 | complete | `scripts/queue_pattern_singles.sh` |
| semgrep-diverse-singles | semgrep | exhaustive | 8 | 104 | 42 | complete | `scripts/queue_diverse.sh` |
| semgrep-diverse-triples | semgrep | exhaustive | 8 | 3,016 | 2,266 | complete | `scripts/queue_diverse.sh` |
| semgrep-hard | semgrep | search | 8 | 4,200 | 1,502 | complete | `scripts/queue_hard_pools.sh` |
| semgrep-hard30 | semgrep | search | 3 | 6,750 | 2,058 | complete | `scripts/queue_hard_pools.sh` |
| semgrep-hard30-q36 | semgrep | search | 3 | 2,700 | 980 | complete | `scripts/queue_ablation.sh` |
| semgrep-hard30-qwen | semgrep | search | 3 | 2,700 | 1,948 | complete | `scripts/queue_hard_pools_qwen.sh` |
| semgrep-hard30-walk | semgrep | search | 3 | 1,350 | 732 | complete | `scripts/queue_walk_check.sh` |
| semgrep-informed-8b | semgrep | search | 3 | 2,700 | 864 | complete | `scripts/queue_informed.sh` |
| semgrep-informed-q36 | semgrep | search | 3 | 2,700 | 1,365 | complete | `scripts/queue_informed.sh` |
| semgrep-informed-qwen | semgrep | search | 3 | 2,700 | 1,754 | complete | `scripts/queue_informed.sh` |
| semgrep-latest-main-singles | semgrep | exhaustive | 15 | 270 | 120 | complete | `scripts/queue_latest.sh` |
| semgrep-latest-official-singles | semgrep | exhaustive | 7 | 126 | 60 | complete | `scripts/queue_latest.sh` |
| semgrep-newops | semgrep | exhaustive | 8 | 120 | 72 | complete | `scripts/queue_newops.sh` |
| semgrep-official-newops | semgrep | exhaustive | 7 | 105 | 63 | complete | `scripts/queue_official.sh` |
| semgrep-official-qual | semgrep | exhaustive | 7 | 7 | 0 | complete | `scripts/queue_official.sh` |
| semgrep-official-triples | semgrep | exhaustive | 7 | 2,639 | 1,904 | complete | `scripts/queue_official.sh` |
| semgrep-path-pairs | semgrep | exhaustive | 6 | 1,026 | 249 | complete | `scripts/queue_path.sh` |
| semgrep-pattern-main-singles | semgrep | exhaustive | 15 | 270 | 120 | complete | `scripts/queue_pattern_singles.sh` |
| semgrep-pattern-official-singles | semgrep | exhaustive | 7 | 126 | 60 | complete | `scripts/queue_pattern_singles.sh` |
| semgrep-promptfix | semgrep | search | 15 | 2,250 | 1,747 | complete | `scripts/queue_hard_pools.sh` |
| semgrep-real-pairs | semgrep | exhaustive | 6 | 1,026 | 648 | complete | `scripts/queue_extra.sh` |
| semgrep-rep1-35b | semgrep | search | 3 | 2,700 | 1,331 | complete | `scripts/queue_repeats.sh` |
| semgrep-rep1-8b | semgrep | search | 3 | 4,050 | 1,189 | complete | `scripts/queue_repeats.sh` |
| semgrep-rep1-coder | semgrep | search | 3 | 2,700 | 1,851 | complete | `scripts/queue_repeats.sh` |
| semgrep-rep2-35b | semgrep | search | 3 | 2,700 | 1,359 | complete | `scripts/queue_repeats.sh` |
| semgrep-rep2-8b | semgrep | search | 3 | 4,050 | 1,177 | complete | `scripts/queue_repeats.sh` |
| semgrep-rep2-coder | semgrep | search | 3 | 2,700 | 1,854 | complete | `scripts/queue_repeats.sh` |
| semgrep-taint-apps-pairs | semgrep | exhaustive | 4 | 684 | 144 | complete | `scripts/queue_apps.sh` |
| semgrep-taint-diverse-singles | semgrep | exhaustive | 10 | 180 | 32 | complete | `scripts/queue_taint.sh` |
| semgrep-taint-main-pairs | semgrep | exhaustive | 15 | 2,565 | 765 | complete | `scripts/queue_taint.sh` |
| semgrep-taint-official-pairs | semgrep | exhaustive | 9 | 1,539 | 477 | complete | `scripts/queue_taint.sh` |
| semgrep-taint-real-pairs | semgrep | exhaustive | 3 | 513 | 150 | complete | `scripts/queue_taint.sh` |
| semgrep-v6 | semgrep | search | 15 | 15,750 | 11,878 | complete | `scripts/queue.sh` |
