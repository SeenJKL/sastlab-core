# Saved Experiment Results

List of all **115** saved run folders in `results/`. Every number below comes directly from the saved files (nothing here is re-scanned).

## How to Read Saved Runs

- **View a search run** (prints a read-only summary from `attempts.jsonl`):
  ```sh
  ./run.sh report results/<folder>
  # or without run.sh:
  python3 -m sastlab report results/<folder>
  ```
- **View a check-all run:** read `summary.json` (totals per seed) and `evaluations.jsonl` (one line per `(seed, mask)`).
- **Re-check all report tables and numbers** in [result.md](../result.md): run `analysis/run_all.sh` (offline, takes about 3 minutes).

## Folder Names and Columns

Run folders usually follow `<scanner>-<corpus>-<kind>` (for example, `semgrep-main-pairs`, `codeql-v6`, `pysa-hard-informed`).

- **Scanner:** `semgrep`, `codeql`, `pysa`, or `bandit` (`-` for helper-script or validation outputs).
- **Kind:**
  - `search`: step-by-step strategy runs saved in `attempts.jsonl`. *Records* = total tries logged; *Evading* = valid same-behavior programs scanned without errors where target rule(s) stopped firing.
  - `exhaustive`: runs that test every combination, saved in `evaluations.jsonl`. *Records* = total `(seed, mask)` pairs checked; *Evading* = valid same-behavior programs scanned without errors that silenced **at least one** target rule. (Check-all runs always log `scan_rules` and `bypassed_rules` for every rule even when `evasion: "all"`, so for Pysa SQL runs an "evading" row stopped 1 or 2 rules, while "silent" counts in [result.md](../result.md) require **both** rules 5005 and 5051 to stop.)
  - `other`: helper-script or validation outputs (`codeql-path-probe`, `codeql-rewrite-catalog`, `mechanism`, `official-validation`, `prompt-order-probe`).

## Run Index

| Folder | Scanner | Kind | Seeds | Records | Evading | State |
| --- | --- | --- | ---: | ---: | ---: | --- |
| bandit-apps-pairs | bandit | exhaustive | 4 | 684 | 51 | complete |
| bandit-cmd-pairs | bandit | exhaustive | 6 | 1,026 | 334 | complete |
| bandit-diverse-pairs | bandit | exhaustive | 10 | 1,710 | 212 | complete |
| bandit-main-pairs | bandit | exhaustive | 15 | 2,565 | 270 | complete |
| bandit-official-pairs | bandit | exhaustive | 9 | 1,539 | 192 | complete |
| bandit-real-pairs | bandit | exhaustive | 6 | 1,026 | 107 | complete |
| codeql-apps-nonflow-pairs | codeql | exhaustive | 5 | 225 | 0 | complete |
| codeql-apps-singles | codeql | exhaustive | 5 | 90 | 45 | complete |
| codeql-cmd-nonflow-pairs | codeql | exhaustive | 8 | 360 | 0 | complete |
| codeql-cmd-singles | codeql | exhaustive | 8 | 144 | 64 | complete |
| codeql-diverse-nonflow-pairs | codeql | exhaustive | 10 | 450 | 0 | complete |
| codeql-diverse-singles | codeql | exhaustive | 10 | 130 | 40 | complete |
| codeql-flow-ops-15seeds | codeql | exhaustive | 15 | 225 | 225 | complete |
| codeql-flow-ops-seed01 | codeql | exhaustive | 1 | 31 | 30 | complete |
| codeql-hard | codeql | search | 4 | 1,680 | 393 | complete |
| codeql-hard-qwen | codeql | search | 2 | 720 | 317 | complete |
| codeql-hard15 | codeql | search | 1 | 900 | 225 | complete |
| codeql-informed-8b | codeql | search | 1 | 360 | 82 | complete |
| codeql-informed-q36 | codeql | search | 1 | 360 | 323 | complete |
| codeql-informed-qwen | codeql | search | 1 | 360 | 117 | complete |
| codeql-latest-main-singles | codeql | exhaustive | 15 | 270 | 135 | complete |
| codeql-latest-official-singles | codeql | exhaustive | 9 | 162 | 81 | complete |
| codeql-more-base | codeql | search | 2 | 720 | 230 | complete |
| codeql-more-informed-8b | codeql | search | 2 | 720 | 149 | complete |
| codeql-more-informed-q36 | codeql | search | 2 | 720 | 647 | complete |
| codeql-more-informed-qwen | codeql | search | 2 | 720 | 195 | complete |
| codeql-more-orig-8b | codeql | search | 2 | 720 | 96 | complete |
| codeql-more-orig-q36 | codeql | search | 2 | 720 | 529 | complete |
| codeql-more-orig-qwen | codeql | search | 2 | 720 | 320 | complete |
| codeql-newops | codeql | exhaustive | 10 | 150 | 120 | complete |
| codeql-official-nonflow-pairs | codeql | exhaustive | 9 | 405 | 0 | complete |
| codeql-official-qual | codeql | exhaustive | 9 | 9 | 0 | complete |
| codeql-official-singles | codeql | exhaustive | 9 | 162 | 81 | complete |
| codeql-path-nonflow-pairs | codeql | exhaustive | 6 | 270 | 0 | complete |
| codeql-path-probe | - | other | - | - | - | - |
| codeql-path-singles | codeql | exhaustive | 6 | 108 | 42 | complete |
| codeql-promptfix | codeql | search | 5 | 750 | 363 | complete |
| codeql-real-nonflow-pairs | codeql | exhaustive | 5 | 225 | 0 | complete |
| codeql-real-singles | codeql | exhaustive | 5 | 90 | 45 | complete |
| codeql-rewrite-catalog | - | other | - | - | - | - |
| codeql-v6 | codeql | search | 5 | 5,250 | 2,896 | complete |
| codeql-v6-seed05-rerun | codeql | search | 1 | 150 | 94 | complete |
| mechanism | - | other | - | - | - | - |
| official-validation | - | other | - | - | - | - |
| prompt-order-probe | - | other | - | - | - | - |
| pysa-apps-pairs | pysa | exhaustive | 5 | 855 | 391 | complete |
| pysa-cmd-pairs | pysa | exhaustive | 8 | 1,368 | 644 | complete |
| pysa-diverse-singles | pysa | exhaustive | 10 | 180 | 84 | complete |
| pysa-hard-any | pysa | search | 3 | 2,025 | 838 | complete |
| pysa-hard-informed | pysa | search | 3 | 2,025 | 238 | complete |
| pysa-hard-informed-35b | pysa | search | 3 | 1,350 | 27 | complete |
| pysa-hard-informed-8b | pysa | search | 3 | 1,350 | 93 | complete |
| pysa-hard-informed-any | pysa | search | 3 | 2,025 | 911 | complete |
| pysa-hard-informed-any-35b | pysa | search | 3 | 1,350 | 750 | complete |
| pysa-hard-informed-noorder | pysa | search | 3 | 1,350 | 4 | complete |
| pysa-hard-qwen | pysa | search | 3 | 3,375 | 300 | complete |
| pysa-hard-qwen-rule | pysa | search | 3 | 675 | 0 | complete |
| pysa-hard-walk | pysa | search | 3 | 675 | 192 | complete |
| pysa-hard2-informed | pysa | search | 3 | 2,700 | 407 | complete |
| pysa-hard2-informed-35b | pysa | search | 3 | 1,350 | 50 | complete |
| pysa-http-main-pairs-s01 | pysa | exhaustive | 1 | 171 | 107 | complete |
| pysa-http-main-singles | pysa | exhaustive | 15 | 270 | 120 | complete |
| pysa-http-official-pairs-o03 | pysa | exhaustive | 1 | 171 | 99 | complete |
| pysa-main-pairs | pysa | exhaustive | 15 | 2,565 | 1,605 | complete |
| pysa-main-singles | pysa | exhaustive | 15 | 270 | 120 | complete |
| pysa-official-pairs | pysa | exhaustive | 9 | 1,539 | 951 | complete |
| pysa-official-singles | pysa | exhaustive | 9 | 162 | 74 | complete |
| pysa-path-pairs | pysa | exhaustive | 6 | 1,026 | 393 | complete |
| pysa-real-pairs | pysa | exhaustive | 5 | 855 | 527 | complete |
| pysa-rep1-35b | pysa | search | 3 | 1,350 | 17 | complete |
| pysa-rep1-8b | pysa | search | 3 | 1,350 | 97 | complete |
| pysa-rep1-coder | pysa | search | 3 | 2,700 | 363 | complete |
| pysa-rep2-35b | pysa | search | 3 | 1,350 | 15 | complete |
| pysa-rep2-8b | pysa | search | 3 | 1,350 | 95 | complete |
| pysa-rep2-coder | pysa | search | 3 | 2,700 | 350 | complete |
| pysa-triples | pysa | exhaustive | 3 | 2,088 | 1,123 | complete |
| semgrep-abl-message | semgrep | search | 3 | 1,350 | 1,321 | complete |
| semgrep-abl-sink | semgrep | search | 3 | 1,350 | 709 | complete |
| semgrep-abl-snippet | semgrep | search | 3 | 1,350 | 752 | complete |
| semgrep-apps-pairs | semgrep | exhaustive | 5 | 855 | 396 | complete |
| semgrep-cmd-pairs | semgrep | exhaustive | 7 | 1,197 | 391 | complete |
| semgrep-controls-main | semgrep | exhaustive | 15 | 225 | 60 | complete |
| semgrep-diverse-singles | semgrep | exhaustive | 8 | 104 | 42 | complete |
| semgrep-diverse-triples | semgrep | exhaustive | 8 | 3,016 | 2,266 | complete |
| semgrep-hard | semgrep | search | 8 | 4,200 | 1,502 | complete |
| semgrep-hard30 | semgrep | search | 3 | 6,750 | 2,058 | complete |
| semgrep-hard30-q36 | semgrep | search | 3 | 2,700 | 980 | complete |
| semgrep-hard30-qwen | semgrep | search | 3 | 2,700 | 1,948 | complete |
| semgrep-hard30-walk | semgrep | search | 3 | 1,350 | 732 | complete |
| semgrep-informed-8b | semgrep | search | 3 | 2,700 | 864 | complete |
| semgrep-informed-q36 | semgrep | search | 3 | 2,700 | 1,365 | complete |
| semgrep-informed-qwen | semgrep | search | 3 | 2,700 | 1,754 | complete |
| semgrep-latest-main-singles | semgrep | exhaustive | 15 | 270 | 120 | complete |
| semgrep-latest-official-singles | semgrep | exhaustive | 7 | 126 | 60 | complete |
| semgrep-newops | semgrep | exhaustive | 8 | 120 | 72 | complete |
| semgrep-official-newops | semgrep | exhaustive | 7 | 105 | 63 | complete |
| semgrep-official-qual | semgrep | exhaustive | 7 | 7 | 0 | complete |
| semgrep-official-triples | semgrep | exhaustive | 7 | 2,639 | 1,904 | complete |
| semgrep-path-pairs | semgrep | exhaustive | 6 | 1,026 | 249 | complete |
| semgrep-pattern-main-singles | semgrep | exhaustive | 15 | 270 | 120 | complete |
| semgrep-pattern-official-singles | semgrep | exhaustive | 7 | 126 | 60 | complete |
| semgrep-promptfix | semgrep | search | 15 | 2,250 | 1,747 | complete |
| semgrep-real-pairs | semgrep | exhaustive | 6 | 1,026 | 648 | complete |
| semgrep-rep1-35b | semgrep | search | 3 | 2,700 | 1,331 | complete |
| semgrep-rep1-8b | semgrep | search | 3 | 4,050 | 1,189 | complete |
| semgrep-rep1-coder | semgrep | search | 3 | 2,700 | 1,851 | complete |
| semgrep-rep2-35b | semgrep | search | 3 | 2,700 | 1,359 | complete |
| semgrep-rep2-8b | semgrep | search | 3 | 4,050 | 1,177 | complete |
| semgrep-rep2-coder | semgrep | search | 3 | 2,700 | 1,854 | complete |
| semgrep-taint-apps-pairs | semgrep | exhaustive | 4 | 684 | 144 | complete |
| semgrep-taint-diverse-singles | semgrep | exhaustive | 10 | 180 | 32 | complete |
| semgrep-taint-main-pairs | semgrep | exhaustive | 15 | 2,565 | 765 | complete |
| semgrep-taint-official-pairs | semgrep | exhaustive | 9 | 1,539 | 477 | complete |
| semgrep-taint-real-pairs | semgrep | exhaustive | 3 | 513 | 150 | complete |
| semgrep-v6 | semgrep | search | 15 | 15,750 | 11,878 | complete |
