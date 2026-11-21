# Third-Party Files and Licenses

All third-party rules, models, and adapted sample programs in this repository keep their original licenses and source details. Check the original project repositories before sharing those files separately.

## Included Third-Party Files

| Path | Original Project | Source Info File | License |
| --- | --- | --- | --- |
| `rules/formatted-sql-query.yaml` | `semgrep/semgrep-rules` (`a84ff9cc2453ca91d581380de4b8b3f272f6f4be`) | [formatted-sql-query.provenance.json](rules/formatted-sql-query.provenance.json) | Semgrep Rules License v1.0 ([rules/NOTICE.md](rules/NOTICE.md)) |
| `rules/dangerous-subprocess-use-audit.yaml` | `semgrep/semgrep-rules` (`a84ff9cc2453ca91d581380de4b8b3f272f6f4be`) | [dangerous-subprocess-use-audit.provenance.json](rules/dangerous-subprocess-use-audit.provenance.json) | Semgrep Rules License v1.0 ([rules/NOTICE.md](rules/NOTICE.md)) |
| `rules/path-traversal-open.yaml` | `semgrep/semgrep-rules` (`16b9e6d45f10649f6a531ec4838ed9924372c3bc`) | [path-traversal-open.provenance.json](rules/path-traversal-open.provenance.json) | Semgrep Rules License v1.0 ([rules/NOTICE.md](rules/NOTICE.md)) |
| `rules/flask-tainted-sql-string.yaml` | `semgrep/semgrep-rules` (`17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9`) | [flask-tainted-sql-string.provenance.json](rules/flask-tainted-sql-string.provenance.json) | Semgrep Rules License v1.0 ([rules/NOTICE.md](rules/NOTICE.md)) |
| [third_party/pysa-models/](third_party/pysa-models/README.md) | `facebook/pyre-check`, commit `d5614e0a75f539443225fce3c3c55a77cfbfb72c` (unchanged) | [third_party/pysa-models/README.md](third_party/pysa-models/README.md) | MIT |
| `corpus_official/seeds/`, `seeds_pysa_hard2/` | Adapted from Semgrep (`a84ff9cc24`) and CodeQL (`codeql-cli/v2.27.1`) test suites | [manifest.json](corpus_official/seeds/manifest.json) and seed docstrings | Same as original files |
| `corpus_real/seeds/` | Hand-adapted from `OWASP-Benchmark/BenchmarkPython` (`f1291485808b66e20ddb6b01b10dc71b3df8c8ba`) and `fportantier/vulpy` (`5249cc8b05a1c37f6b2f757b1cf16a509c327122`) | [corpus_real/SOURCE.txt](corpus_real/SOURCE.txt) | GPL-3.0 and MIT |
| `corpus_apps/seeds/` | Hand-adapted functions from `parsl` `2025.12.22`, `scitokens` `1.8.1`, and `pyload-ng` `0.5.0b3.dev90` PyPI packages | [corpus_apps/SOURCE.txt](corpus_apps/SOURCE.txt) | Apache-2.0 (`parsl`, `scitokens`) and AGPL-3.0 (`pyload-ng`) |

## External Scanner Tools (Not Included)

The scanner programs themselves — Semgrep (`1.178.0`), CodeQL CLI (`2.27.1` with `codeql/python-queries@1.8.11`), Pysa (`pyre-check` `0.10.0`), and Bandit (`1.9.4`) — are not bundled in this repository. Exact versions and SHA-256 checksums are pinned in [Dockerfile](Dockerfile), [requirements.lock](requirements.lock), [requirements-pysa.lock](requirements-pysa.lock), and [requirements-bandit.lock](requirements-bandit.lock).

## Project Files Created Here

The framework code (`sastlab/`), `rules/demo-sqli.yaml`, custom test seeds (`seeds/`, `seeds_diverse/`, `seeds_fstring/`, `seeds_cmd/`, `seeds_path/`, `seeds_pysa_hard/`, `seeds_rerun_s05/`), `configs/`, `analysis/`, `scripts/`, `tests/`, and `results/` were written for this project under the MIT license ([LICENSE](LICENSE)).
