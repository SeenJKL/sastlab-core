# Third-party material

Everything below was copied from the upstream project named, at the commit or version given. Licences are those recorded in the `SOURCE.txt`, `NOTICE.md` and `README.md` files next to the material; check the upstream repository before redistributing.

| Path | Origin | Licence as recorded |
|---|---|---|
| `rules/formatted-sql-query.yaml`, `dangerous-subprocess-use-audit.yaml`, `path-traversal-open.yaml`, `flask-tainted-sql-string.yaml` | Semgrep rules repository, commits and hashes in the `*.provenance.json` files | Semgrep Rules License v1.0 (`rules/NOTICE.md`) |
| `third_party/pysa-models/` | facebook/pyre-check, commit `d5614e0a75f539443225fce3c3c55a77cfbfb72c`, unmodified | MIT (`third_party/pysa-models/README.md`) |
| `corpus_official/seeds/`, `seeds_pysa_hard2/` | seeds adapted from the Semgrep (commit `a84ff9cc24`) and CodeQL (tag `codeql-cli/v2.27.1`) test suites; origin file and line in `corpus_official/seeds/manifest.json` and in each file's docstring | as the upstream files they come from |
| `corpus_real/seeds/` | hand-adapted from OWASP-Benchmark/BenchmarkPython `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` and fportantier/vulpy `5249cc8b05a1c37f6b2f757b1cf16a509c327122` | GPL-3.0 and MIT (`corpus_real/SOURCE.txt`) |
| `corpus_apps/seeds/` | hand-adapted functions from parsl 2025.12.22 and scitokens 1.8.1 (Apache-2.0) and pyload-ng 0.5.0b3.dev90 (AGPL-3.0); wheel hashes in `corpus_apps/SOURCE.txt` | as recorded in `corpus_apps/SOURCE.txt` |

The scanners themselves (Semgrep, CodeQL CLI, Pysa, Bandit) are not included; the Dockerfile and `requirements*.lock` pin the versions.

`rules/demo-sqli.yaml`, the synthetic seeds (`seeds/`, `seeds_diverse/`, `seeds_fstring/`, `seeds_cmd/`, `seeds_path/`, `seeds_pysa_hard/`, `seeds_rerun_s05/`), the framework and the saved results were written for this project.
