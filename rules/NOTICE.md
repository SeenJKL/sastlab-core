# Rules Provenance and License Notice

## Third-Party Semgrep Rules

Four rule files in this directory are verbatim snapshots copied from [`semgrep/semgrep-rules`](https://github.com/semgrep/semgrep-rules) with original metadata preserved:

| Rule File | Upstream Commit | SHA-256 Metadata |
| --- | --- | --- |
| [formatted-sql-query.yaml](formatted-sql-query.yaml) | `a84ff9cc2453ca91d581380de4b8b3f272f6f4be` | [formatted-sql-query.provenance.json](formatted-sql-query.provenance.json) |
| [dangerous-subprocess-use-audit.yaml](dangerous-subprocess-use-audit.yaml) | `a84ff9cc2453ca91d581380de4b8b3f272f6f4be` | [dangerous-subprocess-use-audit.provenance.json](dangerous-subprocess-use-audit.provenance.json) |
| [flask-tainted-sql-string.yaml](flask-tainted-sql-string.yaml) | `17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9` | [flask-tainted-sql-string.provenance.json](flask-tainted-sql-string.provenance.json) |
| [path-traversal-open.yaml](path-traversal-open.yaml) | `16b9e6d45f10649f6a531ec4838ed9924372c3bc` | [path-traversal-open.provenance.json](path-traversal-open.provenance.json) |

These third-party rules are governed by the [Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license) ([upstream license file](https://github.com/semgrep/semgrep-rules/blob/a84ff9cc2453ca91d581380de4b8b3f272f6f4be/LICENSE)).

## First-Party Rules

[demo-sqli.yaml](demo-sqli.yaml) is a synthetic rule fixture created for this project under [LICENSE](../LICENSE) and is separate from the third-party rules above.
