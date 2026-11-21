# Stock Pysa Taint Models

Unchanged stock Pysa taint models copied from [`facebook/pyre-check`](https://github.com/facebook/pyre-check) at commit `d5614e0a75f539443225fce3c3c55a77cfbfb72c` (MIT license):

| Local Folder | Original Repo Path |
| --- | --- |
| `core/` | `stubs/taint/core_privacy_security` |
| `common/` | `stubs/taint/common` |

Main files used by SASTLab:

- `core/taint.config` — defines rules `5005` (SQL flow), `5051` (SQL string building), `5001` and `6065` (command injection), and `5011` (path traversal).
- `core/sqlite3_sinks.pysa` — type-based `sqlite3` sink rules.
