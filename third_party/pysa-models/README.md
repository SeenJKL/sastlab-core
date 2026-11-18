Stock Pysa taint models, copied unmodified from https://github.com/facebook/pyre-check at commit d5614e0a75f539443225fce3c3c55a77cfbfb72c:
`stubs/taint/core_privacy_security` -> `core/`, `stubs/taint/common` -> `common/` (MIT license, see the repository).
The analysis uses `core/taint.config` (rules 5005 and 5051 are the SQL rules) and `core/sqlite3_sinks.pysa`.
