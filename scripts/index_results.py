#!/usr/bin/env python3
"""Write results/INDEX.md: one row per saved run folder with its scanner, size, outcome counts and the command that produced it.

usage:  python3 scripts/index_results.py            # rewrites results/INDEX.md
        python3 scripts/index_results.py --check    # exit 1 if results/INDEX.md is out of date

All numbers are read from the saved files (manifest.json, attempts.jsonl or evaluations.jsonl); nothing is rescanned.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import queue_commands  # noqa: E402

RESULTS = ROOT / "results"
INDEX = RESULTS / "INDEX.md"

HEADER = """# Saved results

One row per folder in `results/`. Every number is read from the saved files; nothing here is rescanned.
`python3 scripts/index_results.py` rewrites this file, and `python3 scripts/queue_commands.py <folder>` prints the exact command line of a folder.

- **Search** runs (`attempts.jsonl`): *records* are logged attempts; *evading* are attempts whose candidate passed the behavior check, was scanned without error, and silenced at least one target rule.
- **Exhaustive** runs (`evaluations.jsonl`): *records* are the enumerated (seed, rewrite set) pairs; *evading* uses the same condition. Exhaustive runs record every rule that stopped firing and ignore `evasion: all`, so for Pysa an evading candidate silenced at least 1 of its 2 rules; the report's silent counts need both.
- Read a search run with `./run.sh report results/<folder>` (prints, changes nothing); the same numbers are in its `summary.json`.
- **Other** folders hold the output of one helper script; their file names say what they contain.

| Folder | Scanner | Kind | Seeds | Records | Evading | State | Produced by |
|---|---|---|---:|---:|---:|---|---|
"""


def lines(path):
    with path.open() as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def describe(folder, producers):
    manifest = {}
    if (folder / "manifest.json").exists():
        manifest = json.loads((folder / "manifest.json").read_text())
    scanner = manifest.get("engine") or (manifest.get("identity") or {}).get("engine") or "-"
    state = manifest.get("state", "-")
    seeds, records, evading, kind = "-", "-", "-", "other"
    if (folder / "attempts.jsonl").exists():
        kind = "search"
        rows = list(lines(folder / "attempts.jsonl"))
        seeds = len({r["seed"] for r in rows})
        records = len(rows)
        evading = sum(1 for r in rows
                      if r.get("bypassed_rules") and (r.get("scan") or {}).get("status") == "ok"
                      and (r.get("oracle") or {}).get("equivalent"))
    elif (folder / "evaluations.jsonl").exists():
        kind = "exhaustive"
        rows = list(lines(folder / "evaluations.jsonl"))
        seeds = len({r["seed"] for r in rows})
        records = len(rows)
        evading = sum(1 for r in rows if r.get("equivalent") and r.get("scan_status") == "ok" and r.get("bypassed_rules"))
    scripts = sorted({script for script, _ in producers}) or ["-"]
    return [folder.name, scanner, kind, str(seeds), f"{records:,}" if isinstance(records, int) else records,
            f"{evading:,}" if isinstance(evading, int) else evading, state,
            ", ".join(f"`scripts/{s}`" if s != "-" else s for s in scripts)]


def build():
    commands = queue_commands.queue_commands()
    rows = []
    for folder in sorted(p for p in RESULTS.iterdir() if p.is_dir()):
        producers = commands.get(folder.name, [])
        row = describe(folder, producers)
        if not producers and folder.name in queue_commands.HELPERS:
            token = next(w for w in queue_commands.HELPERS[folder.name].split() if w.startswith(("scripts/", "analysis/")))
            row[-1] = f"`{token}`"
        rows.append(row)
    return HEADER + "\n".join("| " + " | ".join(r) + " |" for r in rows) + "\n"


def main(argv):
    text = build()
    if "--check" in argv:
        return 0 if INDEX.exists() and INDEX.read_text() == text else 1
    INDEX.write_text(text)
    print(f"wrote {INDEX.relative_to(ROOT)}: {text.count(chr(10)) - HEADER.count(chr(10))} folders")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
