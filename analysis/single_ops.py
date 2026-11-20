"""Per-operator evasion table and aggregate counts from every saved run.
A candidate counts when the scan succeeded and the behavior check says equivalent.
Single-operator rows: distinct (engine, seed, operator) with exactly 1 operator in the mask."""
import collections as C, json
from pathlib import Path
from _paths import RESULTS
R = RESULTS
rd = lambda p: [json.loads(x) for x in (R / p).read_text().splitlines() if x.strip()]

RUNS = {
    "semgrep": {"attempts": ["semgrep-v6", "semgrep-promptfix", "semgrep-hard", "semgrep-hard30", "semgrep-hard30-qwen",
                             "semgrep-hard30-q36", "semgrep-abl-message", "semgrep-abl-snippet", "semgrep-abl-sink"],
                "evals": ["semgrep-diverse-singles", "semgrep-diverse-triples", "semgrep-newops",
                          "semgrep-pattern-main-singles"]},  # pinned 1.178.0 rescan: all 18 single rewrites on the 15 main seeds
    "codeql": {"attempts": ["codeql-v6", "codeql-promptfix", "codeql-hard", "codeql-hard15", "codeql-hard-qwen"],
               "evals": ["codeql-diverse-singles", "codeql-diverse-nonflow-pairs", "codeql-flow-ops-15seeds",
                         "codeql-flow-ops-seed01", "codeql-newops"]},
}


OFFICIAL = {"semgrep": ["semgrep-official-newops", "semgrep-official-triples"],
            "codeql": ["codeql-official-singles", "codeql-official-nonflow-pairs"]}


def rows(engine, official=False):
    """Rows of every saved run; official=True adds the runs on seeds adapted from the official suites."""
    out = []
    for d in RUNS[engine]["attempts"]:
        for a in rd(f"{d}/attempts.jsonl"):
            sc = a["scan"] or {}
            if a["error"] or sc.get("status") != "ok" or not (a["oracle"] or {}).get("equivalent", False):
                continue
            out.append((a["seed"], tuple(sorted(a["operators"])), bool(a["bypassed_rules"]), d))
    for d in RUNS[engine]["evals"] + (OFFICIAL[engine] if official else []):
        for e in rd(f"{d}/evaluations.jsonl"):
            if e["status"] == "evaluated" and e["equivalent"] and e["scan_status"] == "ok":
                out.append((e["seed"], tuple(sorted(e["operators"])), bool(e["bypassed_rules"]), d))
    return out


if __name__ == "__main__":
    for engine in ("semgrep", "codeql"):
        rs = rows(engine)
        uniq = {}
        for seed, ops, ev, d in rs:
            uniq.setdefault((seed, ops), set()).add(ev)
        incons = [k for k, v in uniq.items() if len(v) > 1]
        print(f"\n## {engine}: scanned equivalent rows {len(rs)}, unique (seed, subset) {len(uniq)}, inconsistent verdicts {len(incons)}")
        single = C.defaultdict(dict)
        for (seed, ops), v in uniq.items():
            if len(ops) == 1:
                single[ops[0]][seed] = any(v)
        for op, d in sorted(single.items()):
            main = {s: v for s, v in d.items() if s.startswith("seed_")}
            div = {s: v for s, v in d.items() if not s.startswith("seed_")}
            print(f"  {op:22s} main {sum(main.values())}/{len(main)}   varied {sum(div.values())}/{len(div)}")
