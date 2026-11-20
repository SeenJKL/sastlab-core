"""Check "a CodeQL candidate evades iff it contains a flow-changing rewrite" over every saved CodeQL run on SQL-injection seeds
(main, varied and official corpora). Independent of single_ops.py: the runs are found from the manifests, not listed by hand.
Writes codeql_rule_numbers.tex."""
import collections
import json
from pathlib import Path
from _paths import RESULTS, OUT_DIR

RESULTS = RESULTS
OUT = OUT_DIR / "codeql_rule_numbers.tex"
FLOW = {"dynamic_sink", "char_launder", "deep_nest", "db_roundtrip", "simplequeue_roundtrip", "pickle_roundtrip",
        "partial_sink", "methodcaller_sink", "unbound_sink"}


def identity(directory):
    m = json.loads((directory / "manifest.json").read_text())
    if m.get("kind") == "exhaustive":
        return m["identity"]["engine"], str(m["identity"].get("query"))
    cfg = m.get("config") or {}
    return cfg.get("engine"), str(cfg.get("query"))


def candidates(directory):
    if (directory / "evaluations.jsonl").exists():
        for line in (directory / "evaluations.jsonl").read_text().splitlines():
            e = json.loads(line)
            if e["status"] == "evaluated" and e["equivalent"] and e["scan_status"] == "ok":
                yield e["seed"], tuple(sorted(e["operators"])), bool(e["bypassed_rules"])
    if (directory / "attempts.jsonl").exists():
        for line in (directory / "attempts.jsonl").read_text().splitlines():
            a = json.loads(line)
            scan = a["scan"] or {}
            if a["error"] or scan.get("status") != "ok" or not (a["oracle"] or {}).get("equivalent", False):
                continue
            yield a["seed"], tuple(sorted(a["operators"])), bool(a["bypassed_rules"])


def corpus(seed):
    if seed.startswith("seed_"):
        return "main"
    if seed.startswith("d"):
        return "varied"
    if seed.startswith("o"):
        return "official"
    return None  # command, path, deployed and independent programs have their own checks


verdicts = collections.defaultdict(set)
pinned = collections.defaultdict(set)  # same, without the runs made with CodeQL 2.27.3 (codeql-latest-*)
runs = set()
for d in sorted(RESULTS.iterdir()):
    if not (d / "manifest.json").exists():
        continue
    try:
        engine, query = identity(d)
    except (KeyError, ValueError):
        continue
    if engine != "codeql" or "CWE-089" not in query:
        continue
    for seed, ops, evaded in candidates(d):
        if corpus(seed):
            verdicts[(seed, ops)].add(evaded)
            if not d.name.startswith("codeql-latest"):
                pinned[(seed, ops)].add(evaded)
            runs.add(d.name)
inconsistent = sum(len(v) > 1 for v in verdicts.values())
with_flow = [k for k in verdicts if FLOW & set(k[1])]
without = [k for k in verdicts if not FLOW & set(k[1])]
CONTROLS = {"rename", "format_swap", "literal_slice", "dead_padding"}
controls = [k for k in verdicts if k[1] and set(k[1]) <= CONTROLS]
ev = lambda ks: sum(any(verdicts[k]) for k in ks)
singles = [k for k in verdicts if len(k[1]) == 1]
multi = [k for k in verdicts if len(k[1]) > 1]
detected_single_ops = sorted({k[1][0] for k in singles if not any(verdicts[k])} - {k[1][0] for k in singles if any(verdicts[k])})
evading_single_ops = sorted({k[1][0] for k in singles if any(verdicts[k])})
print("single-rewrite operators that never evade:", detected_single_ops)
print("single-rewrite operators that evade:", evading_single_ops, "equals the 9 flow-changing rewrites:", set(evading_single_ops) == FLOW)
pf = [k for k in pinned if FLOW & set(k[1])]
pn = [k for k in pinned if not FLOW & set(k[1])]
pc = [k for k in pinned if k[1] and set(k[1]) <= CONTROLS]
pe = lambda ks: sum(any(pinned[k]) for k in ks)
print("pinned only:", len(pinned), len(pf), pe(pf), len(pn), pe(pn), len(pc), pe(pc))
lines = {"codeqlRuleRuns": len(runs), "codeqlRuleDistinct": len(verdicts), "codeqlRuleFlow": len(with_flow),
         "codeqlRuleFlowEvade": ev(with_flow), "codeqlRuleNoFlow": len(without), "codeqlRuleNoFlowEvade": ev(without),
         "codeqlRuleInconsistent": inconsistent, "codeqlRuleControls": len(controls), "codeqlRuleControlsEvade": ev(controls),
         "codeqlRuleSingles": len(singles), "codeqlRuleSinglesEvade": ev(singles), "codeqlRuleMulti": len(multi), "codeqlRuleMultiEvade": ev(multi),
         "codeqlRuleLatestRuns": len([r for r in runs if r.startswith("codeql-latest")]),
         "codeqlRulePinnedDistinct": len(pinned), "codeqlRulePinnedFlow": len(pf), "codeqlRulePinnedNoFlow": len(pn)}
text = "\n".join(f"\\newcommand{{\\{k}}}{{{v:,}}}".replace(",", "{,}") for k, v in lines.items()) + "\n"
OUT.write_text(text)
print(text)
