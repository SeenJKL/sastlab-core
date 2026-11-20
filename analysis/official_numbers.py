"""Results on the seeds adapted from the official suites (corpus_official/seeds): tests the two rules found on the synthetic seeds.
CodeQL: a candidate evades iff it contains one of the 9 flow-changing rewrites.
Semgrep: the 5 structural rewrites evade alone; other evading sets are listed.
Run: .sastlab/.venv/bin/python analysis/official_numbers.py"""
import collections as C, json, itertools
from pathlib import Path
from _paths import ROOT, RESULTS
R = RESULTS
rd = lambda p: [json.loads(x) for x in (R / p).read_text().splitlines() if x.strip()]
FLOW = {"dynamic_sink", "char_launder", "deep_nest", "db_roundtrip", "simplequeue_roundtrip", "pickle_roundtrip",
        "partial_sink", "methodcaller_sink", "unbound_sink"}
CORE5 = {"extract_1", "extract_2", "branch_split", "dict_dispatch", "dynamic_sink"}
SINK3 = {"partial_sink", "methodcaller_sink", "unbound_sink"}


def load(names):
    out = {}
    for n in names:
        for r in rd(f"{n}/evaluations.jsonl"):
            out[(r["seed"], tuple(sorted(r["operators"])))] = r
    return out


print("== funnel")
f = json.loads((ROOT / "corpus_official/seeds/funnel.json").read_text())
print(f["funnel"])

for engine, runs in (("codeql", ["codeql-official-singles", "codeql-official-nonflow-pairs"]),
                     ("semgrep", ["semgrep-official-newops", "semgrep-official-triples"])):
    d = load(runs)
    ev = {k: v for k, v in d.items() if v["status"] == "evaluated"}
    inv = len(d) - len(ev)
    errs = sum(v["scan_status"] != "ok" for v in ev.values()); noneq = sum(not v["equivalent"] for v in ev.values())
    seeds = sorted({k[0] for k in d})
    print(f"\n== {engine}: rows {len(d)} (distinct seed x subset), scanned+equivalent {len(ev)}, invalid {inv}, scan errors {errs}, behavior differences {noneq}, seeds run {len(seeds)}")
    if engine == "codeql":
        c = C.Counter((bool(set(k[1]) & FLOW), bool(v["bypassed_rules"])) for k, v in ev.items())
        print(" contains flow & evades", c[(True, True)], "| contains flow & detected", c[(True, False)],
              "| no flow & evades", c[(False, True)], "| no flow & detected", c[(False, False)])
        singles = C.defaultdict(dict)
        for (s, ops), v in ev.items():
            if len(ops) == 1: singles[ops[0]][s] = bool(v["bypassed_rules"])
        for op in sorted(singles): print(f"  {op:22s} {sum(singles[op].values())}/{len(singles[op])}")
        invalid = C.Counter(k[1] for k, v in d.items() if v["status"] != "evaluated"); print(" invalid by subset:", dict(C.Counter(len(k) for k in invalid.elements())))
    else:
        singles = C.defaultdict(dict)
        for (s, ops), v in ev.items():
            if len(ops) == 1: singles[ops[0]][s] = bool(v["bypassed_rules"])
        for op in sorted(singles): print(f"  {op:22s} {sum(singles[op].values())}/{len(singles[op])}")
        # rule: contains one of the 5 structural rewrites (or a sink rewrite) -> evades
        SEM = CORE5 | SINK3
        c = C.Counter((bool(set(k[1]) & SEM), bool(v["bypassed_rules"])) for k, v in ev.items())
        print(" contains core5+sink3 & evades", c[(True, True)], "| & detected", c[(True, False)], "| none & evades", c[(False, True)], "| none & detected", c[(False, False)])
        exc = C.Counter(k[1] for k, v in ev.items() if v["bypassed_rules"] and not (set(k[1]) & SEM))
        print(" evading sets without core5/sink3 rewrite:", dict(exc))
        per = C.Counter(k[0] for k, v in ev.items() if v["bypassed_rules"] and not (set(k[1]) & SEM)); print("  by seed:", dict(per))
