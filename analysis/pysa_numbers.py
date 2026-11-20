"""Numbers for the Pysa comparison, from the saved exhaustive runs only.

Evasion definitions for Pysa (2 stock SQL rules, both must fire on the original program to qualify the seed):
  all   - none of the seed's qualifying rules is reported on the candidate (the headline definition)
  5005  - the plain flow rule 5005 is missing (the view comparable to a data-flow query such as CodeQL's)
A candidate counts only when the scan succeeded and the behavior check says equivalent.
"""
import collections as C, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import single_ops as S

R = S.R
PYSA_RUNS = {"main": ["pysa-main-singles", "pysa-main-pairs"], "varied": ["pysa-diverse-singles"],
             "official": ["pysa-official-singles", "pysa-official-pairs"]}


def load(run):
    d = R / run
    if not (d / "evaluations.jsonl").exists():
        return {}, []
    quals = {q["seed"]: q["qualifying_rules"] for q in json.loads((d / "qualifications.json").read_text())}
    return quals, S.rd(f"{run}/evaluations.jsonl")


def pysa_table():
    """{(corpus, seed, ops): dict(all=bool, f5005=bool)} for scanned equivalent candidates; plus qualification per corpus."""
    out, qual, errors, inequivalent = {}, {}, 0, 0
    for corpus, runs in PYSA_RUNS.items():
        for run in runs:
            quals, rows = load(run)
            for seed, rules in quals.items():
                qual.setdefault(corpus, {})[seed] = rules
            for e in rows:
                if e["status"] != "evaluated":
                    continue
                if e["scan_status"] != "ok":
                    errors += 1
                    continue
                if not e["equivalent"]:
                    inequivalent += 1
                    continue
                rules = quals[e["seed"]]
                seen = set(e["scan_rules"])
                out[(corpus, e["seed"], tuple(sorted(e["operators"])))] = {
                    "all": not (set(rules) & seen), "f5005": "pysa/5005" in rules and "pysa/5005" not in seen,
                    "f5051": "pysa/5051" in rules and "pysa/5051" not in seen}
    return out, qual, errors, inequivalent


def other(engine):
    """{(seed, ops): evades} for the Semgrep or CodeQL verdicts of every saved run (one verdict per pair)."""
    d = {}
    for seed, ops, ev, run in S.rows(engine, official=True):
        d.setdefault((seed, ops), set()).add(ev)
    return {k: any(v) for k, v in d.items() if len(v) == 1}


if __name__ == "__main__":
    table, qual, errors, inequivalent = pysa_table()
    print("scan errors", errors, "not equivalent", inequivalent, "distinct candidates", len(table))
    for corpus, seeds in qual.items():
        both = sum(len(r) == 2 for r in seeds.values())
        print(f"{corpus}: {len(seeds)} seeds, {sum(bool(r) for r in seeds.values())} qualify, {both} with both rules")
    singles = C.defaultdict(lambda: [0, 0, 0, 0])
    for (corpus, seed, ops), v in table.items():
        if len(ops) == 1:
            c = singles[ops[0]]
            c[0] += 1; c[1] += v["all"]; c[2] += v["f5005"]; c[3] += v["f5051"]
    cq, sg = other("codeql"), other("semgrep")
    print("\nsingle rewrites over all Pysa corpora: Pysa seeds / silent / 5005 missing / 5051 missing | CodeQL evading/seeds | Semgrep evading/seeds")
    for op in sorted(singles):
        c = singles[op]
        cs = [v for (s, o), v in cq.items() if o == (op,)]
        ss = [v for (s, o), v in sg.items() if o == (op,)]
        print(f"  {op:22s} {c[0]:3d} {c[1]:3d} {c[2]:3d} {c[3]:3d} | {sum(cs):3d}/{len(cs):3d} | {sum(ss):3d}/{len(ss):3d}")
    for name, ref in (("CodeQL", cq), ("Semgrep", sg)):
        for size in (1, 2):
            tab = C.Counter()
            for (corpus, seed, ops), v in table.items():
                if len(ops) == size and (seed, ops) in ref:
                    tab[(v["all"], ref[(seed, ops)])] += 1
            if tab:
                print(f"\n{name} vs Pysa (silent), {size}-rewrite candidates scanned by both: {sum(tab.values())}")
                print(f"  both detect {tab[(False, False)]}, only Pysa silent {tab[(True, False)]}, only {name} silent {tab[(False, True)]}, both silent {tab[(True, True)]}")
    pairs = {k: v for k, v in table.items() if len(k[2]) == 2}
    if pairs:
        new = [k for k, v in pairs.items() if v["all"] and not any(table.get((k[0], k[1], (o,)), {}).get("all") for o in k[2])]
        print("\npairs:", len(pairs), "silent", sum(v["all"] for v in pairs.values()),
              "silent although neither member is silent alone:", len(new))
        n5005 = [k for k, v in pairs.items() if v["f5005"] and not any(table.get((k[0], k[1], (o,)), {}).get("f5005") for o in k[2])]
        print("rule 5005 missing in a pair although neither member alone:", len(n5005))
