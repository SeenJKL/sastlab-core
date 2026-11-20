"""Independent re-scan of a random sample of the saved Pysa results.

Each sampled candidate is regenerated from its seed and operator subset, its SHA-256 is compared with the logged one, the behavior
check is run again, and the real scanner is run again. The set of rules that fire must equal the logged set (stricter than a
silent/not-silent comparison). Fixed RNG seed 2026; equal numbers of silent candidates, candidates that lose exactly 1 rule, and
candidates that keep both rules.
usage (from the repository root): .sastlab/.venv/bin/python analysis/rescan_pysa.py <n per class>
"""
import hashlib, json, random, sys
from pathlib import Path
from _paths import ROOT

code = ROOT
sys.path.insert(0, str(code))
from sastlab.oracle import Oracle
from sastlab.runner import load_config, scanner_from
from sastlab.transforms import OPERATORS, candidate

n = int(sys.argv[1])
ONLY = sys.argv[2:]  # optional: restrict to these runs
RUNS = {"pysa-main-singles": ("configs/pysa-main.json", "seeds"), "pysa-main-pairs": ("configs/pysa-main.json", "seeds"),
        "pysa-diverse-singles": ("configs/pysa-diverse.json", "seeds_diverse"),
        "pysa-official-singles": ("configs/pysa-official.json", "corpus_official/seeds"),
        "pysa-official-pairs": ("configs/pysa-official.json", "corpus_official/seeds"),
        "pysa-real-pairs": ("configs/pysa-real.json", "corpus_real/seeds"), "pysa-cmd-pairs": ("configs/pysa-cmd.json", "seeds_cmd"),
        "pysa-path-pairs": ("configs/pysa-path.json", "seeds_path"), "pysa-apps-pairs": ("configs/pysa-apps.json", "corpus_apps/seeds"),
        "pysa-triples": ("configs/pysa-triples.json", "seeds_pysa_hard2")}
rows = []
for run, (config, sdir) in RUNS.items():
    if ONLY and run not in ONLY:
        continue
    quals = {q["seed"]: q["qualifying_rules"] for q in json.loads((code / "results" / run / "qualifications.json").read_text())}
    for line in (code / "results" / run / "evaluations.jsonl").read_text().splitlines():
        r = json.loads(line)
        if r["status"] == "evaluated" and r["scan_status"] == "ok" and r["equivalent"]:
            lost = len(set(quals[r["seed"]]) - set(r["scan_rules"]))
            rows.append((r, sdir, config, lost, len(quals[r["seed"]])))
rng = random.Random(2026)
classes = {"silent": [x for x in rows if x[3] == x[4]], "one rule lost": [x for x in rows if x[3] == 1], "both kept": [x for x in rows if x[3] == 0]}
sample = [(name, x) for name, xs in classes.items() for x in rng.sample(xs, n)]
oracle = Oracle(5)
scanners = {}
work = ROOT / ".sastlab/rescan-pysa-work"; work.mkdir(parents=True, exist_ok=True)
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
mask = lambda ops: sum(1 << OPERATORS.index(o) for o in ops)
bad_sha, bad_eq, bad_rules = [], [], []
for name, (r, sdir, config, lost, total) in sample:
    scanner = scanners.setdefault(config, scanner_from(load_config(str(code / config))))
    source = (code / sdir / (r["seed"] + ".py")).read_text()
    cand = candidate(source, mask(r["operators"]))
    if sha(cand) != r["candidate_sha256"]:
        bad_sha.append(r["seed"])
    equivalent = bool(oracle.compare(oracle.evaluate(source), cand).get("equivalent"))
    scan = scanner.scan(cand, work / f"{r['seed']}-{mask(r['operators'])}")
    if equivalent != r["equivalent"]:
        bad_eq.append(r["seed"])
    if scan.status != "ok" or sorted(scan.rules) != sorted(r["scan_rules"]):
        bad_rules.append((r["seed"], r["operators"], r["scan_rules"], scan.rules, scan.status))
print(f"sampled {n} per class from {len(rows)} candidates ({', '.join(f'{k}: {len(v)}' for k, v in classes.items())}) | "
      f"hash mismatches {len(bad_sha)} | behavior-check disagreements {len(bad_eq)} | rule-set disagreements {len(bad_rules)} {bad_rules}")
