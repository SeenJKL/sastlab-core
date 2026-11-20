"""Independent re-scan of a random sample of saved exhaustive results.

For each sampled candidate: regenerate it from the seed and the operator subset, compare its SHA-256 with the logged one,
re-run the behavior check and the real scanner, and compare the verdict with the logged verdict. Target: 0 disagreements.
Fixed RNG seed, equal numbers of evading and detected candidates.
usage (from the repository root):  .sastlab/.venv/bin/python analysis/rescan_sample.py <config> <seed dir> <n per class> <run> [<run> ...]
"""
import hashlib, json, random, sys
from pathlib import Path
from _paths import ROOT

code = ROOT
sys.path.insert(0, str(code))
from sastlab.oracle import Oracle
from sastlab.runner import load_config, scanner_from
from sastlab.transforms import OPERATORS, candidate

config, seed_dir, n, *runs = sys.argv[1:]
n = int(n)
rows = []
for run in runs:
    for line in (code / "results" / run / "evaluations.jsonl").read_text().splitlines():
        r = json.loads(line)
        if r["status"] == "evaluated" and r["scan_status"] == "ok" and r["equivalent"]:
            rows.append(r)
rng = random.Random(2026)
sample = rng.sample([r for r in rows if r["bypassed_rules"]], n) + rng.sample([r for r in rows if not r["bypassed_rules"]], n)
cfg = load_config(str(code / config)); scanner = scanner_from(cfg); oracle = Oracle(5)
work = ROOT / ".sastlab/rescan-work"; work.mkdir(parents=True, exist_ok=True)
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
mask = lambda ops: sum(1 << OPERATORS.index(o) for o in ops)
sha_bad, verdict_bad, eq_bad = [], [], []
for r in sample:
    source = (code / seed_dir / (r["seed"] + ".py")).read_text()
    cand = candidate(source, mask(r["operators"]))
    if sha(cand) != r["candidate_sha256"]:
        sha_bad.append(r["seed"])
    equivalent = bool(oracle.compare(oracle.evaluate(source), cand).get("equivalent"))
    scan = scanner.scan(cand, work / f"{r['seed']}-{mask(r['operators'])}")
    evaded = scan.status == "ok" and equivalent and cfg["target_rules"][0] not in set(scan.rules)
    if equivalent != r["equivalent"]:
        eq_bad.append(r["seed"])
    if evaded != bool(r["bypassed_rules"]):
        verdict_bad.append((r["seed"], r["operators"], bool(r["bypassed_rules"]), evaded, scan.status))
print(f"{runs}: sampled {n} evading + {n} detected | candidate-hash mismatches {len(sha_bad)} | behavior-check disagreements {len(eq_bad)} | "
      f"scanner-verdict disagreements {len(verdict_bad)} {verdict_bad}")
