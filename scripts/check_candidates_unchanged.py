"""Regression check for changes to sastlab/transforms.py: regenerate every saved candidate (seed + operator subset) of every exhaustive run
and compare its SHA-256 with the logged one. Exit status 1 on any difference. usage (from the repository root): .sastlab/.venv/bin/python scripts/check_candidates_unchanged.py"""
import hashlib, json, sys
from pathlib import Path

code = Path.cwd(); sys.path.insert(0, str(code))
from sastlab.transforms import OPERATORS, candidate

SEED_DIRS = [code / d for d in ("seeds", "seeds_diverse", "seeds_fstring", "seeds_cmd", "seeds_path", "corpus_official/seeds", "corpus_real/seeds", "corpus_apps/seeds", "seeds_pysa_hard", "seeds_pysa_hard2")]
seed_files = {p.stem: p for d in SEED_DIRS if d.exists() for p in d.glob("*.py")}
mask = lambda ops: sum(1 << OPERATORS.index(o) for o in ops)
seen, bad, missing = {}, [], 0
for run in sorted((code / "results").iterdir()):
    f = run / "evaluations.jsonl"
    if not f.exists():
        continue
    for line in f.read_text().splitlines():
        r = json.loads(line)
        if r.get("status") != "evaluated" or not r.get("candidate_sha256"):
            continue
        key = (r["seed"], tuple(sorted(r["operators"])))
        if key in seen:
            if seen[key] != r["candidate_sha256"]:
                bad.append(("log disagrees with itself", key))
            continue
        seen[key] = r["candidate_sha256"]
        if r["seed"] not in seed_files:
            missing += 1
            continue
        digest = hashlib.sha256(candidate(seed_files[r["seed"]].read_text(), mask(r["operators"])).encode()).hexdigest()
        if digest != r["candidate_sha256"]:
            bad.append((run.name, key))
print(f"{len(seen)} distinct logged candidates, {missing} with no seed file, {len(bad)} differences {bad[:3]}")
sys.exit(1 if bad else 0)
