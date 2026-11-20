"""Independent re-scan of a random sample of logged search attempts (including attempts answered from the persistent scan cache).

For each sampled attempt with a scan: regenerate the candidate from the seed and the logged mask, compare its SHA-256 with the log, scan it again from scratch
(no cache) and compare the rule set with the logged one. Equal numbers of evading and detected attempts per run where possible; fixed RNG seed.
usage (from the repository root): .sastlab/.venv/bin/python analysis/rescan_attempts.py <n per class> <run> [<run> ...]   (config and seeds read from each run's manifest)"""
import hashlib, json, random, sys
from pathlib import Path
from _paths import ROOT
code = ROOT; sys.path.insert(0, str(code))
from sastlab.runner import load_config, scanner_from
from sastlab.transforms import candidate

n = int(sys.argv[1]); work = ROOT / ".sastlab/rescan-attempts-work"; work.mkdir(parents=True, exist_ok=True)
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
tot = {"checked": 0, "cache_hits": 0, "sha_bad": 0, "verdict_bad": 0}
for run in sys.argv[2:]:
    man = json.loads((code / "results" / run / "manifest.json").read_text())["config"]
    cfgfile = code / "configs" / (run + ".json")
    cfg = load_config(str(cfgfile)); scanner = scanner_from(cfg)
    seeds = (cfgfile.parent / cfg["seeds"]).resolve() if not Path(cfg["seeds"]).is_absolute() else Path(cfg["seeds"])
    rows = {}
    for line in (code / "results" / run / "attempts.jsonl").read_text().splitlines():
        r = json.loads(line)
        if r.get("scan", {}).get("status") == "ok" and r.get("mask") is not None:
            rows[(r["seed"], r["mask"])] = r
    ev = [r for r in rows.values() if r["bypassed_rules"]]; de = [r for r in rows.values() if not r["bypassed_rules"]]
    rng = random.Random(2026)
    sample = rng.sample(ev, min(n, len(ev))) + rng.sample(de, min(n, len(de)))
    bad_sha = bad_v = hits = 0
    for r in sample:
        src = (seeds / (r["seed"] + ".py")).read_text()
        cand = candidate(src, r["mask"])
        if sha(cand) != r["candidate_sha256"]:
            bad_sha += 1
        scan = scanner.scan(cand, work / run / f"{r['seed']}-{r['mask']}")
        logged = sorted({f["rule_id"] for f in r["scan"]["findings"]})
        if scan.status != "ok" or sorted(scan.rules) != logged:
            bad_v += 1; print("DISAGREE", run, r["seed"], r["mask"], logged, sorted(scan.rules), scan.status)
        hits += bool(r.get("cache_hit"))
    print(f"{run}: {len(sample)} attempts ({sum(1 for r in sample if r['bypassed_rules'])} evading), logged-from-cache {hits}, sha mismatches {bad_sha}, verdict disagreements {bad_v}", flush=True)
    for k, v in (("checked", len(sample)), ("cache_hits", hits), ("sha_bad", bad_sha), ("verdict_bad", bad_v)):
        tot[k] += v
print("TOTAL", tot)
