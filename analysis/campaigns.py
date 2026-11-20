"""The two full campaigns (semgrep-v6, codeql-v6) and the model and cache counts quoted in the report.

Per strategy: trajectories, trajectories with an evasion and the mean attempt of the first evasion (over the trajectories
that found one). For codeql-v6 also the scan times. Over every saved run: model requests and fallbacks to a random pick,
and the configs that use the persistent scan cache. Standard library only; prints plain text.
The report quotes the agents of the CodeQL campaign from their rerun with shuffled definitions (codeql-promptfix,
vs_heuristic.py); the means printed here for strategies 3 and 5 are those of the original fixed-order prompt.
"""
import collections
import json
import statistics as st

from _paths import RESULTS, ROOT


def rows(path):
    return [json.loads(line) for line in open(path) if line.strip()]


for run in ("semgrep-v6", "codeql-v6"):
    attempts = rows(RESULTS / run / "attempts.jsonl")
    walks = collections.defaultdict(list)
    for r in attempts:
        walks[(r["strategy"], r["seed"], r["trajectory"])].append(r)
    print(f"{run}: {len(attempts):,} attempts, scanner errors {sum(r['scan']['status'] != 'ok' for r in attempts)}")
    for s in range(1, 8):
        mine = [w for k, w in walks.items() if k[0] == s]
        firsts = [min(r["attempt"] for r in w if r["bypassed_rules"]) for w in mine if any(r["bypassed_rules"] for r in w)]
        mean = f"{st.mean(firsts):.2f}" if firsts else "--"
        print(f"  strategy {s}: {len(firsts)}/{len(mine)} trajectories with an evasion, first evasion at attempt {mean} on average")
    if run == "codeql-v6":
        seconds = [r["scan"]["seconds"] for r in attempts if r["scan"]["status"] == "ok"]
        print(f"  scan seconds: median {st.median(seconds):.0f}, mean {st.mean(seconds):.0f}, slowest {max(seconds):.0f}")

requests, fallbacks = 0, collections.Counter()
for manifest in sorted(RESULTS.glob("*/manifest.json")):
    log = manifest.parent / "llm.jsonl"
    if not log.exists():
        continue
    model = (json.loads(manifest.read_text()).get("config") or {}).get("llm", {}).get("model")
    for r in rows(log):
        requests += 1
        fallbacks[model] += bool(r.get("fallback"))
print(f"model requests over all saved runs: {requests:,}; fallbacks to a random pick: {sum(fallbacks.values())} "
      f"({', '.join(f'{m} {n}' for m, n in fallbacks.most_common() if n)})")
cached = [p.stem for p in sorted((ROOT / "configs").glob("*.json")) if json.loads(p.read_text()).get("scan_cache")]
print(f"configs with the persistent scan cache: {len(cached)} ({', '.join(cached)})")
