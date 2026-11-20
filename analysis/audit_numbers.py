"""Recompute the restricted-search numbers quoted in result.md from the raw attempt logs.
Prints found / mean attempts to first evasion per strategy, seeds used, and paired bootstrap differences over streams."""
import collections as C, json, random, statistics as st, sys
from pathlib import Path
from _paths import RESULTS

R = RESULTS
rd = lambda p: [json.loads(x) for x in (R / p).read_text().splitlines() if x.strip()]


def run(name):
    m = json.loads((R / name / "manifest.json").read_text())
    cfg = m["config"]
    cap = cfg["attempts"]
    T = C.defaultdict(dict)
    for a in rd(f"{name}/attempts.jsonl"):
        T[(a["strategy"], a["seed"], a["trajectory"])][a["attempt"]] = a
    out = {}
    for (s, seed, t), d in T.items():
        f = next((n for n in sorted(d) if d[n]["bypassed_rules"]), cap + 1)
        out[(s, seed, t)] = (f, len(d), sum(1 for x in d.values() if x.get("error")))
    return cfg, cap, out


def stream_means(out, s, seeds=None):
    per = C.defaultdict(list)
    for (st_, seed, t), (f, n, e) in out.items():
        if st_ == s and (seeds is None or seed in seeds):
            per[t].append(f)
    return {t: st.mean(v) for t, v in per.items()}


def boot(a, b, rng, n=5000):
    ts = sorted(a)
    d = [a[t] - b[t] for t in ts]
    bs = sorted(st.mean(rng.choices(d, k=len(d))) for _ in range(n))
    return st.mean(d), bs[int(.025 * n)], bs[int(.975 * n) - 1]


if __name__ == "__main__":
    rng = random.Random(1)
    for name in sys.argv[1:]:
        cfg, cap, out = run(name)
        print(f"\n## {name}  model={cfg['llm']['model']} cap={cap} streams={cfg['trajectories']} strategies={cfg['strategies']}")
        seeds = sorted({k[1] for k in out})
        print("seeds", seeds)
        for s in cfg["strategies"]:
            rows = [v for k, v in out.items() if k[0] == s]
            found = sum(v[0] <= cap for v in rows)
            print(f"  strategy {s}: found {found}/{len(rows)} mean {st.mean(v[0] for v in rows):.2f} scan errors {sum(v[2] for v in rows)}")
