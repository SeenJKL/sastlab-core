"""Restarts of the Metropolis walks (strategies 6 and 7) and the check run without them.

Every saved run except the two walk checks used "metropolis_restart": true (the default): when the current subset holds the last operator of the
order, the walk restarts from the seed, and those runs logged this attempt with restarted=false. A restart shows up as a
proposal whose parent_mask is not the last accepted mask of its trajectory. The script asserts that every such jump goes to
the seed and happens exactly when no later operator is left, counts the jumps, and compares the walks without the restart
(semgrep-hard30-walk, pysa-hard-walk: same pools, seeds, trajectory seeds and budgets) with the saved walks and the heuristic.
Unit of resampling: the stream (trajectory index), averaged over the seeds; 5,000 bootstrap resamples with the generator of
vs_heuristic.py. Writes metropolis_numbers.tex.
"""
import collections
import json
import random
import statistics as st
from pathlib import Path
import sys

from _paths import RESULTS, OUT_DIR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sastlab.transforms import OPERATORS, available  # noqa: E402

OUT = OUT_DIR / "metropolis_numbers.tex"


def rows(run):
    return [json.loads(line) for line in (RESULTS / run / "attempts.jsonl").read_text().splitlines()]


def config(run):
    return json.loads((RESULTS / run / "manifest.json").read_text())["config"]


def restarts(run):
    """(attempts, restarts, restarts on or before the first evasion, trajectories with such a restart, trajectories)."""
    cfg = config(run)
    # the pool of the run; the full campaigns set none and used every operator that existed then (the first 13)
    names = cfg.get("operators") or json.loads((RESULTS / run / "manifest.json").read_text())["operators"]
    assert all(OPERATORS.index(n) == i for i, n in enumerate(json.loads((RESULTS / run / "manifest.json").read_text())["operators"]))
    pool = sorted(OPERATORS.index(n) for n in names)
    walks = collections.defaultdict(list)
    for r in rows(run):
        if r["strategy"] in (6, 7):
            walks[(r["seed"], r["strategy"], r["trajectory"])].append(r)
    total = jumps = early = hit = 0
    for walk in walks.values():
        current, evaded, touched = 0, False, False
        for r in sorted(walk, key=lambda r: r["attempt"]):
            total += 1
            if r["parent_mask"] != current:
                assert r["parent_mask"] == 0 and not available(current, pool), (run, r["seed"], r["trajectory"], r["attempt"])
                jumps += 1
                if not evaded:
                    early += 1
                    touched = True
            else:
                assert cfg.get("metropolis_restart", True) is False or available(current, pool) or current == 0, (run, r["attempt"])
            if r["accepted"]:
                current = r["mask"]
            if r["bypassed_rules"] and r["scan"]["status"] == "ok":
                evaded = True
        hit += touched
    return total, jumps, early, hit, len(walks)


def first_evasions(run, strategy):
    cap = config(run)["attempts"]
    first, keys = {}, set()
    for r in rows(run):
        if r["strategy"] != strategy:
            continue
        key = (r["seed"], r["trajectory"])
        keys.add(key)
        if r["bypassed_rules"] and r["scan"]["status"] == "ok":
            first[key] = min(first.get(key, cap + 1), r["attempt"])
    return {k: first.get(k, cap + 1) for k in keys}, cap


def streams(first):
    per = collections.defaultdict(list)
    for (_seed, t), v in first.items():
        per[t].append(v)
    return {t: st.mean(v) for t, v in per.items()}


def interval(d, n=5000, seed=11):
    r = random.Random(seed)
    m = sorted(st.mean(r.choices(d, k=len(d))) for _ in range(n))
    return m[int(0.025 * n)], m[int(0.975 * n) - 1]


def signed(x):
    return ("$-$" if x < 0 else "$+$") + f"{abs(x):.2f}"


lines = []
print(f"{'run':16s} {'attempts':>8s} {'restarts':>8s} {'before 1st evasion':>18s} {'trajectories hit':>16s}")
for run, tag in (("semgrep-v6", "SemFull"), ("codeql-v6", "FlowFull"), ("semgrep-hard", "SemPilot"), ("codeql-hard", "FlowPilot"),
                 ("semgrep-hard30", "SemPool"), ("codeql-hard15", "FlowPool"), ("pysa-hard-qwen", "PysaPool")):
    total, jumps, early, hit, n = restarts(run)
    print(f"{run:16s} {total:8d} {jumps:8d} {early:18d} {hit:10d} of {n:3d}")
    lines += [f"\\newcommand{{\\restart{tag}Hit}}{{{hit}}}", f"\\newcommand{{\\restart{tag}Traj}}{{{n}}}",
              f"\\newcommand{{\\restart{tag}Early}}{{{early}}}", f"\\newcommand{{\\restart{tag}Attempts}}{{{total}}}",
              f"\\newcommand{{\\restart{tag}Jumps}}{{{jumps}}}"]

for saved, rerun, tag in (("semgrep-hard30", "semgrep-hard30-walk", "Sem"), ("pysa-hard-qwen", "pysa-hard-walk", "Pysa")):
    manifest = RESULTS / rerun / "manifest.json"
    if not manifest.exists() or json.loads(manifest.read_text()).get("state") != "complete":
        print(f"{rerun}: not complete yet (scripts/queue_walk_check.sh)")
        continue
    cfg_a, cfg_b = config(saved), config(rerun)
    same = ("seeds", "operators", "attempts", "trajectories", "base_seed", "metropolis_temperature", "target_rules")
    assert all(Path(str(cfg_a.get(k))).name == Path(str(cfg_b.get(k))).name if k == "seeds" else cfg_a.get(k) == cfg_b.get(k) for k in same), rerun
    assert cfg_b["metropolis_restart"] is False and cfg_b["strategies"] == [6]
    total, jumps, early, hit, n = restarts(rerun)
    assert jumps == 0, (rerun, jumps)
    new, cap = first_evasions(rerun, 6)
    old, _ = first_evasions(saved, 6)
    heur, _ = first_evasions(saved, 2)
    assert set(new) == set(old) == set(heur)
    found = sum(v <= cap for v in new.values())
    mean = st.mean(new.values())
    lines += [f"\\newcommand{{\\walk{tag}Found}}{{{found}}}", f"\\newcommand{{\\walk{tag}Total}}{{{len(new)}}}",
              f"\\newcommand{{\\walk{tag}Mean}}{{{mean:.2f}}}",
              f"\\newcommand{{\\walk{tag}SavedFound}}{{{sum(v <= cap for v in old.values())}}}",
              f"\\newcommand{{\\walk{tag}SavedMean}}{{{st.mean(old.values()):.2f}}}"]
    print(f"{rerun}: {total} attempts, 0 restarts; found {found}/{len(new)}, mean {mean:.2f} "
          f"(saved walk {sum(v <= cap for v in old.values())}/{len(old)}, {st.mean(old.values()):.2f}; "
          f"heuristic {sum(v <= cap for v in heur.values())}/{len(heur)}, {st.mean(heur.values()):.2f})")
    for other, label in ((old, "Saved"), (heur, "Heur")):
        a, b = streams(new), streams(other)
        d = [a[t] - b[t] for t in sorted(a)]
        lo, hi = interval(d)
        lines += [f"\\newcommand{{\\walk{tag}Minus{label}}}{{{signed(st.mean(d))}}}",
                  f"\\newcommand{{\\walk{tag}Minus{label}Ci}}{{[{signed(lo)}, {signed(hi)}]}}"]
        print(f"   walk without restart minus {label.lower()}: {signed(st.mean(d))} [{signed(lo)}, {signed(hi)}] over {len(d)} streams")
OUT.write_text("\n".join(lines) + "\n")
