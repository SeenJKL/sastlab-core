"""Attempts to the first evasion of the LLM agents against the black-box heuristic (strategy 2), original prompt,
plus the Metropolis walk against the heuristic, the full CodeQL campaign and the unreported pilots.
Unit of resampling: the stream (trajectory index), averaged over the seeds; 5,000 bootstrap resamples. Writes vs_heuristic_numbers.tex.
"""
import collections
import json
import random
import statistics as st
from pathlib import Path
from _paths import RESULTS, OUT_DIR

RESULTS = RESULTS
OUT = OUT_DIR / "vs_heuristic_numbers.tex"
SCANNERS = {"Pat": ("semgrep-hard30", {"Eight": "semgrep-hard30", "Coder": "semgrep-hard30-qwen", "Big": "semgrep-hard30-q36"}),
            "Flow": ("codeql-more-base", {"Eight": "codeql-more-orig-8b", "Coder": "codeql-more-orig-qwen", "Big": "codeql-more-orig-q36"})}


def first_evasions(run):
    cap = json.loads((RESULTS / run / "manifest.json").read_text())["config"]["attempts"]
    first, keys = {}, set()
    for line in (RESULTS / run / "attempts.jsonl").read_text().splitlines():
        a = json.loads(line)
        key = (a["strategy"], a["seed"], a["trajectory"])
        keys.add(key)
        if a["bypassed_rules"] and a["scan"]["status"] == "ok":
            first[key] = min(first.get(key, cap + 1), a["attempt"])
    return {k: first.get(k, cap + 1) for k in keys}


def streams(first, strategy):
    per = collections.defaultdict(list)
    for (s, _seed, t), v in first.items():
        if s == strategy:
            per[t].append(v)
    return {t: st.mean(v) for t, v in per.items()}


def signed(x):
    return ("$-$" if x < 0 else "$+$") + f"{abs(x):.2f}"


def interval(d, n=5000, seed=11):
    """95% bootstrap interval of the mean: the resampling and the index of informed_other.py, more_streams.py, prompt_models.py,
    prompt_search.py, pysa_search.py and round2_analysis.py. Every interval has its own generator, so it does not depend on the comparisons computed before it."""
    r = random.Random(seed)
    m = sorted(st.mean(r.choices(d, k=len(d))) for _ in range(n))
    return m[int(0.025 * n)], m[int(0.975 * n) - 1]


lines = []
for scanner, (heuristic_run, agents) in SCANNERS.items():
    heuristic = streams(first_evasions(heuristic_run), 2)
    for model, run in agents.items():
        first = first_evasions(run)
        for strategy, label in ((3, "Hist"), (5, "Diag")):
            agent = streams(first, strategy)
            ts = sorted(set(agent) & set(heuristic))
            d = [agent[t] - heuristic[t] for t in ts]
            lo, hi = interval(d)
            name = f"vh{scanner}{model}{label}"
            lines.append(f"\\newcommand{{\\{name}Diff}}{{{signed(st.mean(d))}}}")
            lines.append(f"\\newcommand{{\\{name}Ci}}{{[{signed(lo)}, {signed(hi)}]}}")
            print(scanner, model, label, len(ts), signed(st.mean(d)), signed(lo), signed(hi))
# restricted Semgrep search (8B run): mean attempts of the three non-agent strategies, a miss counts as budget + 1
base = first_evasions("semgrep-hard30")
for strategy, name in ((1, "semRandMean"), (2, "semHeurMean"), (6, "semMetroMean")):
    values = [v for (s, _seed, _t), v in base.items() if s == strategy]
    lines.append(f"\\newcommand{{\\{name}}}{{{st.mean(values):.2f}}}")


def counted(run, strategy):
    """(found, total) trajectories of one strategy and the mean attempts, a miss counting as budget + 1."""
    first = first_evasions(run)
    cap = json.loads((RESULTS / run / "manifest.json").read_text())["config"]["attempts"]
    v = [x for (s, _seed, _t), x in first.items() if s == strategy]
    return sum(x <= cap for x in v), len(v), st.mean(v)


def paired(run_a, strategy_a, run_b, strategy_b, name):
    """Paired difference a - b over streams (trajectory index, averaged over seeds), 95% bootstrap interval."""
    a, b = streams(first_evasions(run_a), strategy_a), streams(first_evasions(run_b), strategy_b)
    ts = sorted(set(a) & set(b))
    d = [a[t] - b[t] for t in ts]
    lo, hi = interval(d)
    lines.append(f"\\newcommand{{\\{name}}}{{{signed(st.mean(d))}}}")
    lines.append(f"\\newcommand{{\\{name}Ci}}{{[{signed(lo)}, {signed(hi)}]}}")
    print(name, len(ts), signed(st.mean(d)), signed(lo), signed(hi))


# Metropolis (strategy 6) against the heuristic (2), and the informed Pysa diagnostic agent against Metropolis
paired("semgrep-hard30", 6, "semgrep-hard30", 2, "metroHeurSem")
paired("codeql-hard15", 6, "codeql-hard15", 2, "metroHeurFlow")
paired("pysa-hard-qwen", 6, "pysa-hard-qwen", 2, "metroHeurPysa")
paired("pysa-hard-informed", 5, "pysa-hard-qwen", 6, "diagMetroPysa")
# CodeQL pool with 15 streams (codeql-hard15): found and mean attempts of random, heuristic and Metropolis
for strategy, name in ((1, "Rand"), (2, "Heur"), (6, "Metro")):
    f, n, m = counted("codeql-hard15", strategy)
    lines.append(f"\\newcommand{{\\flowPool{name}Found}}{{{f}}}")
    lines.append(f"\\newcommand{{\\flowPool{name}Mean}}{{{m:.2f}}}")
    lines.append(f"\\newcommand{{\\flowPoolTotal}}{{{n}}}") if strategy == 1 else None
# Full CodeQL campaign (5 seeds x 5 streams, 8B model): the non-LLM strategies and the static ranking come from codeql-v6 (operator
# definitions in a fixed order); the two agents were rerun with shuffled definitions in codeql-promptfix.
for strategy, name in ((1, "Rand"), (2, "Heur"), (6, "MetroA"), (7, "MetroB")):
    lines.append(f"\\newcommand{{\\cqFull{name}}}{{{counted('codeql-v6', strategy)[2]:.2f}}}")
f, n, m = counted("codeql-v6", 4)
lines += [f"\\newcommand{{\\cqFullRankFound}}{{{f}}}", f"\\newcommand{{\\cqFullRankTotal}}{{{n}}}"]
for strategy, name in ((3, "Hist"), (5, "Diag")):
    lines.append(f"\\newcommand{{\\cqFull{name}Old}}{{{counted('codeql-v6', strategy)[2]:.2f}}}")
    lines.append(f"\\newcommand{{\\cqFull{name}Fixed}}{{{counted('codeql-promptfix', strategy)[2]:.2f}}}")
    assert counted("codeql-promptfix", strategy)[:2] == (25, 25)
# Pilots on the 9-operator pools with all 7 strategies (5 streams each, original prompt with shuffled definitions)
for run, tag in (("semgrep-hard", "SemPilot"), ("codeql-hard", "FlowPilot")):
    f, n, m = counted(run, 4)
    lines += [f"\\newcommand{{\\{tag}RankFound}}{{{f}}}", f"\\newcommand{{\\{tag}RankTotal}}{{{n}}}"]
    lines += [f"\\newcommand{{\\{tag}SixMean}}{{{counted(run, 6)[2]:.2f}}}", f"\\newcommand{{\\{tag}SevenMean}}{{{counted(run, 7)[2]:.2f}}}"]
OUT.write_text("\n".join(lines) + "\n")
