"""Shared helpers for the analysis scripts: where the saved runs are, how a run is read, what counts as an evasion,
and the statistics the report uses. Standard library only.

Evasion. The framework writes `bypassed_rules` for a candidate only when its scan succeeded and the behavior check
found it equivalent to the seed; the list holds the rules that fired on the seed but not on the candidate. A record
therefore counts as an evasion exactly when `bypassed_rules` is not empty. Runs with `evasion: all` (Pysa searches)
leave the list empty unless every rule of the seed is silent.

Search runs (`attempts.jsonl`) are compared by the attempt of the first evasion in each trajectory; a trajectory
without an evasion counts as budget + 1. A stream is trajectory index k over all seeds of a run: per-seed values are
averaged within a stream, and the stream is the unit of resampling for the bootstrap intervals (5,000 resamples).
"""
import collections
import json
import random
import statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


# ----------------------------------------------------------------------------------------------- reading saved runs

def jsonl(path):
    """The records of a .jsonl file."""
    with open(path) as handle:
        return [json.loads(line) for line in handle if line.strip()]


def manifest(run):
    return json.loads((RESULTS / run / "manifest.json").read_text())


def attempts(run):
    """One record per attempted candidate of a search run."""
    return jsonl(RESULTS / run / "attempts.jsonl")


def evaluations(run):
    """One record per (seed, operator subset) of an exhaustive run."""
    return jsonl(RESULTS / run / "evaluations.jsonl")


def budget(run):
    """Attempts per trajectory of a search run."""
    return manifest(run)["config"]["attempts"]


def evaded(record):
    """True when the scan succeeded, the behavior check passed and a rule that fired on the seed is silent."""
    return bool(record["bypassed_rules"])


def scanned(record):
    """An exhaustive record that counts as a candidate: evaluated, scanned without error and equivalent to its seed."""
    return record.get("status") == "evaluated" and record["scan_status"] == "ok" and record["equivalent"]


# ------------------------------------------------------------------------------------- attempts to the first evasion

def first_evasions(run, strategy, records=None):
    """{(seed, trajectory): attempt of the first evasion, or budget + 1 when the trajectory has none}."""
    cap = budget(run)
    walks = collections.defaultdict(list)
    for r in records if records is not None else attempts(run):
        if r["strategy"] == strategy:
            walks[(r["seed"], r["trajectory"])].append(r)
    return {key: min([r["attempt"] for r in walk if evaded(r)] or [cap + 1]) for key, walk in walks.items()}


def found(firsts, run):
    """Number of trajectories with an evasion."""
    cap = budget(run)
    return sum(v <= cap for v in firsts.values())


def mean(firsts):
    """Mean attempts to the first evasion over all trajectories (a miss counts as budget + 1)."""
    return st.mean(firsts.values())


def per_stream(firsts):
    """{trajectory index: mean over the seeds of that stream}."""
    groups = collections.defaultdict(list)
    for (_seed, trajectory), value in firsts.items():
        groups[trajectory].append(value)
    return {t: st.mean(v) for t, v in sorted(groups.items())}


def paired_difference(firsts_a, firsts_b):
    """Per-stream differences a - b over the (seed, trajectory) pairs both have, averaged over the seeds of a stream."""
    common = sorted(set(firsts_a) & set(firsts_b))
    a = per_stream({k: firsts_a[k] for k in common})
    b = per_stream({k: firsts_b[k] for k in common})
    return [a[t] - b[t] for t in a]


def bootstrap(values, n=5000, seed=11):
    """95% percentile interval of the mean of `values` from n resamples (fixed seed, so the numbers repeat)."""
    rng = random.Random(seed)
    means = sorted(st.mean(rng.choices(values, k=len(values))) for _ in range(n))
    return means[int(0.025 * n)], means[int(0.975 * n) - 1]


def compare(values):
    """Mean of paired stream differences with its interval, as printed in the report: '-5.01 [-6.87, -3.04]'."""
    low, high = bootstrap(values)
    return f"{signed(st.mean(values))} [{signed(low)}, {signed(high)}]"


# ---------------------------------------------------------------------------------------------------------- printing

def signed(x):
    return f"{x:+.2f}"


def claim(quote, *results):
    """Print a sentence of the report and, below it, what the saved runs give."""
    print(f'paper: "{quote}"')
    for line in results:
        print(f"  data: {line}")


def heading(text):
    print(f"\n== {text}")


def table(header, rows):
    """Print rows as an aligned plain-text table."""
    cells = [list(map(str, header))] + [list(map(str, r)) for r in rows]
    widths = [max(len(row[i]) for row in cells) for i in range(len(header))]
    for k, row in enumerate(cells):
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
        if k == 0:
            print("  ".join("-" * w for w in widths))
