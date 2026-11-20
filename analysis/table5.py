"""Table 5 of the report: mean attempts to the first evasion of the two LLM agents,
history-only (strategy 3) and diagnostic (strategy 5), with the original and the informed prompt, on the restricted
pools of Semgrep's pattern rule and CodeQL's data-flow query, for the 8B, coder and 35B models (stdout only).

Saved runs read (results/<name>/), per scanner. All runs of one scanner share the operator pool, the seeds, the
budget and the trajectory seeds (base seed 6223), so trajectory k of seed s is the same stream in every run.
  Semgrep, pattern rule: 9 operators, 3 f-string seeds x 30 streams, 15 attempts
    semgrep-hard30                                    random (strategy 1) and the 8B agents, original prompt
    semgrep-hard30-qwen, semgrep-hard30-q36           coder and 35B agents, original prompt
    semgrep-informed-8b, -qwen, -q36                  8B, coder and 35B agents, informed prompt
  CodeQL, data-flow query: 9 operators, seeds d01 and d02 x 15 streams, 12 attempts
    codeql-more-base                                  random (strategy 1) and heuristic (strategy 2)
    codeql-more-orig-8b, -qwen, -q36                  original prompt
    codeql-more-informed-8b, -qwen, -q36              informed prompt

Method:
  1. Each trajectory (seed, stream k) of a strategy gives the attempt of its first evasion: the scan succeeded, the
     candidate behaves like the seed and the rule no longer fires. A trajectory without one counts as budget + 1.
  2. A cell is the mean over all trajectories and, in brackets, the trajectories that found an evasion.
  3. Diff. is the informed agent minus random choice. The two are paired on (seed, k); the differences of stream k
     are averaged over the seeds, so the unit is the stream (30 for Semgrep, 15 for CodeQL). The table shows the
     mean over streams and a 95% bootstrap interval (5,000 resamples of the streams, fixed seed 11). The agent
     beats random when the interval lies below 0, is worse when it lies above 0, and cannot be told apart from
     random when it includes 0.
  Random choice uses no prompt, so its single value stands under both prompt columns.
Prints Table 5 in the paper's layout. rq3.py and rq4.py import RUNS and first_attempts from here.
"""
import collections
import functools

from common import attempts, budget, compare, first_evasions, found, mean, paired_difference, table

AGENTS = {3: "History-only", 5: "Diagnostic"}
RANDOM, HEURISTIC = 1, 2
# scanner: (run with random choice and the heuristic, {model: (original-prompt run, informed-prompt run)})
RUNS = {
    "Semgrep, pattern rule": ("semgrep-hard30", {
        "8B": ("semgrep-hard30", "semgrep-informed-8b"),
        "Coder": ("semgrep-hard30-qwen", "semgrep-informed-qwen"),
        "35B": ("semgrep-hard30-q36", "semgrep-informed-q36")}),
    "CodeQL, data-flow query": ("codeql-more-base", {
        "8B": ("codeql-more-orig-8b", "codeql-more-informed-8b"),
        "Coder": ("codeql-more-orig-qwen", "codeql-more-informed-qwen"),
        "35B": ("codeql-more-orig-q36", "codeql-more-informed-q36")}),
}


@functools.lru_cache(maxsize=None)
def first_attempts(run, strategy):
    """{(seed, trajectory): attempt of the first evasion, or budget + 1}, after checking that the run is complete:
    every trajectory of the strategy has exactly its budget of attempts."""
    records = attempts(run)
    per_trajectory = collections.Counter((r["seed"], r["trajectory"]) for r in records if r["strategy"] == strategy)
    assert per_trajectory and set(per_trajectory.values()) == {budget(run)}, (run, strategy)
    return first_evasions(run, strategy, records)


def cell(run, strategy):
    """'mean (found/trajectories)', as in the table."""
    firsts = first_attempts(run, strategy)
    return f"{mean(firsts):.2f} ({found(firsts, run)}/{len(firsts)})"


def minus_random(run, strategy, baseline_run):
    """Paired stream difference agent - random with its interval: '-2.32 [-4.52, -0.17]'."""
    agent, random_choice = first_attempts(run, strategy), first_attempts(baseline_run, RANDOM)
    assert set(agent) == set(random_choice), (run, baseline_run)  # same seeds and streams, so every pair exists
    return compare(paired_difference(agent, random_choice))


def rows():
    out = []
    for scanner, (baseline_run, models) in RUNS.items():
        out.append([scanner, "", "", "", ""])
        random_cell = cell(baseline_run, RANDOM)
        out.append(["Random", "--", random_cell, random_cell, "--"])
        for model, (original_run, informed_run) in models.items():
            for strategy, agent in AGENTS.items():
                out.append([model, agent, cell(original_run, strategy), cell(informed_run, strategy),
                            minus_random(informed_run, strategy, baseline_run)])
    return out


def main():
    print("Table 5. Mean attempts to the first evasion (trajectories with an evasion); "
          "Diff. is informed minus random.\n")
    table(["Model", "Agent", "Original", "Informed", "Diff. [95% interval]"], rows())


if __name__ == "__main__":
    main()
