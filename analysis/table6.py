"""Pysa restricted-pool search table (folded into RQ6 prose in the 8-page report; budget 15; no evasion = 16).

Question
  RQ6 of the paper ("Does an agent find the rewrite pair that Pysa needs?"): how many attempts each search strategy
  needs to evade Pysa on the restricted pool, and how the agents change with the prompt they are given.

Data (results/<run>/, all on the 3 seeds of seeds_pysa_hard, 15 trajectories per seed, budget 15, base seed 6223)
  pysa-hard-qwen              Baseline rows: strategy 1 random, 2 heuristic, 6 Metropolis walk (the saved walk with
                              the default restart). Original rows: agents 3 history-only and 5 diagnostic; the prompt
                              names neither Pysa nor the rewrite order.
  pysa-hard-informed-noorder  Tool-aware rows: the prompt also describes Pysa and its 2 rules (llm.prompt_extra).
  pysa-hard-informed          Informed rows: the tool-aware text plus the fixed order in which a candidate grows.
  The agents use the model in each manifest (llm.model).

Method
  1. Pool: the 9 rewrites in the manifest (config.operators), the restricted Pysa pool without the 2 round trips that
     silence Pysa on their own.
  2. Evasion: the scan succeeded, the candidate behaves like its seed and neither Pysa rule (5005, 5051) fires. These
     runs use `evasion: all`, so `bypassed_rules` is filled only then (common.evaded).
  3. Per trajectory (seed, trajectory index): the attempt of its first evasion; a trajectory without one counts as 16
     (budget + 1). Mean = mean over the 45 trajectories; Found = trajectories with an evasion, out of 45.
  4. 95% interval of the mean: a stream is trajectory index k, valued at the mean of its 3 seeds. The 15 stream values
     are resampled with replacement 5,000 times (random seed 11) and the 2.5th and 97.5th percentiles of the resampled
     means form the interval (common.bootstrap). Every stream has all 3 seeds, so the mean of the stream values is the
     mean over the 45 trajectories.

Output (stdout only)
  The prompt each run used (from the manifests), a completeness check, and Table 6 in the paper's layout.
"""
import collections

from common import attempts, bootstrap, budget, first_evasions, found, heading, manifest, mean, per_stream, table

ROWS = [  # (prompt, strategy name, run, strategy number), in the paper's order
    ("Baseline", "Random", "pysa-hard-qwen", 1),
    ("Baseline", "Heuristic", "pysa-hard-qwen", 2),
    ("Baseline", "Metropolis", "pysa-hard-qwen", 6),
    ("Original", "History-only", "pysa-hard-qwen", 3),
    ("Original", "Diagnostic", "pysa-hard-qwen", 5),
    ("Tool-aware", "History-only", "pysa-hard-informed-noorder", 3),
    ("Tool-aware", "Diagnostic", "pysa-hard-informed-noorder", 5),
    ("Informed", "History-only", "pysa-hard-informed", 3),
    ("Informed", "Diagnostic", "pysa-hard-informed", 5),
]
RUNS = list(dict.fromkeys(run for _, _, run, _ in ROWS))


def yes_no(flag):
    return "yes" if flag else "no"


def describe_runs():
    """What each run told the agents beyond the base prompt (config llm.prompt_extra), and its setup."""
    heading("Runs and prompts (from the manifests)")
    for run in RUNS:
        config = manifest(run)["config"]
        extra = config["llm"].get("prompt_extra", "")
        print(f"{run}: model {config['llm']['model']}, {len(config['operators'])} rewrites, "
              f"{config['trajectories']} trajectories, budget {config['attempts']}, base seed {config['base_seed']}; "
              f"prompt describes Pysa's 2 rules: {yes_no('Rule 5005' in extra and 'Rule 5051' in extra)}; "
              f"prompt states the rewrite order: {yes_no('fixed order' in extra)}")


def check_complete(run, strategy):
    """Assert 45 trajectories with every attempt 1..budget present once; return the trajectory count."""
    seen = collections.defaultdict(list)
    for r in attempts(run):
        if r["strategy"] == strategy:
            seen[(r["seed"], r["trajectory"])].append(r["attempt"])
    expected = list(range(1, budget(run) + 1))
    assert len(seen) == 45 and all(sorted(a) == expected for a in seen.values()), (run, strategy)
    return len(seen)


def row(prompt, name, run, strategy):
    """One table row: mean attempts to the first evasion with its stream-bootstrap interval, and Found."""
    firsts = first_evasions(run, strategy)
    low, high = bootstrap(list(per_stream(firsts).values()))
    return [prompt, name, f"{mean(firsts):.2f} [{low:.2f}, {high:.2f}]", f"{found(firsts, run)}/{len(firsts)}"]


def main():
    describe_runs()
    heading("Completeness")
    for prompt, name, run, strategy in ROWS:
        print(f"{prompt} {name} ({run}, strategy {strategy}): {check_complete(run, strategy)} trajectories "
              f"x {budget(run)} attempts")
    heading("Table 6. Attempts to the first evasion on Pysa (budget 15; no evasion = 16)")
    table(["Prompt", "Strategy", "Mean [95% interval]", "Found"], [row(*spec) for spec in ROWS])


if __name__ == "__main__":
    main()
