"""RQ6: does an agent find the rewrite pair that Pysa needs? The numbers of the text (Table 6 itself: table6.py).

Question
  RQ6 of the paper and the Pysa number of its lessons paragraph: what the restricted pool holds, which pool rewrites
  evade Pysa together, how the agents choose with the original prompt, what the tool-aware and informed prompts change,
  and whether the coder diagnostic agent's gain over random choice repeats with other random seeds and other models.

Data (results/<run>/)
  pysa-main-pairs             exhaustive scans of every single rewrite and pair of rewrites on the 15 main seeds
  pysa-hard-qwen              search on the restricted pool (3 main seeds, 15 trajectories, budget 15): random (1),
                              heuristic (2), Metropolis walk (6), agents (3 history-only, 5 diagnostic), original prompt
  pysa-hard-informed-noorder  the agents with the tool-aware prompt (Pysa and its 2 rules described)
  pysa-hard-informed, -35b, -8b   the agents with the informed prompt (also states the rewrite order), coder, 35B and
                              8B models, base seed 6223
  pysa-rep1-*, pysa-rep2-*    the informed-prompt agents again with base seeds 7001 and 7002; the coder run of each
                              repeat also holds the random choice of that base seed

Method
  1. Pool = config.operators of the search manifest; left out = the manifest's other rewrites.
  2. Exhaustive evasion: a candidate scanned without error that behaves like its seed (common.scanned) on which neither
     Pysa rule fires (read from scan_rules: exhaustive runs list each silenced rule on its own in bypassed_rules).
  3. Search evasion = neither Pysa rule fires (`evasion: all`, common.evaded); per trajectory the attempt of the first
     evasion, 16 (budget + 1) for a miss.
  4. char_launder: attempts whose added rewrite (field `operator`) is char_launder, out of a strategy's 675 attempts.
  5. A minus B: per stream (trajectory index) the mean over the 3 seeds of A's value minus B's; mean over the 15
     streams with a 95% bootstrap interval (5,000 resamples, seed 11). A outperforms B when the interval lies below 0;
     they cannot be told apart when it contains 0.
  6. Repeats: each agent minus random choice of the same base seed; pooled = the 45 streams (trajectory index, base
     seed), in that sorted order, resampled the same way.

Output (stdout only): one line per number of the text, labeled with the sentence it backs, in the paper's order.
"""
import statistics as st

from common import attempts, bootstrap, compare, evaluations, first_evasions, found, heading, manifest, \
    paired_difference, per_stream, scanned, signed

SEARCH, TOOL_AWARE, INFORMED, EXHAUSTIVE = "pysa-hard-qwen", "pysa-hard-informed-noorder", "pysa-hard-informed", \
    "pysa-main-pairs"
REPEATS = {6223: ("pysa-hard-qwen", {"coder": "pysa-hard-informed", "35B": "pysa-hard-informed-35b",
                                     "8B": "pysa-hard-informed-8b"}),
           7001: ("pysa-rep1-coder", {m: f"pysa-rep1-{m.lower()}" for m in ("coder", "35B", "8B")}),
           7002: ("pysa-rep2-coder", {m: f"pysa-rep2-{m.lower()}" for m in ("coder", "35B", "8B")})}
RANDOM, HEURISTIC, HISTORY, DIAGNOSTIC, METROPOLIS = 1, 2, 3, 5, 6


def say(label, value):
    print(f"{label}: {value}")


def verdict(values):
    """'mean [interval]' of paired stream differences and where the interval lies relative to 0."""
    low, high = bootstrap(values)
    return f"{compare(values)}, " + ("below 0" if high < 0 else "above 0" if low > 0 else "includes 0")


def silenced_rules(rules):
    """{(seed, frozenset of rewrites): set of Pysa rules silenced} for the exhaustive candidates on the main seeds."""
    return {(r["seed"], frozenset(r["operators"])): set(rules) - set(r["scan_rules"])
            for r in evaluations(EXHAUSTIVE) if scanned(r)}


def seeds_where(silenced, ops, rules):
    """'evading seeds/scanned seeds' for one rewrite subset."""
    hits = [v == set(rules) for (seed, o), v in silenced.items() if o == frozenset(ops)]
    return f"{sum(hits)}/{len(hits)} seeds"


def pool_and_pairs(config, silenced):
    heading("Restricted pool and exhaustive pairs (main seeds)")
    pool, rules = config["operators"], config["target_rules"]
    alone = sorted({next(iter(o)) for (_, o), v in silenced.items() if len(o) == 1 and v == set(rules)})
    say("restricted pool, rewrites", f"{len(pool)} ({', '.join(pool)})")
    say("left out of the pool", ", ".join(op for op in manifest(SEARCH)["operators"] if op not in pool))
    say("the 2 round trips (rewrites that silence Pysa on their own)",
        "; ".join(f"{op} on {seeds_where(silenced, [op], rules)}" for op in alone))
    say("no single pool rewrite silences Pysa: pool rewrites that do", sum(op in pool for op in alone))
    subsets = {o for (_, o), _v in silenced.items() if o <= set(pool)}
    evading = sorted({o for (_, o), v in silenced.items() if o in subsets and v == set(rules)}, key=sorted)
    say("exhaustive pairs: pool subsets that evade Pysa", "; ".join(
        f"{' + '.join(sorted(o))} on {seeds_where(silenced, o, rules)}" for o in evading))
    say("pool subsets of 1-2 rewrites scanned", len(subsets))


def setup(config, records):
    heading("Setup of the search")
    exhaustive_files = manifest(EXHAUSTIVE)["identity"]["seed_sha256"]
    same = all(exhaustive_files.get(s) == h for s, h in manifest(SEARCH)["seed_sha256"].items())
    say("evasion only when neither of the 2 Pysa rules fires",
        f"evasion '{config['evasion']}' over {', '.join(config['target_rules'])}")
    say("3 main seeds", f"{len({r['seed'] for r in records})} (same files as the main seeds: {same})")
    say("15 trajectories each", config["trajectories"])
    say("budget of 15 attempts", config["attempts"])
    say("both agents use Qwen3 Coder Next", ", ".join(sorted({manifest(run)["config"]["llm"]["model"]
                                                               for run in (SEARCH, TOOL_AWARE, INFORMED)})))


def original_prompt(config, records, silenced):
    heading("Original prompt")
    pool = config["operators"]
    firsts = {s: first_evasions(SEARCH, s, records) for s in (RANDOM, HEURISTIC, METROPOLIS, HISTORY, DIAGNOSTIC)}
    say("random, heuristic and Metropolis walk all found evasions", ", ".join(
        f"{found(firsts[s], SEARCH)}/45" for s in (RANDOM, HEURISTIC, METROPOLIS)))
    say("neither agent found a single one (history-only, diagnostic)",
        ", ".join(f"{found(firsts[s], SEARCH)}/45" for s in (HISTORY, DIAGNOSTIC)))
    added = {s: [r["operator"] == "char_launder" for r in records if r["strategy"] == s]
             for s in (HISTORY, DIAGNOSTIC, RANDOM)}
    say("agents added char_launder in 234 and 221 of 675 attempts",
        f"{sum(added[HISTORY])} and {sum(added[DIAGNOSTIC])} of {len(added[HISTORY])}")
    say("compared with 108 for random choice", f"{sum(added[RANDOM])} of {len(added[RANDOM])}")
    alone = [not v for (_, o), v in silenced.items() if o == {"char_launder"}]
    pairs = [v == silenced[(seed, o - {"char_launder"})] for (seed, o), v in silenced.items()
             if "char_launder" in o and len(o) == 2 and o <= set(pool)]
    say("char_launder has no effect on Pysa (exhaustive)", f"alone silences no rule on {sum(alone)}/{len(alone)} "
        f"seeds; added to another pool rewrite, the silenced rules stay the same in {sum(pairs)}/{len(pairs)} pairs")
    ordered = sum(r["operators"] == sorted(r["operators"], key=pool.index) for r in records)
    say("a candidate only adds rewrites later in the fixed order", f"{ordered} of {len(records)} attempts")
    say("the original prompt never states the order", f"extra prompt text: {config['llm'].get('prompt_extra')}")


def new_prompts():
    heading("Tool-aware and informed prompts (exploratory)")
    for run, label in ((TOOL_AWARE, "describing Pysa and its 2 rules: at most 1 of 45"),
                       (INFORMED, "prompt also states the order: 20 and 34 of 45")):
        say(f"{label} (history-only, diagnostic)",
            ", ".join(f"{found(first_evasions(run, s), run)}/45" for s in (HISTORY, DIAGNOSTIC)))
    diagnostic = first_evasions(INFORMED, DIAGNOSTIC)
    for s, name in ((HEURISTIC, "heuristic"), (METROPOLIS, "Metropolis walk")):
        say(f"informed diagnostic agent minus {name} (cannot be told apart)",
            verdict(paired_difference(diagnostic, first_evasions(SEARCH, s))))


def repeats():
    heading("Informed prompt repeated with base seeds 6223, 7001, 7002 (agent minus random choice)")
    for model, strategy in (("coder", DIAGNOSTIC), ("35B", HISTORY), ("35B", DIAGNOSTIC), ("8B", HISTORY),
                            ("8B", DIAGNOSTIC)):
        pooled, means, below = {}, [], 0
        for base, (random_run, runs) in REPEATS.items():
            agent, rnd = first_evasions(runs[model], strategy), first_evasions(random_run, RANDOM)
            assert manifest(runs[model])["config"]["base_seed"] == manifest(random_run)["config"]["base_seed"] == base
            assert set(agent) == set(rnd)
            diffs = paired_difference(agent, rnd)
            pooled.update(zip(((t, base) for t in per_stream(agent)), diffs))
            means.append(st.mean(diffs))
            below += bootstrap(diffs)[1] < 0
        name = f"{model} {'diagnostic' if strategy == DIAGNOSTIC else 'history-only'} agent"
        say(f"{name} ({manifest(REPEATS[7001][1][model])['config']['llm']['model']}), mean difference per run",
            ", ".join(map(signed, means)) + f" ({sum(m < 0 for m in means)} of 3 below 0)")
        say(f"{name}, runs whose interval stays below 0", f"{below} of 3")
        say(f"{name}, pooled over the 3 runs", verdict([pooled[k] for k in sorted(pooled)]))


def lessons():
    heading("Lessons paragraph")
    say("the prompt alone took the coder diagnostic agent on Pysa from 0 to 34 of 45", " -> ".join(
        f"{found(first_evasions(run, DIAGNOSTIC), run)}/45" for run in (SEARCH, INFORMED)) + " (original -> informed)")


def main():
    config, records = manifest(SEARCH)["config"], attempts(SEARCH)
    silenced = silenced_rules(config["target_rules"])
    pool_and_pairs(config, silenced)
    setup(config, records)
    original_prompt(config, records, silenced)
    new_prompts()
    repeats()
    lessons()


if __name__ == "__main__":
    main()
