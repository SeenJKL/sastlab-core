"""RQ3 of the report (Section 4.3, "Do LLM agents find evasions more efficiently than search without a model?").

Saved runs read (results/<name>/):
  semgrep-v6, codeql-v6        full campaigns: 7 strategies x 5 trajectories x 30 attempts, 15 main seeds on Semgrep and
                               5 on CodeQL, 8B model; summary.json holds the run's report card (class of the rule)
  semgrep-hard30               restricted Semgrep pool (3 seeds x 30 streams, 15 attempts): random (strategy 1),
                               heuristic (2), Metropolis walk (6) and the 8B agents with the original prompt
  pysa-hard-qwen               restricted Pysa pool (3 seeds x 15 streams, 15 attempts), with a Metropolis walk
  semgrep-hard30-walk, pysa-hard-walk   the walk rerun without its restart: same pool, seeds, streams and budget
  the agent runs of Table 5    table5.RUNS: original and informed prompt, random and heuristic baselines
  semgrep-rep1-8b, semgrep-rep2-8b      repeats of semgrep-informed-8b (base seeds 7001, 7002), each with its own
                               random choice on the same streams

Method:
  1. Per trajectory (seed, stream k): the attempt of the first evasion (scan ok, behavior equal to the seed, rule
     silent); a trajectory without one counts as budget + 1. Means are over all trajectories.
  2. Two strategies are compared on the same (seed, k) pairs: the differences of stream k are averaged over the
     seeds, and the mean over streams gets a 95% bootstrap interval (5,000 resamples of the streams, seed 11).
     Interval below 0: the first needs fewer attempts (it beats the second); above 0: it is worse; includes 0: the
     two cannot be told apart. The pooled repeats resample their 3 x 30 streams together.
  3. Weak (the proposal's class): a strategy without a model evades on at least half of the rule's seeds.
  4. A walk restarts when a proposal's parent subset is not the walk's last accepted subset. The script asserts that
     every such jump goes back to the seed and happens exactly when no later operator of the pool is left, and
     counts the trajectories with a restart on or before the attempt of their first evasion.
Prints the per-strategy results, then each sentence of RQ3 with the numbers behind it.
"""
import collections
import json
import math
import statistics
from pathlib import Path

from common import RESULTS, attempts, bootstrap, claim, evaded, found, heading, manifest, mean, paired_difference, \
    per_stream, signed, table
from table5 import AGENTS, HEURISTIC, RANDOM, RUNS, first_attempts

NAMES = {1: "random", 2: "heuristic", 3: "history-only agent", 4: "static ranking", 5: "diagnostic agent",
         6: "Metropolis walk (syntax distance)", 7: "Metropolis walk (call chain)"}
WITHOUT_MODEL, WALK = (1, 2, 6, 7), 6
REPEATS_8B = {6223: ("semgrep-informed-8b", "semgrep-hard30"), 7001: ("semgrep-rep1-8b", "semgrep-rep1-8b"),
              7002: ("semgrep-rep2-8b", "semgrep-rep2-8b")}  # base seed: (informed 8B agent run, its random run)
COLUMNS = ORIGINAL_HEURISTIC, ORIGINAL_RANDOM, INFORMED_RANDOM = (
    "Original - heuristic", "Original - random", "Informed - random")  # agent minus baseline, with which prompt
BOTH_8B, BOTH_35B = [("CodeQL", "8B", 3), ("CodeQL", "8B", 5)], [("CodeQL", "35B", 3), ("CodeQL", "35B", 5)]
PARAGRAPH_3 = [  # (sentence of the report, columns, the (scanner, model, strategy) of the agents it is about)
    ("the diagnostic agents of the coder and 35B models needed fewer attempts than the heuristic ... by 4.32 and "
     "2.31 on Semgrep", [ORIGINAL_HEURISTIC], [("Semgrep", "Coder", 5), ("Semgrep", "35B", 5)]),
    ("and by 1.43 and 2.57 on CodeQL", [ORIGINAL_HEURISTIC], [("CodeQL", "Coder", 5), ("CodeQL", "35B", 5)]),
    ("the 8B agents were no better than random choice on Semgrep", [ORIGINAL_RANDOM],
     [("Semgrep", "8B", 3), ("Semgrep", "8B", 5)]),
    ("and worse on CodeQL", [ORIGINAL_RANDOM], BOTH_8B),
    ("[informed prompt] all 3 models then beat random choice on Semgrep", [INFORMED_RANDOM],
     [("Semgrep", m, s) for m in ("8B", "Coder", "35B") for s in AGENTS]),
    ("On CodeQL, the 35B agents still win", [INFORMED_RANDOM], BOTH_35B),
    ("the coder history-only agent becomes worse than random choice", [INFORMED_RANDOM], [("CodeQL", "Coder", 3)]),
    ("and the 8B agents stay worse", [INFORMED_RANDOM], BOTH_8B),
    ("Answer: The 35B agents beat random choice on CodeQL with both prompts", [ORIGINAL_RANDOM, INFORMED_RANDOM],
     BOTH_35B),
    ("and the 8B agents do worse with both", [ORIGINAL_RANDOM, INFORMED_RANDOM], BOTH_8B),
]


def verdict(differences):
    """'-0.23 [-1.63, +1.20] includes 0' for a list of per-stream differences."""
    low, high = bootstrap(differences)
    where = "below 0" if high < 0 else "above 0" if low > 0 else "includes 0"
    return f"{signed(statistics.mean(differences))} [{signed(low)}, {signed(high)}] {where}"


def versus(run_a, strategy_a, run_b, strategy_b):
    a, b = first_attempts(run_a, strategy_a), first_attempts(run_b, strategy_b)
    assert set(a) == set(b), (run_a, run_b)  # the same seeds and streams: every trajectory has its pair
    return verdict(paired_difference(a, b))


def outcome(run, strategy):
    firsts = first_attempts(run, strategy)
    return found(firsts, run), len(firsts), mean(firsts)


def full_campaign(run):
    """{strategy: (found, trajectories, mean)} and the rule's class from the report card, rechecked."""
    heading(f"{run}: full campaign, 8B model")
    result = {s: outcome(run, s) for s in range(1, 8)}
    table(["Strategy", "Name", "Found", "Mean attempts"],
          [[s, NAMES[s], f"{f}/{n}", f"{m:.2f}"] for s, (f, n, m) in result.items()])
    (card,) = json.loads((RESULTS / run / "summary.json").read_text())["report_cards"]
    seeds, records = set(card["qualifying_seeds"]), attempts(run)
    evading = {s: len(seeds & {r["seed"] for r in records if r["strategy"] == s and evaded(r)}) for s in (1, 2)}
    print(f"report card of {card['rule']}: {card['classification']} (random evades on {evading[1]}, the heuristic "
          f"on {evading[2]} of {len(seeds)} seeds; Weak needs {math.ceil(len(seeds) / 2)})")
    return result, card["classification"]


def restarts(run):
    """'h of n': walk trajectories with a restart on or before their first evasion, of all walk trajectories."""
    m = manifest(run)
    order = m["operators"]  # bit i of a mask is operator order[i]
    pool = [order.index(name) for name in m["config"].get("operators") or order]
    restart_on = m["config"].get("metropolis_restart") is not False
    walks = collections.defaultdict(list)
    for r in attempts(run):
        if r["strategy"] in (6, 7):
            walks[(r["seed"], r["strategy"], r["trajectory"])].append(r)
    hit = 0
    for walk in walks.values():
        current, evaded_yet, early = 0, False, False
        for r in sorted(walk, key=lambda r: r["attempt"]):
            last_operator_reached = not any(i >= current.bit_length() for i in pool)
            jumped = r["parent_mask"] != current
            assert jumped == (restart_on and last_operator_reached) and r["parent_mask"] in (current, 0), (run, r)
            early = early or (jumped and not evaded_yet)
            current = r["mask"] if r["accepted"] else current
            evaded_yet = evaded_yet or evaded(r)
        hit += early
    return f"{hit} of {len(walks)}"


def rerun_without_restart(saved, rerun):
    """The walk's mean with and without the restart and the paired comparisons, after checking the setups match."""
    a, b = manifest(saved)["config"], manifest(rerun)["config"]
    keys = ("operators", "attempts", "trajectories", "base_seed", "metropolis_temperature", "target_rules")
    assert all(a.get(k) == b.get(k) for k in keys) and Path(a["seeds"]).name == Path(b["seeds"]).name
    assert b["metropolis_restart"] is False and b["strategies"] == [WALK] and restarts(rerun).startswith("0 ")
    return (f"{saved} -> {rerun}: walk mean {outcome(saved, WALK)[2]:.2f} -> {outcome(rerun, WALK)[2]:.2f}; rerun - "
            f"saved walk {versus(rerun, WALK, saved, WALK)}; rerun - heuristic {versus(rerun, WALK, saved, HEURISTIC)}")


def pooled_8b(strategy):
    """Informed 8B agent minus random in each of the 3 repeats and pooled (90 streams, by stream, then repeat)."""
    streams, lines = {}, []
    for base_seed, (agent_run, random_run) in REPEATS_8B.items():
        assert manifest(agent_run)["config"]["base_seed"] == manifest(random_run)["config"]["base_seed"] == base_seed
        lines.append(f"base seed {base_seed} ({agent_run}): {versus(agent_run, strategy, random_run, RANDOM)}")
        a, b = per_stream(first_attempts(agent_run, strategy)), per_stream(first_attempts(random_run, RANDOM))
        streams.update({(k, base_seed): a[k] - b[k] for k in a})
    return lines + [f"pooled over {len(streams)} streams: {verdict([streams[key] for key in sorted(streams)])}"]


def paragraph_1():
    (semgrep, semgrep_class), (codeql, codeql_class) = full_campaign("semgrep-v6"), full_campaign("codeql-v6")
    promptfix = {s: outcome("codeql-promptfix", s) for s in (3, 5)}  # shuffled-definition rerun of the 8B agents
    semgrep_means, no_model = [m for *_, m in semgrep.values()], [codeql[s][2] for s in WITHOUT_MODEL]
    heading("RQ3, paragraph 1: full campaigns")
    claim("On Semgrep, every strategy found an evasion in every trajectory",
        "found " + ", ".join(f"{f}/{n}" for f, n, _ in semgrep.values()))
    claim("after 1.6 to 2.1 attempts on average", f"{min(semgrep_means):.2f} to {max(semgrep_means):.2f}")
    claim("on CodeQL the strategies without a model needed 2.00 to 2.80 attempts",
        f"{min(no_model):.2f} to {max(no_model):.2f}")
    claim("while the 8B agents needed 3.64 and 4.20",
        f"codeql-promptfix (shuffled definitions): {promptfix[3][2]:.2f} and {promptfix[5][2]:.2f}",
        f"codeql-v6 (fixed definition order): {codeql[3][2]:.2f} and {codeql[5][2]:.2f}")
    claim("the static ranking succeeded in only 16 of 25 trajectories", f"{codeql[4][0]} of {codeql[4][1]}")
    claim("Both rules are therefore Weak", f"Semgrep {semgrep_class}, CodeQL {codeql_class}")


def paragraph_2():
    heading("RQ3, paragraph 2: restricted Semgrep pool (semgrep-hard30) and the walk restarts")
    claim("the heuristic and the Metropolis walk found an evasion in all 90 trajectories after 5.47 and 5.23 attempts",
        *("%s: %d of %d after %.2f" % (NAMES[s], *outcome("semgrep-hard30", s)) for s in (HEURISTIC, WALK)))
    claim("against 66 trajectories and 8.37 attempts for random choice",
        "%d of %d after %.2f" % outcome("semgrep-hard30", RANDOM))
    claim("the heuristic and the walk cannot be told apart [walk - heuristic]",
        versus("semgrep-hard30", WALK, "semgrep-hard30", HEURISTIC))
    claim("This happened before the first evasion in 42 of 90 trajectories here", restarts("semgrep-hard30"))
    claim("and in 30 of 45 on Pysa", restarts("pysa-hard-qwen"))
    claim("a rerun without it changed the means from 5.23 and 9.20 to 5.28 and 9.27, with both paired intervals "
        "including 0", rerun_without_restart("semgrep-hard30", "semgrep-hard30-walk"),
        rerun_without_restart("pysa-hard-qwen", "pysa-hard-walk"))


def paragraph_3():
    heading("RQ3, paragraph 3 and answer: agents minus the heuristic or random choice (runs of Table 5)")
    cmp, rows = {}, []
    for scanner, (base, models) in RUNS.items():
        for model, (original, informed) in models.items():
            for s, agent in AGENTS.items():
                key = (scanner.split(",")[0], model, s)
                cmp[key] = dict(zip(COLUMNS, (versus(original, s, base, HEURISTIC), versus(original, s, base, RANDOM),
                                              versus(informed, s, base, RANDOM))))
                rows.append([key[0], model, agent, *cmp[key].values()])
    table(["Scanner", "Model", "Agent", *COLUMNS], rows)
    for sentence, columns, agents in PARAGRAPH_3:
        claim(sentence, *(f"{sc} {m} {AGENTS[s].lower()}, {c}: {cmp[sc, m, s][c]}"
                        for sc, m, s in agents for c in columns))
    claim("the 8B diagnostic agent [beats random choice on Semgrep] only when its 3 runs are pooled", *pooled_8b(5))


if __name__ == "__main__":
    paragraph_1()
    paragraph_2()
    paragraph_3()
