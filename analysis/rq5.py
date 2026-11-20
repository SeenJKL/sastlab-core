"""RQ5 of the report, "Do the findings carry over to Pysa?": the numbers of its first paragraph and the countable facts
of its answer.

Question
  Pysa tracks taint like CodeQL's query but reports an SQL injection through 2 rules. Which single rewrites and which
  pairs of rewrites silence both rules, and are they the rewrites that silence Semgrep and CodeQL?

Data (results/<run>/, read through table3.py)
  The 5 exhaustive Pysa runs of Table 3 (table3.PYSA_RUNS): pysa-main-singles and pysa-main-pairs (15 main seeds),
  pysa-diverse-singles (12 varied seeds, of which 10 qualify) and pysa-official-singles and pysa-official-pairs
  (9 official seeds). A *-singles run tries each of the 18 rewrites alone on each qualifying seed, a *-pairs run each
  rewrite alone and each pair. The answer also uses the Semgrep and CodeQL columns of Table 3.

Method
  1. Candidates as in table3.py (table3.pysa_candidates): a (seed, set of rewrites) scanned without error and
     equivalent to its seed on the oracle inputs, counted once. Records that were scanned but failed the scan or
     changed behavior are counted on their own; records of a rewrite that does not apply ("invalid") are not scanned.
  2. A candidate evades Pysa when both rules are silenced: 5005 (flow rule) and 5051 (string rule) do not fire.
  3. Singles have 1 rewrite, pairs 2. A pair evades "without a rewrite that evades alone" when it evades and neither
     of its 2 rewrites evades alone on the same seed.
  4. Rewrite classes of Table 1: sink resolution (SINK_RESOLUTION), controls and restructuring (BASELINE).
  5. Answer: an analyzer fails on a rewrite when the rewrite alone silences it on at least 1 seed (a nonzero cell of
     Table 3; for Pysa the both-rules column).

The second paragraph of RQ5 (causes) re-scans with added taint models and is not computed here (see the last line).

Output (stdout only, no file): the paragraph's sentences in order, each with the counts behind it, then the answer.
"""
import collections

from common import claim, evaluations, heading
from table3 import COLUMNS, PYSA_RUNS, pysa_candidates, pysa_rules, single_rewrite_columns

SINK_RESOLUTION = {"dict_dispatch", "dynamic_sink", "partial_sink", "methodcaller_sink", "unbound_sink"}
ROUND_TRIPS = {"db_roundtrip", "simplequeue_roundtrip"}
BASELINE = {"rename", "format_swap", "literal_slice", "dead_padding", "extract_1", "extract_2", "branch_split"}


def corpus(seed):
    return "main" if seed.startswith("seed_") else "varied" if seed.startswith("d") else "official"


def by_corpus(seeds):
    count = collections.Counter(map(corpus, seeds))
    return f"{len(seeds)} ({', '.join(f'{c} {count[c]}' for c in ('main', 'varied', 'official') if count[c])})"


def scope(candidates, singles, pairs):
    rules = pysa_rules()
    records = [e for run in PYSA_RUNS for e in evaluations(run)]
    tried = [e for e in records if len(e["operators"]) == 2]
    scanned = [e for e in records if e["status"] == "evaluated"]
    claim("every single rewrite on the 34 Pysa seeds",
          f"seeds qualifying: {by_corpus([s for s, r in rules.items() if r])} of {len(rules)}",
          f"single candidates: {len(singles):,} of {len({op for _s, (op,) in singles})} rewrites on "
          f"{by_corpus({s for s, _ in singles})} seeds")
    claim("and every pair of the 18 rewrites on the 24 qualifying main and official seeds",
          f"pairs tried: {len(tried):,} on {by_corpus({e['seed'] for e in tried})} seeds, "
          f"{sum(e['status'] == 'invalid' for e in tried)} rejected because a rewrite does not apply",
          f"pair candidates: {len(pairs):,} of {len({op for _s, ops in pairs for op in ops})} rewrites")
    claim("3,994 distinct candidates with no scan error and no change of behavior",
          f"distinct candidates: {len(candidates):,}; scanned records with a scan error: "
          f"{sum(e['scan_status'] != 'ok' for e in scanned)}, "
          f"with a change of behavior: {sum(e['scan_status'] == 'ok' and not e['equivalent'] for e in scanned)}")


def share(values, rule):
    return f"{sum(v[rule] for v in values)}/{len(values)}"


def single_results(singles):
    alone = sorted({op for (_s, (op,)), v in singles.items() if v["both"]})
    claim("Only the round trips through a database or a SimpleQueue silence both Pysa rules on their own",
          f"rewrites that silence both rules alone: {', '.join(alone)} "
          f"({share([v for (_s, (op,)), v in singles.items() if op in alone], 'both')} single candidates)")
    sink = [v for (_s, (op,)), v in singles.items() if op in SINK_RESOLUTION]
    literal = [v for (_s, ops), v in singles.items() if ops == ("literal_slice",)]
    claim("The 5 sink-resolution rewrites remove the flow rule but not the string rule",
          f"flow rule silenced {share(sink, 'flow')}, string rule silenced {share(sink, 'string')}")
    claim("and literal_slice does the reverse",
          f"flow rule silenced {share(literal, 'flow')}, string rule silenced {share(literal, 'string')}")


def pair_results(candidates, pairs):
    combined = [v for (_s, ops), v in pairs.items() if "literal_slice" in ops and set(ops) & SINK_RESOLUTION]
    claim("so all 120 pairs that combine them evade",
          f"pairs of literal_slice and a sink-resolution rewrite that evade: {share(combined, 'both')}")
    evading = [k for k, v in pairs.items() if v["both"]]
    new = [(s, ops) for s, ops in evading if not any(candidates[(s, (op,))]["both"] for op in ops)]
    kinds = collections.Counter(next(op for op in ops if op not in SINK_RESOLUTION) for _s, ops in new
                                if set(ops) & SINK_RESOLUTION)
    claim("Altogether 914 of 3,388 pairs evade, 130 of them without a rewrite that evades alone",
          f"pairs that evade: {len(evading):,} of {len(pairs):,}",
          f"without a rewrite that evades alone: {len(new)}, of which a sink-resolution rewrite with "
          + ", ".join(f"{op} {n}" for op, n in kinds.most_common()))


def answer(candidates, singles, pairs):
    columns = single_rewrite_columns()
    fails = {name: {op for op, seeds in col.items() if any(seeds.values())} for name, col in columns.items()}
    claim("The analyzers fail on different but overlapping sets of rewrites ... The effective rewrites differ",
          *[f"{name}: {', '.join(sorted(ops))}" for name, ops in fails.items()])
    analyzers = {"Semgrep": fails[COLUMNS[0]], "CodeQL": fails[COLUMNS[1]], "Pysa (both rules)": fails[COLUMNS[4]]}
    names = list(analyzers)
    print("  data: shared: " + "; ".join(f"{a} and {b}: {', '.join(sorted(analyzers[a] & analyzers[b])) or 'none'}"
                                         for i, a in enumerate(names) for b in names[i + 1:]))
    baseline = [v for (_s, ops), v in candidates.items() if set(ops) <= BASELINE]
    claim("and the controls and restructuring rewrites fail to evade",
          f"Pysa candidates built only from them (singles and pairs): {share(baseline, 'both')} evade, "
          f"{share(baseline, 'flow')} silence the flow rule")
    claim("Pysa's 2 rules are silenced together only by pairs or by a round trip",
          f"evading singles: {sum(v['both'] for v in singles.values())}, all round trips: "
          f"{all(set(ops) <= ROUND_TRIPS for (_s, ops), v in singles.items() if v['both'])}; "
          f"evading pairs: {sum(v['both'] for v in pairs.values())}")


def main():
    candidates = pysa_candidates()
    singles = {k: v for k, v in candidates.items() if len(k[1]) == 1}
    pairs = {k: v for k, v in candidates.items() if len(k[1]) == 2}
    heading("RQ5, first paragraph: what was scanned")
    scope(candidates, singles, pairs)
    heading("RQ5, first paragraph: single rewrites (Pysa columns of Table 3)")
    single_results(singles)
    heading("RQ5, first paragraph: pairs")
    pair_results(candidates, pairs)
    heading("RQ5, second paragraph: causes")
    print("not computed here: analysis/mechanism_pysa.py, mechanism_codeql.py, mechanism_codeql_flow.py and "
          "mechanism_codeql_probe.py (run by analysis/run_mechanism.sh, need the scanners); saved outputs in "
          "results/mechanism/")
    heading("Answer to RQ5")
    answer(candidates, singles, pairs)


if __name__ == "__main__":
    main()
