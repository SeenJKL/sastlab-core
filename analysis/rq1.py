"""RQ1 of the report ("Which rewrites evade each scanner?"): the numbers in the paragraphs on Semgrep's pattern rule
and CodeQL's data-flow query.

Saved runs, found from the manifests (candidates.every_run), searches and exhaustive runs alike:
  Semgrep: every run of the rule formatted-sql-query with Semgrep 1.178.0 (the 1.182.1 runs belong to RQ2).
  CodeQL:  every run of the query py/sql-injection. The single-rewrite counts use CodeQL 2.27.1 only, the pinned
           version; the rule check uses all runs, including the 2 runs with CodeQL 2.27.3 (codeql-latest-*).
Only seeds of the 3 SQL-injection corpora of RQ1 count: main (seed_*), varied (d*) and official (o*).

Method.
1. Candidates: scanned records equivalent to their seed. A (seed, rewrite set) pair is one distinct candidate however
   often it was scanned; the script counts pairs whose records disagree (0).
2. Single rewrites: for each rewrite, the seeds on which it alone evades, out of the seeds on which it was scanned
   alone (format_swap does not apply to a query built without an f-string or +).
3. Semgrep controls (rename, format_swap, literal_slice, dead_padding): each seed is classified by how it builds the
   query (f-string, .format() or %, read from its source). Rule checked on every candidate built only from controls:
   on .format()/% seeds it evades if and only if it contains literal_slice, on f-string seeds if and only if it
   contains both format_swap and literal_slice; exceptions are counted. semgrep-controls-main, which scanned all 15
   subsets of the controls on the 15 main seeds, is listed on its own.
4. CodeQL: a rewrite is CodeQL-evading when it evades alone on some seed; the set is compared with the 9 named in the
   report. Rule checked on every distinct candidate: it evades if and only if it contains a CodeQL-evading rewrite.
Prints each sentence of the report with the numbers computed for it, then the single-rewrite counts per rewrite.
"""
import collections

from common import claim, heading, table
from candidates import CODEQL_EVADING, CONTROLS, ORIGINAL, every_run, exhaustive, fmt, query_building

ORDER = ORIGINAL + ["dynamic_sink", "partial_sink", "methodcaller_sink", "unbound_sink", "char_launder",
                    "pickle_roundtrip", "deep_nest", "queue_roundtrip", "simplequeue_roundtrip", "db_roundtrip"]


def single_rewrites(cands):
    """{rewrite: (seeds where it alone evades, seeds where it was scanned alone)}."""
    out = collections.defaultdict(lambda: (set(), set()))
    for (seed, ops), ev in cands.items():
        if len(ops) == 1:
            out[ops[0]][1].add(seed)
            if ev:
                out[ops[0]][0].add(seed)
    return out


def fstring(seed):
    return "f-string" in query_building(seed)


def control_rule(seed, ops):
    """Semgrep on control-only candidates: literal_slice evades alone on .format()/% queries, with format_swap on
    f-strings."""
    return {"format_swap", "literal_slice"} <= set(ops) if fstring(seed) else "literal_slice" in ops


def semgrep(runs, cands, disagree):
    heading(f"Semgrep pattern rule: {fmt(len(cands))} distinct candidates from {len(runs)} runs, "
            f"{disagree} with 2 verdicts")
    singles = single_rewrites(cands)
    n = len({seed for seed, _ in cands})
    alone = [op for op in ORDER if len(singles[op][0]) == len(singles[op][1]) == n]
    claim("Eight rewrites evade it alone on all 30 seeds",
          f"{len(alone)} rewrites evade alone on all {n} seeds: {', '.join(alone)}")
    controls = {k: ev for k, ev in cands.items() if set(k[1]) <= CONTROLS}
    rows = []
    for name, group in (("f-string", True), (".format() or %", False)):
        part = {k: ev for k, ev in controls.items() if fstring(k[0]) == group}
        rows.append([name, len({s for s, _ in part}), len(part), sum(part.values()),
                     sum(ev != control_rule(*k) for k, ev in part.items())])
    claim("Among the controls, only literal_slice evades, alone on queries built with .format() or % and together "
          "with format_swap on f-strings",
          f"controls that evade alone: {', '.join(op for op in ORDER if op in CONTROLS and singles[op][0])}; evading "
          f"control-only candidates without literal_slice: "
          f"{sum(ev and 'literal_slice' not in ops for (_s, ops), ev in controls.items())}",
          f"literal_slice alone evades on {len(singles['literal_slice'][0])} seeds: " +
          ", ".join(f"{s} ({'/'.join(sorted(query_building(s)))})" for s in sorted(singles["literal_slice"][0])),
          "control-only candidates, rule: evades iff it contains literal_slice (.format()/% seeds), or format_swap "
          "and literal_slice (f-string seeds):")
    table(["Query built with", "Seeds", "Candidates", "Evade", "Exceptions"], rows)
    subsets = collections.defaultdict(list)
    for (_seed, ops), ev in exhaustive(["semgrep-controls-main"]).items():
        subsets[ops].append(ev)
    print(f"  data: semgrep-controls-main, {len(subsets)} control subsets on 15 main seeds; evading subsets:",
          ", ".join(f"{'+'.join(ops)} ({sum(v)}/{len(v)} seeds)" for ops, v in sorted(subsets.items()) if any(v)))


def codeql(pinned, runs, cands, disagree):
    heading("CodeQL data-flow query")
    singles = single_rewrites(pinned)
    evading = [op for op in ORDER if singles[op][0]]
    claim("None of the 8 original rewrites evades this query alone",
          f"{sum(len(singles[op][0]) for op in ORIGINAL)} of {sum(len(singles[op][1]) for op in ORIGINAL)} "
          "single-rewrite candidates of the 8 original rewrites evade")
    claim("It falls to 9 rewrites ... which we call CodeQL-evading",
          f"{len(evading)} rewrites evade alone on some seed: {', '.join(evading)}; "
          f"same as the 9 listed in the report: {set(evading) == CODEQL_EVADING}")
    claim("dynamic_sink, char_launder, deep_nest and db_roundtrip evade it on all 34 seeds, and the 5 rewrites marked "
          "with a dagger in Table 1 on all 19 seeds where they were tested",
          ", ".join(f"{op} {len(singles[op][0])}/{len(singles[op][1])}" for op in evading))
    with_ev = [ev for (_s, ops), ev in cands.items() if set(ops) & CODEQL_EVADING]
    without = [ev for (_s, ops), ev in cands.items() if not set(ops) & CODEQL_EVADING]
    claim("Among 3,945 distinct candidates from 26 saved runs, all 2,339 that contain at least 1 CodeQL-evading "
          "rewrite evaded and none of the other 1,606 did",
          f"{fmt(len(cands))} distinct candidates from {len(runs)} runs ({disagree} with 2 verdicts)",
          f"with a CodeQL-evading rewrite: {fmt(sum(with_ev))} of {fmt(len(with_ev))} evaded; "
          f"without: {sum(without)} of {fmt(len(without))} evaded",
          f"CodeQL 2.27.1 runs only: {fmt(len(pinned))} distinct candidates, "
          f"{sum(ev != bool(set(ops) & CODEQL_EVADING) for (_s, ops), ev in pinned.items())} exceptions")


def main():
    pattern_rule = every_run("semgrep", "formatted-sql-query", "1.178.0")
    semgrep(*pattern_rule)
    _, pinned, _ = every_run("codeql", "py/sql-injection", "2.27.1")
    codeql(pinned, *every_run("codeql", "py/sql-injection"))
    heading("Seeds on which 1 rewrite evades (Semgrep 1.178.0, CodeQL 2.27.1)")
    sg, cq = single_rewrites(pattern_rule[1]), single_rewrites(pinned)
    table(["Rewrite", "Semgrep pattern rule", "CodeQL data-flow query"],
          [[op, f"{len(sg[op][0])}/{len(sg[op][1])}", f"{len(cq[op][0])}/{len(cq[op][1])}"] for op in ORDER])


if __name__ == "__main__":
    main()
