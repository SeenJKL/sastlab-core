"""RQ2 of the report ("Do the findings hold on other code?"): every number of the section except Table 4 (table4.py).

Saved runs (all exhaustive):
  CodeQL rule      varied: codeql-diverse-singles, codeql-diverse-nonflow-pairs, codeql-newops;
                   official: codeql-official-singles, codeql-official-nonflow-pairs
  Bandit           bandit-{main,diverse,official,real,apps}-pairs (rule B608, SQL) and bandit-cmd-pairs (B602)
  Semgrep taint    semgrep-taint-main-pairs, semgrep-taint-official-pairs, semgrep-taint-real-pairs,
                   semgrep-taint-diverse-singles (rule tainted-sql-string)
  Newer releases   semgrep-pattern-{main,official}-singles (1.178.0) against semgrep-latest-{main,official}-singles
                   (1.182.1); codeql-latest-{main,official}-singles (CodeQL 2.27.3)

Method.
1. A candidate is a (seed, rewrite set) record on a seed where the rule fired, scanned without error and equivalent to
   its seed (candidates.exhaustive); counts are of distinct (seed, rewrite set) pairs. Evaded: the rule fired on the
   seed and is silent on the candidate.
2. Each finding is a rule "a candidate evades if and only if <condition on its rewrites>"; an exception is a candidate
   whose verdict differs from the condition. How a seed builds its query (with +, i.e. concatenated) is read from its
   source (candidates.query_building).
   CodeQL:  contains one of the 9 CodeQL-evading rewrites.
   Bandit:  B608, contains literal_slice, or format_swap on a query built with +;
            B602, contains a sink-resolution rewrite other than unbound_sink.
   Taint:   contains literal_slice, extract_1 or extract_2, or format_swap on a query built with + (the last clause
            was added after seeing the data; the script also prints the exceptions without it).
3. Newer releases: Semgrep, the same (seed, rewrite set) scanned by both versions, counting different verdicts;
   CodeQL 2.27.3, the CodeQL rule above on its single-rewrite candidates.
Prints each sentence of the report with the numbers computed for it, and the Bandit counts per corpus.
"""
from common import claim, heading, table
from candidates import CODEQL_EVADING, SINK_RESOLUTION, exhaustive, fmt, query_building

BANDIT = [("main", "B608"), ("diverse", "B608"), ("official", "B608"), ("real", "B608"), ("apps", "B608"),
          ("cmd", "B602")]
TAINT_RUNS = ["semgrep-taint-main-pairs", "semgrep-taint-official-pairs", "semgrep-taint-real-pairs",
              "semgrep-taint-diverse-singles"]


def concatenated(seed):
    return "+" in query_building(seed)


def codeql_rule(seed, ops):
    return bool(set(ops) & CODEQL_EVADING)


def bandit_b608(seed, ops):
    return "literal_slice" in ops or ("format_swap" in ops and concatenated(seed))


def bandit_b602(seed, ops):
    return bool(set(ops) & (SINK_RESOLUTION - {"unbound_sink"}))


RULES = {"B608": bandit_b608, "B602": bandit_b602}


def taint_rule(seed, ops):
    return bool(set(ops) & {"literal_slice", "extract_1", "extract_2"}) or ("format_swap" in ops and concatenated(seed))


def taint_rule_without_last_clause(seed, ops):
    return bool(set(ops) & {"literal_slice", "extract_1", "extract_2"})


def exceptions(cands, rule):
    return sum(ev != rule(*k) for k, ev in cands.items())


def codeql_corpora():
    heading("CodeQL data-flow query on the varied and official programs")
    varied = exhaustive(["codeql-diverse-singles", "codeql-diverse-nonflow-pairs", "codeql-newops"])
    official = exhaustive(["codeql-official-singles", "codeql-official-nonflow-pairs"])
    claim("CodeQL's rule held on every corpus we scanned, including the varied and official programs (592 and 450 "
          "distinct candidates)",
          *(f"{name}: {fmt(len(c))} distinct candidates, {fmt(sum(c.values()))} evade, "
            f"{exceptions(c, codeql_rule)} exceptions to the rule"
            for name, c in (("varied", varied), ("official", official))))


def bandit():
    heading("Bandit")
    rows, by_rule = [], {"B608": {}, "B602": {}}
    for corpus, rule in BANDIT:
        cands = exhaustive([f"bandit-{corpus}-pairs"])
        by_rule[rule].update(cands)
        rows.append([corpus, rule, len({s for s, _ in cands}), fmt(len(cands)), sum(cands.values()),
                     exceptions(cands, RULES[rule])])
    table(["Corpus", "Rule", "Seeds", "Candidates", "Silent", "Exceptions"], rows)
    claim("Over 7,700 single and paired candidates, B608 stays silent if and only if the candidate contains "
          "literal_slice, or format_swap on a query built with +, and B602 if and only if a sink-resolution rewrite "
          "other than unbound_sink hides the call",
          f"{fmt(sum(len(c) for c in by_rule.values()))} candidates",
          *(f"{rule}: {fmt(len(c))} candidates, {fmt(sum(c.values()))} silent, {exceptions(c, RULES[rule])} exceptions"
            for rule, c in by_rule.items()))


def taint():
    heading("Semgrep taint rule tainted-sql-string")
    cands = exhaustive(TAINT_RUNS)
    sinks = [ev for (_s, ops), ev in cands.items() if len(ops) == 1 and ops[0] in SINK_RESOLUTION]
    claim("the sink-resolution rewrites never evade it",
          f"{sum(sinks)} of {len(sinks)} single sink-resolution candidates evade")
    claim("a candidate evades it if and only if it contains literal_slice, extract_1, extract_2, or format_swap on a "
          "concatenated query (4,462 candidates, the last clause added after seeing the data)",
          f"{fmt(len(cands))} candidates, {fmt(sum(cands.values()))} evade, {exceptions(cands, taint_rule)} exceptions",
          f"without the format_swap clause: {exceptions(cands, taint_rule_without_last_clause)} exceptions")


def newer_releases():
    heading("Newer releases")
    pinned = exhaustive(["semgrep-pattern-main-singles", "semgrep-pattern-official-singles"])
    latest = exhaustive(["semgrep-latest-main-singles", "semgrep-latest-official-singles"])
    both = set(pinned) & set(latest)
    codeql = exhaustive(["codeql-latest-main-singles", "codeql-latest-official-singles"])
    claim("With newer releases, Semgrep 1.182.1 gave the same verdict on all 392 candidates compared, and CodeQL "
          "2.27.3 evaded on exactly the 216 of 428 candidates that contain a CodeQL-evading rewrite",
          f"Semgrep: {len(both)} candidates scanned by 1.178.0 and 1.182.1, "
          f"{sum(pinned[k] != latest[k] for k in both)} with different verdicts",
          f"CodeQL 2.27.3: {len(codeql)} candidates, {sum(codeql.values())} evade, "
          f"{sum(codeql_rule(*k) for k in codeql)} contain a CodeQL-evading rewrite, "
          f"{exceptions(codeql, codeql_rule)} exceptions")


def main():
    codeql_corpora()
    bandit()
    taint()
    newer_releases()


if __name__ == "__main__":
    main()
