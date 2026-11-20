"""Table 3 of the report, "Seeds on which 1 rewrite silences each analyzer", and the RQ1 sentences that describe it.

Question
  RQ1, "Which rewrites evade each scanner?": for each of the 18 rewrites applied alone, on how many seeds does each
  analyzer (Semgrep pattern rule, CodeQL data-flow query, Pysa flow, string and both rules) stop reporting?

Data (results/<run>/, listed by name below: the runs the paper's table was made from)
  Semgrep 1.178.0, rule formatted-sql-query, and CodeQL 2.27.1, query py/sql-injection: the search runs in
  SEMGREP["search"] and CODEQL["search"] (attempts.jsonl) and the exhaustive runs in SEMGREP["exhaustive"] and
  CODEQL["exhaustive"] (evaluations.jsonl), pooled. rq1.py finds these runs from the manifests and gets the same cells.
  Pysa (pyre-check 0.10.0), stock SQL rules: the 5 exhaustive runs in PYSA_RUNS (evaluations.jsonl, plus
  qualifications.json, the rules that fire on each unmodified seed).
  All seeds are SQL-injection programs: main (seed_*), varied (d*) and official (o*).

Method
  1. A candidate is a (seed, set of rewrites) that was scanned without error and behaves like its seed on the oracle
     inputs (common.scanned for an exhaustive record, the same test on a search attempt). A rewrite that does not
     apply to a seed is rejected before scanning (status "invalid") and gives no candidate. A candidate scanned several
     times counts once: for Semgrep and CodeQL a candidate whose records disagree would be dropped (none do); for Pysa
     the later run's record is kept (the 428 repeats agree).
  2. Silenced. Semgrep and CodeQL: the rule that fired on the seed is silent (common.evaded). Pysa: on every
     qualifying seed both rules fire, 5005 (flow rule: user data reaches an SQL sink) and 5051 (string rule: user data
     reaches a string that may be SQL). A Pysa column counts the candidates on which its rule no longer fires; "both
     rules" means none of the seed's rules fires, which is how RQ5 and RQ6 count a Pysa evasion.
  3. A cell is (seeds whose single-rewrite candidate is silenced) / (seeds with a single-rewrite candidate).
  4. Rows follow the framework's operator order (the manifest's list, the bit order of a mask); rewrites whose 5 cells
     are all equal share one row, placed where the first of them stands.
  5. The seeds of an analyzer are those with any single-rewrite candidate; the denominator of a rewrite drops the
     seeds on which it was rejected as not applicable.

Output (stdout only, no file): the RQ1 sentences on the denominators, the table, then the Semgrep and CodeQL sentences
on the rewrites that evade alone on every seed.
"""
import collections
import json

from common import RESULTS, attempts, claim, evaded, evaluations, heading, manifest, scanned, table

SEMGREP = {"search": ["semgrep-v6", "semgrep-promptfix", "semgrep-hard", "semgrep-hard30", "semgrep-hard30-qwen",
                      "semgrep-hard30-q36", "semgrep-abl-message", "semgrep-abl-snippet", "semgrep-abl-sink"],
           "exhaustive": ["semgrep-diverse-singles", "semgrep-diverse-triples", "semgrep-newops",
                          "semgrep-pattern-main-singles", "semgrep-official-newops", "semgrep-official-triples"]}
CODEQL = {"search": ["codeql-v6", "codeql-promptfix", "codeql-hard", "codeql-hard15", "codeql-hard-qwen"],
          "exhaustive": ["codeql-diverse-singles", "codeql-diverse-nonflow-pairs", "codeql-flow-ops-15seeds",
                         "codeql-flow-ops-seed01", "codeql-newops", "codeql-official-singles",
                         "codeql-official-nonflow-pairs"]}
PYSA_RUNS = ["pysa-main-singles", "pysa-main-pairs", "pysa-diverse-singles", "pysa-official-singles",
             "pysa-official-pairs"]
FLOW_RULE, STRING_RULE = "pysa/5005", "pysa/5051"
DAGGER = {"partial_sink", "methodcaller_sink", "unbound_sink", "pickle_roundtrip", "simplequeue_roundtrip"}  # Table 1
COLUMNS = ["Semgrep pattern rule", "CodeQL data-flow query", "Pysa flow rule", "Pysa string rule", "Pysa both rules"]


def key(record):
    """A distinct candidate: (seed, sorted rewrite names)."""
    return record["seed"], tuple(sorted(record["operators"]))


def scanned_attempt(a):
    """A search attempt that is a candidate (the test of common.scanned on its scan and oracle fields)."""
    return not a["error"] and (a["scan"] or {}).get("status") == "ok" and (a["oracle"] or {}).get("equivalent")


def verdicts(runs):
    """{candidate: silenced} for Semgrep or CodeQL, search and exhaustive runs pooled."""
    seen = collections.defaultdict(set)
    for run in runs["search"]:
        for a in filter(scanned_attempt, attempts(run)):
            seen[key(a)].add(evaded(a))
    for run in runs["exhaustive"]:
        for e in filter(scanned, evaluations(run)):
            seen[key(e)].add(evaded(e))
    return {k: v.pop() for k, v in seen.items() if len(v) == 1}


def pysa_rules():
    """{seed: Pysa rules that fire on the unmodified seed}, empty when the seed does not qualify (used by rq5.py)."""
    return {q["seed"]: set(q["qualifying_rules"]) for run in PYSA_RUNS
            for q in json.loads((RESULTS / run / "qualifications.json").read_text())}


def pysa_candidates():
    """{candidate: {"flow": silenced, "string": silenced, "both": silenced}} over the 5 Pysa runs (used by rq5.py)."""
    rules, out = pysa_rules(), {}
    for run in PYSA_RUNS:
        for e in filter(scanned, evaluations(run)):
            seed_rules, fired = rules[e["seed"]], set(e["scan_rules"])
            out[key(e)] = {"flow": FLOW_RULE in seed_rules - fired, "string": STRING_RULE in seed_rules - fired,
                           "both": not seed_rules & fired}
    return out


def singles(candidates, rule=None):
    """{rewrite: {seed: silenced}} over the candidates with exactly 1 rewrite; `rule` picks a Pysa column."""
    out = collections.defaultdict(dict)
    for (seed, ops), value in candidates.items():
        if len(ops) == 1:
            out[ops[0]][seed] = value if rule is None else value[rule]
    return out


def single_rewrite_columns():
    """{column of Table 3: {rewrite: {seed: silenced}}} (used by rq5.py)."""
    pysa = pysa_candidates()
    return dict(zip(COLUMNS, [singles(verdicts(SEMGREP)), singles(verdicts(CODEQL)), singles(pysa, "flow"),
                              singles(pysa, "string"), singles(pysa, "both")]))


def cell(seeds):
    return f"{sum(seeds.values())}/{len(seeds)}"


def merged_rows(order, columns):
    """Rewrites with identical cells share a row, which sits where the first of them stands."""
    groups = {}
    for op in order:
        groups.setdefault(tuple(cell(columns[c][op]) for c in COLUMNS), []).append(op)
    return [[", ".join(ops), *cells] for cells, ops in groups.items()]


def not_applicable(runs, op):
    """Seeds on which the single rewrite `op` was rejected before scanning (status "invalid")."""
    return sorted({e["seed"] for run in runs for e in evaluations(run)
                   if e["status"] == "invalid" and e["operators"] == [op]})


def denominators(order, columns):
    analyzers = {"Semgrep": (columns[COLUMNS[0]], SEMGREP["exhaustive"]),
                 "CodeQL": (columns[COLUMNS[1]], CODEQL["exhaustive"]), "Pysa": (columns[COLUMNS[4]], PYSA_RUNS)}
    claim("Denominators count the seeds scanned, 30 for Semgrep and 34 for CodeQL and Pysa",
          ", ".join(f"{name} {len(set().union(*col.values()))}" for name, (col, _) in analyzers.items()))
    claim("although format_swap does not apply to 6 of them",
          *[f"{name}: rejected on {len(seeds)} seeds ({', '.join(seeds)}); format_swap scanned on "
            f"{len(col['format_swap'])}, rename on {len(col['rename'])}"
            for name, (col, runs) in analyzers.items() for seeds in [not_applicable(runs, "format_swap")]])
    main = collections.defaultdict(set)
    for op in order:
        seeds = columns[COLUMNS[1]][op]
        main[len(seeds)] |= {s for s in seeds if s.startswith("seed_")}
    claim("CodeQL entries with 24 and 18 use 5 of the 15 main seeds and those with 19 use none",
          ", ".join(f"denominator {n}: {len(seeds)} main seeds" for n, seeds in sorted(main.items(), reverse=True)))


def evade_everywhere(order, column):
    """{number of seeds: rewrites silenced on every seed they were scanned on}."""
    out = collections.defaultdict(list)
    for op in order:
        if all(column[op].values()):
            out[len(column[op])].append(op)
    return out


def main():
    order = manifest("pysa-main-singles")["identity"]["operators"]
    columns = single_rewrite_columns()
    heading("RQ1, first paragraph: what Table 3 counts")
    denominators(order, columns)
    heading("Table 3. Seeds on which 1 rewrite silences each analyzer (silenced seeds / seeds scanned)")
    table(["Operator", *COLUMNS], merged_rows(order, columns))
    heading("RQ1, Semgrep's pattern rule")
    alone = evade_everywhere(order, columns[COLUMNS[0]])[30]
    claim("Eight rewrites evade it alone on all 30 seeds", f"{len(alone)} rewrites: {', '.join(alone)}")
    heading("RQ1, CodeQL's data-flow query")
    alone = evade_everywhere(order, columns[COLUMNS[1]])
    claim("dynamic_sink, char_launder, deep_nest and db_roundtrip evade it on all 34 seeds",
          f"on all 34 seeds: {', '.join(alone[34])}")
    claim("and the 5 rewrites marked with a dagger in Table 1 on all 19 seeds where they were tested",
          f"on all 19 seeds: {', '.join(alone[19])}; the dagger rewrites of Table 1: {set(alone[19]) == DAGGER}")


if __name__ == "__main__":
    main()
