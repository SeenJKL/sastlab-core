"""Table 4 of the report ("Candidates scanned in 4 further corpora"), section RQ2 (prints plain text only, no files).

Saved runs (exhaustive, no search), per corpus and analyzer:
  Independent projects  semgrep-real-pairs  codeql-real-singles + codeql-real-nonflow-pairs  pysa-real-pairs
  Deployed projects     semgrep-apps-pairs  codeql-apps-singles + codeql-apps-nonflow-pairs  pysa-apps-pairs
  Command injection     semgrep-cmd-pairs   codeql-cmd-singles + codeql-cmd-nonflow-pairs    pysa-cmd-pairs
  Path traversal        semgrep-path-pairs  codeql-path-singles + codeql-path-nonflow-pairs  pysa-path-pairs
Semgrep and Pysa runs hold every single rewrite and every pair; CodeQL runs hold every single rewrite and the pairs of
the rewrites that do not evade CodeQL alone.

Method.
1. A candidate is a (seed, rewrite set) record on a seed where the analyzer's rule fired (qualifications.json), scanned
   without error and equivalent to its seed (candidates.exhaustive); Cand. counts distinct (seed, rewrite set) pairs.
2. Evade: Semgrep and CodeQL, the rule that fired on the seed is silent; Pysa, none of the seed's rules fires.
3. Semgrep, Other: evading candidates that contain no restructuring rewrite (extract_1, extract_2, branch_split) and
   no sink-resolution rewrite; the script checks that each of them contains literal_slice.
4. CodeQL, Exc.: candidates whose verdict differs from the rule found on the synthetic SQL programs (RQ1): a candidate
   evades if and only if it contains one of the 9 CodeQL-evading rewrites.
5. Pysa, Exc.: candidates whose verdict differs from the prediction of the synthetic SQL programs (RQ5): a round trip
   (db_roundtrip, simplequeue_roundtrip) silences Pysa; otherwise a sink-resolution rewrite silences the 1 rule of a
   command-injection or path-traversal seed, while the 2 rules of an SQL seed need a sink-resolution rewrite together
   with literal_slice.
Prints Table 4, then the checks behind the Other column and the text around the table.
"""
from common import claim, heading, table
from candidates import CODEQL_EVADING, RESTRUCTURING, ROUND_TRIPS, SINK_RESOLUTION, exhaustive, fmt

CORPORA = [  # (row label, run name part, the seeds have 1 Pysa rule)
    ("Independent projects", "real", False),
    ("Deployed projects", "apps", False),
    ("Command injection", "cmd", True),
    ("Path traversal", "path", True),
]


def other(semgrep):
    """Evading Semgrep candidates without a restructuring or sink-resolution rewrite."""
    return [ops for (_seed, ops), ev in semgrep.items() if ev and not set(ops) & (RESTRUCTURING | SINK_RESOLUTION)]


def restructured(semgrep):
    """Verdicts of Semgrep candidates with a restructuring rewrite and no sink-resolution rewrite."""
    return [ev for (_seed, ops), ev in semgrep.items() if set(ops) & RESTRUCTURING and not set(ops) & SINK_RESOLUTION]


def codeql_predicts(ops):
    return bool(set(ops) & CODEQL_EVADING)


def pysa_predicts(ops, one_rule):
    ops = set(ops)
    if ops & ROUND_TRIPS:
        return True
    if one_rule:
        return bool(ops & SINK_RESOLUTION)
    return bool(ops & SINK_RESOLUTION) and "literal_slice" in ops


def exceptions(cands, predicts):
    return sum(ev != predicts(ops) for (_seed, ops), ev in cands.items())


def main():
    rows, others, restructuring = [], [], []
    for label, name, one_rule in CORPORA:
        semgrep = exhaustive([f"semgrep-{name}-pairs"])
        codeql = exhaustive([f"codeql-{name}-singles", f"codeql-{name}-nonflow-pairs"])
        pysa = exhaustive([f"pysa-{name}-pairs"], silent=True)
        rows.append([label, fmt(len(semgrep)), fmt(sum(semgrep.values())), fmt(len(other(semgrep))),
                     fmt(len(codeql)), fmt(sum(codeql.values())), exceptions(codeql, codeql_predicts),
                     fmt(len(pysa)), fmt(sum(pysa.values())),
                     exceptions(pysa, lambda ops: pysa_predicts(ops, one_rule))])
        others.append(f"{label}: {len(other(semgrep))} Other, "
                      f"{sum('literal_slice' in ops for ops in other(semgrep))} with literal_slice")
        restructuring.append(f"{label}: {sum(restructured(semgrep))} of {len(restructured(semgrep))} evade")
    heading("Table 4. Candidates scanned in 4 further corpora")
    table(["Corpus", "Semgrep Cand.", "Evade", "Other", "CodeQL Cand.", "Evade", "Exc.",
           "Pysa Cand.", "Evade", "Exc."], rows)
    heading("Checks behind the text")
    claim("Other counts evading Semgrep candidates without a restructuring or sink-resolution rewrite, all of which "
          "contain literal_slice", *others)
    claim("In command injection and path traversal, the restructuring rewrites no longer evade (Semgrep candidates "
          "with a restructuring rewrite and no sink-resolution rewrite)", *restructuring)


if __name__ == "__main__":
    main()
