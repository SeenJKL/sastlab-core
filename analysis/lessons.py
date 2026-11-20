"""The paragraph "Negative results and lessons" at the end of the report's evaluation: the witness-path probe and the
control-only candidates of 3 analyzers.

Saved runs.
  Path probe: results/codeql-path-probe/probe.jsonl (written by scripts/path_probe.py on the 12 varied seeds). One
    record per (seed, node of CodeQL's witness path, rewrite): the node kind (parameter, definition or use of the
    query), the rewrite ("identity" re-assigns the variable to itself, the 5 others launder it: char_launder,
    deep_nest, pickle, simplequeue, db_roundtrip), whether the program stayed equivalent, and whether CodeQL still
    reported the flow (`detected`).
  Controls:
    CodeQL  every run of py/sql-injection, as in rq1.py (26 runs, CodeQL 2.27.1 and 2.27.3)
    Pysa    pysa-main-singles, pysa-main-pairs, pysa-diverse-singles, pysa-official-singles, pysa-official-pairs
    Semgrep every run of formatted-sql-query with Semgrep 1.178.0, as in rq1.py (28 runs)
  All on the seeds of the main, varied and official SQL-injection corpora.

Method.
1. Path probe: a record counts when its scan succeeded and the program stayed equivalent (the dropped records are
   printed with their seeds). A laundering record evades when `detected` is false; an identity control is flagged
   when `detected` is true.
2. Controls: a candidate is control-only when every rewrite in it is one of rename, format_swap, literal_slice,
   dead_padding. Distinct (seed, rewrite set) candidates are counted as in rq1.py; evasion as defined in
   candidates.py (Pysa: both of its rules silent). For Semgrep the evading ones are checked for literal_slice.
Prints the probe per rewrite and node kind, and each sentence of the report with the numbers computed for it.
"""
import collections

from common import RESULTS, claim, heading, jsonl, table
from candidates import CONTROLS, every_run, exhaustive, fmt

PYSA_RUNS = ["pysa-main-singles", "pysa-main-pairs", "pysa-diverse-singles", "pysa-official-singles",
             "pysa-official-pairs"]


def usable(record):
    return record["scan_status"] == "ok" and record["equivalent"]


def path_probe():
    heading("Witness-path placement probe (CodeQL)")
    records = jsonl(RESULTS / "codeql-path-probe" / "probe.jsonl")
    kept = [r for r in records if usable(r)]
    dropped = collections.Counter(r["seed"] for r in records if not usable(r))
    print(f"{len(records)} records; dropped (scan error or behavior change): {sum(dropped.values())}, from seeds "
          f"{dict(dropped)}; kept {len(kept)} on {len({r['seed'] for r in kept})} seeds, "
          f"{len({(r['seed'], r['line'], r['name']) for r in kept})} witness-path nodes")
    rows = []
    for how in sorted({r["how"] for r in kept}, key=lambda h: (h != "identity", h)):
        group = [r for r in kept if r["how"] == how]
        rows.append([how] + [f"{sum(not r['detected'] for r in group if r['kind'] == k)}/"
                             f"{sum(r['kind'] == k for r in group)}" for k in ("param", "def", "use")])
    table(["Rewrite", "evade at parameter", "at query definition", "at query use"], rows)
    launder = [r for r in kept if r["how"] != "identity"]
    identity = [r for r in kept if r["how"] == "identity"]
    claim("Placing laundering rewrites at each node of CodeQL's witness path ... made no difference (155 of 155 "
          "evaded, 31 of 31 identity controls flagged)",
          f"laundering: {sum(not r['detected'] for r in launder)} of {len(launder)} evaded; identity controls: "
          f"{sum(r['detected'] for r in identity)} of {len(identity)} flagged")


def control_only(cands):
    return {k: ev for k, ev in cands.items() if k[1] and set(k[1]) <= CONTROLS}


def controls():
    heading("Control-only candidates (rename, format_swap, literal_slice, dead_padding)")
    codeql = control_only(every_run("codeql", "py/sql-injection")[1])
    pysa = control_only(exhaustive(PYSA_RUNS, silent=True))
    semgrep = control_only(every_run("semgrep", "formatted-sql-query", "1.178.0")[1])
    sliced = sum(ev and "literal_slice" in ops for (_s, ops), ev in semgrep.items())
    claim("none of 269 control-only candidates evades CodeQL and none of 262 evades Pysa, although 117 of 399 evade "
          "Semgrep through literal_slice",
          f"CodeQL: {fmt(sum(codeql.values()))} of {fmt(len(codeql))} evade",
          f"Pysa: {fmt(sum(pysa.values()))} of {fmt(len(pysa))} evade",
          f"Semgrep: {fmt(sum(semgrep.values()))} of {fmt(len(semgrep))} evade, {fmt(sliced)} of them contain "
          "literal_slice")


def main():
    path_probe()
    controls()


if __name__ == "__main__":
    main()
