"""Definitions shared by table4.py, rq1.py, rq2.py and lessons.py: the rewrite groups the report names, where each seed
program lives, and how the distinct candidates of saved runs are collected. Standard library only.

Candidate. A seed program with a set of rewrites applied to it. A record counts as a candidate only when its scan
succeeded and the behavior check found it equivalent to its seed: common.scanned() for an exhaustive record, the same
test on the `scan` and `oracle` fields for a search attempt. The same (seed, rewrite set) can appear in several runs or
several times in one search run; it is one distinct candidate, and the scripts report whether all its records agree.

Evasion. Semgrep, CodeQL and Bandit: common.evaded(), i.e. a rule that fired on the seed is silent on the candidate.
Pysa has 2 SQL rules; its exhaustive runs list every rule that stopped firing, so a Pysa candidate counts as evading
(silent) only when none of the rules that fired on its seed fires on it.
"""
import ast
import collections
import functools
import json

from common import RESULTS, ROOT, evaded, evaluations, jsonl, manifest, scanned

# Rewrite groups (Table 1 of the report).
CONTROLS = {"rename", "format_swap", "literal_slice", "dead_padding"}
RESTRUCTURING = {"extract_1", "extract_2", "branch_split"}
SINK_RESOLUTION = {"dict_dispatch", "dynamic_sink", "partial_sink", "methodcaller_sink", "unbound_sink"}
ORIGINAL = ["rename", "format_swap", "literal_slice", "dead_padding",  # the 8 rewrites of the proposal
            "extract_1", "extract_2", "branch_split", "dict_dispatch"]
# The rewrites that evade CodeQL alone; rq1.py derives this set from the single-rewrite candidates and compares.
CODEQL_EVADING = {"dynamic_sink", "partial_sink", "methodcaller_sink", "unbound_sink",
                  "char_launder", "pickle_roundtrip", "deep_nest", "simplequeue_roundtrip", "db_roundtrip"}
ROUND_TRIPS = {"db_roundtrip", "simplequeue_roundtrip"}  # the only rewrites that silence both Pysa SQL rules alone

# The seed name prefix tells the corpus and the folder of the program.
CORPORA = {"seed_": ("main", "seeds"), "d": ("varied", "seeds_diverse"), "o": ("official", "corpus_official/seeds"),
           "r": ("independent", "corpus_real/seeds"), "a": ("deployed", "corpus_apps/seeds"),
           "c": ("command", "seeds_cmd"), "p": ("path", "seeds_path")}


def corpus(seed):
    return next(name for prefix, (name, _) in CORPORA.items() if seed.startswith(prefix))


@functools.cache
def query_building(seed):
    """How the seed builds its string: the set of 'f-string', '.format()', '%' and '+' found in its assignments."""
    folder = next(path for prefix, (_, path) in CORPORA.items() if seed.startswith(prefix))
    kinds = set()
    for assign in ast.walk(ast.parse((ROOT / folder / f"{seed}.py").read_text())):
        if not isinstance(assign, ast.Assign):
            continue
        for n in ast.walk(assign.value):
            if isinstance(n, ast.JoinedStr):
                kinds.add("f-string")
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" \
                    and isinstance(n.func.value, ast.Constant):
                kinds.add(".format()")
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod) and isinstance(n.left, ast.Constant):
                kinds.add("%")
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add) and \
                    any(isinstance(m, ast.Constant) and isinstance(m.value, str) for m in ast.walk(n)):
                kinds.add("+")
    return kinds


def key(record):
    """A distinct candidate: (seed, sorted rewrite names)."""
    return record["seed"], tuple(sorted(record["operators"]))


def qualifying_rules(run):
    """{seed: rules that fired on the unmodified seed} of an exhaustive run."""
    return {q["seed"]: q["qualifying_rules"] for q in json.loads((RESULTS / run / "qualifications.json").read_text())}


def exhaustive(runs, silent=False):
    """{(seed, rewrites): evaded} over the scanned records of exhaustive runs, on seeds where the rule fired.
    silent=True uses the Pysa definition: none of the seed's rules fires on the candidate."""
    out = {}
    for run in runs:
        rules = qualifying_rules(run)
        for r in evaluations(run):
            if rules.get(r["seed"]) and scanned(r):
                out[key(r)] = (not set(rules[r["seed"]]) & set(r["scan_rules"])) if silent else evaded(r)
    return out


def scanner_version(run):
    m = manifest(run)
    version = (m.get("identity") or {}).get("scanner_version") or m.get("scanner_version") or ""
    return json.loads(version)["version"] if version.lstrip().startswith("{") else version


def find_runs(engine, rule):
    """Every saved run (search or exhaustive) of `engine` whose target rules include `rule`, read from the manifests."""
    found = []
    for folder in sorted(RESULTS.iterdir()):
        if (folder / "manifest.json").exists():
            m = manifest(folder.name)
            settings = m.get("identity") or m.get("config") or {}
            if settings.get("engine") == engine and rule in (settings.get("target_rules") or []):
                found.append(folder.name)
    return found


def verdicts(runs, corpora):
    """{(seed, rewrites): set of verdicts} over every scanned record of the runs (exhaustive and search), on seeds of
    the given corpora. A set with 2 values would mean the same candidate got 2 verdicts."""
    out = collections.defaultdict(set)
    for run in runs:
        folder = RESULTS / run
        records = jsonl(folder / "evaluations.jsonl") if (folder / "evaluations.jsonl").exists() else []
        records = [r for r in records if scanned(r)]
        if (folder / "attempts.jsonl").exists():
            records += [a for a in jsonl(folder / "attempts.jsonl") if not a["error"] and
                        (a["scan"] or {}).get("status") == "ok" and (a["oracle"] or {}).get("equivalent")]
        for r in records:
            if corpus(r["seed"]) in corpora:
                out[key(r)].add(evaded(r))
    return out


def every_run(engine, rule, version=None, corpora=("main", "varied", "official")):
    """All saved runs of one rule (and scanner version, if given) that hold candidates on the SQL-injection corpora of
    RQ1, merged: (run names, {(seed, rewrites): evaded}, number of candidates whose records disagree)."""
    runs, found = [], collections.defaultdict(set)
    for run in find_runs(engine, rule):
        part = verdicts([run], corpora) if version in (None, scanner_version(run)) else {}
        runs += [run] if part else []
        for k, v in part.items():
            found[k] |= v
    return runs, {k: True in v for k, v in found.items()}, sum(len(v) > 1 for v in found.values())


def fmt(n):
    """Thousands separator as in the report: 3,945."""
    return f"{n:,}"
