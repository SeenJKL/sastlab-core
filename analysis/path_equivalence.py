"""Extended behavior check for the path-traversal candidates: every distinct candidate of every saved path run is regenerated from its seed and
operator subset and run on 14 inputs (existing and missing names, spaces, unicode, a long name, a null byte, traversal strings); its output (lines read, or the
exception type) must equal the baseline's.
usage (from the repository root): .sastlab/.venv/bin/python analysis/path_equivalence.py"""
import json, sys, tempfile
from pathlib import Path
from _paths import ROOT
code = ROOT; sys.path.insert(0, str(code))
from sastlab.transforms import OPERATORS, candidate

RUNS = ["semgrep-path-pairs", "codeql-path-singles", "codeql-path-nonflow-pairs", "pysa-path-pairs"]
INPUTS = ["1", "2", "", "a b", "caf\u00e9", "x" * 300, "1\x00", "../secret", "../public/1", "1/../1", "/etc/hostname-none", ".", "secret", "1.txt"]
mask = lambda ops: sum(1 << OPERATORS.index(o) for o in ops)


def run(source, arg):
    # The path seeds create a fixture directory with mkdtemp() when they are executed; give every call its own temporary directory and remove it.
    with tempfile.TemporaryDirectory(prefix="sastlab-path-eq-", ignore_cleanup_errors=True) as scratch:
        tempfile.tempdir = scratch
        ns = {"__name__": "x"}
        try:
            exec(compile(source, "<s>", "exec"), ns)
            return ns["get_user_profile"](None, arg)
        except Exception as e:
            return "ERR:" + type(e).__name__
        finally:
            tempfile.tempdir = None


cands = {}
for run_name in RUNS:
    for line in (code / "results" / run_name / "evaluations.jsonl").read_text().splitlines():
        r = json.loads(line)
        if r["status"] == "evaluated" and r["scan_status"] == "ok":
            cands[(r["seed"], tuple(sorted(r["operators"])))] = r["equivalent"]
base, diff, n, exploit = {}, [], 0, {}
for (seed, ops), eq in sorted(cands.items()):
    src = (code / "seeds_path" / f"{seed}.py").read_text()
    if seed not in base:
        base[seed] = [run(src, i) for i in INPUTS]
        exploit[seed] = isinstance(base[seed][7], list) and any("SECRET" in str(x) for x in base[seed][7])
    out = [run(candidate(src, mask(ops)), i) for i in INPUTS]
    n += 1
    if out != base[seed]:
        diff.append((seed, ops))
print(f"{n} distinct candidates, {len(INPUTS)} inputs each, candidates with a different output: {len(diff)} {diff[:5]}")
print("seeds where '../secret' returns the secret file:", sum(exploit.values()), "of", len(base))
