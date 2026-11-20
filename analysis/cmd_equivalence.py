"""Extended behavior check for the command-injection candidates: every distinct candidate of every saved cmd run is regenerated from its
seed and operator subset and run on 12 inputs (empty, spaces, quotes, a semicolon injection, a command substitution, unicode); its output
must equal the baseline's. Only echo commands are run.
An input that makes the command fail for the seed itself (the apostrophe: the shell exits with status 2) leaves nothing to compare but the
failure. The exit status of every process a call starts is recorded, because only some seeds raise (check_output) while the others return
normally (run, Popen, os.popen, getoutput); the script prints the seed-input pairs on which the seed's command fails, and a candidate must
also start processes with the same exit statuses as its seed. The shell's own syntax-error message is not shown.
usage (from the repository root): .sastlab/.venv/bin/python analysis/cmd_equivalence.py"""
import contextlib, json, os, subprocess, sys
from pathlib import Path
from _paths import ROOT
sys.path.insert(0, str(ROOT))
from sastlab.transforms import OPERATORS, candidate

RUNS = ["semgrep-cmd-pairs", "codeql-cmd-singles", "codeql-cmd-nonflow-pairs", "pysa-cmd-pairs", "bandit-cmd-pairs"]
INPUTS = ["1", "", "a b", "x  y", "it's", 'say "hi"', "1; echo PWNED", "1 && echo A", "$(echo hi)", "`echo hi`", "caf\u00e9", "a" * 300]
mask = lambda ops: sum(1 << OPERATORS.index(o) for o in ops)


@contextlib.contextmanager
def quiet_stderr():
    """The shell started by a seed inherits file descriptor 2, so point that descriptor at /dev/null (a Python-level redirect would not reach it)."""
    sys.stderr.flush()
    saved = os.dup(2)
    with open(os.devnull, "w") as null:
        os.dup2(null.fileno(), 2)
        try:
            yield
        finally:
            os.dup2(saved, 2)
            os.close(saved)


@contextlib.contextmanager
def recorded_processes():
    """Collect the processes started inside the block, so that their exit status can be read afterwards."""
    started, real = [], subprocess.Popen

    class Recording(real):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            started.append(self)
    subprocess.Popen = Recording
    try:
        yield started
    finally:
        subprocess.Popen = real


def run(source, arg):
    """(value or "ERR:<exception>", exit status of every process the call started)"""
    ns = {"__name__": "x"}
    with recorded_processes() as started:
        try:
            exec(compile(source, "<s>", "exec"), ns)
            value = ns["get_user_profile"](None, arg)
        except Exception as e:
            value = "ERR:" + type(e).__name__
        status = [p.wait(timeout=30) for p in started]
    return value, status


def fails(outcome):
    value, status = outcome
    return (isinstance(value, str) and value.startswith("ERR:")) or any(code != 0 for code in status)


def check(root=ROOT, runs=RUNS):
    """Returns the number of candidates checked, those whose output or process exit statuses differ from the seed's, and the (seed, input) pairs on which the seed's command fails."""
    cands = {}
    for run_name in runs:
        for line in (root / "results" / run_name / "evaluations.jsonl").read_text().splitlines():
            r = json.loads(line)
            if r["status"] == "evaluated" and r["scan_status"] == "ok":
                cands[(r["seed"], tuple(sorted(r["operators"])))] = r["equivalent"]
    base, diff, n = {}, [], 0
    with quiet_stderr():
        for (seed, ops), eq in sorted(cands.items()):
            src = (root / "seeds_cmd" / f"{seed}.py").read_text()
            if seed not in base:
                base[seed] = [run(src, i) for i in INPUTS]
            out = [run(candidate(src, mask(ops)), i) for i in INPUTS]
            n += 1
            if out != base[seed]:
                diff.append((seed, ops))
    failing = [(seed, i) for seed, outs in sorted(base.items()) for i, o in zip(INPUTS, outs) if fails(o)]
    return {"candidates": n, "different": diff, "failing": failing, "seeds": len(base)}


if __name__ == "__main__":
    r = check()
    print(f"{r['candidates']} distinct candidates, {len(INPUTS)} inputs each, candidates with a different output: {len(r['different'])} {r['different'][:5]}")
    print(f"seed-input pairs on which the seed's command fails (exception or non-zero exit status; candidate and seed are then compared on the failure only): {len(r['failing'])} of {r['seeds'] * len(INPUTS)}")
    for seed, i in r["failing"]:
        print(f"  {seed}: {i!r}")
