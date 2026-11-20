"""Taint-aware placement probe (CodeQL only).

The operators in sastlab/transforms.py always apply their value-laundering rewrite at the function entry. Here
the placement comes from the analyzer itself: the CodeQL witness path (SARIF codeFlows) of the baseline finding
lists the nodes inside the subject file, for example the parameter, the assignment that builds the query, and the
query used at the sink. For each such node and each laundering rewrite we insert the rewrite at that node and ask
whether the finding survives. This shows which hop of the analysis loses the taint, which is what a
witness-path-guided metamorphic transformation (as in TaintCC) exploits.

Semgrep reports match spans, not paths, so this probe does not apply to it.

Run from the code directory:
  .sastlab/.venv/bin/python scripts/path_probe.py configs/codeql-diverse.json results/codeql-path-probe
"""
import ast
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sastlab.oracle import Oracle
from sastlab.runner import load_config, scanner_from

LAUNDER = {
    "identity": "{v} = {v}",
    "char_launder": "{v} = ''.join(chr(ord(_c)) for _c in {v})",
    "deep_nest": "_b = " + "[" * 8 + "{v}" + "]" * 8 + "\n{v} = _b" + "[0]" * 8,
    "pickle": "import pickle as _pk\n{v} = _pk.loads(_pk.dumps({v}))",
    "simplequeue": "import queue as _qq\n_sq = _qq.SimpleQueue()\n_sq.put({v})\n{v} = _sq.get()",
    "db_roundtrip": ("import sqlite3 as _s3\n_d = _s3.connect(':memory:')\n_d.execute('CREATE TABLE t (v TEXT)')\n"
                     "_d.execute('INSERT INTO t VALUES (?)', ({v},))\n{v} = _d.execute('SELECT v FROM t').fetchone()[0]"),
}


def subject_nodes(finding):
    """(line, variable) pairs of the witness path inside subject.py, in path order, without duplicates."""
    seen, out = set(), []
    for step in finding["trace"]:
        match = re.fullmatch(r"ControlFlowNode for (\w+)", step["message"])
        if step["path"] == "subject.py" and match and (step["line"], match.group(1)) not in seen:
            seen.add((step["line"], match.group(1)))
            out.append((step["line"], match.group(1)))
    return out


def classify(fn, line, name):
    if fn.lineno == line and any(a.arg == name for a in fn.args.args):
        return "param"
    for stmt in fn.body:
        if stmt.lineno <= line <= stmt.end_lineno:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                return "def"
            return "use"
    return "other"


def rewrite(source, line, name, kind, how):
    """Insert the laundering block for variable `name` at the path node on `line`."""
    tree = ast.parse(source)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "get_user_profile")
    block = ast.parse(LAUNDER[how].format(v=name)).body
    if kind == "param":
        fn.body[0:0] = block
    else:
        index = next(i for i, s in enumerate(fn.body) if s.lineno <= line <= s.end_lineno)
        fn.body[index + (1 if kind == "def" else 0):index + (1 if kind == "def" else 0)] = block
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"


def main():
    config = load_config(sys.argv[1])
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    scanner, oracle = scanner_from(config), Oracle(config.get("oracle_timeout", 5))
    done = set()
    log = out / "probe.jsonl"
    if log.exists():
        done = {(r["seed"], r["line"], r["name"], r["how"]) for r in map(json.loads, log.read_text().splitlines()) if r}
    work = Path(".sastlab/runs/path-probe")
    for path in sorted(Path(config["seeds"]).glob("*.py")):
        source = path.read_text()
        base = scanner.scan(source, work / path.stem / "baseline")
        if base.status != "ok" or not base.findings or "py/sql-injection" not in base.rules:
            print(path.stem, "baseline not flagged; skipped", flush=True)
            continue
        nodes = subject_nodes(base.findings[0])
        fn = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef))
        baseline_oracle = oracle.evaluate(source)
        print(path.stem, "witness nodes in subject:", nodes, flush=True)
        for line, name in nodes:
            kind = classify(fn, line, name)
            for how in LAUNDER:
                if (path.stem, line, name, how) in done:
                    continue
                record = {"seed": path.stem, "line": line, "name": name, "kind": kind, "how": how, "nodes": len(nodes)}
                try:
                    candidate = rewrite(source, line, name, kind, how)
                    record["equivalent"] = bool(oracle.compare(baseline_oracle, candidate).get("equivalent"))
                    t = time.monotonic()
                    scan = scanner.scan(candidate, work / path.stem / f"{line}-{name}-{how}")
                    record.update(scan_status=scan.status, detected=bool(scan.rules), seconds=round(time.monotonic() - t, 1),
                                  error=scan.error[:120])
                except Exception as exc:
                    record.update(equivalent=False, scan_status="not_run", detected=None, error=f"{type(exc).__name__}: {exc}")
                with log.open("a") as f:
                    f.write(json.dumps(record) + "\n")
                print(f"  {path.stem} line {line} {name:8s} {kind:5s} {how:13s} equivalent={record['equivalent']} detected={record['detected']}", flush=True)


if __name__ == "__main__":
    main()
