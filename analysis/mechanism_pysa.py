"""Mechanism checks for the Pysa findings (scratch analysis; scans a handful of candidates).

1. Call graph: does Pysa resolve a call from the entry function to the SQL sink for the baseline and for each sink-resolution rewrite?
2. Model repair: add propagation models for what the round-trip rewrites go through and check whether detection returns.
3. Unbound sink: does Pysa read type(cursor).execute(cursor, query) as a bound call and shift the arguments by 1? Three spellings of the same call.
usage (from the repository root): .sastlab/.venv/bin/python analysis/mechanism_pysa.py
"""
import json, os, sys
from pathlib import Path
from common import ROOT

OUT_DIR = Path(os.environ.get("SASTLAB_OUT", ROOT / "analysis" / "out"))

code = ROOT
sys.path.insert(0, str(code))
from sastlab.scanners import Scanner
from sastlab.transforms import OPERATORS, candidate

PYRE = code / ".sastlab/pysa-venv/bin/pyre"
BASE = [code / "third_party/pysa-models/core", code / "third_party/pysa-models/common"]
WORK = code / ".sastlab/runs/mechanism-pysa"
SEED = (code / "seeds/seed_01.py").read_text()
mask = lambda *ops: sum(1 << OPERATORS.index(o) for o in ops)

REPAIRS = {
    "queue.SimpleQueue": "def _queue.SimpleQueue.put(self, item: TaintInTaintOut[Updates[self]]): ...\n"
                         "def _queue.SimpleQueue.get(self: TaintInTaintOut[LocalReturn]): ...\n",
    "sqlite3 connection": "def sqlite3.Connection.execute(self, sql, parameters: TaintInTaintOut[Updates[self]], /): ...\n"
                          "def sqlite3.Connection.execute(self: TaintInTaintOut[LocalReturn], sql, parameters, /): ...\n"
                          "def sqlite3.Cursor.fetchone(self: TaintInTaintOut[LocalReturn]): ...\n",
}


def scan(name, source, models):
    scanner = Scanner("pysa", str(PYRE), None, 120, models=models, keep_database=True)
    return scanner.scan(source, WORK / name), WORK / name


def entries(directory):
    """Call-graph entries of the entry function: location -> (kind, resolved targets or the unresolved reason)."""
    out = {}
    for line in (directory / "out" / "call-graph.json").read_text().splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get("kind") != "call_graph" or not item["data"]["callable"].endswith("get_user_profile"):
            continue
        for location, value in item["data"]["calls"].items():
            kind, found = next(iter(value)), []
            def walk(x):
                if isinstance(x, dict):
                    for k, v in x.items():
                        if k == "target" and isinstance(v, str):
                            found.append(v)
                        elif k == "unresolved":
                            found.append("UNRESOLVED " + ",".join(v))
                        else:
                            walk(v)
                elif isinstance(x, list):
                    for v in x:
                        walk(v)
            walk(value[kind])
            out[location] = (kind, list(dict.fromkeys(found)))
    return out


def callees(directory):
    """Call targets recorded for the entry function (call-graph.json holds 1 JSON object per line)."""
    found = set()
    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "target" and isinstance(v, str):
                    found.add(v)
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    for line in (directory / "out" / "call-graph.json").read_text().splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get("kind") == "call_graph" and item["data"]["callable"].endswith("get_user_profile"):
            walk(item["data"]["calls"])
    return sorted(found)


if __name__ == "__main__":
    print("== 1. call graph of the entry function")
    graph = ["Pysa call-graph entries of get_user_profile (seed_01 with one rewrite), written by mechanism_pysa.py.",
             "Format: location | kind | resolved targets, or UNRESOLVED and the reason.\n"]
    for op in (None, "dict_dispatch", "dynamic_sink", "partial_sink", "methodcaller_sink", "unbound_sink"):
        src = SEED if op is None else candidate(SEED, mask(op))
        result, d = scan(op or "baseline", src, BASE)
        c = callees(d)
        hit = [x for x in c if "sqlite3" in x and "execute" in x]
        print(f"{op or 'baseline':20s} rules {result.rules} | references to an sqlite3 execute (call or attribute access): {hit} | all callees: {[x for x in c if 'sqlite3' in x or 'execute' in x][:6]}")
        graph.append(f"## {op or 'baseline'}")
        graph += [f"  {loc:34s} | {kind:20s} | {'; '.join(found)}" for loc, (kind, found) in entries(d).items()]
        graph.append("")
    (OUT_DIR / "mechanism").mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "mechanism" / "pysa_callgraph.txt").write_text("\n".join(graph))
    print("== 2. model repair")
    extra = WORK / "repair-models"
    extra.mkdir(parents=True, exist_ok=True)
    for label, op in (("queue.SimpleQueue", "simplequeue_roundtrip"), ("sqlite3 connection", "db_roundtrip")):
        for repaired in (False, True):
            models = BASE + ([extra / label.replace(" ", "_").replace(".", "_")] if repaired else [])
            if repaired:
                d = extra / label.replace(" ", "_").replace(".", "_")
                d.mkdir(exist_ok=True)
                (d / "repair.pysa").write_text(REPAIRS[label])
            result, _ = scan(f"{op}-{'repaired' if repaired else 'stock'}", candidate(SEED, mask(op)), models)
            print(f"{op:24s} {'with added models' if repaired else 'stock models':18s} status {result.status} rules {result.rules} {result.error[:200]}")
    print("== 3. unbound sink, three spellings of the call (rules that fire)")
    unbound = candidate(SEED, mask("unbound_sink"))
    line = "type(cursor).execute(cursor, query)"
    assert line in unbound
    for k, (label, spelling) in enumerate((("type(cursor).execute(cursor, query)  [the rewrite]", line),
                            ("type(cursor).execute(query)  [bound shape, not runnable]", "type(cursor).execute(query)"),
                            ("sqlite3.Cursor.execute(cursor, query)", "sqlite3.Cursor.execute(cursor, query)"))):
        src = unbound.replace(line, spelling)
        if "import sqlite3" not in src:
            src = "import sqlite3\n" + src
        result, _ = scan(f"unbound-{k}", src, BASE)
        print(f"{label:60s} status {result.status} rules {result.rules} {result.error[:200]}")
