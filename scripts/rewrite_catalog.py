"""Catalog of hand-written semantics-preserving rewrites of seed_01, scanned with CodeQL and the oracle.

Purpose: explain *why* the flow operators evade CodeQL's py/sql-injection query. Each variant changes either how the
tainted parameter travels before it reaches the query (taint-step variants) or how the sink is called (sink variants).
The question per variant: is the SQL injection still reported? Variants that are not behaviour-equivalent on the
oracle's two inputs are reported as such and excluded from conclusions.

Usage (from the code directory, after sourcing nothing else):
  PYTHONPATH=. .sastlab/.venv/bin/python scripts/rewrite_catalog.py configs/codeql.json results/codeql-rewrite-catalog [group ...]
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sastlab.oracle import Oracle
from sastlab.runner import load_config, scanner_from

SEED = Path("seeds/seed_01.py").read_text()
HEADER, BODY = SEED.split("def get_user_profile(db_conn, user_id):\n")
SINK = "    cursor.execute(query)\n"
assert SINK in BODY


def taint(group, name, prelude, imports=""):
    return {"group": group, "name": name, "imports": imports, "prelude": prelude}


def sink(group, name, replacement, imports=""):
    return {"group": group, "name": name, "imports": imports, "sink": replacement}


def nest(depth, kind):
    if kind == "list":
        return f"_b = {'[' * depth}user_id{']' * depth}\nuser_id = _b{'[0]' * depth}"
    if kind == "tuple":
        return f"_b = {'(' * depth}user_id,{'),' * (depth - 1)}{')' if depth else ''}\nuser_id = _b{'[0]' * depth}"
    return "_b = " + "{'k': " * depth + "user_id" + "}" * depth + "\nuser_id = _b" + "['k']" * depth


V = [taint("control", "identity", "pass")]
# containers that hold the value and give it back
V += [
    taint("container", "list_append_pop", "_l = []\n_l.append(user_id)\nuser_id = _l.pop()"),
    taint("container", "list_literal_index", "_l = [user_id]\nuser_id = _l[0]"),
    taint("container", "dict_store_load", "_d = {}\n_d['k'] = user_id\nuser_id = _d['k']"),
    taint("container", "dict_literal", "_d = {'k': user_id}\nuser_id = _d['k']"),
    taint("container", "set_next_iter", "user_id = next(iter({user_id}))"),
    taint("container", "tuple_unpack", "(user_id,) = (user_id,)"),
    taint("container", "deque_append_pop", "_q = _c.deque()\n_q.append(user_id)\nuser_id = _q.pop()", "import collections as _c"),
    taint("container", "queue_put_get", "_q = _q_.Queue()\n_q.put(user_id)\nuser_id = _q.get()", "import queue as _q_"),
    taint("container", "lifo_put_get", "_q = _q_.LifoQueue()\n_q.put(user_id)\nuser_id = _q.get()", "import queue as _q_"),
    taint("container", "simplequeue_put_get", "_q = _q_.SimpleQueue()\n_q.put(user_id)\nuser_id = _q.get()", "import queue as _q_"),
    taint("container", "object_attribute", "_o = type('B', (), {})()\n_o.v = user_id\nuser_id = _o.v"),
    taint("container", "stringio", "user_id = _io.StringIO(user_id).read()", "import io as _io"),
]
# nesting depth sweep
for kind in ("list", "tuple", "dict"):
    for depth in (1, 2, 3, 4, 5, 6, 8):
        V.append(taint(f"nest_{kind}", f"{kind}_depth_{depth}", nest(depth, kind)))
# string-level transformations
V += [
    taint("string", "str_call", "user_id = str(user_id)"),
    taint("string", "concat_empty", "user_id = user_id + ''"),
    taint("string", "slice_all", "user_id = user_id[:]"),
    taint("string", "join_single", "user_id = ''.join([user_id])"),
    taint("string", "encode_decode", "user_id = user_id.encode().decode()"),
    taint("string", "chr_ord_generator", "user_id = ''.join(chr(ord(_c)) for _c in user_id)"),
    taint("string", "chr_ord_listcomp", "user_id = ''.join([chr(ord(_c)) for _c in user_id])"),
    taint("string", "chr_ord_map", "user_id = ''.join(map(chr, map(ord, user_id)))"),
    taint("string", "ord_only_roundtrip_via_list", "user_id = ''.join([_c for _c in user_id])"),
    taint("string", "base64", "user_id = _b64.b64decode(_b64.b64encode(user_id.encode())).decode()", "import base64 as _b64"),
    taint("string", "json_roundtrip", "user_id = _j.loads(_j.dumps(user_id))", "import json as _j"),
    taint("string", "pickle_roundtrip", "user_id = _p.loads(_p.dumps(user_id))", "import pickle as _p"),
    taint("string", "format_call", "user_id = '{}'.format(user_id)"),
]
# data returns to the program through a callee
V += [
    taint("call", "identity_function", "def _ident(x):\n    return x\nuser_id = _ident(user_id)"),
    taint("call", "lambda_identity", "user_id = (lambda x: x)(user_id)"),
    taint("call", "module_level_identity", "user_id = _ident_mod(user_id)", "def _ident_mod(x):\n    return x"),
    taint("call", "db_roundtrip",
          "_d = _s3.connect(':memory:')\n_d.execute('CREATE TABLE t (v TEXT)')\n_d.execute('INSERT INTO t VALUES (?)', (user_id,))\n"
          "user_id = _d.execute('SELECT v FROM t').fetchone()[0]", "import sqlite3 as _s3"),
]
# how the sink is called
V += [
    sink("sink", "alias_bound_method", "    _run = cursor.execute\n    _run(query)\n"),
    sink("sink", "getattr_literal", "    getattr(cursor, 'execute')(query)\n"),
    sink("sink", "getattr_computed", "    getattr(cursor, 'exe' + 'cute')(query)\n"),
    sink("sink", "dict_dispatch", "    {'run': cursor.execute}['run'](query)\n"),
    sink("sink", "methodcaller", "    _o.methodcaller('execute', query)(cursor)\n", "import operator as _o"),
    sink("sink", "partial", "    _f.partial(cursor.execute)(query)\n", "import functools as _f"),
    sink("sink", "unbound_via_type", "    type(cursor).execute(cursor, query)\n"),
    sink("sink", "wrapper_function", "    _exec(cursor, query)\n", "def _exec(c, q):\n    return c.execute(q)\n"),
]


def build(v):
    head = HEADER.rstrip("\n") + "\n" + (v["imports"] + "\n" if v["imports"] else "")
    body = BODY
    if "sink" in v:
        body = body.replace(SINK, v["sink"])
    else:
        pre = "".join("    " + line + "\n" for line in v["prelude"].split("\n"))
        body = pre + body
    return head + "def get_user_profile(db_conn, user_id):\n" + body


def main():
    config_path, out = sys.argv[1], Path(sys.argv[2])
    only = sys.argv[3:]  # optional group names
    config = load_config(config_path)
    scanner, oracle = scanner_from(config), Oracle(config.get("oracle_timeout", 5))
    out.mkdir(parents=True, exist_ok=True)
    done = {}
    if (out / "catalog.jsonl").exists():
        done = {json.loads(l)["name"]: 1 for l in (out / "catalog.jsonl").read_text().splitlines() if l.strip()}
    base = oracle.evaluate(SEED)
    work = Path(".sastlab/runs/rewrite-catalog")
    for v in V:
        if v["name"] in done or (only and v["group"] not in only):
            continue
        source = build(v)
        record = {"name": v["name"], "group": v["group"], "source_sha": __import__("hashlib").sha256(source.encode()).hexdigest()}
        try:
            compile(source, "<v>", "exec")
            comparison = oracle.compare(base, source)
            record["equivalent"] = bool(comparison.get("equivalent"))
            record["oracle_error"] = comparison.get("error", "")
            t = time.monotonic()
            scan = scanner.scan(source, work / v["name"])
            record.update(scan_status=scan.status, detected=bool(scan.rules), rules=sorted(scan.rules),
                          scan_seconds=round(time.monotonic() - t, 1), error=scan.error[:200])
        except Exception as exc:  # a variant that does not compile is a catalog bug, not a result
            record.update(equivalent=False, scan_status="not_run", detected=None, error=f"{type(exc).__name__}: {exc}")
        with (out / "catalog.jsonl").open("a") as f:
            f.write(json.dumps(record) + "\n")
        (out / "sources").mkdir(exist_ok=True)
        (out / "sources" / f"{v['name']}.py").write_text(source)
        print(f"{v['group']:10s} {v['name']:28s} equivalent={record['equivalent']} detected={record['detected']}", flush=True)


if __name__ == "__main__":
    main()
