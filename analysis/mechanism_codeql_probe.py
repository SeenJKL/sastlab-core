"""CodeQL mechanism probe: for candidates built from seed_01 with 1 rewrite, list the nodes that the stock SqlInjection query treats as a source,
as a sink in subject.py, and as a sink that the source reaches (a CodeQL query run on a fresh database).
usage (from the repository root): .sastlab/.venv/bin/python analysis/mechanism_codeql_probe.py"""
import shutil, subprocess, sys
from pathlib import Path
from common import ROOT

code = ROOT; sys.path.insert(0, str(code))
from sastlab.scanners import WRAPPER
from sastlab.transforms import OPERATORS, candidate

CQ = str((code / ".sastlab/tools/codeql/codeql").resolve())
W = (code / ".sastlab/runs/mech-codeql2").resolve()
PROBE = W / "probe" / "sinks.ql"
SRC = (code / "seeds/seed_01.py").read_text()
mask = lambda *ops: sum(1 << OPERATORS.index(o) for o in ops)

# The probe query and its pack are written below the work directory (.sastlab/ is not part of a checkout).
PROBE_QUERY = """import python
import semmle.python.security.dataflow.SqlInjectionQuery

from DataFlow::Node n, string kind
where
  n.getLocation().getFile().getBaseName() = "subject.py" and SqlInjectionFlow::flowTo(n) and kind = "reached-sink"
  or
  n.getLocation().getFile().getBaseName() = "subject.py" and n instanceof Sink and kind = "sink"
  or
  n instanceof Source and kind = "source"
select kind, n.getLocation().getFile().getBaseName(), n.getLocation().getStartLine(), n.toString()
"""
PROBE_PACK = 'name: sastlab/probe\nversion: 0.0.1\ndependencies:\n  codeql/python-all: "*"\n'


def write_probe(query=PROBE):
    query.parent.mkdir(parents=True, exist_ok=True)
    query.write_text(PROBE_QUERY)
    (query.parent / "qlpack.yml").write_text(PROBE_PACK)
    return query


def probe(name, source, query=PROBE):
    if query == PROBE:
        write_probe(query)
    d = W / name
    shutil.rmtree(d, ignore_errors=True)
    (d / "src").mkdir(parents=True)
    (d / "src/subject.py").write_text(source); (d / "src/web_entry.py").write_text(WRAPPER)
    p = subprocess.run([CQ, "database", "create", str(d / "db"), "--language=python", f"--source-root={d / 'src'}", "--threads=1"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr[-400:]
    p = subprocess.run([CQ, "query", "run", f"--database={d / 'db'}", str(query), "--threads=1", "--output", str(d / "r.bqrs")], capture_output=True, text=True)
    assert p.returncode == 0, (p.stdout + p.stderr)[-600:]
    p = subprocess.run([CQ, "bqrs", "decode", "--format=csv", "--no-titles", str(d / "r.bqrs")], capture_output=True, text=True)
    shutil.rmtree(d / "db", ignore_errors=True)
    rows = [r.split(",") for r in p.stdout.strip().splitlines() if r]
    return rows


if __name__ == "__main__":
    for op in (None, "dynamic_sink", "methodcaller_sink", "partial_sink", "unbound_sink", "deep_nest", "db_roundtrip"):
        rows = probe(op or "baseline", SRC if op is None else candidate(SRC, mask(op)))
        kinds = {}
        for r in rows:
            kinds.setdefault(r[0].strip('"'), []).append(r[2])
        print(f"{op or 'baseline':18s} source nodes {len(kinds.get('source', []))} | sink nodes in subject.py {kinds.get('sink', [])} | sinks reached from a source {kinds.get('reached-sink', [])}")
