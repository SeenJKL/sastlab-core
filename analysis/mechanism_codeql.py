"""Mechanism checks for the CodeQL findings: add the missing standard-library taint steps as a CodeQL data extension (model pack)
and check whether the alert returns. Each candidate is scanned with the stock pack and with the extension, on a fresh database.
usage (from the repository root): .sastlab/.venv/bin/python analysis/mechanism_codeql.py
"""
import json, shutil, subprocess, sys
from pathlib import Path
from _paths import ROOT

code = ROOT
sys.path.insert(0, str(code))
from sastlab.scanners import WRAPPER
from sastlab.transforms import OPERATORS, candidate

CQ = str(code / ".sastlab/tools/codeql/codeql")
QUERY = "codeql/python-queries@1.8.11:Security/CWE-089/SqlInjection.ql"
W = code / ".sastlab/runs/mech-codeql"
mask = lambda *ops: sum(1 << OPERATORS.index(o) for o in ops)

ROWS = {
    "simplequeue_roundtrip": ['["queue.SimpleQueue", "Member[put,put_nowait]", "Argument[0,item:]", "Argument[self]", "taint"]',
                              '["queue.SimpleQueue", "Member[get,get_nowait]", "Argument[self]", "ReturnValue", "taint"]'],
    "pickle_roundtrip": ['["pickle", "Member[dumps]", "Argument[0,obj:]", "ReturnValue", "taint"]',
                         '["pickle", "Member[loads]", "Argument[0,data:]", "ReturnValue", "taint"]'],
    "char_launder": ['["builtins", "Member[chr]", "Argument[0]", "ReturnValue", "taint"]',
                     '["builtins", "Member[ord]", "Argument[0]", "ReturnValue", "taint"]'],
}


def run(command):
    p = subprocess.run(command, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def alerts(sarif):
    return sum(len(r["results"]) for r in json.loads(Path(sarif).read_text())["runs"])


def pack(op):
    d = W / f"pack-{op}"
    (d / "ext").mkdir(parents=True, exist_ok=True)
    (d / "qlpack.yml").write_text("name: sastlab/ext\nversion: 0.0.1\nlibrary: true\nextensionTargets:\n  codeql/python-all: '*'\n"
                                  "dataExtensions:\n  - ext/*.model.yml\n")
    (d / "ext" / "m.model.yml").write_text("extensions:\n  - addsTo:\n      pack: codeql/python-all\n      extensible: summaryModel\n    data:\n"
                                           + "".join(f"      - {row}\n" for row in ROWS[op]))
    return d


def scan(name, source, extension=None):
    d = W / name
    shutil.rmtree(d, ignore_errors=True)
    (d / "src").mkdir(parents=True)
    (d / "src/subject.py").write_text(source)
    (d / "src/web_entry.py").write_text(WRAPPER)
    c, out = run([CQ, "database", "create", str(d / "db"), "--language=python", f"--source-root={d / 'src'}", "--threads=1"])
    assert c == 0, out[-500:]
    cmd = [CQ, "database", "analyze", str(d / "db"), QUERY, "--rerun", "--format=sarifv2.1.0", f"--output={d / 'r.sarif'}", "--threads=1"]
    if extension:
        cmd += [f"--additional-packs={extension}", "--model-packs=sastlab/ext@0.0.1"]
    c, out = run(cmd)
    assert c == 0, out[-500:]
    n = alerts(d / "r.sarif")
    shutil.rmtree(d / "db", ignore_errors=True)
    return n


if __name__ == "__main__":
    for seed in ("seeds/seed_01.py", "corpus_official/seeds/o05_semgrep.py"):
        src = (code / seed).read_text()
        tag = Path(seed).stem
        print(f"== {seed}: baseline alerts {scan(tag + '-base', src)}")
        for op in ["queue_roundtrip"] + list(ROWS):
            cand = candidate(src, mask(op))
            stock = scan(f"{tag}-{op}-stock", cand)
            ext = scan(f"{tag}-{op}-ext", cand, pack(op)) if op in ROWS else "-"
            print(f"{op:24s} stock pack: {stock} alert(s) | with added standard-library steps: {ext}")
