"""Extended behavior-equivalence check: every unique candidate from the saved SQL runs is re-run on a richer database
and 20 inputs (the campaigns used 2 inputs, 3 rows). Candidate = regenerated from seed + mask."""
import contextlib, io, json, sqlite3, sys, collections as C
from pathlib import Path
from common import ROOT
code = ROOT; sys.path.insert(0, str(code))
from sastlab.transforms import candidate, OPERATORS
R = code / "results"
PAYLOADS = ["1", "2", "3", "4", "5", "999", "", " 1", "1' OR '1'='1", "' OR 1=1 --", "1' AND '1'='2", "1' UNION SELECT '9','x','y' --",
            "o'brien", "\u00e9mile", "%", "a" * 5000, "1; DROP TABLE users", "\\", "1 OR 1=1", '1" OR "1"="1']
ROWS = [("1", "alice", "admin"), ("2", "bob", "user"), ("3", "carol", "user"), ("4", "o'brien", "user"), ("5", "\u00e9mile", "admin"), ("10", "dave", "user")]
def run(source):
    out = []
    ns = {"__name__": "ext"}
    with contextlib.redirect_stdout(io.StringIO()):
        exec(compile(source, "<s>", "exec"), ns)
        for p in PAYLOADS:
            db = sqlite3.connect(":memory:")
            if ns.get("SASTLAB_FIXTURE"):  # seed harvested from an official suite: its own tables, 3 rows
                db.executescript(ns["SASTLAB_FIXTURE"])
            else:
                db.executescript("CREATE TABLE users (id TEXT, username TEXT, role TEXT);")
                db.executemany("INSERT INTO users VALUES (?,?,?)", ROWS)
            try:
                out.append([list(r) for r in ns["get_user_profile"](db, p)])
            except Exception as e:
                out.append("ERR:" + type(e).__name__)
            db.close()
    return out
ms = lambda ops: sum(1 << OPERATORS.index(o) for o in ops)
sources = [  # (run, seed dir, kind)
    ("semgrep-v6", "seeds", "a"), ("semgrep-controls-main", "seeds", "e"), ("codeql-v6", "seeds", "a"), ("semgrep-promptfix", "seeds", "a"), ("codeql-promptfix", "seeds", "a"),
    ("semgrep-hard30", "seeds_fstring", "a"), ("semgrep-hard30-qwen", "seeds_fstring", "a"), ("semgrep-hard", "seeds_diverse", "a"),
    ("codeql-hard", "seeds_diverse", "a"), ("codeql-hard-qwen", "seeds_diverse", "a"), ("codeql-hard15", "seeds_diverse", "a"),
    ("codeql-flow-ops-15seeds", "seeds", "e"), ("codeql-flow-ops-seed01", "seeds", "e"),
    ("semgrep-diverse-triples", "seeds_diverse", "e"), ("codeql-diverse-singles", "seeds_diverse", "e"),
    ("codeql-diverse-nonflow-pairs", "seeds_diverse", "e"), ("codeql-newops", "seeds_diverse", "e"), ("semgrep-newops", "seeds_diverse", "e"),
    ("semgrep-official-newops", "corpus_official/seeds", "e"), ("semgrep-official-triples", "corpus_official/seeds", "e"),
    ("codeql-official-singles", "corpus_official/seeds", "e"), ("codeql-official-nonflow-pairs", "corpus_official/seeds", "e"),
    ("pysa-main-singles", "seeds", "e"), ("pysa-main-pairs", "seeds", "e"), ("pysa-diverse-singles", "seeds_diverse", "e"),
    ("pysa-official-singles", "corpus_official/seeds", "e"), ("pysa-official-pairs", "corpus_official/seeds", "e"),
    ("semgrep-real-pairs", "corpus_real/seeds", "e"), ("codeql-real-singles", "corpus_real/seeds", "e"),
    ("codeql-real-nonflow-pairs", "corpus_real/seeds", "e"), ("pysa-real-pairs", "corpus_real/seeds", "e"),
    ("semgrep-taint-main-pairs", "seeds", "e"), ("semgrep-taint-official-pairs", "corpus_official/seeds", "e"),
    ("semgrep-taint-real-pairs", "corpus_real/seeds", "e"), ("semgrep-taint-diverse-singles", "seeds_diverse", "e"),
    ("codeql-latest-main-singles", "seeds", "e"), ("codeql-latest-official-singles", "corpus_official/seeds", "e"),
    # Deployed-project corpus, Pysa triples, and the agent runs of the prompt ablations, informed prompts, repeats and extra CodeQL streams
    # (kind "n" = attempts, including attempts answered from the scan cache)
    ("semgrep-apps-pairs", "corpus_apps/seeds", "e"), ("semgrep-taint-apps-pairs", "corpus_apps/seeds", "e"), ("codeql-apps-singles", "corpus_apps/seeds", "e"),
    ("codeql-apps-nonflow-pairs", "corpus_apps/seeds", "e"), ("pysa-apps-pairs", "corpus_apps/seeds", "e"), ("pysa-triples", "seeds_pysa_hard2", "e"),
    ("semgrep-pattern-main-singles", "seeds", "e"), ("semgrep-pattern-official-singles", "corpus_official/seeds", "e"),
    ("semgrep-latest-main-singles", "seeds", "e"), ("semgrep-latest-official-singles", "corpus_official/seeds", "e"),
    # Bandit (singles and pairs), SQL corpora; its command-injection run is in cmd_equivalence.py
    ("bandit-main-pairs", "seeds", "e"), ("bandit-diverse-pairs", "seeds_diverse", "e"), ("bandit-official-pairs", "corpus_official/seeds", "e"),
    ("bandit-real-pairs", "corpus_real/seeds", "e"), ("bandit-apps-pairs", "corpus_apps/seeds", "e")]
sources += [(n, "seeds_pysa_hard", "n") for n in ("pysa-hard-qwen", "pysa-hard-qwen-rule", "pysa-hard-informed", "pysa-hard-informed-35b", "pysa-hard-informed-8b",
            "pysa-hard-informed-any", "pysa-hard-informed-any-35b", "pysa-hard-informed-noorder", "pysa-hard-any", "pysa-rep1-coder", "pysa-rep1-35b", "pysa-rep1-8b",
            "pysa-rep2-coder", "pysa-rep2-35b", "pysa-rep2-8b")]
sources += [(n, "seeds_pysa_hard2", "n") for n in ("pysa-hard2-informed", "pysa-hard2-informed-35b")]
sources += [(n, "seeds_fstring", "n") for n in ("semgrep-hard30-q36", "semgrep-informed-8b", "semgrep-informed-q36", "semgrep-informed-qwen", "semgrep-rep1-8b", "semgrep-rep1-coder",
            "semgrep-rep1-35b", "semgrep-rep2-8b", "semgrep-rep2-coder", "semgrep-rep2-35b")]
sources += [(n, "seeds_diverse", "n") for n in ("codeql-informed-8b", "codeql-informed-q36", "codeql-informed-qwen", "codeql-more-base", "codeql-more-informed-8b", "codeql-more-informed-q36",
            "codeql-more-informed-qwen", "codeql-more-orig-8b", "codeql-more-orig-q36", "codeql-more-orig-qwen")]
cand = {}  # (dir, seed, mask) -> evading?
for name, sdir, kind in sources:
    f = R / name / ("attempts.jsonl" if kind in ("a", "n") else "evaluations.jsonl")
    if not f.exists():
        print("MISSING RUN", name); continue
    for line in f.read_text().splitlines():
        r = json.loads(line)
        if kind == "n":
            if r.get("scan", {}).get("status") != "ok" or r.get("mask") is None: continue
            key, ev = (sdir, r["seed"], r["mask"]), bool(r["bypassed_rules"])
        elif kind == "a":
            if r["scan"]["status"] != "ok" or not r["scanner_invoked"]: continue
            key, ev = (sdir, r["seed"], r["mask"]), bool(r["bypassed_rules"])
        else:
            if r.get("status") != "evaluated" or r["scan_status"] != "ok": continue
            key, ev = (sdir, r["seed"], ms(r["operators"])), bool(r["bypassed_rules"])
        cand[key] = cand.get(key, False) or ev
base = {}; stats = C.Counter(); bad = []; missing_base = set()
for (sdir, seed, mask), ev in sorted(cand.items()):
    p = code / sdir / (seed + ".py")
    if not p.exists(): missing_base.add((sdir, seed)); continue
    if (sdir, seed) not in base: base[(sdir, seed)] = (p.read_text(), run(p.read_text()))
    src, b = base[(sdir, seed)]
    try: c = candidate(src, mask)
    except ValueError: stats["not_regenerable"] += 1; continue
    same = run(c) == b
    stats[("evading" if ev else "detected", "same" if same else "DIFFERENT")] += 1
    if not same: bad.append((sdir, seed, mask, ev))
print("unique candidates:", f"{len(cand):,}", "| missing seed files:", sorted(missing_base)[:5])
print(dict(stats))
print("different-behavior candidates:", bad[:15], "total", len(bad))
# is each baseline actually exploitable under the richer inputs? (injection input returns more rows than the nominal one)
OR = [PAYLOADS.index(x) for x in ("1' OR '1'='1", "1 OR 1=1", '1" OR "1"="1')]
live = sum(1 for (src, b) in base.values() if any(isinstance(b[i], list) and len(b[i]) > len(b[0]) for i in OR))
print("baseline seeds:", len(base), "| exploit live (an OR-payload returns more rows):", live)
print("baseline seeds not live under the 3 standard OR payloads:", sorted(s for (d, s), (src, b) in base.items() if not any(isinstance(b[i], list) and len(b[i]) > len(b[0]) for i in OR)))
