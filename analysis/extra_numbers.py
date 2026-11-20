"""Numbers for the additional corpora (command injection seeds_cmd, programs from independent projects corpus_real) for the 3 analyzers.

An exhaustive run covers all single rewrites and pairs (Semgrep, Pysa) or singles and pairs of the 9 non-flow rewrites (CodeQL).
Evasion: Semgrep and CodeQL: the qualifying rule stopped firing; Pysa: none of its qualifying rules fires (silent).
Writes extra.tex (per-rewrite rows, single rewrites) and extra_numbers.tex (macros).
"""
import collections as C, json, sys
from pathlib import Path
from _paths import RESULTS, OUT_DIR

R = RESULTS
OUT = OUT_DIR
sys.path.insert(0, str(R.parent))
from sastlab.transforms import OPERATORS

RUNS = {("cmd", "semgrep"): ["semgrep-cmd-pairs"], ("cmd", "codeql"): ["codeql-cmd-singles", "codeql-cmd-nonflow-pairs"], ("cmd", "pysa"): ["pysa-cmd-pairs"],
        ("real", "semgrep"): ["semgrep-real-pairs"], ("real", "codeql"): ["codeql-real-singles", "codeql-real-nonflow-pairs"], ("real", "pysa"): ["pysa-real-pairs"],
        ("apps", "semgrep"): ["semgrep-apps-pairs"], ("apps", "codeql"): ["codeql-apps-singles", "codeql-apps-nonflow-pairs"], ("apps", "pysa"): ["pysa-apps-pairs"],
        ("path", "semgrep"): ["semgrep-path-pairs"], ("path", "codeql"): ["codeql-path-singles", "codeql-path-nonflow-pairs"], ("path", "pysa"): ["pysa-path-pairs"]}
FLOW = {"dynamic_sink", "char_launder", "deep_nest", "db_roundtrip", "simplequeue_roundtrip", "pickle_roundtrip", "partial_sink", "methodcaller_sink", "unbound_sink"}
HIDE = {"dict_dispatch", "dynamic_sink", "partial_sink", "methodcaller_sink", "unbound_sink"}
STRUCT = HIDE | {"extract_1", "extract_2", "branch_split"}
RT = {"db_roundtrip", "simplequeue_roundtrip"}


def fmt(n):
    return f"{n:,}".replace(",", "{,}")


def load(corpus, engine):
    cand, qualified, seeds, errors, inequivalent = {}, set(), set(), 0, 0
    for run in RUNS[(corpus, engine)]:
        d = R / run
        if not (d / "evaluations.jsonl").exists() or not (d / "qualifications.json").exists():
            continue
        quals = {q["seed"]: q["qualifying_rules"] for q in json.loads((d / "qualifications.json").read_text())}
        seeds |= set(quals)
        qualified |= {s for s, r in quals.items() if r}
        for line in (d / "evaluations.jsonl").read_text().splitlines():
            e = json.loads(line)
            if e["status"] != "evaluated" or not quals[e["seed"]]:
                continue
            if e["scan_status"] != "ok":
                errors += 1
                continue
            if not e["equivalent"]:
                inequivalent += 1
                continue
            silent = not (set(quals[e["seed"]]) & set(e["scan_rules"]))
            cand[(e["seed"], tuple(sorted(e["operators"])))] = silent if engine == "pysa" else bool(e["bypassed_rules"])
    return cand, qualified, seeds, errors, inequivalent


def main():
    macros, data = {}, {}
    for corpus, cname in (("cmd", "Cmd"), ("real", "Real"), ("apps", "Apps"), ("path", "Path")):
        for engine, ename in (("semgrep", "Sg"), ("codeql", "Cq"), ("pysa", "Py")):
            cand, qualified, seeds, errors, inequivalent = load(corpus, engine)
            data[(corpus, engine)] = cand
            p = f"extra{cname}{ename}"
            macros.update({p + "Seeds": len(seeds), p + "Qual": len(qualified), p + "Cand": fmt(len(cand)), p + "Evade": fmt(sum(cand.values())),
                           p + "Errors": errors, p + "NotEquiv": inequivalent})
            if engine == "codeql":
                exc = [k for k, v in cand.items() if bool(set(k[1]) & FLOW) != v]
                macros[p + "FlowWith"] = fmt(sum(1 for k in cand if set(k[1]) & FLOW))
                macros[p + "FlowExceptions"] = len(exc)
            if engine == "semgrep":
                rule = HIDE if corpus in ("cmd", "path") else STRUCT
                exc = [k for k, v in cand.items() if bool(set(k[1]) & rule) != v]
                macros[p + "RuleWith"] = fmt(sum(1 for k in cand if set(k[1]) & rule))
                macros[p + "RuleExceptions"] = len(exc)
                macros[p + "RuleExceptionsLs"] = sum(1 for k in exc if "literal_slice" in k[1])
            if engine == "pysa":
                rt = {k: v for k, v in cand.items() if set(k[1]) & RT}
                macros[p + "RtTotal"] = fmt(len(rt)); macros[p + "RtSilent"] = fmt(sum(rt.values()))
                macros[p + "Pairs"] = fmt(sum(len(k[1]) == 2 for k in cand)); macros[p + "PairsSilent"] = fmt(sum(v for k, v in cand.items() if len(k[1]) == 2))
                other = {k: v for k, v in cand.items() if k not in rt}
                macros[p + "OtherSilent"] = fmt(sum(other.values())); macros[p + "OtherTotal"] = fmt(len(other))
                # prediction from the SQL study: command injection has 1 rule per seed, so a sink-resolution rewrite suffices; SQL has 2 rules,
                # so a sink-resolution rewrite must be paired with literal_slice. A round trip silences both.
                def predicted(ops):
                    if set(ops) & RT:
                        return True
                    if corpus in ("cmd", "path"):
                        return bool(set(ops) & HIDE)
                    return bool(set(ops) & HIDE) and "literal_slice" in ops
                exc = [k for k, v in cand.items() if predicted(k[1]) != v]
                macros[p + "PredWith"] = fmt(sum(1 for k in cand if predicted(k[1]))); macros[p + "PredExceptions"] = len(exc)
                macros[p + "SinkLsSilent"] = fmt(sum(v for k, v in cand.items() if len(k[1]) == 2 and "literal_slice" in k[1] and set(k[1]) & HIDE and k not in rt))
                macros[p + "SinkLsTotal"] = fmt(sum(1 for k in cand if len(k[1]) == 2 and "literal_slice" in k[1] and set(k[1]) & HIDE and k not in rt))
    rows = []
    for op in OPERATORS:
        cells = []
        for corpus in ("cmd", "real"):
            for engine in ("semgrep", "codeql", "pysa"):
                cand = data[(corpus, engine)]
                v = [x for (s, o), x in cand.items() if o == (op,)]
                cells.append(f"{sum(v)}/{len(v)}" if v else "--")
        rows.append(f"{op.replace('_', chr(92) + '_')} & " + " & ".join(cells) + " \\\\")
    (OUT / "extra.tex").write_text("% Generated by analysis/extra_numbers.py -- do not edit.\n" + "\n".join(rows).removesuffix("\\\\").rstrip() + "\n")
    (OUT / "extra_numbers.tex").write_text("% Generated by analysis/extra_numbers.py -- do not edit.\n" +
                                           "\n".join(f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in macros.items()) + "\n")
    for k, v in macros.items():
        print(k, v)


if __name__ == "__main__":
    main()
