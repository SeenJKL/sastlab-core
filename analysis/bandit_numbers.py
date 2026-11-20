"""Bandit results: candidates, silent candidates and exceptions to the observed rule, per corpus.
Writes bandit_numbers.tex."""
import ast, json
from pathlib import Path
from _paths import ROOT, OUT_DIR

CODE = ROOT
OUT = OUT_DIR / "bandit_numbers.tex"
RUNS = {"Main": ("bandit-main-pairs", "seeds", "sql"), "Diverse": ("bandit-diverse-pairs", "seeds_diverse", "sql"),
        "Official": ("bandit-official-pairs", "corpus_official/seeds", "sql"), "Real": ("bandit-real-pairs", "corpus_real/seeds", "sql"),
        "Apps": ("bandit-apps-pairs", "corpus_apps/seeds", "sql"), "Cmd": ("bandit-cmd-pairs", "seeds_cmd", "cmd")}
HIDERS = {"dict_dispatch", "dynamic_sink", "partial_sink", "methodcaller_sink"}


def builds_with_plus(source):
    """True if some assignment builds a string with the + operator."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
            if any(isinstance(n, ast.Constant) and isinstance(n.value, str) for n in ast.walk(node.value)):
                return True
    return False


def predicted(kind, ops, plus):
    if kind == "cmd":
        return bool(HIDERS & set(ops))
    return "literal_slice" in ops or ("format_swap" in ops and plus)


lines, total = [], {"seeds": 0, "cand": 0, "silent": 0, "exc": 0, "err": 0, "noneq": 0}
for name, (run, seeds, kind) in RUNS.items():
    rows = [json.loads(l) for l in (CODE / "results" / run / "evaluations.jsonl").read_text().splitlines()]
    assert json.loads((CODE / "results" / run / "manifest.json").read_text())["state"] == "complete"
    plus = {s: builds_with_plus((CODE / seeds / f"{s}.py").read_text()) for s in {r["seed"] for r in rows}}
    ev = [r for r in rows if r["status"] == "evaluated"]
    scanned = [r for r in ev if r["scan_status"] == "ok"]
    silent = [r for r in scanned if r["bypassed_rules"]]
    exc = [r for r in scanned if bool(r["bypassed_rules"]) != predicted(kind, r["operators"], plus[r["seed"]])]
    vals = {"Seeds": len({r["seed"] for r in rows}), "Cand": len(scanned), "Silent": len(silent), "Exc": len(exc),
            "Err": len(ev) - len(scanned), "Noneq": sum(not r["equivalent"] for r in scanned)}
    for k, v in vals.items():
        lines.append(f"\\newcommand{{\\bandit{name}{k}}}{{{v:,}}}".replace(",", "{,}") if v >= 1000 else f"\\newcommand{{\\bandit{name}{k}}}{{{v}}}")
    key = {"Seeds": "seeds", "Cand": "cand", "Silent": "silent", "Exc": "exc", "Err": "err", "Noneq": "noneq"}
    for k, v in key.items():
        total[v] += vals[k]
for k, v in total.items():
    lines.append(f"\\newcommand{{\\banditAll{k.capitalize()}}}{{{v:,}}}".replace(",", "{,}") if v >= 1000 else f"\\newcommand{{\\banditAll{k.capitalize()}}}{{{v}}}")
OUT.write_text("\n".join(lines) + "\n")
print("\n".join(lines))
