"""Analysis of the restricted search on Pysa (pool without the single-rewrite evaders; success = neither SQL rule fires).

For each strategy: mean attempts to the first evasion (a trajectory without one counts as budget + 1), trajectories with an evasion,
95% bootstrap interval over streams, and paired differences between strategies (a stream is a trajectory index, averaged over the seeds), with sign-flip tests.
Writes pysa_search.tex (rows) and pysa_search_numbers.tex (macros).
"""
import collections, json, random, statistics as st, sys
from pathlib import Path
from _paths import RESULTS, OUT_DIR

R = RESULTS
OUT = OUT_DIR
NAMES = {1: "Random baseline", 2: "Blackbox heuristic", 3: "History-only agent", 5: "Diagnostic agent", 6: "AST-distance Metropolis"}


def rows(run):
    return [json.loads(l) for l in (R / run / "attempts.jsonl").read_text().splitlines() if l.strip()]


def cl(keys, vals):
    """Average the paired values of one stream (trajectory index) over the seeds, so that the unit of resampling is the stream, as stated in the method section."""
    g = collections.defaultdict(list)
    for k, v in zip(keys, vals):
        g[k[1]].append(v)
    return [st.mean(v) for _, v in sorted(g.items())]


def bootstrap(values, n=5000, seed=11):
    rng = random.Random(seed)
    means = sorted(st.mean(rng.choices(values, k=len(values))) for _ in range(n))
    return means[int(0.025 * n)], means[int(0.975 * n) - 1]


def sign_flip_p(diffs, n=5000, seed=5):
    rng = random.Random(seed)
    observed = abs(st.mean(diffs))
    hits = sum(abs(st.mean(d * rng.choice((-1, 1)) for d in diffs)) >= observed - 1e-12 for _ in range(n))
    return (hits + 1) / (n + 1)


def firsts(records, strategy, budget):
    groups = collections.defaultdict(list)
    for r in records:
        if r["strategy"] == strategy:
            groups[(r["seed"], r["trajectory"])].append(r)
    out = {}
    for key, g in groups.items():
        assert len(g) == budget, (key, len(g))
        hit = [r["attempt"] for r in g if r["bypassed_rules"]]
        out[key] = (min(hit) if hit else budget + 1, bool(hit))
    return out


def fmt_p(p):
    return "$<0.001$" if p < 0.001 else f"{p:.3f}"


def main():
    main_run, rule_run = "pysa-hard-qwen", "pysa-hard-qwen-rule"
    cfg = json.loads((R / main_run / "manifest.json").read_text())["config"]
    budget = cfg["attempts"]
    A = rows(main_run)
    errors = sum(r["scan"]["status"] != "ok" for r in A)
    by = {s: firsts(A, s, budget) for s in sorted({r["strategy"] for r in A})}
    macros, lines = {}, []
    streams = sorted(by[1])
    for s, d in by.items():
        v = [d[k][0] for k in streams]
        lo, hi = bootstrap(cl(streams, v))
        lines.append(f"{s}. {NAMES[s]} & {st.mean(v):.2f} [{lo:.2f}, {hi:.2f}] & {sum(d[k][1] for k in streams)}/{len(streams)} \\\\")
        macros[f"pysaSearchMean{['', 'One', 'Two', 'Three', 'Four', 'Five', 'Six'][s]}"] = f"{st.mean(v):.2f}"
    if (R / rule_run / "attempts.jsonl").exists():
        B = rows(rule_run)
        d = firsts(B, 5, budget)
        v = [d[k][0] for k in streams]
        lo, hi = bootstrap(cl(streams, v))
        lines.append(f"5. Diagnostic agent, rule id only & {st.mean(v):.2f} [{lo:.2f}, {hi:.2f}] & {sum(d[k][1] for k in streams)}/{len(streams)} \\\\")
        macros["pysaSearchMeanRuleOnly"] = f"{st.mean(v):.2f}"
        by["rule"] = d
    diffs = []
    for a, b, label in ((1, 3, "3 $-$ 1"), (1, 5, "5 $-$ 1"), (3, 5, "5 $-$ 3"), (1, 2, "2 $-$ 1"), (1, 6, "6 $-$ 1"), (5, "rule", "5 (rule id only) $-$ 5")):
        if a in by and b in by and set(by[a]) == set(by[b]):
            x = [by[b][k][0] - by[a][k][0] for k in streams]
            xs = cl(streams, x)
            lo, hi = bootstrap(xs)
            diffs.append(f"Strategy {label} & ${st.mean(x):+.2f}$ & [${lo:+.2f}$, ${hi:+.2f}$] & {fmt_p(sign_flip_p(xs))} \\\\")
            key = {(1, 3): "ThreeOne", (1, 5): "FiveOne", (1, 2): "TwoOne", (1, 6): "SixOne"}.get((a, b))
            if key:
                macros[f"pysaSearchDiff{key}"] = f"{st.mean(x):+.2f}".replace("-", "$-$").replace("+", "$+$") if False else f"{abs(st.mean(x)):.2f}"
                macros[f"pysaSearchCi{key}"] = f"[{lo:.2f}, {hi:.2f}]".replace("-", "$-$") if False else f"{min(abs(lo), abs(hi)):.2f} to {max(abs(lo), abs(hi)):.2f}"
    llm = rows(main_run) and [json.loads(l) for l in (R / main_run / "llm.jsonl").read_text().splitlines() if l.strip()] if (R / main_run / "llm.jsonl").exists() else []
    macros.update(pysaSearchStreams=len(streams), pysaSearchBudget=budget, pysaSearchAttempts=len(A), pysaSearchErrors=errors,
                  pysaSearchLlmCalls=len(llm), pysaSearchFallbacks=sum(bool(r.get("fallback")) for r in llm))
    # how often an agent tried the 2 ingredients of an evasion (literal_slice and a sink-resolution rewrite) in some candidate of a stream
    names = {1: "One", 2: "Two", 3: "Three", 5: "Five", 6: "Six"}
    SINK = {"dict_dispatch", "dynamic_sink"}
    def tried(records, strategy):
        g = collections.defaultdict(list)
        for r in records:
            if r["strategy"] == strategy:
                g[(r["seed"], r["trajectory"])].append(r)
        ls = sum(any("literal_slice" in r["operators"] for r in v) for v in g.values())
        sk = sum(any(set(r["operators"]) & SINK for r in v) for v in g.values())
        both = sum(any("literal_slice" in r["operators"] for r in v) and any(set(r["operators"]) & SINK for r in v) for v in g.values())
        return ls, sk, both
    for s in names:
        if s in by:
            ls, sk, both = tried(A, s)
            macros.update({f"pysaSearchTriedLs{names[s]}": ls, f"pysaSearchTriedSink{names[s]}": sk, f"pysaSearchTriedBoth{names[s]}": both})
    def char_stats(records, strategy):
        g = collections.defaultdict(list)
        for r in records:
            if r["strategy"] == strategy:
                g[(r["seed"], r["trajectory"])].append(r)
        added = sum(r["operators"][-1] == "char_launder" for v in g.values() for r in v)
        early = sum({"char_launder", "queue_roundtrip"} <= {r["operators"][-1] for r in sorted(v, key=lambda r: r["attempt"])[:4]} for v in g.values())
        return added, early
    for s in (1, 3, 5):
        added, early = char_stats(A, s)
        macros.update({f"pysaSearchChar{names[s]}": added, f"pysaSearchCharEarly{names[s]}": early})
    if (R / rule_run / "attempts.jsonl").exists():
        added, early = char_stats([dict(r, strategy=5) for r in B], 5)
        macros.update({"pysaSearchCharRule": added, "pysaSearchCharEarlyRule": early})
    if "rule" in by:
        ls, sk, both = tried([dict(r, strategy=5) for r in B], 5)
        macros.update({"pysaSearchTriedLsRule": ls, "pysaSearchTriedSinkRule": sk, "pysaSearchTriedBothRule": both})
    # which minimal sets were found
    sets = collections.Counter(tuple(sorted(r["operators"])) for r in A if r["bypassed_rules"] and r["candidate_sha256"])
    first_sets = collections.Counter()
    for r in A:
        pass
    (OUT / "pysa_search.tex").write_text("% Generated by analysis/pysa_search.py -- do not edit.\n" + "\n".join(lines).rstrip("\\ ") + "\n")
    import re as _re
    short = {"Random baseline": "Random", "Blackbox heuristic": "Heuristic", "AST-distance Metropolis": "Metropolis"}
    base = [f"Baseline & {short[m.group(1)]} & {m.group(2)}" for m in (_re.match(r"\d\. (Random baseline|Blackbox heuristic|AST-distance Metropolis) & (.*)", l) for l in lines) if m]
    (OUT / "pysa_baselines.tex").write_text("% Generated by analysis/pysa_search.py -- do not edit.\n" + "\n".join(base) + "\n")
    (OUT / "pysa_search_paired.tex").write_text("% Generated by analysis/pysa_search.py -- do not edit.\n" + "\n".join(diffs).rstrip("\\ ") + "\n")
    (OUT / "pysa_search_numbers.tex").write_text("% Generated by analysis/pysa_search.py -- do not edit.\n" + "\n".join(
        f"\\newcommand{{\\{k}}}{{{v if isinstance(v, str) else f'{v:,}'.replace(',', '{,}')}}}" for k, v in macros.items()) + "\n")
    print("\n".join(lines)); print(); print("\n".join(diffs)); print(macros)
    print("evading operator sets seen (top):", sets.most_common(6))


if __name__ == "__main__":
    main()
