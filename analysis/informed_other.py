"""Informed prompt on the Semgrep pattern rule (3 seeds x 30 streams) and the CodeQL query (seeds d01 and d02, 30 streams), 3 models, history-only (3) and
diagnostic (5) agents. Original = blind prompt (earlier runs). Baselines: random and heuristic of the original run on the same streams.
Writes informed_other.tex (rows) and prints the paired differences."""
import collections, json, random, statistics as st
from pathlib import Path
from _paths import RESULTS, OUT_DIR

R = RESULTS
OUT = OUT_DIR
# (scanner, model): (original run, informed run); baseline for random/heuristic is the 8B original run of the scanner (all strategies, same streams)
CELLS = [("Pattern rule", "8B", "semgrep-hard30", "semgrep-informed-8b"), ("Pattern rule", "Coder", "semgrep-hard30-qwen", "semgrep-informed-qwen"),
         ("Pattern rule", "35B", "semgrep-hard30-q36", "semgrep-informed-q36"),
         ("Data-flow query", "8B", "codeql-more-orig-8b", "codeql-more-informed-8b"), ("Data-flow query", "Coder", "codeql-more-orig-qwen", "codeql-more-informed-qwen"),
         ("Data-flow query", "35B", "codeql-more-orig-q36", "codeql-more-informed-q36")]
SHORT = {"Pattern rule": "Pattern", "Data-flow query": "Data-flow"}
BASE = {"Pattern rule": "semgrep-hard30", "Data-flow query": "codeql-more-base"}
AGENT = {3: "History-only", 5: "Diagnostic"}


def firsts(run, strategy, keys=None):
    rows = [json.loads(l) for l in (R / run / "attempts.jsonl").read_text().splitlines() if l.strip()]
    budget = json.loads((R / run / "manifest.json").read_text())["config"]["attempts"]
    g = collections.defaultdict(list)
    for r in rows:
        if r["strategy"] == strategy and (keys is None or (r["seed"], r["trajectory"]) in keys):
            g[(r["seed"], r["trajectory"])].append(r)
    bad = [k for k, v in g.items() if len(v) != budget]
    if bad:
        return None, budget
    return {k: min([r["attempt"] for r in v if r["bypassed_rules"]] or [budget + 1]) for k, v in g.items()}, budget


def cl(keys, vals):
    """Average the paired differences of one stream (trajectory index) over the seeds, so that the unit of resampling is the stream, as in the method section."""
    g = collections.defaultdict(list)
    for k, v in zip(keys, vals):
        g[k[1]].append(v)
    return [st.mean(v) for _, v in sorted(g.items())]


def boot(x, n=5000, seed=11):
    rng = random.Random(seed)
    m = sorted(st.mean(rng.choices(x, k=len(x))) for _ in range(n))
    return m[int(0.025 * n)], m[int(0.975 * n) - 1]


def p_flip(x, n=5000, seed=5):
    rng = random.Random(seed)
    o = abs(st.mean(x))
    return (sum(abs(st.mean(d * rng.choice((-1, 1)) for d in x)) >= o - 1e-12 for _ in range(n)) + 1) / (n + 1)


def sgn(v):
    return f"{v:+.2f}".replace("-", "$-$").replace("+", "$+$")


def main():
    lines, macros = [], {}
    SC = {"Pattern rule": "Pat", "Data-flow query": "Flow"}; MD = {"8B": "Eight", "Coder": "Coder", "35B": "Big"}; AG = {3: "Hist", 5: "Diag"}
    for scanner in ("Pattern rule", "Data-flow query"):
        rnd, b = firsts(BASE[scanner], 1)
        keys = set(rnd)
        if lines:  # the heading of the first scanner is written in the table environment: \multicolumn cannot follow \input
            lines.append(f"\\multicolumn{{5}}{{@{{}}l}}{{\\emph{{{scanner}}}}} \\\\")
        lines.append(f"Random & -- & -- & {st.mean(rnd.values()):.2f} ({sum(v <= b for v in rnd.values())}/{len(rnd)}) & -- \\\\")
        per = {}
        macros[f"inf{SC[scanner]}RandMean"] = f"{st.mean(rnd.values()):.2f}"; macros[f"inf{SC[scanner]}RandFound"] = sum(v <= b for v in rnd.values()); macros[f"inf{SC[scanner]}Streams"] = len({k[1] for k in rnd}); macros[f"inf{SC[scanner]}Units"] = len(rnd)
        for sc, model, orig, inf in CELLS:
            if sc != scanner or not (R / inf / "attempts.jsonl").exists():
                continue
            for s in (3, 5):
                f, _ = firsts(inf, s, keys)
                if f is None:
                    continue
                o = firsts(orig, s, keys)[0] if orig else None
                ks = sorted(set(f) & set(rnd))
                dr = [f[k] - rnd[k] for k in ks]
                lo, hi = boot(cl(ks, dr))
                orig_txt = f"{st.mean(o.values()):.2f} ({sum(v <= b for v in o.values())}/{len(o)})" if o else "--"
                lines.append(f"{model} & {AGENT[s]} & {orig_txt} & {st.mean(f.values()):.2f} ({sum(v <= b for v in f.values())}/{len(f)}) & {sgn(st.mean(dr))} [{sgn(lo)}, {sgn(hi)}] \\\\")
                k = f"inf{SC[scanner]}{MD[model]}{AG[s]}"
                macros.update({k + "Diff": sgn(st.mean(dr)), k + "Ci": f"[{sgn(lo)}, {sgn(hi)}]", k + "P": ("$<0.001$" if p_flip(cl(ks, dr)) < 0.001 else f"{p_flip(cl(ks, dr)):.3f}"),
                               k + "Found": f"{sum(v <= b for v in f.values())}", k + "Mean": f"{st.mean(f.values()):.2f}", k + "Streams": len(f)})
                if o:
                    ko = sorted(set(o) & set(rnd)); do = [o[k_] - rnd[k_] for k_ in ko]
                    lo_o, hi_o = boot(cl(ko, do))
                    macros.update({k + "OrigFound": f"{sum(v <= b for v in o.values())}", k + "OrigMean": f"{st.mean(o.values()):.2f}", k + "OrigDiff": sgn(st.mean(do)),
                                   k + "OrigCi": f"[{sgn(lo_o)}, {sgn(hi_o)}]", k + "OrigStreams": len(o)})
                per[(model, s)] = f
                print(scanner, model, AGENT[s], "orig", orig_txt, "| informed", f"{st.mean(f.values()):.2f} {sum(v <= b for v in f.values())}/{len(f)}", f"| vs random {st.mean(dr):+.2f} [{lo:+.2f},{hi:+.2f}] p={p_flip(cl(ks, dr)):.4f}")
            oh, od = (firsts(orig, 3, keys)[0], firsts(orig, 5, keys)[0]) if orig else (None, None)
            if oh and od:
                ko = sorted(set(oh) & set(od))
                d0 = [od[k_] - oh[k_] for k_ in ko]
                lo0, hi0 = boot(cl(ko, d0))
                kk0 = f"inf{SC[scanner]}{MD[model]}FbOrig"
                macros.update({kk0 + "Diff": sgn(st.mean(d0)), kk0 + "Ci": f"[{sgn(lo0)}, {sgn(hi0)}]"})
                print("   feedback with the original prompt (diag - hist)", scanner, model, f"{st.mean(d0):+.2f} [{lo0:+.2f},{hi0:+.2f}]")
            if (model, 3) in per and (model, 5) in per:
                h, g = per[(model, 3)], per[(model, 5)]
                ks = sorted(set(h) & set(g))
                d = [g[k_] - h[k_] for k_ in ks]
                lo, hi = boot(cl(ks, d))
                kk = f"inf{SC[scanner]}{MD[model]}Fb"
                macros.update({kk + "Diff": sgn(st.mean(d)), kk + "Ci": f"[{sgn(lo)}, {sgn(hi)}]"})
                print("   feedback (diag - hist)", scanner, model, f"{st.mean(d):+.2f} [{lo:+.2f},{hi:+.2f}]")
    (OUT / "informed_other_numbers.tex").write_text("% Generated by analysis/informed_other.py -- do not edit.\n" + "".join("\\newcommand{\\%s}{%s}\n" % (k, v) for k, v in macros.items()))
    (OUT / "informed_other.tex").write_text("% Generated by analysis/informed_other.py -- do not edit.\n" + "\n".join(lines).rstrip("\\ ") + "\n")


if __name__ == "__main__":
    main()
