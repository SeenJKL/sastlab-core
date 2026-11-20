"""Numbers for the second-round results (hard pool, prompt bias, new seeds, rewrite catalog).
Standard library only; prints a plain-text summary of the saved results. Fixed seeds for resampling.
Run: .sastlab/.venv/bin/python analysis/round2_analysis.py"""
import collections as C, json, random, statistics as st
from pathlib import Path
from _paths import RESULTS
R = RESULTS
load = lambda p: [json.loads(x) for x in (R / p).read_text().splitlines() if x.strip()]

A = load("semgrep-hard30/attempts.jsonl")
T = C.defaultdict(dict)
for a in A: T[(a["seed"], a["strategy"], a["trajectory"])][a["attempt"]] = a
first = lambda k: next((n for n in sorted(T[k]) if T[k][n]["bypassed_rules"]), 16)
seeds = sorted({k[0] for k in T}); N = 30
F = {s: {(sd, t): first((sd, s, t)) for sd in seeds for t in range(1, N + 1)} for s in (1, 2, 3, 5, 6)}
print("semgrep-hard30: strategy | found/90 | mean attempts to first evasion (failure = 16) | median")
for s, d in F.items():
    v = list(d.values()); print(f" s{s} | {sum(x < 16 for x in v)} | {st.mean(v):.2f} | {st.median(v)}")
rng = random.Random(7)


def boot(d, n=5000, seed=11):
    """95% bootstrap interval of the mean: the resampling and the index of informed_other.py, more_streams.py, prompt_models.py, prompt_search.py and pysa_search.py."""
    r = random.Random(seed)
    m = sorted(st.mean(r.choices(d, k=len(d))) for _ in range(n))
    return m[int(0.025 * n)], m[int(0.975 * n) - 1]


def paired(a, b):
    d = [st.mean(F[a][(sd, t)] - F[b][(sd, t)] for sd in seeds) for t in range(1, N + 1)]
    lo, hi = boot(d); obs = st.mean(d)
    p = sum(abs(st.mean(x * rng.choice((-1, 1)) for x in d)) >= abs(obs) - 1e-12 for _ in range(5000)) / 5000
    return obs, lo, hi, p
for a, b in ((3, 1), (3, 2), (5, 1), (5, 2), (5, 3), (2, 1), (6, 1), (3, 6)):
    o, l, h, p = paired(a, b); print(f" s{a}-s{b}: {o:+.2f} [{l:+.2f},{h:+.2f}] p={p:.3f}")
for s in (3, 5):
    P = [a for a in A if a["strategy"] == s and a["attempt"] == 1]; c = C.Counter(a["operator"] for a in P)
    print(f" s{s} first pick rename {c['rename']}/{len(P)}, extract_1 {c['extract_1']}/{len(P)}")


# ---- Evasion rate by the taint-analysis class of the operators present (campaign data, 13 operators) ----
OPS = "rename format_swap literal_slice dead_padding extract_1 extract_2 branch_split dict_dispatch dynamic_sink char_launder deep_nest db_roundtrip queue_roundtrip".split()
TAX = {"rename": "control", "format_swap": "control", "literal_slice": "control", "dead_padding": "control",  # mirrors sastlab.transforms.TAXONOMY
       "extract_1": "interprocedural", "extract_2": "interprocedural", "branch_split": "control-flow",
       "dict_dispatch": "sink-resolution", "dynamic_sink": "sink-resolution", "char_launder": "value-propagation",
       "deep_nest": "container", "queue_roundtrip": "container", "db_roundtrip": "second-order-storage"}
for eng in ("semgrep-v6", "codeql-v6"):
    U = {}
    for a in load(f"{eng}/attempts.jsonl"):
        if a["scan"]["status"] == "ok": U[(a["seed"], a["mask"])] = bool(a["bypassed_rules"])
    g = C.defaultdict(lambda: [0, 0])
    for (sd, m), v in U.items():
        cl = {TAX[o] for i, o in enumerate(OPS) if m >> i & 1}
        extra = cl - {"control"}
        key = "control only" if not extra else (next(iter(extra)) + " only (+control)" if len(extra) == 1 else None)
        if key: g[key][0] += v; g[key][1] += 1
    print(f"\n{eng}: unique candidates by class of non-control operators present (evading/total)")
    for k, (e, n) in sorted(g.items()): print(f"  {k:42s} {e}/{n}")


# ---- Witness-path placement probe (CodeQL), results/codeql-path-probe ----
P = load("codeql-path-probe/probe.jsonl")
bad = {r["seed"] for r in P if not r["equivalent"]}  # seeds whose baseline exploit is not live under the oracle
P = [r for r in P if r["seed"] not in bad]
print(f"\npath probe: {len(P)} candidates, {len({r['seed'] for r in P})} seeds (excluded {sorted(bad)}), "
      f"scan errors {sum(r['scan_status'] != 'ok' for r in P)}")
for how in ("identity", "char_launder", "deep_nest", "pickle", "simplequeue", "db_roundtrip"):
    byk = {k: [r for r in P if r["how"] == how and r["kind"] == k] for k in ("param", "def", "use")}
    print(f"  {how:13s}", {k: f"{sum(r['detected'] is False for r in v)}/{len(v)} evade" for k, v in byk.items()})


# ---- Larger model (qwen3-coder-next), strategies 3 and 5, hard Semgrep search ----
Q = load("semgrep-hard30-qwen/attempts.jsonl")
for a in Q: T[(a["seed"], 100 + a["strategy"], a["trajectory"])][a["attempt"]] = a
for s_ in (103, 105): F[s_] = {(sd, t): first((sd, s_, t)) for sd in seeds for t in range(1, N + 1)}
print("\nqwen3-coder-next (strategy ids 103 = history-only, 105 = diagnostic):")
for s_ in (103, 105):
    v = list(F[s_].values()); print(f" s{s_}: found {sum(x < 16 for x in v)}/90, mean {st.mean(v):.2f}, median {st.median(v)}")
for a_, b_ in ((103, 1), (103, 2), (105, 2), (105, 103), (105, 5)):
    o, l, h, p = paired(a_, b_); print(f" s{a_}-s{b_}: {o:+.2f} [{l:+.2f},{h:+.2f}] p={p:.3f}")
c = C.Counter(a["operator"] for a in Q if a["strategy"] == 5 and a["attempt"] == 1)
print(" s5 first pick:", c.most_common(3))


# ---- CodeQL hard pool (llama3.1:8b), results/codeql-hard ----
H = load("codeql-hard/attempts.jsonl"); HT = C.defaultdict(dict)
for a in H: HT[(a["seed"], a["strategy"], a["trajectory"])][a["attempt"]] = a
hs = sorted({k[0] for k in HT})
print("\ncodeql-hard (12 attempts; failure = 13): strategy | found/20 | mean first")
for s_ in range(1, 8):
    v = [next((n for n in sorted(HT[(sd, s_, t)]) if HT[(sd, s_, t)][n]["bypassed_rules"]), 13) for sd in hs for t in range(1, 6)]
    print(f" s{s_} | {sum(x < 13 for x in v)}/{len(v)} | {st.mean(v):.2f}")


# ---- CodeQL hard pool, seed d01, 15 streams (llama strategies 1,2,3,5,6; qwen 3,5), failure = 13 ----
H15 = load("codeql-hard15/attempts.jsonl"); HQ = [a for a in load("codeql-hard-qwen/attempts.jsonl") if a["seed"].startswith("d01")]
def f15(A, s_):
    T_ = C.defaultdict(dict)
    for a in A:
        if a["strategy"] == s_ and a["seed"].startswith("d01"): T_[a["trajectory"]][a["attempt"]] = a
    return {t: next((n for n in sorted(d) if d[n]["bypassed_rules"]), 13) for t, d in T_.items()}
G = {s_: f15(H15, s_) for s_ in (1, 2, 3, 5, 6)}; G[103] = f15(HQ, 3); G[105] = f15(HQ, 5)
print("\ncodeql-hard15 (d01, 15 streams):")
for s_, d_ in G.items():
    v = list(d_.values()); print(f" s{s_}: found {sum(x < 13 for x in v)}/15, mean {st.mean(v):.2f}")
def paired15(a, b):
    d = [G[a][t] - G[b][t] for t in sorted(G[a])]; o = st.mean(d)
    lo, hi = boot(d)
    p = sum(abs(st.mean(x * rng.choice((-1, 1)) for x in d)) >= abs(o) - 1e-12 for _ in range(5000)) / 5000
    return o, lo, hi, p
for a_, b_ in ((3, 1), (5, 1), (5, 3), (6, 1), (103, 1), (105, 1), (103, 2), (105, 2), (105, 103)):
    o, l, h, p = paired15(a_, b_); print(f" s{a_}-s{b_}: {o:+.2f} [{l:+.2f},{h:+.2f}] p={p:.3f}")


# ---- Diagnostic-field ablation (qwen3-coder-next, strategy 5) and qwen3.6:35b, hard Semgrep pool ----
def firsts(name, strat):
    T_ = C.defaultdict(dict)
    for a in load(f"{name}/attempts.jsonl"):
        if a["strategy"] == strat: T_[(a["seed"], a["trajectory"])][a["attempt"]] = a
    return {k: next((n for n in sorted(d) if d[n]["bypassed_rules"]), 16) for k, d in T_.items()}
X = {"full": firsts("semgrep-hard30-qwen", 5), "hist": firsts("semgrep-hard30-qwen", 3), "message": firsts("semgrep-abl-message", 5),
     "snippet": firsts("semgrep-abl-snippet", 5), "line": firsts("semgrep-abl-sink", 5), "q36 hist": firsts("semgrep-hard30-q36", 3),
     "q36 diag": firsts("semgrep-hard30-q36", 5), "heuristic": firsts("semgrep-hard30", 2), "random": firsts("semgrep-hard30", 1)}
print("\nablation / second model (found/90, mean):")
for k, d in X.items(): v = list(d.values()); print(f" {k:10s} {sum(x < 16 for x in v)}/90 {st.mean(v):.2f}")
def pX(a, b):
    d = [st.mean(X[a][(sd, t)] - X[b][(sd, t)] for sd in seeds) for t in range(1, 31)]; o = st.mean(d)
    lo, hi = boot(d)
    p = sum(abs(st.mean(x * rng.choice((-1, 1)) for x in d)) >= abs(o) - 1e-12 for _ in range(5000)) / 5000
    return o, lo, hi, p
for a_, b_ in (("message", "full"), ("snippet", "hist"), ("line", "hist"), ("q36 diag", "q36 hist"), ("q36 diag", "heuristic"), ("q36 diag", "random"), ("q36 hist", "heuristic"), ("q36 hist", "hist")):
    o, l, h, p = pX(a_, b_); print(f" {a_} - {b_}: {o:+.2f} [{l:+.2f},{h:+.2f}] p={p:.3f}")
