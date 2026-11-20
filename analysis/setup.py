"""Numbers of the report's Approach, Implementation and Experimental Setup sections (Sections 2, 3 and 4.2), and
Table 2 ("The 7 corpora"), counted from the repository and the saved runs (prints plain text only, no files written).

Read:
  seeds/, seeds_diverse/, corpus_official/seeds/, corpus_real/seeds/, corpus_apps/seeds/, seeds_cmd/, seeds_path/
      the 7 corpora; a seed is a .py file that defines the entry function get_user_profile (other files such as
      corpus_official/seeds/manifest.json and funnel.json describe the harvest and are not counted)
  results/semgrep-v6, results/codeql-v6      the full campaigns (manifest config: attempts N, trajectories K,
                                              strategies; attempts.jsonl: seeds, attempts and CodeQL scan seconds)
  results/semgrep-hard30, results/codeql-more-base   manifests of the restricted pools (operators, seeds, streams,
                                              budget); the logged candidates of all Table 5 runs on each pool give the
                                              pool's minimal evading operator sets
  results/*/llm.jsonl and manifests           every model decision and its fallback flag; the run's model,
                                              temperature and prompt-token cap
  configs/*.json                              experiment configs; scan_cache marks the runs that used the scan cache
  results/codeql-rewrite-catalog/catalog.jsonl   hand-written rewrites of one seed, each checked for equivalence and
                                              scanned with CodeQL

Method: plain counts. A minimal evading set is an operator subset whose candidate evaded on a seed while none of
its proper subsets did; the script also checks that every proper subset was in fact scanned (otherwise minimality
would only mean "not visited"), that a candidate scanned in several runs always got the same verdict, and that
every scanned candidate containing a minimal set evaded.
Prints each count next to the report's sentence.
"""
import collections
import json
import statistics
from pathlib import Path

from common import RESULTS, ROOT, attempts, claim, evaded, heading, jsonl, manifest, table
from table5 import RUNS

CORPORA = [("Main", "seeds", "synthetic, query built with an f-string"),
           ("Varied", "seeds_diverse", "synthetic, other query constructions"),
           ("Official", "corpus_official/seeds", "adapted from the test suites of the rules"),
           ("Independent", "corpus_real/seeds", "OWASP BenchmarkPython, vulpy"),
           ("Deployed", "corpus_apps/seeds", "Parsl, SciTokens, pyLoad releases"),
           ("Command", "seeds_cmd", "synthetic, CWE-78"), ("Path", "seeds_path", "synthetic, CWE-22")]
NOT_WRITTEN_BY_US = ("Official", "Independent", "Deployed")


def seed_count(folder):
    return sum("def get_user_profile(" in p.read_text() for p in (ROOT / folder).glob("*.py"))


def search_setup(run):
    """(attempts N, trajectories K, strategies, seeds, attempt records, operators in the pool or None)."""
    config, records = manifest(run)["config"], attempts(run)
    return (config["attempts"], config["trajectories"], len(config["strategies"]), len({r["seed"] for r in records}),
            len(records), len(config["operators"]) if config.get("operators") else None)


def minimal_evading_sets(runs):
    """{operator names: seeds where they are a minimal evading set}, after the checks in the module docstring."""
    verdict = {}
    for run in runs:
        for r in attempts(run):
            if r["scan"]["status"] == "ok":
                # the same candidate always gets the same verdict, so the runs can be merged
                assert verdict.setdefault((r["seed"], r["mask"]), evaded(r)) == evaded(r)
    names, minimal = manifest(runs[0])["operators"], collections.Counter()  # bit i of a mask is names[i]
    for seed in sorted({s for s, _ in verdict}):
        evading = [m for (s, m), v in verdict.items() if s == seed and v]
        sets = [m for m in evading if not any(o != m and o & m == o for o in evading)]
        for mask in sets:
            sub = (mask - 1) & mask
            while sub:  # every non-empty proper subset was scanned and detected (the empty one is the seed)
                assert verdict.get((seed, sub)) is False, (seed, mask, sub)
                sub = (sub - 1) & mask
            minimal[" + ".join(n for i, n in enumerate(names) if mask >> i & 1)] += 1
        assert all(v for (s, m), v in verdict.items() if s == seed and any(m & x == x for x in sets))
    seeds = len({s for s, _ in verdict})
    return "; ".join(f"{names} (minimal on {n} of {seeds} seeds)" for names, n in minimal.items())


def model_requests():
    """(model decisions, {model: fallbacks}, {(temperature, prompt-token cap, prompt): runs}) over all saved runs."""
    decisions, fallbacks, settings = 0, collections.Counter(), collections.Counter()
    for log in sorted(RESULTS.glob("*/llm.jsonl")):
        records = jsonl(log)
        if not records:  # the two walk reruns use no model and leave an empty log
            continue
        llm = manifest(log.parent.name)["config"]["llm"]
        prompt = "informed" if llm.get("prompt_extra") else "original"  # the informed prompt adds prompt_extra
        settings[llm["temperature"], llm["max_prompt_tokens"], prompt] += 1
        for r in records:
            decisions += "decision" in r  # a failed request is retried and carries no decision
            fallbacks[llm["model"]] += r["fallback"]
    return decisions, fallbacks, settings


def main():
    heading("Table 2: the 7 corpora")
    counts = {name: seed_count(folder) for name, folder, _ in CORPORA}
    table(["Corpus", "Programs", "Origin", "Folder"], [[n, counts[n], o, f] for n, f, o in CORPORA])
    claim("the 20 programs we did not write [Official + Independent + Deployed]",
        " + ".join(str(counts[n]) for n in NOT_WRITTEN_BY_US) + f" = {sum(counts[n] for n in NOT_WRITTEN_BY_US)}")

    heading("Experimental setup: search budgets")
    lines = []
    for run in ("semgrep-v6", "codeql-v6"):
        n, k, strategies, seeds, records, _ = search_setup(run)
        assert records == seeds * strategies * k * n
        lines.append(f"{run}: N={n}, K={k}, {strategies} strategies, {seeds} seeds, {records:,} attempts")
    claim("Our full campaigns run N=30 attempts and K=5 trajectories for all 7 strategies, covering 15 seeds for Semgrep "
        "(15,750 attempts) and 5 seeds for CodeQL (5,250 attempts)", *lines)
    for run, scanner, quote in (
            ("semgrep-hard30", "Semgrep, pattern rule", "The restricted Semgrep pool includes 9 operators and 2 "
             "minimal evading combinations, either extract_1 by itself or format_swap together with literal_slice, "
             "running on 3 f-string seeds with 30 streams and 15 attempts"),
            ("codeql-more-base", "CodeQL, data-flow query", "The restricted CodeQL pool also uses 9 operators with 1 "
             "minimal evading set, char_launder, running on 2 seeds with 15 streams and 12 attempts")):
        n, k, _, seeds, _, operators = search_setup(run)
        pool_runs = sorted({r for pair in RUNS[scanner][1].values() for r in pair} | {run})
        claim(quote, f"{run}: {operators} operators, {seeds} seeds ({Path(manifest(run)['config']['seeds']).name}), "
                   f"{k} streams, {n} attempts",
            f"minimal evading sets over the {len(pool_runs)} runs on this pool: {minimal_evading_sets(pool_runs)}")

    heading("Experimental setup: CodeQL scan times in the full campaign (codeql-v6)")
    seconds = [r["scan"]["seconds"] for r in attempts("codeql-v6") if r["scan"]["status"] == "ok"]
    claim("scans took 14 s at the median and 19 s on average ... with the slowest of all 5,250 scans finishing in 196 s",
        f"median {statistics.median(seconds):.0f} s, mean {statistics.mean(seconds):.0f} s, slowest "
        f"{max(seconds):.0f} s, over {len(seconds):,} scans")

    heading("Models and model client, over every saved run with model requests")
    decisions, fallbacks, settings = model_requests()
    claim("which replaced the choice of the model in 79 out of roughly 76,000 decisions (0.1%), with 73 of those coming "
        "from the 8B model", f"{sum(fallbacks.values())} of {decisions:,} decisions "
                             f"({sum(fallbacks.values()) / decisions:.1%}); by model: {dict(+fallbacks)}")
    claim("running at a temperature of 0.2. Each request is capped at 2,500 prompt tokens",
        *(f"temperature {t}, cap {cap:,} tokens, {prompt} prompt: {n} run{'s' * (n > 1)}"
          for (t, cap, prompt), n in settings.items()))

    heading("Approach and toolbox")
    cached = [p.stem for p in sorted((ROOT / "configs").glob("*.json")) if json.loads(p.read_text()).get("scan_cache")]
    in_manifest = [p.parent.name for p in sorted(RESULTS.glob("*/manifest.json"))
                   if (manifest(p.parent.name).get("config") or {}).get("scan_cache")]  # exhaustive runs: no config
    claim("A subset that was tried before is evaluated again, from a scan cache in 19 later runs",
        f"{len(cached)} configs in configs/ set scan_cache",
        f"{len(in_manifest)} saved manifests record it; not recorded in {sorted(set(cached) - set(in_manifest))}")
    catalog = jsonl(RESULTS / "codeql-rewrite-catalog" / "catalog.jsonl")
    evading = [v for v in catalog if v["equivalent"] and v["scan_status"] == "ok" and not v["detected"]]
    claim("the 17 variants that evaded CodeQL in a catalog of 59",
        f"{len(evading)} of {len(catalog)} (equivalent to the seed, scanned, not detected)")

if __name__ == "__main__":
    main()
