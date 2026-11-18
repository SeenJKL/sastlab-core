"""Recompute per-engine, per-rule results from persisted attempts."""
from collections import defaultdict
import math


def summarize(manifest, qualifications, attempts):
    config = manifest["config"]
    strategies = config["strategies"]
    cards = []
    for rule in sorted({r for q in qualifications for r in q["qualifying_rules"]}):
        seeds = {q["seed"] for q in qualifications if rule in q["qualifying_rules"]}
        success = {s: {a["seed"] for a in attempts if a["strategy"] == s and rule in a["bypassed_rules"]} & seeds
                   for s in range(1, 8)}
        tau = math.ceil(len(seeds) / 2)
        union = set().union(*success.values())
        relevant = [a for a in attempts if a["seed"] in seeds]
        counts = defaultdict(set)
        for a in relevant:
            counts[a["seed"], a["strategy"], a["trajectory"]].add(a["attempt"])
        expected_ids = set(range(1, config["attempts"] + 1))
        complete = manifest.get("state") == "complete" and set(strategies) == set(range(1, 8)) and all(
            counts[seed, strategy, trajectory] == expected_ids
            for seed in seeds for strategy in range(1, 8) for trajectory in range(1, config["trajectories"] + 1))
        complete = complete and all(q.get("scan", {}).get("status") == "ok" and q.get("oracle", {}).get("ok", False) for q in qualifications)
        complete = complete and all(a["scan"]["status"] == "ok" and not a.get("error") and a.get("oracle", {}).get("ok", False) for a in relevant)
        full_budget = config["attempts"] == 30 and config["trajectories"] == 5
        weak = next((s for s in (1, 2) if len(success[s]) >= tau), None)
        guided = next((s for s in range(3, 8) if len(success[s]) >= tau), None)
        if len(seeds) < 3:
            classification = "excluded"
        elif not complete or not full_budget:
            classification = "incomplete"
        elif weak:
            classification = "weak"
        elif guided or len(union) >= tau:
            classification = "guidance-sensitive"
        else:
            classification = "robust"
        cumulative = set()
        first_crossing = None
        for s in range(1, 8):
            cumulative |= success[s]
            if first_crossing is None and len(cumulative) >= tau:
                first_crossing = s
        cards.append({"engine": manifest["engine"], "rule": rule, "qualifying_seeds": sorted(seeds),
                      "S_rule": len(seeds), "threshold": tau, "exploratory": 3 <= len(seeds) <= 5,
                      "classification": classification, "complete": complete, "full_budget": full_budget,
                      "synthetic_corpus": config.get("corpus_kind") == "synthetic",
                      "individual_successes": {str(s): sorted(v) for s, v in success.items()},
                      "portfolio_successes": sorted(union), "individual_crossing": weak or guided,
                      "portfolio_first_crossing_after_strategy": first_crossing})
    strategy_metrics = []
    for strategy in strategies:
        records = [a for a in attempts if a["strategy"] == strategy]
        times, evading = {}, defaultdict(set)
        trajectories = {(a["seed"], a["trajectory"]) for a in records}
        for a in records:
            if a["bypassed_rules"]:
                evading[a["seed"], a["trajectory"]].add(a["candidate_sha256"])
            if a["bypassed_rules"]:
                key = a["seed"] + ":" + str(a["trajectory"])
                times.setdefault(key, {"attempt": a["attempt"], "wall_seconds": a["elapsed_seconds"], "charged_seconds": a.get("charged_seconds")})
        strategy_metrics.append({"strategy": strategy, "attempts": len(records),
            "unique_candidates": len({(a["seed"], a["candidate_sha256"]) for a in records}),
            "scanner_invocations": sum(a["scanner_invoked"] for a in records),
            "cache_hits": sum(a["cache_hit"] for a in records),
            "scanner_errors": sum(a["scan"]["status"] == "error" for a in records),
            "verified_bypass_attempts": sum(bool(a["bypassed_rules"]) for a in records),
            "distinct_bypass_candidates": len({(a["seed"], a["candidate_sha256"]) for a in records if a["bypassed_rules"]}),
            "distinct_bypass_per_trajectory": (sum(len(v) for v in evading.values()) / len(trajectories)) if trajectories else 0,
            "time_to_first_bypass": times, "wall_time_comparable": not config.get("cache", False)})
    return {"engine": manifest["engine"], "report_cards": cards, "strategy_metrics": strategy_metrics,
            "qualification_failures": [q["seed"] for q in qualifications if not q["qualifying_rules"]]}
