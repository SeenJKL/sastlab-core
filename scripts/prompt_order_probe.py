"""A/B probe: does the fixed order of operator definitions in the system prompt bias the first pick?
Both conditions send the same first-attempt observation (seed_01, baseline detected, empty history) with the
candidate list shuffled per call; only the order of the definitions differs. No scanner is involved.
usage (from the repository root, with SOCLAAS_API_KEY set):  python3 scripts/prompt_order_probe.py [calls per condition]"""
import collections, json, random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sastlab import llm as L
from sastlab.transforms import OPERATORS
from sastlab.runner import load_config

CODEQL, SEM = {"dynamic_sink", "char_launder", "deep_nest", "db_roundtrip"}, {"extract_1", "extract_2", "branch_split", "dict_dispatch", "dynamic_sink"}


def fixed_order_prompt(seed, universe=None, extra=""):
    """Replacement for llm.system_prompt that keeps the definitions in their fixed order (same parameters as the original)."""
    return L.SYSTEM + (" " + extra if extra else "")


def main(calls=60):
    cfg = load_config("configs/codeql.json")
    client = L.SoCLaaS(**{k: v for k, v in cfg["llm"].items() if k not in ("provider",)}, min_interval=0.3)
    shuffled = L.system_prompt
    out = {"calls_per_condition": calls, "conditions": {}}
    try:
        for condition in ("fixed_order", "shuffled_order"):
            L.system_prompt = fixed_order_prompt if condition == "fixed_order" else shuffled
            picks = []
            for i in range(calls):
                seed = 910000 + i * 3
                names = L.random.Random(seed).sample(list(OPERATORS), len(OPERATORS))
                state = {"available": names, "diff": "", "verdict": "detected", "history": []}
                picks.append(client.choose(state, names, random.Random(seed), seed))
            audit = client.audit[-calls:]
            c = collections.Counter(picks)
            out["conditions"][condition] = {"picks": dict(c.most_common()), "pick_rename": c["rename"],
                "in_codeql_sufficient": sum(p in CODEQL for p in picks),
                "in_semgrep_sufficient": sum(p in SEM for p in picks), "errors": sum("error" in r for r in audit),
                "fallbacks": sum(bool(r.get("fallback")) for r in audit)}
            print(condition, out["conditions"][condition], flush=True)
    finally:
        L.system_prompt = shuffled
    Path("results/prompt-order-probe/summary.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 60)
