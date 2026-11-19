import difflib
import math
import random
from .scanners import compact_trace
from .transforms import OPERATORS, available, call_depth, candidate, syntax_distance


def shuffled(names, seed):
    """Deterministic per-call presentation order, so list position carries no information."""
    return random.Random(seed).sample(list(names), len(names))

STRATEGIES = {1: "naive", 2: "blackbox", 3: "blackbox_agent", 4: "static_greybox",
              5: "trace_agent", 6: "metric_syntax", 7: "metric_depth"}


DIAGNOSTIC_FIELDS = ("rule", "message", "sink", "snippet", "trace")


def observation(strategy, seed_source, current_source, scan, history, choices, fields=None, target_rules=None):
    state = {"available": [OPERATORS[i] for i in choices],
             "diff": "\n".join(difflib.unified_diff(seed_source.splitlines(), current_source.splitlines(), n=1)),
             # with target_rules, a finding of another rule does not count as detected (the runner's verdict)
             "verdict": "error" if scan.status != "ok" else ("detected" if (set(scan.rules) & set(target_rules) if target_rules is not None
                                                             else scan.findings) else "clean"),
             "history": [{"mask": h["mask"], "verdict": h["verdict"]} for h in history[-3:]]}
    if strategy == 5:
        # `fields` (default: all) restricts which parts of a finding the agent sees; used for the ablation study.
        full = lambda f: {"rule": f["rule_id"], "message": f["message"], "sink": f["start_line"],
                          "snippet": f["snippet"], "trace": compact_trace(f["trace"])}
        keep = DIAGNOSTIC_FIELDS if fields is None else fields
        state["diagnostics"] = [{k: v for k, v in full(f).items() if k in keep} for f in scan.findings
                                if target_rules is None or f["rule_id"] in target_rules]  # the same rules as the verdict
    return state


class Search:
    def __init__(self, strategy, trajectory_seed, source, llm=None, metadata="", temperature=0.25, pool=None, diagnostic_fields=None, order="increasing",
                 metropolis_restart=True, target_rules=None):
        if order not in ("increasing", "any"):
            raise ValueError("order must be 'increasing' or 'any'")
        self.order = order
        self.metropolis_restart = metropolis_restart
        self.target_rules = target_rules
        self.strategy, self.source, self.llm = strategy, source, llm
        self.pool = None if pool is None else sorted(OPERATORS.index(n) for n in pool)
        if self.pool is not None and not self.pool:
            raise ValueError("Operator pool is empty")
        self.diagnostic_fields = None if diagnostic_fields is None else tuple(diagnostic_fields)
        self.seed = trajectory_seed
        self.rng = random.Random(trajectory_seed)
        self.temperature = temperature
        self.ranking = [OPERATORS[i] for i in (self.pool if self.pool is not None else range(len(OPERATORS)))]
        if strategy == 4:
            order = shuffled(self.ranking, trajectory_seed)
            self.ranking = llm.choose({"available": order, "metadata": metadata,
                                      "task": "Rank all operators once"}, order, self.rng,
                                     trajectory_seed, ranking=True, universe=self.ranking)

    def available(self, mask):
        if self.order == "any":
            # Any operator not yet in the candidate; the candidate is a function of the set, so order of addition does not matter.
            return [i for i in (self.pool if self.pool is not None else range(len(OPERATORS))) if not mask >> i & 1]
        return available(mask, self.pool)

    def select(self, mask, scan, history, attempt):
        choices = self.available(mask)
        restarted = not choices
        if restarted and (self.strategy not in (6, 7) or self.metropolis_restart):
            mask, choices = 0, self.available(0)
        if self.strategy in (6, 7):
            # Metropolis toggles an operator on or off. Removing one lowers the distance metric, so moves can
            # actually be rejected. Mask 0 (the seed) is not a target, so a one-operator subset has one move fewer;
            # accept() has no Hastings correction for this: the walk is a search heuristic, not a sampler.
            # With metropolis_restart (the default, and the setting of every saved run except the two walk checks
            # semgrep-hard30-walk and pysa-hard-walk) the walk also restarts from the seed, like strategies 1 to 5, when
            # the current subset holds the last operator of the order (saved runs logged these attempts as not restarted).
            # With metropolis_restart false every proposal toggles one operator of the current subset.
            flips = [i for i in (self.pool if self.pool is not None else range(len(OPERATORS))) if mask ^ (1 << i)]
            index = self.rng.choice(flips)
            child = mask ^ (1 << index)
            return mask, child, ("-" if mask >> index & 1 else "") + OPERATORS[index], restarted and self.metropolis_restart
        if self.strategy == 1:
            index = self.rng.choice(choices)
        elif self.strategy == 2:
            # Prioritize unseen candidates, rare operators, and prior clean outcomes.
            visited = {h["mask"] for h in history}
            def score(i):
                child = mask | (1 << i)
                uses = sum(h["operator"] == OPERATORS[i] for h in history)
                successes = sum(h["operator"] == OPERATORS[i] and h["verdict"] == "clean" for h in history)
                return (child not in visited, -uses, successes)
            best = max(score(i) for i in choices)
            index = self.rng.choice([i for i in choices if score(i) == best])
        elif self.strategy == 4:
            index = min(choices, key=lambda i: self.ranking.index(OPERATORS[i]))
        else:
            call_seed = self.seed * 100000 + attempt * 3
            names = shuffled([OPERATORS[i] for i in choices], call_seed)
            state = observation(self.strategy, self.source, candidate(self.source, mask), scan, history,
                                [OPERATORS.index(n) for n in names], self.diagnostic_fields, self.target_rules)
            name = self.llm.choose(state, names, self.rng, call_seed, universe=self.ranking)
            index = OPERATORS.index(name)
        return mask, mask | (1 << index), OPERATORS[index], restarted

    def accept(self, parent_source, child_source):
        if self.strategy not in (6, 7):
            return True, None
        parent_syntax = syntax_distance(self.source, parent_source)
        child_syntax = syntax_distance(self.source, child_source)
        metric = "syntax"
        before, after = parent_syntax, child_syntax
        if self.strategy == 7:
            a, b = call_depth(parent_source), call_depth(child_source)
            if a != b:
                before, after, metric = a, b, "depth"
        delta = after - before
        probability = 1.0 if delta >= 0 else math.exp(delta / self.temperature)
        accepted = self.rng.random() < probability
        return accepted, {"metric": metric, "before": before, "after": after, "probability": probability}
