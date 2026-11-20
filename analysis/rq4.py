"""RQ4 of the report (Section 4.3, "Does scanner feedback help the agent?").

The diagnostic agent (strategy 5) sees what the history-only agent (strategy 3) sees plus the scanner's diagnostics
(rule identifier, message, line, snippet and, for CodeQL, the path). Both agents of one model run in the same saved
run on the same seeds and streams, so their trajectories pair up exactly.

Saved runs read (results/<name>/):
  the agent runs of Table 5 (table5.RUNS)  Semgrep pattern rule (3 seeds x 30 streams, 15 attempts) and CodeQL query
                                           (2 seeds x 15 streams, 12 attempts); 8B, coder and 35B models; original
                                           prompt (semgrep-hard30, -hard30-qwen, -hard30-q36, codeql-more-orig-*) and
                                           informed prompt (semgrep-informed-*, codeql-more-informed-*)
  semgrep-abl-message, semgrep-abl-snippet, semgrep-abl-sink
                                           coder-model diagnostic agent on the Semgrep pool that sees only one field of
                                           the diagnostics: the rule message, the code snippet, or the line ("sink")
                                           of the finding (config key diagnostic_fields); else as semgrep-hard30-qwen

Method:
  1. Per trajectory (seed, stream k): attempt of the first evasion, budget + 1 when there is none.
  2. Feedback effect = diagnostic minus history-only agent of the same model and prompt, paired on (seed, k),
     averaged over the seeds of each stream, mean over streams with a 95% bootstrap interval (5,000 resamples,
     seed 11). Below 0: feedback reduces the attempts; above 0: it adds attempts; includes 0: no measurable effect.
  3. Ablation: each one-field agent against the coder history-only agent (no feedback) and the full diagnostic
     agent, all from runs with the same pool, seeds, streams, budget and model.
Prints the comparisons and each sentence of RQ4 with the numbers behind it.
"""
from common import claim, heading, manifest, table
from rq3 import outcome, versus
from table5 import RUNS

HISTORY, DIAGNOSTIC = 3, 5
CODER_RUN = "semgrep-hard30-qwen"  # coder model, original prompt, Semgrep pool: full diagnostics and no feedback
ARMS = [("none", CODER_RUN, HISTORY), ("all", CODER_RUN, DIAGNOSTIC),
        ("message", "semgrep-abl-message", DIAGNOSTIC), ("snippet", "semgrep-abl-snippet", DIAGNOSTIC),
        ("line", "semgrep-abl-sink", DIAGNOSTIC)]  # (feedback the agent sees, run, strategy)
SAME_SETUP = ("seeds", "operators", "attempts", "trajectories", "base_seed", "target_rules", "llm")


def feedback_effects():
    """{(prompt, scanner, model): diagnostic - history-only}, printed as a table."""
    effects = {}
    for prompt, which in (("original", 0), ("informed", 1)):
        for scanner, (_baseline, models) in RUNS.items():
            for model, runs in models.items():
                run = runs[which]
                effects[prompt, scanner.split(",")[0], model] = versus(run, DIAGNOSTIC, run, HISTORY)
    table(["Prompt", "Scanner", "Model", "Diagnostic - history-only"], [[*k, v] for k, v in effects.items()])
    return effects


def ablation():
    """{feedback: (found, mean, fields, minus history-only, minus full diagnostic)} of the coder agents."""
    reference, result = manifest(CODER_RUN)["config"], {}
    for feedback, run, strategy in ARMS:
        config = manifest(run)["config"]
        assert all(config[k] == reference[k] for k in SAME_SETUP), run  # only the diagnostic fields differ
        f, n, m = outcome(run, strategy)
        fields = "none (history-only agent)" if strategy == HISTORY else config.get("diagnostic_fields") or "all"
        result[feedback] = (f"{f}/{n}", f"{m:.2f}", fields,
                            versus(run, strategy, CODER_RUN, HISTORY) if strategy == DIAGNOSTIC else "",
                            versus(run, strategy, CODER_RUN, DIAGNOSTIC) if run != CODER_RUN else "")
    table(["Feedback", "Found", "Mean", "Diagnostic fields seen", "Minus history-only", "Minus full diagnostic"],
          [[k, *v] for k, v in result.items()])
    return result


def main():
    heading("Feedback effect: diagnostic minus history-only agent, same model, prompt and streams")
    effects = feedback_effects()
    heading("Ablation of the diagnostics: coder model, Semgrep pool, original prompt")
    rows = ablation()

    heading("RQ4, the report's sentences")

    def coder_35b(prompt, scanner):
        return [f"{scanner} {model}, {prompt} prompt: {effects[prompt, scanner, model]}" for model in ("Coder", "35B")]

    claim("With the original prompt, scanner feedback reduces the attempts of the coder and 35B diagnostic agents "
        "relative to their history-only versions by 3.32 and 6.77 on Semgrep", *coder_35b("original", "Semgrep"))
    claim("and by 1.17 and 1.23 on CodeQL, with every interval below 0", *coder_35b("original", "CodeQL"))
    claim("but it does not help the 8B model",
        *(f"{scanner} 8B, original prompt: {effects['original', scanner, '8B']}" for scanner in ("Semgrep", "CodeQL")))
    claim("an agent that saw only the rule message found an evasion in 90 of 90 trajectories after 1.06 attempts",
        f"{rows['message'][0]} after {rows['message'][1]} (semgrep-abl-message)")
    claim("against 88 of 90 after 4.47 without feedback",
        f"{rows['none'][0]} after {rows['none'][1]} (history-only agent of {CODER_RUN})")
    claim("while the snippet or the line number alone gave no gain",
        *(f"{field} only, minus history-only: {rows[field][3]}" for field in ("snippet", "line")))
    claim("With the informed prompt, the gain shrinks to 0.57 and 0.82 attempts on Semgrep",
        *coder_35b("informed", "Semgrep"))
    claim("and disappears on CodeQL", *coder_35b("informed", "CodeQL"))
    claim("Answer: Feedback helps the coder and 35B models but not the 8B model",
        "the original-prompt lines of the first table")

if __name__ == "__main__":
    main()
