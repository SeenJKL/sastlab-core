import copy
import json
from pathlib import Path
import random
import time

import pytest

from sastlab.llm import SoCLaaS, SYSTEM, bounded_observation, encode, system_prompt
from sastlab.oracle import Oracle
from sastlab.oracle_worker import evaluate
from sastlab.report import summarize
from sastlab.runner import failed_baselines, load_config, run
from sastlab.scanners import Scan, compact_trace, parse_sarif, parse_semgrep
from sastlab.search import Search, observation
from sastlab.transforms import CORE_OPERATORS, FLOW_OPERATORS, OPERATORS, OPERATOR_HELP, SINK_OPERATORS, TAXONOMY, available, call_depth, candidate, syntax_distance

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "seeds/seed_01.py").read_text()


@pytest.mark.parametrize("path", sorted((ROOT / "seeds").glob("*.py")), ids=lambda p: p.stem)
def test_all_masks_preserve_both_inputs(path):
    source = path.read_text()
    baseline = evaluate(source)
    assert len(baseline[0]) == 1 and len(baseline[1]) == 3
    texts, masks = set(), list(range(256))
    # Flow-breaking operators: every subset, alone and on top of none / all core operators.
    flow = [1 << OPERATORS.index(o) for o in FLOW_OPERATORS]
    subsets = [sum(f for i, f in enumerate(flow) if pick >> i & 1) for pick in range(1, 1 << len(flow))]
    masks += subsets + [255 | subset for subset in subsets]
    for mask in masks:
        transformed = candidate(source, mask)
        assert evaluate(transformed) == baseline, (path, mask)
        assert transformed == candidate(source, mask)
        texts.add(transformed)
    assert len(texts) == len(masks)


def test_canonical_dag():
    paths = {0}
    def visit(mask):
        for i in available(mask):
            child = mask | 1 << i
            assert child not in paths
            paths.add(child)
            visit(child)
    visit(0)
    assert len(paths) == 1 << len(OPERATORS)
    assert available((1 << len(OPERATORS)) - 1) == []
    with pytest.raises(ValueError):
        candidate(SOURCE, 1 << len(OPERATORS))
    assert OPERATORS[:8] == CORE_OPERATORS  # core mask numbers keep their meaning
    assert OPERATORS[:13] == CORE_OPERATORS + FLOW_OPERATORS[:5]  # so do the first thirteen


def test_flow_operators_rewrite_the_flow_not_the_behavior():
    source = candidate(SOURCE, 1 << OPERATORS.index("dynamic_sink"))
    assert "getattr(cursor, 'exe' + 'cute')" in source and ".execute" not in source
    assert "ord(" in candidate(SOURCE, 1 << OPERATORS.index("char_launder"))
    assert "[0][0][0][0][0][0][0][0]" in candidate(SOURCE, 1 << OPERATORS.index("deep_nest"))
    assert "import sqlite3 as _mt_sqlite3" in candidate(SOURCE, 1 << OPERATORS.index("db_roundtrip"))
    assert "queue" in candidate(SOURCE, 1 << OPERATORS.index("queue_roundtrip"))
    # They compose with the structural operators, including branch_split and extraction.
    everything = candidate(SOURCE, (1 << 15) - 1)  # all core and flow operators (sink operators exclude each other)
    assert evaluate(everything) == evaluate(SOURCE)


def test_metric_depth_and_distance():
    assert call_depth(candidate(SOURCE, 16)) == 1
    assert call_depth(candidate(SOURCE, 32)) == 2
    assert call_depth(candidate(SOURCE, 48)) == 3
    assert syntax_distance(SOURCE, SOURCE) == 0
    assert syntax_distance(SOURCE, candidate(SOURCE, 1)) > 0


def test_oracle_rejects_fixed_changed_and_broken_programs():
    oracle = Oracle()
    baseline = oracle.evaluate(SOURCE)
    assert oracle.exploitable(baseline)
    fixed = SOURCE.replace("cursor.execute(query)", 'cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))')
    assert not oracle.compare(baseline, fixed)["equivalent"]
    assert not oracle.exploitable(oracle.evaluate(fixed))
    assert not oracle.compare(baseline, SOURCE.replace("return cursor.fetchall()", "return []"))["equivalent"]
    assert not oracle.compare(baseline, "raise RuntimeError('broken')")["equivalent"]
    started = time.monotonic()
    assert not Oracle(timeout=0.1).evaluate("while True: pass")["ok"]
    assert time.monotonic() - started < 3


def semgrep_data():
    return {"results": [{"check_id": "r", "path": "subject.py", "start": {"line": 2}, "end": {"line": 3},
                         "extra": {"message": "msg", "severity": "WARNING", "lines": "not trusted"}}],
            "paths": {"scanned": ["subject.py"]}, "errors": []}


def test_semgrep_parser_reads_local_snippet_and_fails_closed():
    parsed = parse_semgrep(semgrep_data(), {"subject.py": "a\nb\nc\nd"})
    assert parsed[0]["snippet"] == "b\nc"
    assert parsed[0]["trace"] == []
    for bad in ({}, {"results": []}, {**semgrep_data(), "errors": [{"message": "parse failure"}]}):
        with pytest.raises(ValueError):
            parse_semgrep(bad, {})


def sarif_data():
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"rules": [{"id": "py/sql-injection"}]}},
        "results": [{"ruleIndex": 0, "message": {"text": "SQLi"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "subject.py"}, "region": {"startLine": 2}}}],
            "codeFlows": [{"threadFlows": [{"locations": [{"kinds": ["call"],
                "location": {"physicalLocation": {"region": {"startLine": 1}}, "message": {"text": "source"}}}]}]}]}]}]}


def test_sarif_parser_and_trace_truncation():
    parsed = parse_sarif(sarif_data(), {"subject.py": "a\nb"})
    assert parsed[0]["rule_id"] == "py/sql-injection"
    assert parsed[0]["trace"][0]["call_boundary"]
    trace = [{"line": i, "call_boundary": i == 6} for i in range(15)]
    assert [x["line"] for x in compact_trace(trace)] == [0, 1, 2, 6, 12, 13, 14]
    bad = sarif_data()
    bad["runs"][0]["invocations"] = [{"executionSuccessful": False}]
    with pytest.raises(ValueError):
        parse_sarif(bad, {})


class FakeLLM:
    def __init__(self):
        self.audit = []
        self.observations = []
        self.rank_calls = 0

    def identity(self):
        return {"test_double": True}

    def choose(self, obs, names, rng, seed, ranking=False, universe=None):
        self.universe = universe
        self.observations.append(copy.deepcopy(obs))
        self.rank_calls += int(ranking)
        return rng.sample(names, len(names)) if ranking else rng.choice(names)


class FakeScanner:
    def version(self):
        return "test-double"

    def scan(self, source, directory):
        # A scanner fixture only; real scan verification is a separate integration run.
        if "_mt_extract_" in source:
            return Scan("ok")
        return Scan("ok", [{"rule_id": "r", "message": "secret trace", "start_line": 2,
                            "snippet": "secret", "trace": [], "severity": "WARNING"}])


def test_observation_ablation():
    scan = FakeScanner().scan(SOURCE, None)
    history = [{"mask": 1, "verdict": "detected", "operator": "rename"}]
    black = observation(3, SOURCE, SOURCE, scan, history, [0, 1])
    trace = observation(5, SOURCE, SOURCE, scan, history, [0, 1])
    assert "secret" not in json.dumps(black)
    assert trace.pop("diagnostics")
    assert black == trace


def test_validation_retries_and_uniform_fallback(monkeypatch):
    monkeypatch.setenv("SOCLAAS_API_KEY", "test-value")
    llm = SoCLaaS()
    responses = iter([{"choices": [{"message": {"content": '{"operator":"exec"}'}, "finish_reason": "stop"}],
                       "usage": {"prompt_tokens": 100}}] * 3)
    llm.request = lambda *args: next(responses)
    assert llm.choose({"available": ["rename"]}, ["rename"], random.Random(1), 1) == "rename"
    assert len(llm.audit) == 4 and llm.audit[-1]["fallback"]
    llm = SoCLaaS()
    llm.request = lambda *args: {"choices": [{"message": {"content": '{"ranking":["rename","rename"]}'}, "finish_reason": "stop"}],
                                 "usage": {"prompt_tokens": 100}}
    assert sorted(llm.choose({"available": ["rename", "format_swap"]}, ["rename", "format_swap"], random.Random(1), 1, ranking=True)) == ["format_swap", "rename"]
    assert llm.audit[-1]["fallback"]


def test_prompt_budget_remains_valid_json():
    obs = {"available": list(OPERATORS), "diff": "x" * 10000, "history": [{"mask": 1, "verdict": "detected"}] * 100,
           "diagnostics": [{"message": "long" * 1000, "trace": [{"message": "x" * 1000}] * 20}]}
    bounded = bounded_observation(obs)
    assert len(encode(bounded).encode()) + len(SYSTEM.encode()) + 128 <= 2500
    assert bounded["available"] == list(OPERATORS)
    assert len(obs["history"]) == 100


def test_all_strategies_have_full_budget_and_replay(tmp_path, monkeypatch):
    # In-process test oracle keeps exhaustive search tests fast; subprocess path tested above.
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = {"engine": "semgrep", "seeds": str(ROOT / "seeds"), "seed_limit": 1,
              "rules": str(ROOT / "rules/demo-sqli.yaml"), "attempts": 30, "trajectories": 2,
              "strategies": list(range(1, 8)), "base_seed": 100, "cache": True,
              "metropolis_temperature": 0.25, "work_dir": str(tmp_path / "work"),
            "operators": list(OPERATORS[:13])}  # small pool so walks reach a leaf within the test budget
    llm = FakeLLM()
    run(config, tmp_path / "a", FakeScanner(), llm)
    run(config, tmp_path / "b", FakeScanner(), FakeLLM())
    def read(name):
        return [json.loads(line) for line in (tmp_path / name / "attempts.jsonl").read_text().splitlines()]
    a, b = read("a"), read("b")
    assert len(a) == 7 * 2 * 30
    assert [r["mask"] for r in a] == [r["mask"] for r in b]
    assert llm.rank_calls == 2
    assert {r["trajectory_seed"] for r in a} == {101, 102}
    assert any(r["restarted"] for r in a)
    assert all(not r["bypassed_rules"] or (r["oracle"]["equivalent"] and r["scan"]["status"] == "ok") for r in a)


def report_fixture():
    manifest = {"state": "complete", "engine": "semgrep", "config": {"strategies": list(range(1, 8)), "attempts": 30, "trajectories": 5}}
    qualifications = [{"seed": str(i), "qualifying_rules": ["r"], "scan": {"status": "ok"}, "oracle": {"ok": True}} for i in range(6)]
    records = [{"seed": str(i), "strategy": s, "trajectory": k, "attempt": n, "bypassed_rules": [],
                "scan": {"status": "ok"}, "oracle": {"ok": True}, "candidate_sha256": str(n), "cache_hit": False,
                "scanner_invoked": True, "elapsed_seconds": n}
               for i in range(6) for s in range(1, 8) for k in range(1, 6) for n in range(1, 31)]
    return manifest, qualifications, records


def test_report_threshold_union_and_incomplete():
    manifest, qualifications, records = report_fixture()
    def card():
        return summarize(manifest, qualifications, records)["report_cards"][0]
    assert card()["classification"] == "robust"
    for r in records:
        if (r["strategy"], r["seed"]) in {(3, "0"), (4, "1"), (5, "2")}:
            r["bypassed_rules"] = ["r"]
    assert card()["classification"] == "guidance-sensitive"
    assert card()["individual_crossing"] is None
    assert card()["portfolio_first_crossing_after_strategy"] == 5
    for r in records:
        if r["strategy"] == 1 and r["seed"] in {"0", "1", "2"}:
            r["bypassed_rules"] = ["r"]
    assert card()["classification"] == "weak"
    records.pop()
    assert card()["classification"] == "incomplete"


def test_scanner_error_never_bypasses(tmp_path, monkeypatch):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    class BrokenAfterBaseline(FakeScanner):
        def scan(self, source, directory):
            return super().scan(source, directory) if Path(directory).name == "baseline" else Scan("error", error="timeout")
    config = {"engine": "semgrep", "seeds": str(ROOT / "seeds"), "seed_limit": 1, "attempts": 2,
              "trajectories": 1, "strategies": [1], "base_seed": 1, "cache": True,
              "metropolis_temperature": 0.25, "work_dir": str(tmp_path / "work"),
            "operators": list(OPERATORS[:13])}  # small pool so walks reach a leaf within the test budget
    run(config, tmp_path / "out", BrokenAfterBaseline())
    rows = [json.loads(x) for x in (tmp_path / "out/attempts.jsonl").read_text().splitlines()]
    assert not any(r["bypassed_rules"] for r in rows)
    assert all(r["scan"]["status"] == "error" for r in rows)


def test_prompt_ablation_preserves_common_fields_under_pressure():
    scan = FakeScanner().scan(SOURCE, None)
    scan.findings[0]["message"] *= 100
    history = [{"mask": i, "verdict": "detected", "operator": "rename"} for i in range(20)]
    args = (SOURCE, candidate(SOURCE, 63), scan, history, [6, 7])
    black = bounded_observation(observation(3, *args))
    trace = bounded_observation(observation(5, *args))
    trace.pop("diagnostics")
    assert black == trace


def test_oracle_infrastructure_error_blocks_robust_report():
    manifest, qualifications, records = report_fixture()
    records[0]["oracle"] = {"ok": False, "error": "timeout"}
    assert summarize(manifest, qualifications, records)["report_cards"][0]["classification"] == "incomplete"


def test_interrupted_manifest_blocks_complete_classification():
    manifest, qualifications, records = report_fixture()
    manifest["state"] = "interrupted"
    assert summarize(manifest, qualifications, records)["report_cards"][0]["classification"] == "incomplete"


def test_failed_baseline_blocks_complete_classification():
    manifest, qualifications, records = report_fixture()
    qualifications.append({"seed": "failed", "qualifying_rules": [], "scan": {"status": "error"}, "oracle": {"ok": True}})
    assert summarize(manifest, qualifications, records)["report_cards"][0]["classification"] == "incomplete"


def test_scanner_subprocess_error_and_codeql_commands(tmp_path, monkeypatch):
    from sastlab import scanners
    commands = []
    def success(command, timeout, cwd=None):
        commands.append(command)
        for arg in command:
            if arg.startswith("--output="):
                Path(arg.split("=", 1)[1]).write_text(json.dumps(sarif_data()))
        return 0, "", ""
    monkeypatch.setattr(scanners, "run_process", success)
    scanner = scanners.Scanner("codeql", "codeql", None, query="codeql/python-queries@1.8.11:Security/CWE-089/SqlInjection.ql")
    result = scanner.scan(SOURCE, tmp_path / "codeql")
    assert result.status == "ok" and result.rules == ["py/sql-injection"]
    assert commands[0][1:3] == ["database", "create"]
    assert commands[1][1:3] == ["database", "analyze"]
    assert "--format=sarifv2.1.0" in commands[1]
    monkeypatch.setattr(scanners, "run_process", lambda *args: (2, "", "broken scanner"))
    assert scanner.scan(SOURCE, tmp_path / "failure").status == "error"
    semgrep = scanners.Scanner("semgrep", "semgrep", "rules.yaml")
    assert semgrep.scan(SOURCE, tmp_path / "sg-failure").status == "error"
    monkeypatch.setattr(scanners, "run_process", lambda *args: (0, "not JSON", ""))
    assert semgrep.scan(SOURCE, tmp_path / "sg-malformed").status == "error"


class InterruptingScanner(FakeScanner):
    """Dies like a killed process after a fixed number of candidate scans."""
    def __init__(self, limit):
        self.limit, self.count = limit, 0

    def scan(self, source, directory):
        if Path(directory).name != "baseline":
            self.count += 1
            if self.count > self.limit:
                raise KeyboardInterrupt
        return super().scan(source, directory)


def resume_config(tmp_path):
    return {"engine": "semgrep", "seeds": str(ROOT / "seeds"), "seed_limit": 2,
            "rules": str(ROOT / "rules/demo-sqli.yaml"), "attempts": 6, "trajectories": 2,
            "strategies": list(range(1, 8)), "base_seed": 100, "cache": False,
            "metropolis_temperature": 0.25, "work_dir": str(tmp_path / "work"),
            "operators": list(OPERATORS[:13])}  # small pool so walks reach a leaf within the test budget


def rows(path):
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x]


@pytest.mark.parametrize("limit", [7, 100])
def test_resume_matches_uninterrupted_run(tmp_path, monkeypatch, limit):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = resume_config(tmp_path)
    run(config, tmp_path / "ref", FakeScanner(), FakeLLM())
    with pytest.raises(KeyboardInterrupt):
        run(config, tmp_path / "out", InterruptingScanner(limit), FakeLLM())
    partial = rows(tmp_path / "out/attempts.jsonl")
    assert 0 < len(partial) < len(rows(tmp_path / "ref/attempts.jsonl"))
    # A kill can also leave a half-written final line.
    with (tmp_path / "out/attempts.jsonl").open("a") as stream:
        stream.write('{"seed": "seed_0')
    run(config, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True)
    key = lambda r: (r["seed"], r["strategy"], r["trajectory"], r["attempt"], r["mask"], r["bypassed_rules"].__len__())
    assert [key(r) for r in rows(tmp_path / "out/attempts.jsonl")] == [key(r) for r in rows(tmp_path / "ref/attempts.jsonl")]
    assert json.loads((tmp_path / "out/trajectories.json").read_text()) == json.loads((tmp_path / "ref/trajectories.json").read_text())
    assert json.loads((tmp_path / "out/qualifications.json").read_text())[0]["seed"] == "seed_01"
    out, ref = (json.loads((tmp_path / d / "summary.json").read_text()) for d in ("out", "ref"))
    assert out["report_cards"] == ref["report_cards"]
    manifest = json.loads((tmp_path / "out/manifest.json").read_text())
    assert manifest["state"] == "complete" and len(manifest["resumes"]) == 1
    assert manifest["resumes"][0]["kept_attempts"] + manifest["resumes"][0]["discarded_attempts"] == len(partial)
    assert len(rows(tmp_path / "out/llm.jsonl")) == len(rows(tmp_path / "ref/llm.jsonl"))
    bypass_files = {(p.parent.name, int(p.stem)) for p in (tmp_path / "out/bypasses").glob("*/*.py")}
    assert bypass_files == {(r["seed"], r["mask"]) for r in rows(tmp_path / "out/attempts.jsonl") if r["bypassed_rules"]}


def test_resume_discards_only_incomplete_trajectories(tmp_path, monkeypatch):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = resume_config(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        run(config, tmp_path / "out", InterruptingScanner(15), FakeLLM())  # 2 full trajectories + 3 attempts
    run(config, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True)
    resume = json.loads((tmp_path / "out/manifest.json").read_text())["resumes"][0]
    assert resume["kept_attempts"] == 12 and resume["discarded_attempts"] == 3
    assert len(rows(tmp_path / "out/discarded-partial.jsonl")) >= 3


def test_resume_refuses_changed_experiment_and_complete_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = resume_config(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        run(config, tmp_path / "out", InterruptingScanner(5), FakeLLM())
    before = (tmp_path / "out/attempts.jsonl").read_text()
    with pytest.raises(ValueError, match="configuration differs"):
        run({**config, "attempts": 7}, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True)
    assert (tmp_path / "out/attempts.jsonl").read_text() == before  # validation precedes any change
    run(config, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True)
    with pytest.raises(ValueError, match="already complete"):
        run(config, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True)
    with pytest.raises(ValueError, match="Nothing to resume"):
        run(config, tmp_path / "missing", FakeScanner(), FakeLLM(), resume=True)


def test_exhaustive_covers_every_mask_and_resumes(tmp_path, monkeypatch):
    from sastlab.exhaustive import exhaustive
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = {"engine": "semgrep", "seeds": str(ROOT / "seeds"), "rules": str(ROOT / "rules/demo-sqli.yaml")}
    core = list(CORE_OPERATORS)
    exhaustive(config, tmp_path / "ref", 1, scanner=FakeScanner(), operators=core)
    ref = rows(tmp_path / "ref/evaluations.jsonl")
    assert sorted(r["mask"] for r in ref) == list(range(1, 256))
    assert all(r["equivalent"] for r in ref if r["status"] == "evaluated")
    # FakeScanner stops reporting when an extraction helper exists, so those masks evade.
    summary = json.loads((tmp_path / "ref/summary.json").read_text())
    assert summary["complete"] and summary["total_evading"] == sum(bool(r["bypassed_rules"]) for r in ref) > 0
    with pytest.raises(KeyboardInterrupt):
        exhaustive(config, tmp_path / "out", 1, scanner=InterruptingScanner(40), operators=core)
    assert len(rows(tmp_path / "out/evaluations.jsonl")) == 40
    exhaustive(config, tmp_path / "out", 1, resume=True, scanner=FakeScanner(), operators=core)
    key = lambda r: (r["seed"], r["mask"], r["equivalent"], tuple(r["bypassed_rules"]))
    assert [key(r) for r in rows(tmp_path / "out/evaluations.jsonl")] == [key(r) for r in ref]
    with pytest.raises(ValueError, match="already complete"):
        exhaustive(config, tmp_path / "out", 1, resume=True, scanner=FakeScanner(), operators=core)
    with pytest.raises(ValueError, match="operators must be unique"):
        exhaustive(config, tmp_path / "bad", 1, scanner=FakeScanner(), operators=["nope"])


class BaselineDown(FakeScanner):
    """The baseline scan of every seed times out; candidate scans work."""
    def scan(self, source, directory):
        return Scan("error", error="TimeoutExpired: simulated") if Path(directory).name == "baseline" else super().scan(source, directory)


def test_exhaustive_stops_on_a_failed_baseline_scan_and_resumes(tmp_path, monkeypatch):
    from sastlab.exhaustive import exhaustive
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = {"engine": "semgrep", "seeds": str(ROOT / "seeds"), "rules": str(ROOT / "rules/demo-sqli.yaml")}
    operators = list(CORE_OPERATORS)[:3]
    exhaustive(config, tmp_path / "ref", 1, scanner=FakeScanner(), operators=operators)
    with pytest.raises(RuntimeError, match="baseline scan of seed_01 failed"):
        exhaustive(config, tmp_path / "out", 1, scanner=BaselineDown(), operators=operators)
    manifest = json.loads((tmp_path / "out/manifest.json").read_text())
    summary = json.loads((tmp_path / "out/summary.json").read_text())
    assert manifest["state"] == "interrupted" and rows(tmp_path / "out/evaluations.jsonl") == [] and not summary["complete"]
    exhaustive(config, tmp_path / "out", 1, resume=True, scanner=FakeScanner(), operators=operators)
    key = lambda r: (r["seed"], r["mask"], r["equivalent"], tuple(r["bypassed_rules"]))
    assert [key(r) for r in rows(tmp_path / "out/evaluations.jsonl")] == [key(r) for r in rows(tmp_path / "ref/evaluations.jsonl")]
    assert json.loads((tmp_path / "out/summary.json").read_text())["complete"]


def test_summary_is_not_complete_when_a_baseline_scan_did_not_finish():
    from sastlab.exhaustive import summarize_exhaustive
    ok = {"seed": "a", "qualifying_rules": ["r"], "scan": {"status": "ok"}}
    down = {"seed": "b", "qualifying_rules": [], "scan": {"status": "error"}}
    unflagged = {"seed": "c", "qualifying_rules": [], "scan": {"status": "ok"}}
    rows_a = [{"seed": "a", "mask": m, "status": "evaluated", "equivalent": True, "scan_status": "ok", "bypassed_rules": []} for m in (1, 2)]
    assert summarize_exhaustive(rows_a, [ok, unflagged], 2, 2)["complete"]       # an unflagged seed is not an error
    assert not summarize_exhaustive(rows_a, [ok, down], 2, 2)["complete"]        # a failed baseline scan is


def test_run_command_exits_1_when_a_baseline_scan_failed(tmp_path, monkeypatch, capsys):
    from sastlab import cli
    state = {"qualifications": [{"seed": "seed_01", "scan": {"status": "ok"}}, {"seed": "seed_02", "scan": {"status": "error"}}]}

    def finished(config, output, **options):
        output.mkdir(parents=True, exist_ok=True)
        (output / "qualifications.json").write_text(json.dumps(state["qualifications"]))
        return output
    monkeypatch.setattr(cli, "run", finished)
    assert cli.main(["run", "--config", str(ROOT / "configs" / "smoke.json"), "--output", str(tmp_path / "out")]) == 1
    message = capsys.readouterr().err
    assert "seed_02" in message and "--rerun-errors" in message and "seed_01" not in message
    state["qualifications"] = [{"seed": "seed_01", "scan": {"status": "ok"}}]
    assert cli.main(["run", "--config", str(ROOT / "configs" / "smoke.json"), "--output", str(tmp_path / "out")]) == 0

def test_metropolis_walks_the_lattice_and_can_reject(tmp_path, monkeypatch):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = {"engine": "semgrep", "seeds": str(ROOT / "seeds"), "seed_limit": 1,
              "rules": str(ROOT / "rules/demo-sqli.yaml"), "attempts": 30, "trajectories": 5,
              "strategies": [6, 7], "base_seed": 100, "cache": False,
              "metropolis_temperature": 0.25, "work_dir": str(tmp_path / "work"),
            "operators": list(OPERATORS[:13])}  # small pool so walks reach a leaf within the test budget
    run(config, tmp_path / "out", FakeScanner())
    attempts = rows(tmp_path / "out/attempts.jsonl")
    for strategy in (6, 7):
        mine = [r for r in attempts if r["strategy"] == strategy]
        last, jumps = {}, []                                   # a restart is logged exactly where the walk jumps to the seed
        for r in mine:
            jumps.append(r["parent_mask"] != last.get(r["trajectory"], 0))
            if r["accepted"]:
                last[r["trajectory"]] = r["mask"]
        assert [r["restarted"] for r in mine] == jumps and all(r["parent_mask"] == 0 for r in mine if r["restarted"])
        assert all(r["mask"] != 0 for r in mine)              # the unmodified seed is never a target
        assert any(not r["accepted"] for r in mine)           # moves that reduce the metric get rejected
        assert any(r["operator"].startswith("-") for r in mine)
        assert all(r["metric"]["probability"] < 1 for r in mine if r["metric"] and not r["accepted"])
    walks = {s: [(r["trajectory"], r["mask"]) for r in attempts if r["strategy"] == s] for s in (6, 7)}
    assert walks[6] != walks[7]                               # depth fallback now changes decisions


def test_metropolis_restart_flag_controls_the_reset_at_the_end_of_the_order(tmp_path, monkeypatch):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    base = {"engine": "semgrep", "seeds": str(ROOT / "seeds"), "seed_limit": 1,
            "rules": str(ROOT / "rules/demo-sqli.yaml"), "attempts": 30, "trajectories": 4,
            "strategies": [6, 7], "base_seed": 100, "cache": False, "metropolis_temperature": 0.25,
            "operators": ["rename", "literal_slice", "dead_padding", "char_launder"]}  # small pool: the last operator is reached

    def jumps(path):
        """Proposals whose parent is not the last accepted subset of the same trajectory."""
        found, current = [], {}
        for r in rows(path):
            key = (r["seed"], r["strategy"], r["trajectory"])
            if r["parent_mask"] != current.get(key, 0):
                found.append(r)
            if r["accepted"]:
                current[key] = r["mask"]
        return found

    run({**base, "work_dir": str(tmp_path / "w1")}, tmp_path / "default", FakeScanner())
    reset = jumps(tmp_path / "default/attempts.jsonl")
    assert reset and all(r["parent_mask"] == 0 and r["restarted"] for r in reset)   # default: restart from the seed, logged
    run({**base, "metropolis_restart": False, "work_dir": str(tmp_path / "w2")}, tmp_path / "walk", FakeScanner())
    walk = rows(tmp_path / "walk/attempts.jsonl")
    assert not jumps(tmp_path / "walk/attempts.jsonl")             # every proposal toggles the current subset
    assert all(bin(r["parent_mask"] ^ r["mask"]).count("1") == 1 for r in walk)
    assert any(r["parent_mask"] >> OPERATORS.index("char_launder") & 1 for r in walk)  # it does reach the last operator
    for bad in ("yes", 1):
        path = tmp_path / f"bad_{bad}.json"
        path.write_text(json.dumps({**base, "metropolis_restart": bad}))
        with pytest.raises(ValueError, match="metropolis_restart"):
            load_config(path)


def test_llm_sees_shuffled_operator_order_deterministically():
    class Recorder:
        def __init__(self):
            self.calls = []
        def choose(self, obs, names, rng, seed, ranking=False, universe=None):
            self.calls.append((list(obs["available"]), list(names), seed, ranking))
            return names if ranking else names[0]
    def go():
        llm = Recorder()
        search = Search(4, 6224, SOURCE, llm, "rule text")
        agent = Search(3, 6224, SOURCE, llm)
        scan = FakeScanner().scan(SOURCE, None)
        for attempt in range(1, 6):
            agent.select(0, scan, [], attempt)
        return llm.calls, search.ranking
    first, ranking = go()
    second, _ = go()
    assert first == second                                    # deterministic
    assert first[0][0] != list(OPERATORS) and sorted(first[0][0]) == sorted(OPERATORS)
    assert ranking == first[0][1]                             # an echoing model is no longer canonical order
    assert any(call[0] != sorted(call[0], key=OPERATORS.index) for call in first[1:])


class ThrottledScanner(FakeScanner):
    """Fails like a throttled machine: scans whose artifact path contains a marker time out."""
    def __init__(self, markers=(), after_baseline=False):
        self.markers, self.after_baseline = markers, after_baseline

    def scan(self, source, directory):
        down = any(m in str(directory) for m in self.markers) or (self.after_baseline and Path(directory).name != "baseline")
        return Scan("error", error="TimeoutExpired: simulated") if down else super().scan(source, directory)


def attempt_key(r):
    return (r["seed"], r["strategy"], r["trajectory"], r["attempt"], r["mask"], len(r["bypassed_rules"]))


def test_rerun_errors_repairs_a_finished_run(tmp_path, monkeypatch):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = {**resume_config(tmp_path), "max_scan_failures": 0}  # guard off: let the run finish with gaps
    run(config, tmp_path / "ref", FakeScanner(), FakeLLM())
    # seed_02 is entirely down (even its baseline), and strategy 3 trajectory 1 of seed_01 fails.
    run(config, tmp_path / "out", ThrottledScanner(("seed_02", "/s3-k1-")), FakeLLM())
    manifest = json.loads((tmp_path / "out/manifest.json").read_text())
    qualified = json.loads((tmp_path / "out/qualifications.json").read_text())
    assert manifest["state"] == "complete" and qualified[1]["qualifying_rules"] == []
    assert failed_baselines(tmp_path / "out") == ["seed_02"] and failed_baselines(tmp_path / "ref") == []
    assert len(rows(tmp_path / "out/attempts.jsonl")) < len(rows(tmp_path / "ref/attempts.jsonl"))
    with pytest.raises(ValueError, match="already complete"):
        run(config, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True)
    run(config, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True, rerun_errors=True)
    # Rerun trajectories are appended, so file order differs from the reference; the records do not.
    assert sorted(attempt_key(r) for r in rows(tmp_path / "out/attempts.jsonl")) == sorted(attempt_key(r) for r in rows(tmp_path / "ref/attempts.jsonl"))
    resume = json.loads((tmp_path / "out/manifest.json").read_text())["resumes"][0]
    assert resume["rerun_errors"] and resume["discarded_attempts"] == 6  # the six failed attempts of one trajectory
    assert json.loads((tmp_path / "out/qualifications.json").read_text())[1]["qualifying_rules"]
    assert failed_baselines(tmp_path / "out") == []
    assert not any(r["scan"]["status"] != "ok" for r in rows(tmp_path / "out/attempts.jsonl"))
    with pytest.raises(ValueError, match="No scanner failures"):
        run(config, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True, rerun_errors=True)


def test_consecutive_scanner_failures_stop_the_run_and_resume(tmp_path, monkeypatch):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = {**resume_config(tmp_path), "max_scan_failures": 3, "scanner_timeout": 120}
    run(config, tmp_path / "ref", FakeScanner(), FakeLLM())
    with pytest.raises(RuntimeError, match="3 consecutive scanner failures"):
        run(config, tmp_path / "out", ThrottledScanner(after_baseline=True), FakeLLM())
    assert json.loads((tmp_path / "out/manifest.json").read_text())["state"] == "interrupted"
    assert len(rows(tmp_path / "out/attempts.jsonl")) == 3  # stopped right after the third failure
    # A longer scanner timeout is an infrastructure change, allowed on resume and recorded there.
    run({**config, "scanner_timeout": 300}, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True)
    assert [attempt_key(r) for r in rows(tmp_path / "out/attempts.jsonl")] == [attempt_key(r) for r in rows(tmp_path / "ref/attempts.jsonl")]
    assert json.loads((tmp_path / "out/manifest.json").read_text())["resumes"][0]["scanner_timeout"] == 300


def test_system_prompt_definitions_are_shuffled_but_complete():
    from sastlab.transforms import OPERATOR_HELP
    prompts = {system_prompt(seed) for seed in range(40)}
    assert len(prompts) > 20  # order varies with the seed
    first = {p.split("Operators: ")[1].split(" = ")[0] for p in prompts}
    assert len(first) > 5  # no operator is always listed first
    for p in prompts:
        assert len(p.encode()) == len(SYSTEM.encode())  # same length, so the token budget still holds
        assert all(f"{n} = {text}" in p for n, text in OPERATOR_HELP.items())
    assert system_prompt(7) == system_prompt(7)


def test_operator_pool_restricts_every_strategy(tmp_path, monkeypatch):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    pool = ["rename", "dead_padding", "extract_1", "deep_nest"]
    config = {**resume_config(tmp_path), "operators": pool, "strategies": [1, 2, 3, 4, 5, 6, 7]}
    llm = FakeLLM()
    run(config, tmp_path / "out", FakeScanner(), llm)
    attempts = rows(tmp_path / "out/attempts.jsonl")
    used = {op.lstrip("-") for r in attempts for op in r["operators"] + ([r["operator"]] if r["operator"] else [])}
    assert used and used <= set(pool)
    assert all(set(o["available"]) <= set(pool) for o in llm.observations)
    assert set(llm.universe) == set(pool)
    with pytest.raises(ValueError, match="operators must be"):
        load_cfg = __import__("sastlab.runner", fromlist=["load_config"]).load_config
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"engine": "semgrep", "operators": ["nope", "rename"]}))
        load_cfg(p)


def test_system_prompt_lists_only_the_pool():
    prompt = system_prompt(3, ["rename", "deep_nest"])
    assert "rename = " in prompt and "deep_nest = " in prompt and "extract_1 = " not in prompt


def test_every_operator_has_help_and_a_taxonomy_class():
    assert set(OPERATORS) == set(OPERATOR_HELP) == set(TAXONOMY)
    assert len(set(OPERATORS)) == len(OPERATORS) == 18


@pytest.mark.parametrize("path", sorted((ROOT / "seeds_diverse").glob("*.py")), ids=lambda p: p.stem)
def test_new_operators_preserve_behavior_on_diverse_seeds(path):
    source = path.read_text()
    baseline = evaluate(source)
    new = [1 << OPERATORS.index(o) for o in ("simplequeue_roundtrip", "pickle_roundtrip") + SINK_OPERATORS]
    checked = 0
    for mask in new + [a | b for a in new for b in new if a < b] + [(1 << len(OPERATORS)) - 1 - (1 << OPERATORS.index("format_swap"))]:
        try:
            transformed = candidate(source, mask)
        except ValueError:
            continue  # an operator that does not apply to this shape is rejected, never silently skipped
        assert evaluate(transformed) == baseline, (path.stem, mask)
        checked += 1
    assert checked >= len(new)


def test_sink_operators_reject_when_no_execute_call_is_left():
    mask = (1 << OPERATORS.index("dynamic_sink")) | (1 << OPERATORS.index("partial_sink"))
    with pytest.raises(ValueError, match="no direct execute call"):
        candidate(SOURCE, mask)
    assert "partial(cursor.execute)" in candidate(SOURCE, 1 << OPERATORS.index("partial_sink"))
    assert "methodcaller('execute'" in candidate(SOURCE, 1 << OPERATORS.index("methodcaller_sink"))
    assert "type(cursor).execute(cursor," in candidate(SOURCE, 1 << OPERATORS.index("unbound_sink"))


def test_pool_run_resumes_after_operators_are_appended(tmp_path, monkeypatch):
    import sastlab.runner as runner_module
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    pool = list(OPERATORS[:13])
    config = {**resume_config(tmp_path), "operators": pool}
    run(config, tmp_path / "ref", FakeScanner(), FakeLLM())
    with pytest.raises(KeyboardInterrupt):
        run(config, tmp_path / "out", InterruptingScanner(9), FakeLLM())
    saved = json.loads((tmp_path / "out/manifest.json").read_text())
    saved["operators"] = list(OPERATORS[:13])  # as if written before five operators were appended
    (tmp_path / "out/manifest.json").write_text(json.dumps(saved))
    run(config, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True)
    assert sorted(attempt_key(r) for r in rows(tmp_path / "out/attempts.jsonl")) == sorted(attempt_key(r) for r in rows(tmp_path / "ref/attempts.jsonl"))
    # Without a pool the appended operators would change the search space, so resume is refused.
    saved = json.loads((tmp_path / "out/manifest.json").read_text())
    saved["state"], saved["operators"] = "interrupted", list(OPERATORS[:13])
    (tmp_path / "out/manifest.json").write_text(json.dumps(saved))
    with pytest.raises(ValueError, match="operators differs"):
        run({k: v for k, v in config.items() if k != "operators"}, tmp_path / "out", FakeScanner(), FakeLLM(), resume=True)


def test_diagnostic_fields_restrict_what_the_trace_agent_sees(tmp_path, monkeypatch):
    from sastlab.search import observation
    finding = {"rule_id": "r", "message": "secret msg", "start_line": 7, "snippet": "cursor.execute(q)", "trace": [], "severity": "WARNING"}
    scan = Scan("ok", [finding])
    full = observation(5, SOURCE, SOURCE, scan, [], [0])["diagnostics"][0]
    assert set(full) == {"rule", "message", "sink", "snippet", "trace"}
    assert set(observation(5, SOURCE, SOURCE, scan, [], [0], ("message",))["diagnostics"][0]) == {"message"}
    assert observation(5, SOURCE, SOURCE, scan, [], [0], ("sink",))["diagnostics"][0] == {"sink": 7}
    assert "diagnostics" not in observation(3, SOURCE, SOURCE, scan, [], [0], ("sink",))  # other strategies never see them
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    llm = FakeLLM()
    run({**resume_config(tmp_path), "strategies": [5], "diagnostic_fields": ["snippet"]}, tmp_path / "o", FakeScanner(), llm)
    seen = [o["diagnostics"] for o in llm.observations if o.get("diagnostics")]
    assert seen and all(set(x) == {"snippet"} for ds in seen for x in ds)
    from sastlab.runner import load_config
    bad = tmp_path / "bad.json"; bad.write_text(json.dumps({"engine": "semgrep", "diagnostic_fields": ["nope"]}))
    with pytest.raises(ValueError, match="diagnostic_fields"):
        load_config(bad)


class TwoRuleScanner(FakeScanner):
    """Two qualifying rules: extract_1 silences rule a, char_launder silences rule b."""

    def scan(self, source, directory):
        rules = [("a", "_mt_extract_" not in source), ("b", "chr(ord(" not in source)]
        return Scan("ok", [{"rule_id": r, "message": "m", "start_line": 2, "snippet": "s", "trace": [], "severity": "WARNING"}
                           for r, fires in rules if fires])


@pytest.mark.parametrize("evasion", ["any", "all"])
def test_evasion_all_requires_every_qualifying_rule_to_be_silent(tmp_path, monkeypatch, evasion):
    monkeypatch.setattr(Oracle, "evaluate", lambda self, source: {"ok": True, "outputs": evaluate(source)})
    config = {"engine": "semgrep", "seeds": str(ROOT / "seeds"), "seed_limit": 1, "rules": str(ROOT / "rules/demo-sqli.yaml"),
              "attempts": 8, "trajectories": 3, "strategies": [1], "base_seed": 5, "cache": True, "evasion": evasion,
              "metropolis_temperature": 0.25, "work_dir": str(tmp_path / "work"),
              "operators": ["extract_1", "char_launder", "rename", "dead_padding"]}
    run(config, tmp_path / "out", TwoRuleScanner(), FakeLLM())
    rows = [json.loads(line) for line in (tmp_path / "out" / "attempts.jsonl").read_text().splitlines()]
    hits = [r for r in rows if r["bypassed_rules"]]
    assert hits
    both = {r["seed"] for r in hits if sorted(r["bypassed_rules"]) == ["a", "b"]}
    if evasion == "all":
        assert all(sorted(r["bypassed_rules"]) == ["a", "b"] for r in hits)
    else:
        assert any(len(r["bypassed_rules"]) == 1 for r in hits)
