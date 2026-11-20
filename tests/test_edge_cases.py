"""Tests for transform scope and docstring handling, target-rule filtering, exhaustive work_dir, CodeQL identity, and replay configs."""
import json
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sastlab.exhaustive import exhaustive  # noqa: E402
from sastlab.oracle import Oracle  # noqa: E402
from sastlab.report import summarize  # noqa: E402
from sastlab.scanners import Scan, Scanner  # noqa: E402
from sastlab.search import observation  # noqa: E402
from sastlab.transforms import OPERATORS, candidate  # noqa: E402


def mask(*ops):
    return sum(1 << OPERATORS.index(o) for o in ops)


def program(body, prelude=""):
    return f"import sqlite3\n{prelude}def get_user_profile(db_conn, user_id):\n{body}"


INNER = ("    cursor = db_conn.cursor()\n"
         "    cursor.execute(query)\n"
         "    return cursor.fetchall()\n")


def equivalent(source, operators):
    oracle = Oracle()
    return oracle.compare(oracle.evaluate(source), candidate(source, mask(*operators)))["equivalent"]


@pytest.mark.parametrize("operator", ["extract_1", "extract_2"])
def test_extract_does_not_pass_comprehension_variables(operator):
    source = program("    query = \"SELECT id FROM users WHERE id = '\" + ''.join(ch for ch in user_id) + \"'\"\n" + INNER)
    assert "(ch, user_id)" not in candidate(source, mask(operator))
    assert equivalent(source, [operator])


def test_rename_keeps_a_global_shadowed_by_a_comprehension_and_renames_except_targets():
    shadow = program("    tag = ch\n    query = \"SELECT id FROM users WHERE id = '\" + user_id + \"'\" + ''.join(ch for ch in '')\n" + INNER,
                     prelude="ch = 'x'\n")
    assert equivalent(shadow, ["rename"])
    handler = program("    e = 0\n    query = f\"SELECT id FROM users WHERE id = '{user_id}'\"\n    cursor = db_conn.cursor()\n"
                      "    try:\n        cursor.execute(query)\n    except Exception as e:\n        raise e\n    return cursor.fetchall()\n")
    assert equivalent(handler, ["rename"]) and "except Exception as _mt_local_" in candidate(handler, mask("rename"))


@pytest.mark.parametrize("operator", ["char_launder", "deep_nest", "db_roundtrip", "queue_roundtrip",
                                      "simplequeue_roundtrip", "pickle_roundtrip"])
def test_flow_operators_keep_the_docstring(operator):
    namespace = {}
    exec(candidate(program('    """Doc."""\n    query = f"SELECT id FROM users WHERE id = \'{user_id}\'"\n' + INNER), mask(operator)), namespace)
    assert namespace["get_user_profile"].__doc__ == "Doc."


def test_agent_verdict_counts_only_the_target_rules():
    scan = Scan("ok", [{"rule_id": "B101", "message": "m", "start_line": 1, "snippet": "", "trace": [], "severity": "LOW"}])
    assert observation(3, "x = 1\n", "x = 1\n", scan, [], [0], target_rules=["B608"])["verdict"] == "clean"
    assert observation(3, "x = 1\n", "x = 1\n", scan, [], [0], target_rules=["B101"])["verdict"] == "detected"
    assert observation(3, "x = 1\n", "x = 1\n", scan, [], [0])["verdict"] == "detected"  # without a target list: any finding
    assert observation(5, "x = 1\n", "x = 1\n", scan, [], [0], target_rules=["B608"])["diagnostics"] == []
    assert [d["rule"] for d in observation(5, "x = 1\n", "x = 1\n", scan, [], [0], target_rules=["B101"])["diagnostics"]] == ["B101"]


class OneRule:
    def version(self):
        return "test-double"

    def scan(self, source, directory):
        return Scan("ok", [{"rule_id": "r", "message": "m", "start_line": 1, "snippet": "", "trace": [], "severity": "LOW"}])


def test_exhaustive_writes_to_the_configured_work_dir(tmp_path):
    config = {"engine": "semgrep", "seeds": str(ROOT / "seeds"), "rules": str(ROOT / "rules/demo-sqli.yaml"),
              "work_dir": str(tmp_path / "work")}
    exhaustive(config, tmp_path / "out", seed_limit=1, scanner=OneRule(), operators=["rename"], max_ops=1)
    manifest = json.loads((tmp_path / "out/manifest.json").read_text())
    assert manifest["work_dir"].startswith(str(tmp_path / "work"))


def test_codeql_version_identity_has_no_install_paths(tmp_path):
    fake = tmp_path / "codeql"
    fake.write_text("#!/bin/sh\necho '{\"version\": \"2.27.1\", \"unpackedLocation\": \"/somewhere\", \"configFileLocation\": \"/home/x\"}'\n")
    fake.chmod(0o755)
    identity = json.loads(Scanner("codeql", str(fake), None).version())
    assert identity == {"version": "2.27.1"}


def test_report_does_not_depend_on_the_order_of_the_attempts():
    run = ROOT / "results" / "semgrep-hard"
    if not run.is_dir():
        pytest.skip("no saved results in this tree")
    manifest = json.loads((run / "manifest.json").read_text())
    qualifications = json.loads((run / "qualifications.json").read_text())
    attempts = [json.loads(line) for line in (run / "attempts.jsonl").read_text().splitlines()]
    shuffled = attempts[:]
    random.Random(1).shuffle(shuffled)
    assert summarize(manifest, qualifications, shuffled) == summarize(manifest, qualifications, attempts)


def test_replay_configs_pin_the_operator_pool_of_the_full_campaigns():
    for name in ("semgrep", "codeql"):
        manifest = ROOT / "results" / f"{name}-v6" / "manifest.json"
        if not manifest.is_file():
            pytest.skip("no saved results in this tree")
        config = json.loads((ROOT / "configs" / f"{name}-v6.json").read_text())
        assert config["operators"] == json.loads(manifest.read_text())["operators"]
