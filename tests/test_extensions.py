"""Tests for the options: free operator order, prompt text appended to the system prompt, Flask-route marking for Semgrep taint mode."""
import ast
import pytest

from sastlab.llm import system_prompt, bounded_observation, SoCLaaS
from sastlab.scanners import routed_for_semgrep
from sastlab.search import Search
from sastlab.transforms import OPERATORS

SEED = '''import sqlite3

def get_user_profile(db_conn, user_id):
    query = f"SELECT name FROM users WHERE id = {user_id}"
    return db_conn.execute(query).fetchall()
'''


def test_increasing_order_is_default_and_any_order_offers_every_unused_operator():
    pool = ["rename", "literal_slice", "dict_dispatch"]
    inc = Search(1, 1, SEED, pool=pool)
    anyo = Search(1, 1, SEED, pool=pool, order="any")
    mask = 1 << OPERATORS.index("dict_dispatch")
    assert inc.available(mask) == []                                  # nothing later than the last operator
    assert sorted(OPERATORS[i] for i in anyo.available(mask)) == ["literal_slice", "rename"]
    assert anyo.available(0) == inc.available(0)


def test_order_is_validated():
    with pytest.raises(ValueError):
        Search(1, 1, SEED, order="sideways")


def test_prompt_extra_is_appended_and_counted_in_the_budget():
    base = system_prompt(3, None)
    assert system_prompt(3, None, "EXTRA SENTENCE.").endswith(" EXTRA SENTENCE.")
    assert system_prompt(3, None, "EXTRA SENTENCE.").startswith(base)
    obs = {"available": ["rename"], "diff": "x" * 5000, "history": [], "verdict": "detected"}
    small = len(str(bounded_observation(obs, 2500, 0)))
    large = len(str(bounded_observation(obs, 2500, 300)))
    assert large < small                                              # a longer system prompt leaves less room for the observation


def test_llm_client_takes_prompt_extra(monkeypatch):
    monkeypatch.setenv("SASTLAB_TEST_KEY", "k")
    llm = SoCLaaS(api_key_env="SASTLAB_TEST_KEY", prompt_extra="Context: test.")
    payload = llm.payload({"a": 1}, {"type": "object"}, 1)
    assert payload["messages"][0]["content"].endswith("Context: test.")


def test_routed_for_semgrep_adds_one_decorator_and_keeps_the_program_valid():
    routed = routed_for_semgrep(SEED)
    lines = routed.split("\n")
    assert lines.count('@app.route("/<user_input>")') == 1
    assert lines[lines.index('@app.route("/<user_input>")') + 1].startswith("def get_user_profile")
    ast.parse(routed)
    assert [l for l in lines if l != '@app.route("/<user_input>")'] == SEED.split("\n")


def test_routed_for_semgrep_needs_the_entry_function():
    with pytest.raises(ValueError):
        routed_for_semgrep("def other(a, b):\n    return a\n")


def test_scan_cache_key_uses_scan_dict_roundtrip():
    from sastlab.scanners import Scan
    scan = Scan("ok", [{"rule_id": "r", "message": "m", "start_line": 1, "end_line": 1, "snippet": "", "trace": []}], "", 1.5)
    data = scan.to_dict()
    again = Scan(data["status"], data["findings"], data.get("error", ""), data.get("seconds", 0))
    assert again.rules == scan.rules and again.to_dict() == data
