"""Path-traversal class (CWE-22): seeds, sink rewrites on the builtin open, and the stock rules' own tests."""
import json
from pathlib import Path

import pytest

from sastlab.oracle import Oracle
from sastlab.transforms import OPERATORS, candidate

ROOT = Path(__file__).resolve().parent.parent
SEEDS = sorted((ROOT / "seeds_path").glob("*.py"))
mask = lambda *ops: sum(1 << OPERATORS.index(o) for o in ops)


def test_there_are_8_seeds():
    assert len(SEEDS) == 8


@pytest.mark.parametrize("seed", SEEDS, ids=lambda p: p.stem)
def test_every_seed_is_exploitable(seed):
    result = Oracle(5).evaluate(seed.read_text())
    assert result["ok"] and Oracle.exploitable(result), result


def test_sink_rewrites_on_open():
    source = (ROOT / "seeds_path/p01_open_fstring.py").read_text()
    assert "{'run': open}['run'](path)" in candidate(source, mask("dict_dispatch"))
    dyn = candidate(source, mask("dynamic_sink"))
    assert "getattr(_mt_builtins, 'op' + 'en')(path)" in dyn and "import builtins as _mt_builtins" in dyn
    assert "_mt_functools.partial(open)(path)" in candidate(source, mask("partial_sink"))
    for operator in ("methodcaller_sink", "unbound_sink"):
        with pytest.raises(ValueError):
            candidate(source, mask(operator))


@pytest.mark.parametrize("operator", ["dict_dispatch", "dynamic_sink", "partial_sink", "rename", "format_swap", "literal_slice", "extract_1", "char_launder"])
def test_rewrites_keep_behavior_on_open(operator):
    source = (ROOT / "seeds_path/p01_open_fstring.py").read_text()
    base = Oracle(5)
    baseline = base.evaluate(source)
    assert base.compare(baseline, candidate(source, mask(operator)))["equivalent"]


def test_stock_semgrep_rules_pass_their_own_tests():
    for name in ("path-traversal-open", "tainted-sql-string"):
        path = ROOT / f"results/official-validation/semgrep-suite-{name}.json"
        if not path.exists():
            pytest.skip("official-validation results not present")
        assert json.loads(path.read_text())["passed"]
