"""Command-injection seeds (seeds_cmd): the rewrites that apply keep the behavior, and module-level sinks are handled."""
from pathlib import Path

import pytest

from sastlab.oracle import Oracle
from sastlab.oracle_worker import evaluate
from sastlab.transforms import OPERATORS, candidate

SEEDS = sorted((Path(__file__).resolve().parent.parent / "seeds_cmd").glob("*.py"))


@pytest.mark.parametrize("path", SEEDS, ids=lambda p: p.stem)
def test_seed_is_exploitable_and_every_applicable_rewrite_keeps_behavior(path):
    source = path.read_text()
    base = {"ok": True, "outputs": evaluate(source)}
    assert Oracle.exploitable(base)
    applied = 0
    for index, operator in enumerate(OPERATORS):
        try:
            changed = candidate(source, 1 << index)
        except ValueError:
            assert operator in ("unbound_sink", "format_swap"), operator
            continue
        applied += 1
        assert evaluate(changed) == base["outputs"], operator
    assert applied >= 16


def test_unbound_sink_is_rejected_for_module_level_sinks():
    source = SEEDS[0].read_text()
    with pytest.raises(ValueError, match="module"):
        candidate(source, 1 << OPERATORS.index("unbound_sink"))


def test_sink_operators_name_the_command_function():
    source = SEEDS[0].read_text()
    assert "getattr(subprocess, 'check_' + 'output')" in candidate(source, 1 << OPERATORS.index("dynamic_sink"))
    assert "methodcaller('check_output'" in candidate(source, 1 << OPERATORS.index("methodcaller_sink"))
