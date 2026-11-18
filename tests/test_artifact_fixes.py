"""Regression tests for defects found while reviewing the artifact as a stranger would use it from a clean checkout."""
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sastlab import cli, scanners
from sastlab.exhaustive import summarize_exhaustive
from sastlab.oracle import Oracle
from sastlab.runner import load_config, scan_cache_settings, scanner_from
from sastlab.transforms import OPERATORS, candidate

mask = lambda *ops: sum(1 << OPERATORS.index(o) for o in ops)
needs_results = pytest.mark.skipif(not (ROOT / "results").is_dir(), reason="no saved results in this tree")


# --- behavior check leaves nothing behind ------------------------------------------------------------------------

@pytest.fixture
def private_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr(tempfile, "tempdir", None)
    return tmp_path


def test_oracle_removes_the_temp_directories_a_path_seed_creates(private_tmp):
    source = (ROOT / "seeds_path/p01_open_fstring.py").read_text()
    result = Oracle().evaluate(source)
    assert result["ok"], result
    assert list(private_tmp.iterdir()) == []


def test_oracle_removes_its_scratch_directory_after_a_timeout(private_tmp):
    source = (ROOT / "seeds_path/p01_open_fstring.py").read_text() + "\nimport time\ntime.sleep(30)\n"
    result = Oracle(timeout=1).evaluate(source)
    assert not result["ok"]
    assert list(private_tmp.iterdir()) == []


# --- rename and dead_padding on a seed whose query is inline at the call site -------------------------------------

INLINE = (ROOT / "corpus_apps/seeds/a04_scitokens_getkeyinfo.py").read_text()


@pytest.mark.parametrize("operators", [("rename",), ("dead_padding",), ("rename", "dead_padding")])
def test_operators_without_assignment_need_apply_to_inline_query_seeds(operators):
    transformed = candidate(INLINE, mask(*operators))
    assert transformed != INLINE
    baseline = Oracle().evaluate(INLINE)
    assert Oracle().compare(baseline, transformed)["equivalent"]
    if "dead_padding" in operators:
        lines = transformed.splitlines()
        sink = next(i for i, line in enumerate(lines) if ".execute(" in line)
        assert lines[sink - 2].strip() == "if False:" and lines[sink - 1].strip() == "_mt_unused = 0"


@pytest.mark.parametrize("operator", ["format_swap", "literal_slice", "extract_1", "extract_2", "branch_split"])
def test_operators_that_rewrite_the_query_still_reject_inline_query_seeds(operator):
    with pytest.raises(ValueError, match="top-level query assignment"):
        candidate(INLINE, mask(operator))


def test_dead_padding_keeps_its_place_before_the_query_assignment():
    seed = (ROOT / "seeds/seed_01.py").read_text()
    lines = candidate(seed, mask("dead_padding")).splitlines()
    padding = next(i for i, line in enumerate(lines) if line.strip() == "if False:")
    assert lines[padding + 2].lstrip().startswith("query")


# --- unbound_sink also rejects receivers that are modules imported inside the function or with from-imports ---------

@pytest.mark.parametrize("import_line", ["import sqlite3 as lib", "from os import path as lib"])
def test_unbound_sink_rejects_a_receiver_bound_by_a_local_import(import_line):
    source = (f"def get_user_profile(db_conn, user_id):\n    {import_line}\n"
              "    query = \"SELECT 1 WHERE x = '\" + user_id + \"'\"\n    return lib.execute(query)\n")
    with pytest.raises(ValueError, match="receiver is a module"):
        candidate(source, mask("unbound_sink"))


# --- API ----------------------------------------------------------------------------------------------------------

def test_summarize_exhaustive_needs_the_number_of_enumerated_masks():
    rows = [{"seed": "s", "mask": m, "status": "evaluated", "equivalent": True, "scan_status": "ok", "bypassed_rules": []}
            for m in (1, 2, 3)]
    qualifications = [{"seed": "s", "qualifying_rules": ["r"], "scan": {"status": "ok"}}]
    with pytest.raises(TypeError):
        summarize_exhaustive(rows, qualifications)
    assert summarize_exhaustive(rows, qualifications, 3)["complete"] is True
    assert summarize_exhaustive(rows, qualifications, 7)["complete"] is False


@needs_results
def test_report_prints_without_touching_the_run_unless_asked(tmp_path):
    source = ROOT / "results/codeql-v6-seed05-rerun"
    run = tmp_path / "run"
    run.mkdir()
    for name in ("manifest.json", "qualifications.json", "attempts.jsonl"):
        (run / name).write_bytes((source / name).read_bytes())
    saved = json.loads((source / "summary.json").read_text())

    out = io.StringIO()
    with redirect_stdout(out):
        assert cli.main(["report", str(run)]) == 0
    assert json.loads(out.getvalue()) == saved
    assert not (run / "summary.json").exists()

    with redirect_stdout(io.StringIO()):
        assert cli.main(["report", str(run), "--write"]) == 0
    assert json.loads((run / "summary.json").read_text()) == saved


PYRE = ROOT / ".sastlab" / "pysa-venv" / "bin" / "pyre"


@pytest.mark.skipif(not PYRE.is_file(), reason="Pysa environment not installed")
@pytest.mark.parametrize("config, seed", [("configs/pysa-cmd.json", "seeds_cmd/c01_check_output_fstring.py"),
                                          ("configs/pysa-path.json", "seeds_path/p01_open_fstring.py")])
def test_sqlite_annotation_does_not_change_what_pysa_reports_on_other_classes(tmp_path, monkeypatch, config, seed):
    # typed_for_pysa annotates the first parameter with sqlite3.Connection for every class; it is only needed for SQL sinks.
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        scanner = scanner_from(load_config(config))
        source = (ROOT / seed).read_text()
        typed = scanner.scan(source, tmp_path / "typed")
        monkeypatch.setattr(scanners, "typed_for_pysa", lambda text: (text, ["db_conn", "user_id"]))
        plain = scanner.scan(source, tmp_path / "plain")
    finally:
        os.chdir(cwd)
    assert typed.status == plain.status == "ok" and typed.rules and typed.rules == plain.rules


def test_scan_cache_key_follows_the_contents_of_the_pysa_models(tmp_path):
    class FakeScanner:
        def __init__(self, models):
            self.models = models

        def version(self):
            return "v1"

    config = {"engine": "pysa", "pysa_source": "http-server"}
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "x.pysa").write_text("def f(): ...\n")
    key = scan_cache_settings(config, FakeScanner([str(tmp_path / "a")]))
    assert key == scan_cache_settings(config, FakeScanner([str(tmp_path / "b")]))  # where the models are does not matter
    (tmp_path / "b" / "x.pysa").write_text("def g(): ...\n")
    assert key != scan_cache_settings(config, FakeScanner([str(tmp_path / "b")]))  # what they say does
    assert len(scan_cache_settings({"engine": "semgrep"}, FakeScanner([]))) == 7  # engines without models keep the old key
