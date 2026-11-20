import json
from pathlib import Path

import pytest

from sastlab.scanners import PYSA_ENTRY, Scanner, parse_pysa, typed_for_pysa
from sastlab.transforms import OPERATORS, candidate

SEED = Path(__file__).resolve().parent.parent / "seeds" / "seed_01.py"


def test_typed_copy_annotates_first_parameter_only():
    typed, names = typed_for_pysa("def get_user_profile(db_conn, user_id):\n    return 1\n")
    assert typed.splitlines()[0] == "import sqlite3"
    assert "def get_user_profile(db_conn: sqlite3.Connection, user_id):" in typed
    assert names == ["db_conn", "user_id"]


def test_typed_copy_follows_renamed_parameters_and_keeps_annotations():
    typed, names = typed_for_pysa("def get_user_profile(c: sqlite3.Connection, uid: str):\n    return 1\n")
    assert names == ["c", "uid"] and typed.count("sqlite3.Connection") == 1


@pytest.mark.parametrize("operator", OPERATORS)
def test_every_single_rewrite_stays_parseable_and_typed(operator):
    typed, names = typed_for_pysa(candidate(SEED.read_text(), 1 << OPERATORS.index(operator)))
    compile(typed, "x", "exec")
    assert len(names) >= 2


def test_missing_entry_is_an_error():
    with pytest.raises(ValueError):
        typed_for_pysa("def other(a, b):\n    pass\n")


def write_output(tmp_path, lines):
    path = tmp_path / "taint-output.json"
    path.write_text("\n".join(json.dumps(x) for x in lines))
    return path


def test_parse_pysa_keeps_only_sql_rules(tmp_path):
    entry = {"kind": "model", "data": {"callable": "subject." + PYSA_ENTRY}}
    sql = {"kind": "issue", "data": {"code": 5005, "line": 4, "filename": "src/subject.py", "message": "m"}}
    other = {"kind": "issue", "data": {"code": 5001, "line": 4, "filename": "src/subject.py", "message": "m"}}
    found = parse_pysa(write_output(tmp_path, [entry, sql, other]), {"subject.py": "a\nb\nc\nd\n"})
    assert [f["rule_id"] for f in found] == ["pysa/5005"] and found[0]["snippet"] == "d"


def test_parse_pysa_fails_closed_without_entry_model(tmp_path):
    with pytest.raises(ValueError):
        parse_pysa(write_output(tmp_path, [{"kind": "issue", "data": {"code": 5005}}]), {})


def test_pysa_scanner_unavailable_binary_is_an_error_scan(tmp_path):
    scan = Scanner("pysa", str(tmp_path / "nope" / "pyre"), None, 5, models=[]).scan(SEED.read_text(), tmp_path / "d")
    assert scan.status == "error" and scan.findings == []


PYRE = Path(__file__).resolve().parent.parent / ".sastlab" / "pysa-venv" / "bin" / "pyre"
MODELS = Path(__file__).resolve().parent.parent / "third_party" / "pysa-models"


@pytest.mark.skipif(not PYRE.is_file(), reason="Pysa environment not installed")
def test_live_scan_inside_the_repository_sees_only_the_scanned_file(tmp_path):
    # Scanning below the repository root must not adopt its pyproject.toml and .gitignore
    # (which would type-check the whole repository instead of just the scanned file).
    work = Path(__file__).resolve().parent.parent / ".sastlab" / "runs" / "pytest-pysa"
    scanner = Scanner("pysa", str(PYRE), None, 120, models=[MODELS / "core", MODELS / "common"])
    scan = scanner.scan(SEED.read_text(), work / "base")
    evaded = scanner.scan(candidate(SEED.read_text(), 1 << OPERATORS.index("db_roundtrip")), work / "db")
    assert scan.status == "ok" and scan.rules == ["pysa/5005", "pysa/5051"]
    assert evaded.status == "ok" and evaded.rules == []
    assert "Checking 1 files" in (work / "base" / "scanner.log").read_text()
    import shutil
    shutil.rmtree(work, ignore_errors=True)


def test_unknown_pysa_source_mode_is_rejected():
    with pytest.raises(ValueError):
        Scanner("pysa", "pyre", None, 5, models=[], pysa_source="nope")


@pytest.mark.skipif(not PYRE.is_file(), reason="Pysa environment not installed")
def test_live_scan_with_the_stock_http_server_source():
    # No model of ours: the stock source BaseHTTPRequestHandler.path reaches the candidate through a handler method.
    work = Path(__file__).resolve().parent.parent / ".sastlab" / "runs" / "pytest-pysa-http"
    scanner = Scanner("pysa", str(PYRE), None, 120, models=[MODELS / "core", MODELS / "common"], pysa_source="http-server")
    base = scanner.scan(SEED.read_text(), work / "base")
    hidden = scanner.scan(candidate(SEED.read_text(), 1 << OPERATORS.index("dynamic_sink")), work / "dyn")
    assert base.status == "ok" and base.rules == ["pysa/5005", "pysa/5051"]
    assert hidden.status == "ok" and hidden.rules == ["pysa/5051"]
    import shutil
    shutil.rmtree(work, ignore_errors=True)
