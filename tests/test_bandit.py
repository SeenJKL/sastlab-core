import json
from pathlib import Path
import pytest
from sastlab.scanners import Scanner, parse_bandit

ROOT = Path(__file__).resolve().parent.parent
BANDIT = ROOT / ".sastlab" / "bandit-venv" / "bin" / "bandit"


def report(results, errors=()):
    return {"errors": list(errors), "metrics": {"/x/subject.py": {}, "_totals": {}}, "results": results}


def test_parse_bandit_keeps_rule_line_and_snippet():
    source = "a = 1\nq = 'x' + y\n"
    data = report([{"test_id": "B608", "issue_text": "SQL", "issue_severity": "MEDIUM", "filename": "/x/subject.py",
                    "line_number": 2, "line_range": [2]}])
    findings = parse_bandit(data, {"subject.py": source})
    assert [(f["rule_id"], f["start_line"], f["snippet"]) for f in findings] == [("bandit/B608", 2, "q = 'x' + y")]


def test_parse_bandit_fails_closed():
    with pytest.raises(ValueError):
        parse_bandit(report([], errors=[{"filename": "subject.py", "reason": "syntax error"}]), {})
    with pytest.raises(ValueError):
        parse_bandit({"metrics": {"_totals": {}}, "results": []}, {})  # subject.py not scanned
    with pytest.raises(ValueError):
        parse_bandit({"results": "x"}, {})


@pytest.mark.skipif(not BANDIT.is_file(), reason="bandit venv not installed")
def test_bandit_live_flags_seed_and_literal_slice_silences(tmp_path):
    from sastlab.transforms import OPERATORS, candidate
    source = (ROOT / "seeds" / "seed_01.py").read_text()
    scanner = Scanner("bandit", str(BANDIT), None)
    assert scanner.scan(source, tmp_path / "a").rules == ["bandit/B608"]
    mask = 1 << list(OPERATORS).index("literal_slice")
    assert scanner.scan(candidate(source, mask), tmp_path / "b").rules == []
