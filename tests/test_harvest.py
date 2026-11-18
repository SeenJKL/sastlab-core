"""Tests for the oracle's per-seed fixture constants (SASTLAB_FIXTURE and SASTLAB_EXPLOIT)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastlab.oracle import Oracle  # noqa: E402
from sastlab.transforms import candidate  # noqa: E402


def test_oracle_uses_seed_fixture_and_rewrites_keep_behaviour():
    seed = (
        "SASTLAB_FIXTURE = 'CREATE TABLE bar (id NUMERIC, foo NUMERIC, baz NUMERIC);"
        "INSERT INTO bar VALUES (1,1,1);INSERT INTO bar VALUES (2,2,2);INSERT INTO bar VALUES (3,3,3);'\n"
        "SASTLAB_EXPLOIT = '1 OR 1=1'\n"
        "def get_user_profile(db_conn, user_id):\n"
        "    query = 'SELECT foo FROM bar WHERE baz = %s' % user_id\n"
        "    cursor = db_conn.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    oracle = Oracle()
    baseline = oracle.evaluate(seed)
    assert baseline["ok"] and Oracle.exploitable(baseline)
    # constants survive every rewrite, and a rewritten candidate is behavior-equivalent on the seed's own fixture
    for mask in (1, 1 << 8, (1 << 4) | (1 << 9)):
        assert oracle.compare(baseline, candidate(seed, mask))["equivalent"], mask


def test_default_oracle_contract_is_unchanged():
    seed = (ROOT / "seeds/seed_01.py").read_text()
    result = Oracle().evaluate(seed)
    assert result["outputs"][0] == [["1", "alice", "admin"]] and len(result["outputs"][1]) == 3
