"""CodeQL mechanism checks for the 2 flow rewrites whose sink is recognized (deep_nest, db_roundtrip).
1. deep_nest: box the input in d nested lists, d = 1..8, and report whether the stock query still alerts.
2. db_roundtrip: add summary models for the sqlite3 write and read as a data extension and check whether the alert returns.
usage (from the repository root): .sastlab/.venv/bin/python analysis/mechanism_codeql_flow.py"""
import sys
from pathlib import Path
from common import ROOT

code = ROOT; sys.path.insert(0, str(code))
import mechanism_codeql as M
from sastlab.transforms import OPERATORS, candidate

SRC = (code / "seeds/seed_01.py").read_text()
HEAD = SRC[:SRC.index("def get_user_profile")]
BODY = SRC[SRC.index("    query ="):]


def nested(depth):
    box = "[" * depth + "user_id" + "]" * depth
    return HEAD + f"def get_user_profile(db_conn, user_id):\n    _mt_box = {box}\n    user_id = _mt_box" + "[0]" * depth + "\n" + BODY


CONNECT = "Member[connect].ReturnValue"
VARIANTS = {
    "connect-path, tuple element": [f'["sqlite3", "{CONNECT}.Member[execute]", "Argument[1].TupleElement[0]", "Argument[self]", "taint"]',
                                    f'["sqlite3", "{CONNECT}.Member[execute]", "Argument[self]", "ReturnValue", "taint"]',
                                    f'["sqlite3", "{CONNECT}.Member[execute].ReturnValue.Member[fetchone]", "Argument[self]", "ReturnValue", "taint"]'],
    "connect-path, whole argument": [f'["sqlite3", "{CONNECT}.Member[execute]", "Argument[1]", "Argument[self]", "taint"]',
                                     f'["sqlite3", "{CONNECT}.Member[execute]", "Argument[self]", "ReturnValue", "taint"]',
                                     f'["sqlite3", "{CONNECT}.Member[execute].ReturnValue.Member[fetchone]", "Argument[self]", "ReturnValue", "taint"]'],
    "tuple-as-argument": ['["sqlite3.Connection", "Member[execute]", "Argument[1]", "Argument[self]", "taint"]',
                          '["sqlite3.Connection", "Member[execute]", "Argument[self]", "ReturnValue", "taint"]',
                          '["sqlite3.Cursor", "Member[fetchone]", "Argument[self]", "ReturnValue", "taint"]'],
    "tuple-element": ['["sqlite3.Connection", "Member[execute]", "Argument[1].TupleElement[0]", "Argument[self]", "taint"]',
                      '["sqlite3.Connection", "Member[execute]", "Argument[self]", "ReturnValue", "taint"]',
                      '["sqlite3.Cursor", "Member[fetchone]", "Argument[self]", "ReturnValue", "taint"]'],
}

if __name__ == "__main__":
    if "--db-only" not in sys.argv:
        print("== deep_nest depth sweep")
        for d in range(1, 9):
            print(f"depth {d}: {M.scan(f'nest{d}', nested(d))} alert(s)")
    print("== db_roundtrip, stock pack and with added sqlite3 models")
    cand = candidate(SRC, M.mask("db_roundtrip"))
    print("stock:", M.scan("db-stock", cand))
    for name, rows in VARIANTS.items():
        M.ROWS["db_" + name] = rows
        print(f"{name}:", M.scan("db-" + name, cand, M.pack("db_" + name)))
