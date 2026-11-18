"""Adapted from https://github.com/github/codeql @ 6e9f9e3839, query-tests/CWE-089-SqlInjection/sql_injection.py, function show_user, line 21. Input: parameter username."""
SASTLAB_FIXTURE = 'CREATE TABLE users (id NUMERIC, username NUMERIC);INSERT INTO users VALUES (1, 1);INSERT INTO users VALUES (2, 2);INSERT INTO users VALUES (3, 3);'
SASTLAB_EXPLOIT = "1' OR '1'='1"

def _mt_extract_1_0(_mt_local_3):
    return "#SELECT * FROM users WHERE username = '%s'"[1:] % _mt_local_3

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_local_3 = ''.join((chr(ord(_mt_c)) for _mt_c in _mt_local_3))
    _mt_local_2 = _mt_extract_1_0(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    getattr(_mt_local_0, 'exe' + 'cute')(_mt_local_2)
    return _mt_local_0.fetchall()
