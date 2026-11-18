"""Adapted from https://github.com/github/codeql @ 6e9f9e3839, query-tests/CWE-089-SqlInjection/sql_injection.py, function show_user, line 21. Input: parameter username."""
SASTLAB_FIXTURE = 'CREATE TABLE users (id NUMERIC, username NUMERIC);INSERT INTO users VALUES (1, 1);INSERT INTO users VALUES (2, 2);INSERT INTO users VALUES (3, 3);'
SASTLAB_EXPLOIT = "1' OR '1'='1"

def get_user_profile(db_conn, user_id):
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    if False:
        _mt_unused = 0
    query = "#SELECT * FROM users WHERE username = '%s'"[1:] % user_id
    cursor = db_conn.cursor()
    {'run': cursor.execute}['run'](query)
    return cursor.fetchall()
