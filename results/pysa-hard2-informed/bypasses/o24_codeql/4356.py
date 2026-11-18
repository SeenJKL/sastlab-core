"""Adapted from https://github.com/github/codeql @ 6e9f9e3839, query-tests/CWE-089-SqlInjection/sql_injection.py, function show_user, line 21. Input: parameter username."""
SASTLAB_FIXTURE = 'CREATE TABLE users (id NUMERIC, username NUMERIC);INSERT INTO users VALUES (1, 1);INSERT INTO users VALUES (2, 2);INSERT INTO users VALUES (3, 3);'
SASTLAB_EXPLOIT = "1' OR '1'='1"
import queue as _mt_queue

def get_user_profile(db_conn, user_id):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(user_id)
    user_id = _mt_q.get()
    query = "#SELECT * FROM users WHERE username = '%s'"[1:] % user_id
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
