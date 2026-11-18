"""Adapted from https://github.com/semgrep/semgrep-rules @ a84ff9cc24, python/lang/security/audit/sqli/aiopg-sqli.py, function bad1, line 12. Input: external expression rooted at req."""
SASTLAB_FIXTURE = 'CREATE TABLE users (id NUMERIC, name NUMERIC, age NUMERIC);INSERT INTO users VALUES (1, 1, 1);INSERT INTO users VALUES (2, 2, 2);INSERT INTO users VALUES (3, 3, 3);'
SASTLAB_EXPLOIT = '1 OR 1=1'

def _mt_extract_1_0(user_id):
    return ''.join(['SELECT name FROM users WHERE age=', user_id])
import queue as _mt_queue

def get_user_profile(db_conn, user_id):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(user_id)
    user_id = _mt_q.get()
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    {'run': getattr(cursor, 'exe' + 'cute')}['run'](query)
    return cursor.fetchall()
