"""Adapted from https://github.com/semgrep/semgrep-rules @ a84ff9cc24, python/lang/security/audit/sqli/aiopg-sqli.py, function bad1, line 12. Input: external expression rooted at req."""
SASTLAB_FIXTURE = 'CREATE TABLE users (id NUMERIC, name NUMERIC, age NUMERIC);INSERT INTO users VALUES (1, 1, 1);INSERT INTO users VALUES (2, 2, 2);INSERT INTO users VALUES (3, 3, 3);'
SASTLAB_EXPLOIT = '1 OR 1=1'
import queue as _mt_queue

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(_mt_local_3)
    _mt_local_3 = _mt_q.get()
    _mt_local_2 = '#SELECT name FROM users WHERE age='[1:] + _mt_local_3
    _mt_local_0 = _mt_local_1.cursor()
    {'run': _mt_local_0.execute}['run'](_mt_local_2)
    return _mt_local_0.fetchall()
