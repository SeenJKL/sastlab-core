"""Adapted from https://github.com/semgrep/semgrep-rules @ a84ff9cc24, python/lang/security/audit/sqli/aiopg-sqli.py, function bad1, line 12. Input: external expression rooted at req."""
SASTLAB_FIXTURE = 'CREATE TABLE users (id NUMERIC, name NUMERIC, age NUMERIC);INSERT INTO users VALUES (1, 1, 1);INSERT INTO users VALUES (2, 2, 2);INSERT INTO users VALUES (3, 3, 3);'
SASTLAB_EXPLOIT = '1 OR 1=1'

def _mt_extract_1_0(_mt_local_3):
    return ''.join(['SELECT name FROM users WHERE age=', _mt_local_3])

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_local_2 = _mt_extract_1_0(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    {'run': getattr(_mt_local_0, 'exe' + 'cute')}['run'](_mt_local_2)
    return _mt_local_0.fetchall()
