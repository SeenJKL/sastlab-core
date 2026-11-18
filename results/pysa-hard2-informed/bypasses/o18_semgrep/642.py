"""Adapted from https://github.com/semgrep/semgrep-rules @ a84ff9cc24, python/lang/security/audit/sqli/aiopg-sqli.py, function bad1, line 12. Input: external expression rooted at req."""
SASTLAB_FIXTURE = 'CREATE TABLE users (id NUMERIC, name NUMERIC, age NUMERIC);INSERT INTO users VALUES (1, 1, 1);INSERT INTO users VALUES (2, 2, 2);INSERT INTO users VALUES (3, 3, 3);'
SASTLAB_EXPLOIT = '1 OR 1=1'

def get_user_profile(db_conn, user_id):
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    query = ''.join(['SELECT name FROM users WHERE age=', user_id])
    cursor = db_conn.cursor()
    {'run': cursor.execute}['run'](query)
    return cursor.fetchall()
