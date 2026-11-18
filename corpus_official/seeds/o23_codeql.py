"""Adapted from https://github.com/github/codeql @ 6e9f9e3839, query-tests/CWE-089-SqlInjection/app.py, function unsafe, line 23. Input: parameter name."""
SASTLAB_FIXTURE = 'CREATE TABLE users (id NUMERIC, name NUMERIC);INSERT INTO users VALUES (1, 1);INSERT INTO users VALUES (2, 2);INSERT INTO users VALUES (3, 3);'
SASTLAB_EXPLOIT = '1 OR 1=1'
def get_user_profile(db_conn, user_id):
    query = 'select * from users where name=' + user_id
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
