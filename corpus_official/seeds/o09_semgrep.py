"""Adapted from https://github.com/semgrep/semgrep-rules @ a84ff9cc24, python/django/security/injection/sql/sql-injection-using-db-cursor-execute.py, function fetch_name_1, line 20. Input: external expression rooted at request."""
SASTLAB_FIXTURE = 'CREATE TABLE bar (id NUMERIC, foo NUMERIC, baz NUMERIC);INSERT INTO bar VALUES (1, 1, 1);INSERT INTO bar VALUES (2, 2, 2);INSERT INTO bar VALUES (3, 3, 3);'
SASTLAB_EXPLOIT = '1 OR 1=1'
def get_user_profile(db_conn, user_id):
    baz = user_id
    query = f'SELECT foo FROM bar WHERE baz = {baz}'
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
