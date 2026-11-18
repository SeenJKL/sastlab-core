"""Adapted from https://github.com/semgrep/semgrep-rules @ a84ff9cc24, python/aws-lambda/security/sqlalchemy-sqli.py, function handler, line 46. Input: external expression rooted at event."""
SASTLAB_FIXTURE = 'CREATE TABLE foobar (id NUMERIC);INSERT INTO foobar VALUES (1);INSERT INTO foobar VALUES (2);INSERT INTO foobar VALUES (3);'
SASTLAB_EXPLOIT = "1' OR '1'='1"
def get_user_profile(db_conn, user_id):
    query = f"SELECT * FROM foobar WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
