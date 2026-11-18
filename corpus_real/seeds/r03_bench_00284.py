"""Adapted from OWASP-Benchmark/BenchmarkPython @ f129148580, testcode/BenchmarkTest00284.py, function BenchmarkTest00284_post (expected result: real SQL injection, GPL-3.0). Input: request wrapper replaced by the entry parameter; conditional flow kept; connection helper and response plumbing replaced."""
SASTLAB_FIXTURE = "CREATE TABLE USERS (username TEXT, password TEXT);INSERT INTO USERS VALUES ('alice','1');INSERT INTO USERS VALUES ('bob','2');INSERT INTO USERS VALUES ('carol','3');"
SASTLAB_EXPLOIT = "1' OR '1'='1"
def get_user_profile(db_conn, user_id):
    param = user_id
    if not param:
        param = ""
    bar = "This should never happen"
    if 'should' in bar:
        bar = param
    sql = f"SELECT username from USERS where password = '{bar}'"
    cur = db_conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
