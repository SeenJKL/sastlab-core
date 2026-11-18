"""Adapted from OWASP-Benchmark/BenchmarkPython @ f129148580, testcode/BenchmarkTest00454.py, function BenchmarkTest00454_post (expected result: real SQL injection, GPL-3.0). Input: request header replaced by the entry parameter; base64 round trip kept; connection helper and response plumbing replaced."""
SASTLAB_FIXTURE = "CREATE TABLE USERS (username TEXT, password TEXT);INSERT INTO USERS VALUES ('alice','1');INSERT INTO USERS VALUES ('bob','2');INSERT INTO USERS VALUES ('carol','3');"
SASTLAB_EXPLOIT = "1' OR '1'='1"
def get_user_profile(db_conn, user_id):
    param = user_id
    if not param:
        param = ""
    import base64
    tmp = base64.b64encode(param.encode('utf-8'))
    bar = base64.b64decode(tmp).decode('utf-8')
    sql = f"SELECT username from USERS where password = '{bar}'"
    cur = db_conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
