"""Adapted from OWASP-Benchmark/BenchmarkPython @ f129148580, testcode/BenchmarkTest00455.py, function BenchmarkTest00455_post (expected result: real SQL injection, GPL-3.0). Input: request header replaced by the entry parameter; flow through a dict kept; connection helper and response plumbing replaced."""
SASTLAB_FIXTURE = "CREATE TABLE USERS (username TEXT, password TEXT);INSERT INTO USERS VALUES ('alice','1');INSERT INTO USERS VALUES ('bob','2');INSERT INTO USERS VALUES ('carol','3');"
SASTLAB_EXPLOIT = "1' OR '1'='1"
def get_user_profile(db_conn, user_id):
    param = user_id
    if not param:
        param = ""
    map61311 = {}
    map61311['keyA-61311'] = 'a-Value'
    map61311['keyB-61311'] = param
    map61311['keyC'] = 'another-Value'
    bar = map61311['keyB-61311']
    sql = f"SELECT username from USERS where password = '{bar}'"
    cur = db_conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
