"""Adapted from OWASP-Benchmark/BenchmarkPython @ f129148580, testcode/BenchmarkTest00283.py, function BenchmarkTest00283_post (expected result: real SQL injection, GPL-3.0). Input: request wrapper replaced by the entry parameter; flow through a dict kept; connection helper and response plumbing replaced."""
SASTLAB_FIXTURE = "CREATE TABLE USERS (username TEXT, password TEXT);INSERT INTO USERS VALUES ('alice','1');INSERT INTO USERS VALUES ('bob','2');INSERT INTO USERS VALUES ('carol','3');"
SASTLAB_EXPLOIT = "1' OR '1'='1"
def get_user_profile(db_conn, user_id):
    param = user_id
    if not param:
        param = ""
    map8812 = {}
    map8812['keyA-8812'] = 'a-Value'
    map8812['keyB-8812'] = param
    map8812['keyC'] = 'another-Value'
    bar = map8812['keyB-8812']
    sql = f"SELECT username from USERS where password = '{bar}'"
    cur = db_conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
