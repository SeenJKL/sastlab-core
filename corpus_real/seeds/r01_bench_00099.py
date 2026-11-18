"""Adapted from OWASP-Benchmark/BenchmarkPython @ f129148580, testcode/BenchmarkTest00099.py, function BenchmarkTest00099_post (expected result: real SQL injection, GPL-3.0). Input: form parameter replaced by the entry parameter; flow through configparser kept; connection helper and response plumbing replaced by db_conn.cursor().execute and fetchall."""
SASTLAB_FIXTURE = "CREATE TABLE USERS (username TEXT, password TEXT);INSERT INTO USERS VALUES ('alice','1');INSERT INTO USERS VALUES ('bob','2');INSERT INTO USERS VALUES ('carol','3');"
SASTLAB_EXPLOIT = "1' OR '1'='1"
def get_user_profile(db_conn, user_id):
    param = user_id
    if not param:
        param = ""
    import configparser
    bar = 'safe!'
    conf52528 = configparser.ConfigParser()
    conf52528.add_section('section52528')
    conf52528.set('section52528', 'keyA-52528', 'a-Value')
    conf52528.set('section52528', 'keyB-52528', param)
    bar = conf52528.get('section52528', 'keyB-52528')
    sql = f"SELECT username from USERS where password = '{bar}'"
    cur = db_conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
