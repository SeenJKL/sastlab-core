"""Adapted from https://github.com/semgrep/semgrep-rules @ a84ff9cc24, python/aws-lambda/security/pymysql-sqli.py, function lambda_handler, line 51. Input: external expression rooted at event."""
SASTLAB_FIXTURE = 'CREATE TABLE rideTransactions (id NUMERIC, userId NUMERIC, stationId NUMERIC, stationName NUMERIC, duration NUMERIC, price NUMERIC, createdDate NUMERIC);INSERT INTO rideTransactions VALUES (1, 1, 1, 1, 1, 1, 1);INSERT INTO rideTransactions VALUES (2, 2, 2, 2, 2, 2, 2);INSERT INTO rideTransactions VALUES (3, 3, 3, 3, 3, 3, 3);'
SASTLAB_EXPLOIT = '1" OR "1"="1'

def _mt_extract_1_0(user_id):
    return '#\n          SELECT\n            id\n            ,userId\n            ,stationId\n            ,stationName\n            ,duration\n            ,price\n            ,createdDate\n          FROM\n            rideTransactions\n          WHERE\n            userId = "{}"\n          ORDER BY\n            createdDate DESC;\n          '[1:].format(user_id)
import queue as _mt_queue

def get_user_profile(db_conn, user_id):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(user_id)
    user_id = _mt_q.get()
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    user_id = user_id
    if False:
        _mt_unused = 0
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    {'run': cursor.execute}['run'](query)
    return cursor.fetchall()
