"""Adapted from https://github.com/semgrep/semgrep-rules @ a84ff9cc24, python/aws-lambda/security/pymysql-sqli.py, function lambda_handler, line 51. Input: external expression rooted at event."""
SASTLAB_FIXTURE = 'CREATE TABLE rideTransactions (id NUMERIC, userId NUMERIC, stationId NUMERIC, stationName NUMERIC, duration NUMERIC, price NUMERIC, createdDate NUMERIC);INSERT INTO rideTransactions VALUES (1, 1, 1, 1, 1, 1, 1);INSERT INTO rideTransactions VALUES (2, 2, 2, 2, 2, 2, 2);INSERT INTO rideTransactions VALUES (3, 3, 3, 3, 3, 3, 3);'
SASTLAB_EXPLOIT = '1" OR "1"="1'

def _mt_extract_1_0(_mt_local_3):
    return '#\n          SELECT\n            id\n            ,userId\n            ,stationId\n            ,stationName\n            ,duration\n            ,price\n            ,createdDate\n          FROM\n            rideTransactions\n          WHERE\n            userId = "{}"\n          ORDER BY\n            createdDate DESC;\n          '[1:].format(_mt_local_3)

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_local_3 = _mt_local_3
    _mt_local_2 = _mt_extract_1_0(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    getattr(_mt_local_0, 'exe' + 'cute')(_mt_local_2)
    return _mt_local_0.fetchall()
