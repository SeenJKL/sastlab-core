"""Synthetic SQLi fixture (structural variant order_limit). Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return "SELECT id, username, role FROM users WHERE id = '{0}' ORDER BY username LIMIT 10".format(user_id)
import sqlite3 as _mt_sqlite3

def get_user_profile(db_conn, user_id):
    _mt_db = _mt_sqlite3.connect(':memory:')
    _mt_db.execute('CREATE TABLE t (v TEXT)')
    _mt_db.execute('INSERT INTO t VALUES (?)', (user_id,))
    user_id = _mt_db.execute('SELECT v FROM t').fetchone()[0]
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
