"""Synthetic SQLi fixture (structural variant percent). Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return "SELECT id, username, role FROM users WHERE id = '%s'" % user_id
import sqlite3 as _mt_sqlite3

def get_user_profile(db_conn, user_id):
    _mt_db = _mt_sqlite3.connect(':memory:')
    _mt_db.execute('CREATE TABLE t (v TEXT)')
    _mt_db.execute('INSERT INTO t VALUES (?)', (user_id,))
    user_id = _mt_db.execute('SELECT v FROM t').fetchone()[0]
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
