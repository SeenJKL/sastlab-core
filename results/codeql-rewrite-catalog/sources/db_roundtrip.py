"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import sqlite3 as _s3
def get_user_profile(db_conn, user_id):
    _d = _s3.connect(':memory:')
    _d.execute('CREATE TABLE t (v TEXT)')
    _d.execute('INSERT INTO t VALUES (?)', (user_id,))
    user_id = _d.execute('SELECT v FROM t').fetchone()[0]
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
