"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import sqlite3 as _mt_sqlite3

def get_user_profile(db_conn, user_id):
    _mt_db = _mt_sqlite3.connect(':memory:')
    _mt_db.execute('CREATE TABLE t (v TEXT)')
    _mt_db.execute('INSERT INTO t VALUES (?)', (user_id,))
    user_id = _mt_db.execute('SELECT v FROM t').fetchone()[0]
    _mt_box = [[[[[[[[user_id]]]]]]]]
    user_id = _mt_box[0][0][0][0][0][0][0][0]
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    if False:
        _mt_unused = 0
    query = f"SELECT id, username, role FROM users WHERE TRIM(id) = '{user_id}'"
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
