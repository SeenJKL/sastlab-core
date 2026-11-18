"""Synthetic SQLi fixture (structural variant no_cursor). Not a harvested benchmark."""
import sqlite3 as _mt_sqlite3

def get_user_profile(_mt_local_0, _mt_local_2):
    _mt_db = _mt_sqlite3.connect(':memory:')
    _mt_db.execute('CREATE TABLE t (v TEXT)')
    _mt_db.execute('INSERT INTO t VALUES (?)', (_mt_local_2,))
    _mt_local_2 = _mt_db.execute('SELECT v FROM t').fetchone()[0]
    _mt_local_1 = "#SELECT id, username, role FROM users WHERE id = '{0}'"[1:].format(_mt_local_2)
    return _mt_local_0.execute(_mt_local_1).fetchall()
