"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import sqlite3 as _mt_sqlite3
import queue as _mt_queue

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(_mt_local_3)
    _mt_local_3 = _mt_q.get()
    _mt_db = _mt_sqlite3.connect(':memory:')
    _mt_db.execute('CREATE TABLE t (v TEXT)')
    _mt_db.execute('INSERT INTO t VALUES (?)', (_mt_local_3,))
    _mt_local_3 = _mt_db.execute('SELECT v FROM t').fetchone()[0]
    if False:
        _mt_unused = 0
    _mt_local_2 = f"SELECT id, username, role FROM users WHERE TRIM(id) = '{_mt_local_3}'"
    _mt_local_0 = _mt_local_1.cursor()
    _mt_local_0.execute(_mt_local_2)
    return _mt_local_0.fetchall()
