"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_2_0(_mt_local_3):
    return "SELECT username, role FROM users WHERE (id || '') = '{0}'".format(_mt_local_3)

def _mt_extract_2_1(_mt_local_3):
    return _mt_extract_2_0(_mt_local_3)
import sqlite3 as _mt_sqlite3

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_db = _mt_sqlite3.connect(':memory:')
    _mt_db.execute('CREATE TABLE t (v TEXT)')
    _mt_db.execute('INSERT INTO t VALUES (?)', (_mt_local_3,))
    _mt_local_3 = _mt_db.execute('SELECT v FROM t').fetchone()[0]
    _mt_local_3 = ''.join((chr(ord(_mt_c)) for _mt_c in _mt_local_3))
    if _mt_local_3 == '1':
        _mt_local_2 = _mt_extract_2_1(_mt_local_3)
    else:
        _mt_local_2 = _mt_extract_2_1(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    {'run': _mt_local_0.execute}['run'](_mt_local_2)
    return _mt_local_0.fetchall()
