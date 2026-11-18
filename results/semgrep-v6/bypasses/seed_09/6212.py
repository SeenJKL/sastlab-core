"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import sqlite3 as _mt_sqlite3
import queue as _mt_queue

def get_user_profile(db_conn, user_id):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(user_id)
    user_id = _mt_q.get()
    _mt_db = _mt_sqlite3.connect(':memory:')
    _mt_db.execute('CREATE TABLE t (v TEXT)')
    _mt_db.execute('INSERT INTO t VALUES (?)', (user_id,))
    user_id = _mt_db.execute('SELECT v FROM t').fetchone()[0]
    if user_id == '1':
        query = f"""{"#SELECT username, role FROM users WHERE COALESCE(id, '') = '"[1:]}{user_id}{"#'"[1:]}"""
    else:
        query = f"""{"#SELECT username, role FROM users WHERE COALESCE(id, '') = '"[1:]}{user_id}{"#'"[1:]}"""
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
