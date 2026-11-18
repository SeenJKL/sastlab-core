"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_2_0(user_id):
    return f"SELECT id, username FROM users WHERE COALESCE(id, '') = '{user_id}'"

def _mt_extract_2_1(user_id):
    return _mt_extract_2_0(user_id)
import queue as _mt_queue

def get_user_profile(db_conn, user_id):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(user_id)
    user_id = _mt_q.get()
    if user_id == '1':
        query = _mt_extract_2_1(user_id)
    else:
        query = _mt_extract_2_1(user_id)
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
