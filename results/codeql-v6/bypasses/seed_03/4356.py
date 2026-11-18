"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import queue as _mt_queue

def get_user_profile(db_conn, user_id):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(user_id)
    user_id = _mt_q.get()
    query = f"""{"#SELECT id, username, role FROM users WHERE TRIM(id) = '"[1:]}{user_id}{"#'"[1:]}"""
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
