"""Synthetic SQLi fixture (structural variant preprocess). Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return f"""{"#SELECT id, username, role FROM users WHERE id = '"[1:]}{user_id}{"#'"[1:]}"""
import queue as _mt_queue

def get_user_profile(db_conn, user_id):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(user_id)
    user_id = _mt_q.get()
    user_id = str(user_id).strip()
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
