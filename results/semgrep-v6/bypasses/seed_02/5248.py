"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import queue as _mt_queue

def get_user_profile(db_conn, user_id):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(user_id)
    user_id = _mt_q.get()
    _mt_box = [[[[[[[[user_id]]]]]]]]
    user_id = _mt_box[0][0][0][0][0][0][0][0]
    query = f"SELECT id, username, role FROM users WHERE CAST(id AS TEXT) = '{user_id}'"
    cursor = db_conn.cursor()
    {'run': cursor.execute}['run'](query)
    return cursor.fetchall()
