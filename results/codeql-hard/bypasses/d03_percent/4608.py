"""Synthetic SQLi fixture (structural variant percent). Not a harvested benchmark."""
import queue as _mt_queue

def get_user_profile(db_conn, user_id):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(user_id)
    user_id = _mt_q.get()
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    query = "SELECT id, username, role FROM users WHERE id = '%s'" % user_id
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
