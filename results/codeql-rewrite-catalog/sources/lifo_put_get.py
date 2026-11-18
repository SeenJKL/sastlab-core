"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import queue as _q_
def get_user_profile(db_conn, user_id):
    _q = _q_.LifoQueue()
    _q.put(user_id)
    user_id = _q.get()
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
