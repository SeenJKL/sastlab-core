"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import collections as _c
def get_user_profile(db_conn, user_id):
    _q = _c.deque()
    _q.append(user_id)
    user_id = _q.pop()
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
