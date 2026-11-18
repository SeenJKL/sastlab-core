"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import json as _j
def get_user_profile(db_conn, user_id):
    user_id = _j.loads(_j.dumps(user_id))
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
