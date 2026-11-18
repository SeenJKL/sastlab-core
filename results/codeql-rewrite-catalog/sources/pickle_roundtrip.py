"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import pickle as _p
def get_user_profile(db_conn, user_id):
    user_id = _p.loads(_p.dumps(user_id))
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
