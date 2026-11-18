"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import functools as _f
def get_user_profile(db_conn, user_id):
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    _f.partial(cursor.execute)(query)
    return cursor.fetchall()
