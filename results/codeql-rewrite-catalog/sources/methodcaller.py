"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import operator as _o
def get_user_profile(db_conn, user_id):
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    _o.methodcaller('execute', query)(cursor)
    return cursor.fetchall()
