"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import io as _io
def get_user_profile(db_conn, user_id):
    user_id = _io.StringIO(user_id).read()
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
