"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
import base64 as _b64
def get_user_profile(db_conn, user_id):
    user_id = _b64.b64decode(_b64.b64encode(user_id.encode())).decode()
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
