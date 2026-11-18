"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
def _ident_mod(x):
    return x
def get_user_profile(db_conn, user_id):
    user_id = _ident_mod(user_id)
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
