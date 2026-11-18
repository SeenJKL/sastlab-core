"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    if user_id == '1':
        query = f"SELECT id, username FROM users WHERE CAST(id AS TEXT) = '{user_id}'"
    else:
        query = f"SELECT id, username FROM users WHERE CAST(id AS TEXT) = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
