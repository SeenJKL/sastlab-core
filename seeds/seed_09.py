"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""
def get_user_profile(db_conn, user_id):
    query = f"SELECT username, role FROM users WHERE COALESCE(id, '') = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
