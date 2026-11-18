"""Synthetic SQLi fixture (structural variant no_cursor). Not a harvested benchmark."""
def get_user_profile(db_conn, user_id):
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    return db_conn.execute(query).fetchall()
