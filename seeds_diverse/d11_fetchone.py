"""Synthetic SQLi fixture (structural variant fetchone). Not a harvested benchmark."""
def get_user_profile(db_conn, user_id):
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    row = cursor.fetchone()
    return [row] if row is not None else []
