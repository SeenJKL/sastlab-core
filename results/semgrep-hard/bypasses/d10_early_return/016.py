"""Synthetic SQLi fixture (structural variant early_return). Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return f"SELECT id, username, role FROM users WHERE id = '{user_id}'"

def get_user_profile(db_conn, user_id):
    if not user_id:
        return []
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
