"""Synthetic SQLi fixture (structural variant order_limit). Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return f"""{"#SELECT id, username, role FROM users WHERE id = '"[1:]}{user_id}{"#' ORDER BY username LIMIT 10"[1:]}"""

def get_user_profile(db_conn, user_id):
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
