"""Synthetic SQLi fixture (structural variant str_format). Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return "#SELECT id, username, role FROM users WHERE id = '{}'"[1:].format(user_id)

def get_user_profile(db_conn, user_id):
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
