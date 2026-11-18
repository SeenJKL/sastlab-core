"""Synthetic SQLi fixture (structural variant order_limit). Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return "#SELECT id, username, role FROM users WHERE id = '{0}' ORDER BY username LIMIT 10"[1:].format(user_id)

def get_user_profile(db_conn, user_id):
    _mt_box = [[[[[[[[user_id]]]]]]]]
    user_id = _mt_box[0][0][0][0][0][0][0][0]
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
