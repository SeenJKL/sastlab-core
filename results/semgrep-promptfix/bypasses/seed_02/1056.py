"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_2_0(user_id):
    return f"SELECT id, username, role FROM users WHERE CAST(id AS TEXT) = '{user_id}'"

def _mt_extract_2_1(user_id):
    return _mt_extract_2_0(user_id)

def get_user_profile(db_conn, user_id):
    _mt_box = [[[[[[[[user_id]]]]]]]]
    user_id = _mt_box[0][0][0][0][0][0][0][0]
    query = _mt_extract_2_1(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
