"""Synthetic SQLi fixture (structural variant str_format). Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    _mt_box = [[[[[[[[user_id]]]]]]]]
    user_id = _mt_box[0][0][0][0][0][0][0][0]
    query = "#SELECT id, username, role FROM users WHERE id = '{}'"[1:].format(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
