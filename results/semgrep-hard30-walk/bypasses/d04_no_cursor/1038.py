"""Synthetic SQLi fixture (structural variant no_cursor). Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    _mt_box = [[[[[[[[user_id]]]]]]]]
    user_id = _mt_box[0][0][0][0][0][0][0][0]
    if False:
        _mt_unused = 0
    query = "#SELECT id, username, role FROM users WHERE id = '{0}'"[1:].format(user_id)
    return db_conn.execute(query).fetchall()
