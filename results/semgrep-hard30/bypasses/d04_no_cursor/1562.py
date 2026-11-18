"""Synthetic SQLi fixture (structural variant no_cursor). Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return "SELECT id, username, role FROM users WHERE id = '{0}'".format(user_id)

def get_user_profile(db_conn, user_id):
    _mt_box = [[[[[[[[user_id]]]]]]]]
    user_id = _mt_box[0][0][0][0][0][0][0][0]
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    if False:
        _mt_unused = 0
    query = _mt_extract_1_0(user_id)
    return db_conn.execute(query).fetchall()
