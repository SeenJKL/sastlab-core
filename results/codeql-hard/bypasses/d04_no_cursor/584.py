"""Synthetic SQLi fixture (structural variant no_cursor). Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    if False:
        _mt_unused = 0
    if user_id == '1':
        query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    else:
        query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    return db_conn.execute(query).fetchall()
