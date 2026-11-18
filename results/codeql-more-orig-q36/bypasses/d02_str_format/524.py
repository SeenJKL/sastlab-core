"""Synthetic SQLi fixture (structural variant str_format). Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    if False:
        _mt_unused = 0
    query = "#SELECT id, username, role FROM users WHERE id = '{}'"[1:].format(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
