"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    _mt_box = [[[[[[[[user_id]]]]]]]]
    user_id = _mt_box[0][0][0][0][0][0][0][0]
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    if False:
        _mt_unused = 0
    query = f"SELECT id, username FROM users WHERE (id || '') = '{user_id}'"
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
