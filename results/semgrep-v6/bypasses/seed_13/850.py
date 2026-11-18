"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return "SELECT id, username FROM users WHERE TRIM(id) = '{0}'".format(user_id)

def get_user_profile(db_conn, user_id):
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    if user_id == '1':
        query = _mt_extract_1_0(user_id)
    else:
        query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
